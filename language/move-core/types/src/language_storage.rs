// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub const CODE_TAG: u8 = 0;
pub const RESOURCE_TAG: u8 = 1;

pub const CORE_CODE_ADDRESS: AccountAddress = AccountAddress::new([
    0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8,
]);

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub enum TypeTag {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(StructTag),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub struct StructTag {
    pub address: AccountAddress,
    pub module: Identifier,
    pub name: Identifier,
    // TODO: rename to "type_args" (or better "ty_args"?)
    pub type_params: Vec<TypeTag>,
}

impl StructTag {
    pub fn access_vector(&self) -> Vec<u8> {
        let mut key = vec![RESOURCE_TAG];
        key.append(&mut bcs::to_bytes(self).unwrap());
        key
    }

    pub fn module_id(&self) -> ModuleId {
        ModuleId::new(self.address, self.module.to_owned())
    }
}

/// Represents the intitial key into global storage where we first index by the address, and then
/// the struct tag
#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub struct ResourceKey {
    pub address: AccountAddress,
    pub type_: StructTag,
}

impl ResourceKey {
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    pub fn type_(&self) -> &StructTag {
        &self.type_
    }
}

impl ResourceKey {
    pub fn new(address: AccountAddress, type_: StructTag) -> Self {
        ResourceKey { address, type_ }
    }
}

/// Represents the initial key into global storage where we first index by the address, and then
/// the struct tag
#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
#[cfg_attr(any(test, feature = "fuzzing"), proptest(no_params))]
pub struct ModuleId {
    address: AccountAddress,
    name: Identifier,
}

impl From<ModuleId> for (AccountAddress, Identifier) {
    fn from(module_id: ModuleId) -> Self {
        (module_id.address, module_id.name)
    }
}

impl ModuleId {
    pub fn new(address: AccountAddress, name: Identifier) -> Self {
        ModuleId { address, name }
    }

    pub fn name(&self) -> &IdentStr {
        &self.name
    }

    pub fn address(&self) -> &AccountAddress {
        &self.address
    }

    pub fn access_vector(&self) -> Vec<u8> {
        let mut key = vec![CODE_TAG];
        key.append(&mut bcs::to_bytes(self).unwrap());
        key
    }
}

impl Display for ModuleId {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}::{}", self.address, self.name)
    }
}

impl Display for StructTag {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "0x{}::{}::{}",
            self.address.short_str_lossless(),
            self.module,
            self.name
        )?;
        if let Some(first_ty) = self.type_params.first() {
            write!(f, "<")?;
            write!(f, "{}", first_ty)?;
            for ty in self.type_params.iter().skip(1) {
                write!(f, ", {}", ty)?;
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}

impl Display for TypeTag {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            TypeTag::Struct(s) => write!(f, "{}", s),
            TypeTag::Vector(ty) => write!(f, "Vector<{}>", ty),
            TypeTag::U8 => write!(f, "U8"),
            TypeTag::U64 => write!(f, "U64"),
            TypeTag::U128 => write!(f, "U128"),
            TypeTag::Address => write!(f, "Address"),
            TypeTag::Signer => write!(f, "Signer"),
            TypeTag::Bool => write!(f, "Bool"),
        }
    }
}

// =================================================================================================
// Type definition with free type variables

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum Type {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<Type>),
    Struct(StructType),
    TypeArg(usize),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct StructType {
    pub address: AccountAddress,
    pub module: Identifier,
    pub name: Identifier,
    pub type_params: Vec<Type>,
}

impl Type {
    pub fn is_free(&self) -> bool {
        match self {
            Type::TypeArg(_) => true,
            Type::Bool | Type::U8 | Type::U64 |  Type::U128 | Type::Address | Type::Signer | Type::Vector(_) => false,
            Type::Struct(s) => s.is_free(),
        }
    }
    pub fn subst(self, type_args: &[TypeTag]) -> Option<TypeTag> {
        Some(match self {
            Type::Bool => TypeTag::Bool,
            Type::U8 => TypeTag::U8,
            Type::U64 => TypeTag::U64,
            Type::U128 => TypeTag::U128,
            Type::Address => TypeTag::Address,
            Type::Signer => TypeTag::Signer,
            Type::Vector(ty) => TypeTag::Vector(Box::new(ty.subst(type_args)?)),
            Type::Struct(s) => TypeTag::Struct(s.subst(type_args)?),
            Type::TypeArg(idx) => type_args
                .get(idx)?
                .clone(),
        })
    }

    pub fn to_type_tag(self) -> Option<TypeTag> {
        self.subst(&[])
    }
}

impl StructType {
    pub fn is_free(&self) -> bool {
        self.type_params.is_empty() || self.type_params.iter().all(|ty| ty.is_free())
    }

    pub fn subst(self, type_args: &[TypeTag]) -> Option<StructTag> {
        Some(StructTag {
            address: self.address,
            module: self.module,
            name: self.name,
            type_params: self
                .type_params
                .into_iter()
                .map(|ty| ty.subst(type_args))
                .collect::<Option<Vec<_>>>()?,
        })
    }

    pub fn to_struct_tag(self) -> Option<StructTag> {
        self.subst(&[])
    }
}

impl From<TypeTag> for Type {
    fn from(ty: TypeTag) -> Type {
        match ty {
            TypeTag::Bool => Type::Bool,
            TypeTag::U8 => Type::U8,
            TypeTag::U64 => Type::U64,
            TypeTag::U128 => Type::U128,
            TypeTag::Address => Type::Address,
            TypeTag::Signer => Type::Signer,
            TypeTag::Vector(ty) => Type::Vector(Box::new(Type::from(*ty))),
            TypeTag::Struct(s) => Type::Struct(s.into()),
        }
    }
}

impl From<StructTag> for StructType {
    fn from(ty: StructTag) -> StructType {
        StructType {
            name: ty.name,
            module: ty.module,
            address: ty.address,
            type_params: ty.type_params.into_iter().map(Type::from).collect(),
        }
    }
}


impl Display for StructType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "0x{}::{}::{}",
            self.address.short_str_lossless(),
            self.module,
            self.name
        )?;
        if let Some(first_ty) = self.type_params.first() {
            write!(f, "<")?;
            write!(f, "{}", first_ty)?;
            for ty in self.type_params.iter().skip(1) {
                write!(f, ", {}", ty)?;
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Type::Struct(s) => write!(f, "{}", s),
            Type::Vector(ty) => write!(f, "Vector<{}>", ty),
            Type::U8 => write!(f, "U8"),
            Type::U64 => write!(f, "U64"),
            Type::U128 => write!(f, "U128"),
            Type::Address => write!(f, "Address"),
            Type::Signer => write!(f, "Signer"),
            Type::Bool => write!(f, "Bool"),
            Type::TypeArg(i) => write!(f, "#{:?}", i),
        }
    }
}
