// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use std::{collections::BTreeMap, path::PathBuf};

pub type AddressDeclarations = BTreeMap<Identifier, Option<AccountAddress>>;
pub type DevAddressDeclarations = BTreeMap<Identifier, AccountAddress>;
pub type Version = (u64, u64, u64);
pub type Dependencies = BTreeMap<Identifier, Dependency>;
pub type Substitution = BTreeMap<Identifier, SubstOrRename>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceManifest {
    pub package: PackageInfo,
    pub addresses: Option<AddressDeclarations>,
    pub dev_address_assignments: Option<DevAddressDeclarations>,
    pub build: Option<BuildInfo>,
    pub dependencies: Dependencies,
    pub dev_dependencies: Dependencies,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PackageInfo {
    pub name: Identifier,
    pub version: Version,
    pub authors: Vec<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Dependency {
    pub local: Option<PathBuf>,
    pub subst: Option<Substitution>,
    pub version: Option<Version>,
    pub digest: Option<Vec<u8>>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct BuildInfo {
    pub source_version: Option<Version>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SubstOrRename {
    RenameFrom(Identifier),
    Assign(AccountAddress),
}
