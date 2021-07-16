// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Contains types and related functions.

use crate::{
    ast::QualifiedSymbol,
    model::{GlobalEnv, ModuleId, StructEnv, StructId},
    symbol::{Symbol, SymbolPool},
};
use move_core_types::language_storage::{StructTag, TypeTag};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::Formatter,
};

/// Represents a type.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum Type {
    Primitive(PrimitiveType),
    Tuple(Vec<Type>),
    Vector(Box<Type>),
    Struct(ModuleId, StructId, Vec<Type>),
    TypeParameter(u16),

    // Types only appearing in programs.
    Reference(bool, Box<Type>),

    // Types only appearing in specifications
    Fun(Vec<Type>, Box<Type>),
    TypeDomain(Box<Type>),
    ResourceDomain(ModuleId, StructId, Option<Vec<Type>>),
    TypeLocal(Symbol),

    // Temporary types used during type checking
    Error,
    Var(u16),
}

pub const BOOL_TYPE: Type = Type::Primitive(PrimitiveType::Bool);
pub const NUM_TYPE: Type = Type::Primitive(PrimitiveType::Num);

/// Represents a primitive (builtin) type.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum PrimitiveType {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    // Types only appearing in specifications
    Num,
    Range,
    TypeValue,
    EventStore,
}

/// A type substitution.
#[derive(Debug, Clone)]
pub struct Substitution {
    subs: BTreeMap<u16, Type>,
}

/// Represents an error resulting from type unification.
pub enum TypeUnificationError {
    TypeMismatch(Type, Type),
    ArityMismatch(String, usize, usize),
    CyclicSubstitution(Type, Type),
}

impl PrimitiveType {
    /// Returns true if this type is a specification language only type
    pub fn is_spec(&self) -> bool {
        use PrimitiveType::*;
        match self {
            Bool | U8 | U64 | U128 | Address | Signer => false,
            Num | Range | TypeValue | EventStore => true,
        }
    }

    /// Attempt to convert this type into a language_storage::TypeTag
    pub fn into_type_tag(self) -> Option<TypeTag> {
        use PrimitiveType::*;
        Some(match self {
            Bool => TypeTag::Bool,
            U8 => TypeTag::U8,
            U64 => TypeTag::U64,
            U128 => TypeTag::U128,
            Address => TypeTag::Address,
            Signer => TypeTag::Signer,
            Num | Range | TypeValue | EventStore => return None,
        })
    }
}

impl Type {
    pub fn new_prim(p: PrimitiveType) -> Type {
        Type::Primitive(p)
    }

    /// Determines whether this is a type parameter.
    pub fn is_type_parameter(&self) -> bool {
        matches!(self, Type::TypeParameter(..))
    }

    /// Determines whether this is a reference.
    pub fn is_reference(&self) -> bool {
        matches!(self, Type::Reference(_, _))
    }

    /// Determines whether this is a mutable reference.
    pub fn is_mutable_reference(&self) -> bool {
        matches!(self, Type::Reference(true, _))
    }

    /// Determines whether this is an immutable reference.
    pub fn is_immutable_reference(&self) -> bool {
        matches!(self, Type::Reference(false, _))
    }

    /// Determines whether this type is a struct.
    pub fn is_struct(&self) -> bool {
        matches!(self, Type::Struct(..))
    }

    /// Determines whether this type is a vector
    pub fn is_vector(&self) -> bool {
        matches!(self, Type::Vector(..))
    }

    /// Determines whether this is a struct, or a vector of structs, or a reference to any of
    /// those.
    pub fn is_struct_or_vector_of_struct(&self) -> bool {
        match self.skip_reference() {
            Type::Struct(..) => true,
            Type::Vector(ety) => ety.is_struct_or_vector_of_struct(),
            _ => false,
        }
    }

    /// Returns true if this type is a specification language only type or contains specification
    /// language only types
    pub fn is_spec(&self) -> bool {
        use Type::*;
        match self {
            Primitive(p) => p.is_spec(),
            Fun(..) | TypeDomain(..) | TypeLocal(..) | ResourceDomain(..) | Error => true,
            Var(..) | TypeParameter(..) => false,
            Tuple(ts) => ts.iter().any(|t| t.is_spec()),
            Struct(_, _, ts) => ts.iter().any(|t| t.is_spec()),
            Vector(et) => et.is_spec(),
            Reference(_, bt) => bt.is_spec(),
        }
    }

    /// Returns true if this is any number type.
    pub fn is_number(&self) -> bool {
        if let Type::Primitive(p) = self {
            if let PrimitiveType::U8
            | PrimitiveType::U64
            | PrimitiveType::U128
            | PrimitiveType::Num = p
            {
                return true;
            }
        }
        false
    }
    /// Returns true if this is an address or signer type.
    pub fn is_signer_or_address(&self) -> bool {
        matches!(
            self,
            Type::Primitive(PrimitiveType::Signer) | Type::Primitive(PrimitiveType::Address)
        )
    }

    /// Return true if this is an account address
    pub fn is_address(&self) -> bool {
        matches!(self, Type::Primitive(PrimitiveType::Address))
    }

    /// Skip reference type.
    pub fn skip_reference(&self) -> &Type {
        if let Type::Reference(_, bt) = self {
            &*bt
        } else {
            self
        }
    }

    /// If this is a struct type, replace the type instantiation.
    pub fn replace_struct_instantiation(&self, inst: &[Type]) -> Type {
        match self {
            Type::Struct(mid, sid, _) => Type::Struct(*mid, *sid, inst.to_vec()),
            _ => self.clone(),
        }
    }

    /// If this is a struct type, return the associated struct env and type parameters.
    pub fn get_struct<'env>(
        &'env self,
        env: &'env GlobalEnv,
    ) -> Option<(StructEnv<'env>, &'env [Type])> {
        if let Type::Struct(module_idx, struct_idx, params) = self {
            Some((env.get_module(*module_idx).into_struct(*struct_idx), params))
        } else {
            None
        }
    }

    /// Require this to be a struct, if so extracts its content.
    pub fn require_struct(&self) -> (ModuleId, StructId, &[Type]) {
        if let Type::Struct(mid, sid, targs) = self {
            (*mid, *sid, targs.as_slice())
        } else {
            panic!("expected `Type::Struct`, found: `{:?}`", self)
        }
    }

    /// Instantiates type parameters in this type.
    pub fn instantiate(&self, params: &[Type]) -> Type {
        if params.is_empty() {
            self.clone()
        } else {
            self.replace(Some(params), None, None)
        }
    }

    /// Instantiate type parameters in the vector of types.
    pub fn instantiate_vec(vec: Vec<Type>, params: &[Type]) -> Vec<Type> {
        if params.is_empty() {
            vec
        } else {
            vec.into_iter().map(|ty| ty.instantiate(params)).collect()
        }
    }

    /// Instantiate type parameters in the slice of types.
    pub fn instantiate_slice(slice: &[Type], params: &[Type]) -> Vec<Type> {
        if params.is_empty() {
            slice.to_owned()
        } else {
            slice.iter().map(|ty| ty.instantiate(params)).collect()
        }
    }

    /// Replace the given type local.
    pub fn replace_type_local(&self, local: Symbol, repl: Type) -> Type {
        let mut subs = BTreeMap::new();
        subs.insert(local, repl);
        self.replace(None, None, Some(&subs))
    }

    /// A helper function to do replacement of type parameters and/or type variables.
    fn replace(
        &self,
        params: Option<&[Type]>,
        subs: Option<&Substitution>,
        type_local_subs: Option<&BTreeMap<Symbol, Type>>,
    ) -> Type {
        let replace_vec = |types: &[Type]| {
            types
                .iter()
                .map(|t| t.replace(params, subs, type_local_subs))
                .collect()
        };
        match self {
            Type::TypeParameter(i) => {
                if let Some(ps) = params {
                    ps[*i as usize].clone()
                } else {
                    self.clone()
                }
            }
            Type::Var(i) => {
                if let Some(s) = subs {
                    if let Some(t) = s.subs.get(i) {
                        // Recursively call replacement again here, in case the substitution s
                        // refers to type variables.
                        // TODO: a more efficient approach is to maintain that type assignments
                        // are always fully specialized w.r.t. to the substitution.
                        t.replace(params, subs, type_local_subs)
                    } else {
                        self.clone()
                    }
                } else {
                    self.clone()
                }
            }
            Type::TypeLocal(sym) => {
                if let Some(subs) = type_local_subs {
                    if let Some(t) = subs.get(sym) {
                        t.clone()
                    } else {
                        self.clone()
                    }
                } else {
                    self.clone()
                }
            }
            Type::Reference(is_mut, bt) => {
                Type::Reference(*is_mut, Box::new(bt.replace(params, subs, type_local_subs)))
            }
            Type::Struct(mid, sid, args) => Type::Struct(*mid, *sid, replace_vec(args)),
            Type::Fun(args, result) => Type::Fun(
                replace_vec(args),
                Box::new(result.replace(params, subs, type_local_subs)),
            ),
            Type::Tuple(args) => Type::Tuple(replace_vec(args)),
            Type::Vector(et) => Type::Vector(Box::new(et.replace(params, subs, type_local_subs))),
            Type::TypeDomain(et) => {
                Type::TypeDomain(Box::new(et.replace(params, subs, type_local_subs)))
            }
            Type::ResourceDomain(..) | Type::Primitive(..) | Type::Error => self.clone(),
        }
    }

    /// Checks whether this type contains a type for which the predicate is true.
    pub fn contains<P>(&self, p: &P) -> bool
    where
        P: Fn(&Type) -> bool,
    {
        if p(self) {
            true
        } else {
            let contains_vec = |ts: &[Type]| ts.iter().any(p);
            match self {
                Type::Reference(_, bt) => bt.contains(p),
                Type::Struct(_, _, args) => contains_vec(args),
                Type::Fun(args, result) => contains_vec(args) || result.contains(p),
                Type::Tuple(args) => contains_vec(args),
                Type::Vector(et) => et.contains(p),
                _ => false,
            }
        }
    }

    /// Returns true if this type is incomplete, i.e. contains any type variables.
    pub fn is_incomplete(&self) -> bool {
        use Type::*;
        match self {
            Var(_) => true,
            Tuple(ts) => ts.iter().any(|t| t.is_incomplete()),
            Fun(ts, r) => ts.iter().any(|t| t.is_incomplete()) || r.is_incomplete(),
            Struct(_, _, ts) => ts.iter().any(|t| t.is_incomplete()),
            Vector(et) => et.is_incomplete(),
            Reference(_, bt) => bt.is_incomplete(),
            TypeDomain(bt) => bt.is_incomplete(),
            Error | Primitive(..) | TypeLocal(..) | TypeParameter(_) | ResourceDomain(..) => false,
        }
    }

    /// Return true if this type contains free type variables
    pub fn is_open(&self) -> bool {
        use Type::*;
        match self {
            TypeParameter(_) | TypeLocal(_) => true,
            Primitive(_) | ResourceDomain(..) => false,
            Tuple(ts) => ts.iter().any(|t| t.is_open()),
            Fun(ts, r) => ts.iter().any(|t| t.is_open()) || r.is_open(),
            Struct(_, _, ts) => ts.iter().any(|t| t.is_open()),
            Vector(et) => et.is_open(),
            Reference(_, bt) => bt.is_open(),
            TypeDomain(bt) => bt.is_open(),
            Error | Var(_) => {
                panic!("Invariant violation: is_open should be called after type checking")
            }
        }
    }

    /// Compute used modules in this type, adding them to the passed set.
    pub fn module_usage(&self, usage: &mut BTreeSet<ModuleId>) {
        use Type::*;
        match self {
            Tuple(ts) => ts.iter().for_each(|t| t.module_usage(usage)),
            Fun(ts, r) => {
                ts.iter().for_each(|t| t.module_usage(usage));
                r.module_usage(usage);
            }
            Struct(mid, _, ts) => {
                usage.insert(*mid);
                ts.iter().for_each(|t| t.module_usage(usage));
            }
            Vector(et) => et.module_usage(usage),
            Reference(_, bt) => bt.module_usage(usage),
            TypeDomain(bt) => bt.module_usage(usage),
            _ => {}
        }
    }

    pub fn into_struct_tag(self, env: &GlobalEnv) -> Option<StructTag> {
        use Type::*;
        if self.is_open() {
            None
        } else {
            Some (
                match self {
		    Struct(mid, sid, ts) =>
                        env.get_struct_tag(mid, sid, &ts)
                            .expect("Invariant violation: struct type argument contains incomplete, tuple, reference, or spec type"),

                    _ => return None
		}
	    )
        }
    }

    /// Attempt to convert this type into a language_storage::TypeTag
    pub fn into_type_tag(self, env: &GlobalEnv) -> Option<TypeTag> {
        use Type::*;
        if self.is_open() || self.is_reference() || self.is_spec() {
            None
        } else {
            Some (
                match self {
                    Primitive(p) => p.into_type_tag().expect("Invariant violation: unexpected spec primitive"),
                    Struct(mid, sid, ts) =>TypeTag::Struct(
                        env.get_struct_tag(mid, sid, &ts)
                            .expect("Invariant violation: struct type argument contains incomplete, tuple, reference, or spec type")
                    ),
                    Vector(et) => TypeTag::Vector(
                        Box::new(et.into_type_tag(env)
                                 .expect("Invariant violation: vector type argument contains incomplete, tuple, reference, or spec type"))
                    ),
                    Tuple(..) | Error | Fun(..) | TypeDomain(..) | ResourceDomain(..) | TypeParameter(..) | TypeLocal(..) | Var(..) | Reference(..) =>
                        return None
                }
            )
        }
    }

    /// Create a `Type` from `t`
    pub fn from_type_tag(t: &TypeTag, env: &GlobalEnv) -> Self {
        use Type::*;
        match t {
            TypeTag::Bool => Primitive(PrimitiveType::Bool),
            TypeTag::U8 => Primitive(PrimitiveType::U8),
            TypeTag::U64 => Primitive(PrimitiveType::U64),
            TypeTag::U128 => Primitive(PrimitiveType::U128),
            TypeTag::Address => Primitive(PrimitiveType::Address),
            TypeTag::Signer => Primitive(PrimitiveType::Signer),
            TypeTag::Struct(s) => {
                let qid = env.find_struct_by_tag(&s).unwrap_or_else(|| {
                    panic!("Invariant violation: couldn't resolve struct {:?}", s)
                });
                let type_args = s
                    .type_params
                    .iter()
                    .map(|arg| Self::from_type_tag(arg, env))
                    .collect();
                Struct(qid.module_id, qid.id, type_args)
            }
            TypeTag::Vector(type_param) => Vector(Box::new(Self::from_type_tag(type_param, env))),
        }
    }

    /// Get the unbound type variables in the type.
    pub fn get_vars(&self) -> BTreeSet<u16> {
        let mut vars = BTreeSet::new();
        self.internal_get_vars(&mut vars);
        vars
    }

    fn internal_get_vars(&self, vars: &mut BTreeSet<u16>) {
        use Type::*;
        match self {
            Var(id) => {
                vars.insert(*id);
            }
            Tuple(ts) => ts.iter().for_each(|t| t.internal_get_vars(vars)),
            Fun(ts, r) => {
                r.internal_get_vars(vars);
                ts.iter().for_each(|t| t.internal_get_vars(vars));
            }
            Struct(_, _, ts) => ts.iter().for_each(|t| t.internal_get_vars(vars)),
            Vector(et) => et.internal_get_vars(vars),
            Reference(_, bt) => bt.internal_get_vars(vars),
            TypeDomain(bt) => bt.internal_get_vars(vars),
            Error | Primitive(..) | TypeParameter(..) | TypeLocal(..) | ResourceDomain(..) => {}
        }
    }

    pub fn visit<F: FnMut(&Type)>(&self, visitor: &mut F) {
        let visit_slice = |s: &[Type], visitor: &mut F| {
            for ty in s {
                ty.visit(visitor);
            }
        };
        match self {
            Type::Tuple(tys) => visit_slice(tys, visitor),
            Type::Vector(bt) => bt.visit(visitor),
            Type::Struct(_, _, tys) => visit_slice(tys, visitor),
            Type::Reference(_, ty) => ty.visit(visitor),
            Type::Fun(tys, ty) => {
                visit_slice(tys, visitor);
                ty.visit(visitor);
            }
            Type::TypeDomain(bt) => bt.visit(visitor),
            _ => {}
        }
        visitor(self)
    }
}

/// A parameter for type unification that specifies the type compatibility rules to follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variance {
    /// Co-variance is allowed in all depths of the recursive type unification process
    Allow,
    /// Co-variance is only allowed for the outermost type unification round
    Shallow,
    /// Co-variance is not allowed at all
    Disallow,
}

impl Substitution {
    /// Creates a new substitution.
    pub fn new() -> Self {
        Self {
            subs: BTreeMap::new(),
        }
    }

    /// Binds the type variables.
    pub fn bind(&mut self, var: u16, ty: Type) {
        self.subs.insert(var, ty);
    }

    /// Specializes the type, substituting all variables bound in this substitution.
    pub fn specialize(&self, t: &Type) -> Type {
        t.replace(None, Some(self), None)
    }

    /// Unify two types, returning the unified type.
    ///
    /// This currently implements the following notion of type compatibility:
    ///
    /// - 1) References are dropped (i.e. &T and T are compatible)
    /// - 2) All integer types are compatible if co-variance is allowed.
    /// - 3) With the joint effect of 1) and 2), if (P, Q) is compatible under co-variance,
    ///      (&P, Q), (P, &Q), and (&P, &Q) are all compatible under co-variance.
    /// - 4) If in two tuples (P1, P2, ..., Pn) and (Q1, Q2, ..., Qn), all (Pi, Qi) pairs are
    ///      compatible under co-variance, then the two tuples are compatible under co-variance.
    ///
    /// The substitution will be refined by variable assignments as needed to perform
    /// unification. If unification fails, the substitution will be in some intermediate state;
    /// to implement transactional unification, the substitution must be cloned before calling
    /// this.
    pub fn unify(
        &mut self,
        variance: Variance,
        t1: &Type,
        t2: &Type,
    ) -> Result<Type, TypeUnificationError> {
        // Derive the variance level for recursion
        let sub_variance = match variance {
            Variance::Allow => Variance::Allow,
            Variance::Shallow | Variance::Disallow => Variance::Disallow,
        };
        // If any of the arguments is a reference, drop it for unification, but ensure
        // it is put back since we need to maintain this information for later phases.
        if let Type::Reference(is_mut, bt1) = t1 {
            // Avoid creating nested references.
            let t2 = if let Type::Reference(_, bt2) = t2 {
                bt2.as_ref()
            } else {
                t2
            };
            return Ok(Type::Reference(
                *is_mut,
                Box::new(self.unify(sub_variance, bt1.as_ref(), t2)?),
            ));
        }
        if let Type::Reference(is_mut, bt2) = t2 {
            return Ok(Type::Reference(
                *is_mut,
                Box::new(self.unify(sub_variance, t1, bt2.as_ref())?),
            ));
        }

        // Substitute or assign variables.
        if let Some(rt) = self.try_substitute_or_assign(variance, false, &t1, &t2)? {
            return Ok(rt);
        }
        if let Some(rt) = self.try_substitute_or_assign(variance, true, &t2, &t1)? {
            return Ok(rt);
        }

        // Accept any error type.
        if matches!(t1, Type::Error) {
            return Ok(t2.clone());
        }
        if matches!(t2, Type::Error) {
            return Ok(t1.clone());
        }

        // Unify matching structured types.
        match (t1, t2) {
            (Type::Primitive(p1), Type::Primitive(p2)) => {
                if p1 == p2 {
                    return Ok(t1.clone());
                }
                // All integer types are compatible if co-variance is allowed.
                if matches!(variance, Variance::Allow | Variance::Shallow)
                    && t1.is_number()
                    && t2.is_number()
                {
                    return Ok(Type::Primitive(PrimitiveType::Num));
                }
            }
            (Type::TypeParameter(idx1), Type::TypeParameter(idx2)) => {
                if idx1 == idx2 {
                    return Ok(t1.clone());
                }
            }
            (Type::Tuple(ts1), Type::Tuple(ts2)) => {
                return Ok(Type::Tuple(self.unify_vec(
                    sub_variance,
                    ts1,
                    ts2,
                    "tuples",
                )?));
            }
            (Type::Fun(ts1, r1), Type::Fun(ts2, r2)) => {
                return Ok(Type::Fun(
                    self.unify_vec(sub_variance, ts1, ts2, "functions")?,
                    Box::new(self.unify(sub_variance, &*r1, &*r2)?),
                ));
            }
            (Type::Struct(m1, s1, ts1), Type::Struct(m2, s2, ts2)) => {
                if m1 == m2 && s1 == s2 {
                    return Ok(Type::Struct(
                        *m1,
                        *s1,
                        self.unify_vec(sub_variance, ts1, ts2, "structs")?,
                    ));
                }
            }
            (Type::Vector(e1), Type::Vector(e2)) => {
                return Ok(Type::Vector(Box::new(self.unify(
                    sub_variance,
                    &*e1,
                    &*e2,
                )?)));
            }
            (Type::TypeDomain(e1), Type::TypeDomain(e2)) => {
                return Ok(Type::TypeDomain(Box::new(self.unify(
                    sub_variance,
                    &*e1,
                    &*e2,
                )?)));
            }
            (Type::TypeLocal(s1), Type::TypeLocal(s2)) => {
                if s1 == s2 {
                    return Ok(Type::TypeLocal(*s1));
                }
            }
            _ => {}
        }
        Err(TypeUnificationError::TypeMismatch(
            self.specialize(t1),
            self.specialize(t2),
        ))
    }

    /// Helper to unify two type vectors.
    fn unify_vec(
        &mut self,
        variance: Variance,
        ts1: &[Type],
        ts2: &[Type],
        item_name: &str,
    ) -> Result<Vec<Type>, TypeUnificationError> {
        if ts1.len() != ts2.len() {
            return Err(TypeUnificationError::ArityMismatch(
                item_name.to_owned(),
                ts1.len(),
                ts2.len(),
            ));
        }
        let mut rs = vec![];
        for i in 0..ts1.len() {
            rs.push(self.unify(variance, &ts1[i], &ts2[i])?);
        }
        Ok(rs)
    }

    /// Tries to substitute or assign a variable. Returned option is Some if unification
    /// was performed, None if not.
    fn try_substitute_or_assign(
        &mut self,
        variance: Variance,
        swapped: bool,
        t1: &Type,
        t2: &Type,
    ) -> Result<Option<Type>, TypeUnificationError> {
        if let Type::Var(v1) = t1 {
            if let Some(s1) = self.subs.get(&v1).cloned() {
                return if swapped {
                    // Place the type terms in the right order again, so we
                    // get the 'expected vs actual' direction right.
                    Ok(Some(self.unify(variance, t2, &s1)?))
                } else {
                    Ok(Some(self.unify(variance, &s1, t2)?))
                };
            }
            let is_t1_var = |t: &Type| {
                if let Type::Var(v2) = t {
                    v1 == v2
                } else {
                    false
                }
            };
            // Skip the cycle check if we are unifying the same two variables.
            if is_t1_var(t2) {
                return Ok(Some(t1.clone()));
            }
            // Cycle check.
            if !t2.contains(&is_t1_var) {
                self.subs.insert(*v1, t2.clone());
                Ok(Some(t2.clone()))
            } else {
                // It is not clear to me whether this can ever occur given we do no global
                // unification with recursion, but to be on the save side, we have it.
                Err(TypeUnificationError::CyclicSubstitution(
                    self.specialize(t1),
                    self.specialize(t2),
                ))
            }
        } else {
            Ok(None)
        }
    }
}

impl Default for Substitution {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeUnificationError {
    pub fn message(&self, display_context: &TypeDisplayContext) -> String {
        match self {
            TypeUnificationError::TypeMismatch(t1, t2) => {
                format!(
                    "expected `{}` but found `{}`",
                    t2.display(display_context),
                    t1.display(display_context),
                )
            }
            TypeUnificationError::ArityMismatch(item, a1, a2) => {
                format!("{} have different arity ({} != {})", item, a1, a2)
            }
            TypeUnificationError::CyclicSubstitution(t1, t2) => {
                format!(
                    "[internal] type unification cycle check failed ({} =?= {})",
                    t1.display(display_context),
                    t2.display(display_context),
                )
            }
        }
    }
}

/// Data providing context for displaying types.
pub enum TypeDisplayContext<'a> {
    WithoutEnv {
        symbol_pool: &'a SymbolPool,
        reverse_struct_table: &'a BTreeMap<(ModuleId, StructId), QualifiedSymbol>,
    },
    WithEnv {
        env: &'a GlobalEnv,
        type_param_names: Option<Vec<Symbol>>,
    },
}

impl<'a> TypeDisplayContext<'a> {
    pub fn symbol_pool(&self) -> &SymbolPool {
        match self {
            TypeDisplayContext::WithEnv { env, .. } => env.symbol_pool(),
            TypeDisplayContext::WithoutEnv { symbol_pool, .. } => symbol_pool,
        }
    }
}

/// Helper for type displays.
pub struct TypeDisplay<'a> {
    type_: &'a Type,
    context: &'a TypeDisplayContext<'a>,
}

impl Type {
    pub fn display<'a>(&'a self, context: &'a TypeDisplayContext<'a>) -> TypeDisplay<'a> {
        TypeDisplay {
            type_: self,
            context,
        }
    }
}

impl<'a> fmt::Display for TypeDisplay<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Type::*;
        let comma_list = |f: &mut Formatter<'_>, ts: &[Type]| -> fmt::Result {
            let mut first = true;
            for t in ts {
                if first {
                    first = false
                } else {
                    f.write_str(", ")?;
                }
                write!(f, "{}", t.display(self.context))?;
            }
            Ok(())
        };
        match self.type_ {
            Primitive(p) => write!(f, "{}", p),
            Tuple(ts) => {
                f.write_str("(")?;
                comma_list(f, ts)?;
                f.write_str(")")
            }
            Vector(t) => write!(f, "vector<{}>", t.display(self.context)),
            TypeDomain(t) => write!(f, "domain<{}>", t.display(self.context)),
            ResourceDomain(mid, sid, inst_opt) => {
                write!(f, "resources<{}", self.struct_str(*mid, *sid))?;
                if let Some(inst) = inst_opt {
                    f.write_str("<")?;
                    comma_list(f, inst)?;
                    f.write_str(">")?;
                }
                f.write_str(">")
            }
            TypeLocal(s) => write!(f, "{}", s.display(self.context.symbol_pool())),
            Fun(ts, t) => {
                f.write_str("|")?;
                comma_list(f, ts)?;
                f.write_str("|")?;
                write!(f, "{}", t.display(self.context))
            }
            Struct(mid, sid, ts) => {
                write!(f, "{}", self.struct_str(*mid, *sid))?;
                if !ts.is_empty() {
                    f.write_str("<")?;
                    comma_list(f, ts)?;
                    f.write_str(">")?;
                }
                Ok(())
            }
            Reference(is_mut, t) => {
                f.write_str("&")?;
                if *is_mut {
                    f.write_str("mut ")?;
                }
                write!(f, "{}", t.display(self.context))
            }
            TypeParameter(idx) => {
                if let TypeDisplayContext::WithEnv {
                    env,
                    type_param_names: Some(names),
                } = self.context
                {
                    let idx = *idx as usize;
                    if idx < names.len() {
                        write!(f, "{}", names[idx].display(env.symbol_pool()))
                    } else {
                        write!(f, "#{}", idx)
                    }
                } else {
                    write!(f, "#{}", idx)
                }
            }
            Var(idx) => write!(f, "?{}", idx),
            Error => f.write_str("*error*"),
        }
    }
}

impl<'a> TypeDisplay<'a> {
    fn struct_str(&self, mid: ModuleId, sid: StructId) -> String {
        match self.context {
            TypeDisplayContext::WithoutEnv {
                symbol_pool,
                reverse_struct_table,
            } => {
                if let Some(sym) = reverse_struct_table.get(&(mid, sid)) {
                    sym.display(symbol_pool).to_string()
                } else {
                    "??unknown??".to_string()
                }
            }
            TypeDisplayContext::WithEnv { env, .. } => {
                let struct_env = env.get_module(mid).into_struct(sid);
                format!(
                    "{}::{}",
                    struct_env.module_env.get_name().display(env.symbol_pool()),
                    struct_env.get_name().display(env.symbol_pool())
                )
            }
        }
    }
}

impl fmt::Display for PrimitiveType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use PrimitiveType::*;
        match self {
            Bool => f.write_str("bool"),
            U8 => f.write_str("u8"),
            U64 => f.write_str("u64"),
            U128 => f.write_str("u128"),
            Address => f.write_str("address"),
            Signer => f.write_str("signer"),
            Range => f.write_str("range"),
            Num => f.write_str("num"),
            TypeValue => f.write_str("type"),
            EventStore => f.write_str("estore"),
        }
    }
}
