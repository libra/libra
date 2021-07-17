// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, LinkedList},
};

use itertools::Itertools;
use num::{BigInt, BigUint, FromPrimitive};

use move_core_types::value::MoveValue;
use move_ir_types::location::Spanned;
use move_lang::{
    expansion::ast as EA, hlir::ast as HA, naming::ast as NA, parser::ast as PA, shared::Name,
};

use crate::{
    ast::{Exp, ExpData, LocalVarDecl, ModuleName, Operation, QualifiedSymbol, QuantKind, Value},
    builder::{
        model_builder::{ConstEntry, LocalVarEntry, SpecFunEntry},
        module_builder::ModuleBuilder,
    },
    model::{FieldId, Loc, ModuleId, NodeId, QualifiedId, SpecFunId, StructId},
    symbol::{Symbol, SymbolPool},
    ty::{PrimitiveType, Substitution, Type, TypeDisplayContext, Variance, BOOL_TYPE},
};

#[derive(Debug)]
pub(crate) struct ExpTranslator<'env, 'translator, 'module_translator> {
    pub parent: &'module_translator mut ModuleBuilder<'env, 'translator>,
    /// A symbol table for type parameters.
    pub type_params_table: BTreeMap<Symbol, Type>,
    /// Type parameters in sequence they have been added.
    pub type_params: Vec<(Symbol, Type)>,
    /// A scoped symbol table for local names. The first element in the list contains the most
    /// inner scope.
    pub local_table: LinkedList<BTreeMap<Symbol, LocalVarEntry>>,
    /// When compiling a condition, the result type of the function the condition is associated
    /// with.
    pub result_type: Option<Type>,
    /// Status for the `old(...)` expression form.
    pub old_status: OldExpStatus,
    /// The currently build type substitution.
    pub subs: Substitution,
    /// A counter for generating type variables.
    pub type_var_counter: u16,
    /// A marker to indicate the node_counter start state.
    pub node_counter_start: usize,
    /// The locals which have been accessed with this build. The boolean indicates whether
    /// they ore accessed in `old(..)` context.
    pub accessed_locals: BTreeSet<(Symbol, bool)>,
    /// The number of outer context scopes in  `local_table` which are accounted for in
    /// `accessed_locals`. See also documentation of function `mark_context_scopes`.
    pub outer_context_scopes: usize,
    /// A flag to indicate whether we are translating expressions in a spec fun.
    pub translating_fun_as_spec_fun: bool,
    /// A flag to indicate whether errors have been generated so far.
    pub errors_generated: RefCell<bool>,
    /// Set containing all the functions called during translation.
    pub called_spec_funs: BTreeSet<(ModuleId, SpecFunId)>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum OldExpStatus {
    NotSupported,
    OutsideOld,
    InsideOld,
}

/// # General

impl<'env, 'translator, 'module_translator> ExpTranslator<'env, 'translator, 'module_translator> {
    pub fn new(parent: &'module_translator mut ModuleBuilder<'env, 'translator>) -> Self {
        let node_counter_start = parent.parent.env.next_free_node_number();
        Self {
            parent,
            type_params_table: BTreeMap::new(),
            type_params: vec![],
            local_table: LinkedList::new(),
            result_type: None,
            old_status: OldExpStatus::NotSupported,
            subs: Substitution::new(),
            type_var_counter: 0,
            node_counter_start,
            accessed_locals: BTreeSet::new(),
            outer_context_scopes: 0,
            /// Following flags used to translate pure Move functions.
            translating_fun_as_spec_fun: false,
            errors_generated: RefCell::new(false),
            called_spec_funs: BTreeSet::new(),
        }
    }

    pub fn new_with_old(
        parent: &'module_translator mut ModuleBuilder<'env, 'translator>,
        allow_old: bool,
    ) -> Self {
        let mut et = ExpTranslator::new(parent);
        if allow_old {
            et.old_status = OldExpStatus::OutsideOld;
        } else {
            et.old_status = OldExpStatus::NotSupported;
        };
        et
    }

    pub fn translate_fun_as_spec_fun(&mut self) {
        self.translating_fun_as_spec_fun = true;
    }

    /// Extract a map from names to types from the scopes of this build.
    pub fn extract_var_map(&self) -> BTreeMap<Symbol, LocalVarEntry> {
        let mut vars: BTreeMap<Symbol, LocalVarEntry> = BTreeMap::new();
        for s in &self.local_table {
            vars.extend(s.clone());
        }
        vars
    }

    // Get type parameters from this build.
    #[allow(unused)]
    pub fn get_type_params(&self) -> Vec<Type> {
        self.type_params
            .iter()
            .map(|(_, t)| t.clone())
            .collect_vec()
    }

    // Get type parameters with names from this build.
    pub fn get_type_params_with_name(&self) -> Vec<(Symbol, Type)> {
        self.type_params.clone()
    }

    /// Shortcut for accessing symbol pool.
    pub fn symbol_pool(&self) -> &SymbolPool {
        self.parent.parent.env.symbol_pool()
    }

    /// Shortcut for translating a Move AST location into ours.
    pub fn to_loc(&self, loc: &move_ir_types::location::Loc) -> Loc {
        self.parent.parent.env.to_loc(loc)
    }

    /// Shortcut for reporting an error.
    pub fn error(&self, loc: &Loc, msg: &str) {
        if self.translating_fun_as_spec_fun {
            *self.errors_generated.borrow_mut() = true;
        } else {
            self.parent.parent.error(loc, msg);
        }
    }

    /// Creates a fresh type variable.
    fn fresh_type_var(&mut self) -> Type {
        let var = Type::Var(self.type_var_counter);
        self.type_var_counter += 1;
        var
    }

    /// Shortcut to create a new node id.
    fn new_node_id(&self) -> NodeId {
        self.parent.parent.env.new_node_id()
    }

    /// Shortcut to create a new node id and assigns type and location to it.
    pub fn new_node_id_with_type_loc(&self, ty: &Type, loc: &Loc) -> NodeId {
        self.parent.parent.env.new_node(loc.clone(), ty.clone())
    }

    // Short cut for getting node type.
    pub fn get_node_type(&self, node_id: NodeId) -> Type {
        self.parent.parent.env.get_node_type(node_id)
    }

    // Short cut for getting node type.
    fn get_node_type_opt(&self, node_id: NodeId) -> Option<Type> {
        self.parent.parent.env.get_node_type_opt(node_id)
    }

    // Short cut for getting node location.
    #[allow(dead_code)]
    fn get_node_loc(&self, node_id: NodeId) -> Loc {
        self.parent.parent.env.get_node_loc(node_id)
    }

    // Short cut for getting node instantiation.
    fn get_node_instantiation_opt(&self, node_id: NodeId) -> Option<Vec<Type>> {
        self.parent.parent.env.get_node_instantiation_opt(node_id)
    }

    /// Shortcut to update node type.
    pub fn update_node_type(&self, node_id: NodeId, ty: Type) {
        self.parent.parent.env.update_node_type(node_id, ty);
    }

    /// Shortcut to set/update instantiation for the given node id.
    fn set_node_instantiation(&self, node_id: NodeId, instantiation: Vec<Type>) {
        self.parent
            .parent
            .env
            .set_node_instantiation(node_id, instantiation);
    }

    fn update_node_instantiation(&self, node_id: NodeId, instantiation: Vec<Type>) {
        self.parent
            .parent
            .env
            .update_node_instantiation(node_id, instantiation);
    }

    /// Finalizes types in this build, producing errors if some could not be inferred
    /// and remained incomplete.
    pub fn finalize_types(&mut self) {
        for i in self.node_counter_start..self.parent.parent.env.next_free_node_number() {
            let node_id = NodeId::new(i);

            if let Some(ty) = self.get_node_type_opt(node_id) {
                let ty = self.finalize_type(node_id, &ty);
                self.update_node_type(node_id, ty);
            }
            if let Some(inst) = self.get_node_instantiation_opt(node_id) {
                let inst = inst
                    .iter()
                    .map(|ty| self.finalize_type(node_id, ty))
                    .collect_vec();
                self.update_node_instantiation(node_id, inst);
            }
        }
    }

    /// Finalize the the given type, producing an error if it is not complete.
    fn finalize_type(&self, node_id: NodeId, ty: &Type) -> Type {
        let ty = self.subs.specialize(ty);
        if ty.is_incomplete() {
            // This type could not be fully inferred.
            let loc = self.parent.parent.env.get_node_loc(node_id);
            self.error(
                &loc,
                &format!(
                    "unable to infer type: `{}`",
                    ty.display(&self.type_display_context())
                ),
            );
        }
        ty
    }

    /// Fix any free type variables remaining in this expression build to a freshly
    /// generated type parameter, adding them to the passed vector.
    #[allow(unused)]
    pub fn fix_types(&mut self, generated_params: &mut Vec<Type>) {
        if self.parent.parent.env.has_errors() {
            return;
        }
        for i in self.node_counter_start..self.parent.parent.env.next_free_node_number() {
            let node_id = NodeId::new(i);

            if let Some(ty) = self.get_node_type_opt(node_id) {
                let ty = self.fix_type(generated_params, &ty);
                self.update_node_type(node_id, ty);
            }
            if let Some(inst) = self.get_node_instantiation_opt(node_id) {
                let inst = inst
                    .iter()
                    .map(|ty| self.fix_type(generated_params, ty))
                    .collect_vec();
                self.update_node_instantiation(node_id, inst);
            }
        }
    }

    /// Fix the given type, replacing any remaining free type variables with a type parameter.
    fn fix_type(&mut self, generated_params: &mut Vec<Type>, ty: &Type) -> Type {
        // First specialize the type.
        let ty = self.subs.specialize(ty);
        // Next get whatever free variables remain.
        let vars = ty.get_vars();
        // Assign a type parameter to each free variable and add it to substitution.
        for var in vars {
            let type_param = Type::TypeParameter(generated_params.len() as u16);
            generated_params.push(type_param.clone());
            self.subs.bind(var, type_param);
        }
        // Return type with type parameter substitution applied.
        self.subs.specialize(&ty)
    }

    /// Constructs a type display context used to visualize types in error messages.
    fn type_display_context(&self) -> TypeDisplayContext<'_> {
        TypeDisplayContext::WithoutEnv {
            symbol_pool: self.symbol_pool(),
            reverse_struct_table: &self.parent.parent.reverse_struct_table,
        }
    }

    /// Creates an error expression.
    pub fn new_error_exp(&mut self) -> ExpData {
        let id =
            self.new_node_id_with_type_loc(&Type::Error, &self.parent.parent.env.internal_loc());
        ExpData::Invalid(id)
    }

    /// Enters a new scope in the locals table.
    pub fn enter_scope(&mut self) {
        self.local_table.push_front(BTreeMap::new());
    }

    /// Exits the most inner scope of the locals table.
    pub fn exit_scope(&mut self) {
        self.local_table.pop_front();
    }

    /// Mark the current active scope level as context, i.e. symbols which are not
    /// declared in this expression. This is used to determine what
    /// `get_accessed_context_locals` returns.
    #[allow(unused)]
    pub fn mark_context_scopes(mut self) -> Self {
        self.outer_context_scopes = self.local_table.len();
        self
    }

    /// Gets the locals this build has accessed so far and which belong to the
    /// context, i.a. are not declared in this expression.
    #[allow(unused)]
    pub fn get_accessed_context_locals(&self) -> Vec<(Symbol, bool)> {
        self.accessed_locals.iter().cloned().collect_vec()
    }

    /// Defines a type parameter.
    pub fn define_type_param(&mut self, loc: &Loc, name: Symbol, ty: Type) {
        self.type_params.push((name, ty.clone()));
        if self.type_params_table.insert(name, ty).is_some() {
            let param_name = name.display(self.symbol_pool());
            self.parent
                .parent
                .error(loc, &format!("duplicate declaration of `{}`", param_name));
        }
    }

    /// Defines a local in the most inner scope. This produces an error
    /// if the name already exists. The operation option is used for names
    /// which represent special operations.
    pub fn define_local(
        &mut self,
        loc: &Loc,
        name: Symbol,
        type_: Type,
        operation: Option<Operation>,
        temp_index: Option<usize>,
    ) {
        self.internal_define_local(loc, name, type_, operation, temp_index)
    }

    /// Defines a let local.
    pub fn define_let_local(&mut self, loc: &Loc, name: Symbol, type_: Type) {
        self.internal_define_local(loc, name, type_, None, None)
    }

    fn internal_define_local(
        &mut self,
        loc: &Loc,
        name: Symbol,
        type_: Type,
        operation: Option<Operation>,
        temp_index: Option<usize>,
    ) {
        let entry = LocalVarEntry {
            loc: loc.clone(),
            type_,
            operation,
            temp_index,
        };
        if let Some(old) = self
            .local_table
            .front_mut()
            .expect("symbol table empty")
            .insert(name, entry)
        {
            let display = name.display(self.symbol_pool());
            self.error(loc, &format!("duplicate declaration of `{}`", display));
            self.error(&old.loc, &format!("previous declaration of `{}`", display));
        }
    }

    /// Lookup a local in this build.
    pub fn lookup_local(&mut self, name: Symbol, in_old: bool) -> Option<&LocalVarEntry> {
        let mut depth = self.local_table.len();
        for scope in &self.local_table {
            if let Some(entry) = scope.get(&name) {
                if depth <= self.outer_context_scopes {
                    // Account for access if this belongs to one of the outer scopes
                    // considered context (i.e. not declared in this expression).
                    self.accessed_locals.insert((name, in_old));
                }
                return Some(entry);
            }
            depth -= 1;
        }
        None
    }

    /// Analyzes the sequence of type parameters as they are provided via the source AST and enters
    /// them into the environment. Returns a vector for representing them in the target AST.
    pub fn analyze_and_add_type_params<'a, I>(&mut self, type_params: I) -> Vec<(Symbol, Type)>
    where
        I: IntoIterator<Item = &'a Name>,
    {
        type_params
            .into_iter()
            .enumerate()
            .map(|(i, n)| {
                let ty = Type::TypeParameter(i as u16);
                let sym = self.symbol_pool().make(n.value.as_str());
                self.define_type_param(&self.to_loc(&n.loc), sym, ty.clone());
                (sym, ty)
            })
            .collect_vec()
    }

    /// Analyzes the sequence of function parameters as they are provided via the source AST and
    /// enters them into the environment. Returns a vector for representing them in the target AST.
    pub fn analyze_and_add_params(
        &mut self,
        params: &[(PA::Var, EA::Type)],
        for_move_fun: bool,
    ) -> Vec<(Symbol, Type)> {
        params
            .iter()
            .enumerate()
            .map(|(idx, (v, ty))| {
                let ty = self.translate_type(ty);
                let sym = self.symbol_pool().make(v.0.value.as_str());
                self.define_local(
                    &self.to_loc(&v.0.loc),
                    sym,
                    ty.clone(),
                    None,
                    // If this is for a proper Move function (not spec function), add the
                    // index so we can resolve this to a `Temporary` expression instead of
                    // a `LocalVar`.
                    if for_move_fun { Some(idx) } else { None },
                );
                (sym, ty)
            })
            .collect_vec()
    }

    /// Displays a call target for error messages.
    fn display_call_target(&mut self, module: &Option<ModuleName>, name: Symbol) -> String {
        if let Some(m) = module {
            if m != &self.parent.parent.builtin_module() {
                // Only print the module name if it is not the pseudo builtin module.
                return format!(
                    "{}",
                    QualifiedSymbol {
                        module_name: m.clone(),
                        symbol: name,
                    }
                    .display(self.symbol_pool())
                );
            }
        }
        format!("{}", name.display(self.symbol_pool()))
    }

    /// Displays a call target candidate for error messages.
    fn display_call_cand(
        &mut self,
        module: &Option<ModuleName>,
        name: Symbol,
        entry: &SpecFunEntry,
    ) -> String {
        let target = self.display_call_target(module, name);
        let type_display_context = self.type_display_context();
        format!(
            "{}({}): {}",
            target,
            entry
                .arg_types
                .iter()
                .map(|ty| ty.display(&type_display_context))
                .join(", "),
            entry.result_type.display(&type_display_context)
        )
    }
}

/// # Type Translation

impl<'env, 'translator, 'module_translator> ExpTranslator<'env, 'translator, 'module_translator> {
    /// Translates an hlir type into a target AST type.
    pub fn translate_hlir_single_type(&mut self, ty: &HA::SingleType) -> Type {
        use HA::SingleType_::*;
        match &ty.value {
            Ref(is_mut, ty) => {
                let ty = self.translate_hlir_base_type(&*ty);
                if ty == Type::Error {
                    Type::Error
                } else {
                    Type::Reference(*is_mut, Box::new(ty))
                }
            }
            Base(ty) => self.translate_hlir_base_type(&*ty),
        }
    }

    fn translate_hlir_base_type(&mut self, ty: &HA::BaseType) -> Type {
        use HA::{BaseType_::*, TypeName_::*};
        use NA::{BuiltinTypeName_::*, TParam};
        match &ty.value {
            Param(TParam {
                user_specified_name,
                ..
            }) => {
                let sym = self.symbol_pool().make(user_specified_name.value.as_str());
                self.type_params_table[&sym].clone()
            }
            Apply(_, type_name, args) => {
                let loc = self.to_loc(&type_name.loc);
                match &type_name.value {
                    Builtin(builtin_type_name) => match &builtin_type_name.value {
                        Address => Type::new_prim(PrimitiveType::Address),
                        Signer => Type::new_prim(PrimitiveType::Signer),
                        U8 => Type::new_prim(PrimitiveType::U8),
                        U64 => Type::new_prim(PrimitiveType::U64),
                        U128 => Type::new_prim(PrimitiveType::U128),
                        Vector => Type::Vector(Box::new(self.translate_hlir_base_type(&args[0]))),
                        Bool => Type::new_prim(PrimitiveType::Bool),
                    },
                    ModuleType(m, n) => {
                        let addr_bytes = self.parent.parent.resolve_address(&loc, &m.value.address);
                        let module_name = ModuleName::from_address_bytes_and_name(
                            addr_bytes,
                            self.symbol_pool().make(m.value.module.0.value.as_str()),
                        );
                        let symbol = self.symbol_pool().make(n.0.value.as_str());
                        let qsym = QualifiedSymbol {
                            module_name,
                            symbol,
                        };
                        let rty = self.parent.parent.lookup_type(&loc, &qsym);
                        if !args.is_empty() {
                            // Replace type instantiation.
                            if let Type::Struct(mid, sid, _) = &rty {
                                let arg_types = self.translate_hlir_base_types(args);
                                if arg_types.iter().any(|x| *x == Type::Error) {
                                    Type::Error
                                } else {
                                    Type::Struct(*mid, *sid, arg_types)
                                }
                            } else {
                                Type::Error
                            }
                        } else {
                            rty
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn translate_hlir_base_types(&mut self, tys: &[HA::BaseType]) -> Vec<Type> {
        tys.iter()
            .map(|t| self.translate_hlir_base_type(t))
            .collect()
    }

    /// Translates a source AST type into a target AST type.
    pub fn translate_type(&mut self, ty: &EA::Type) -> Type {
        use EA::Type_::*;
        match &ty.value {
            Apply(access, args) => {
                if let EA::ModuleAccess_::Name(n) = &access.value {
                    let check_zero_args = |et: &mut Self, ty: Type| {
                        if args.is_empty() {
                            ty
                        } else {
                            et.error(&et.to_loc(&n.loc), "expected no type arguments");
                            Type::Error
                        }
                    };
                    // Attempt to resolve as builtin type.
                    match n.value.as_str() {
                        "bool" => {
                            return check_zero_args(self, Type::new_prim(PrimitiveType::Bool));
                        }
                        "u8" => return check_zero_args(self, Type::new_prim(PrimitiveType::U8)),
                        "u64" => return check_zero_args(self, Type::new_prim(PrimitiveType::U64)),
                        "u128" => {
                            return check_zero_args(self, Type::new_prim(PrimitiveType::U128));
                        }
                        "num" => return check_zero_args(self, Type::new_prim(PrimitiveType::Num)),
                        "range" => {
                            return check_zero_args(self, Type::new_prim(PrimitiveType::Range));
                        }
                        "address" => {
                            return check_zero_args(self, Type::new_prim(PrimitiveType::Address));
                        }
                        "signer" => {
                            return check_zero_args(self, Type::new_prim(PrimitiveType::Signer));
                        }
                        "type" => {
                            return check_zero_args(self, Type::new_prim(PrimitiveType::TypeValue));
                        }
                        "vector" => {
                            if args.len() != 1 {
                                self.error(
                                    &self.to_loc(&ty.loc),
                                    "expected one type argument for `vector`",
                                );
                                return Type::Error;
                            } else {
                                return Type::Vector(Box::new(self.translate_type(&args[0])));
                            }
                        }
                        _ => {}
                    }
                    // Attempt to resolve as a type parameter.
                    let sym = self.symbol_pool().make(n.value.as_str());
                    if let Some(ty) = self.type_params_table.get(&sym).cloned() {
                        return check_zero_args(self, ty);
                    }
                    // Attempt to resolve as a type value.
                    if let Some(entry) = self.lookup_local(sym, false) {
                        let ty = entry.type_.clone();
                        self.check_type(
                            &self.to_loc(&n.loc),
                            &ty,
                            &Type::new_prim(PrimitiveType::TypeValue),
                            "in type",
                        );
                        return check_zero_args(self, Type::TypeLocal(sym));
                    }
                }
                let loc = self.to_loc(&access.loc);
                let sym = self.parent.module_access_to_qualified(access);
                let rty = self.parent.parent.lookup_type(&loc, &sym);
                // Replace type instantiation.
                if let Type::Struct(mid, sid, params) = &rty {
                    if params.len() != args.len() {
                        self.error(&loc, "type argument count mismatch");
                        Type::Error
                    } else {
                        Type::Struct(*mid, *sid, self.translate_types(args))
                    }
                } else if !args.is_empty() {
                    self.error(&loc, "type cannot have type arguments");
                    Type::Error
                } else {
                    rty
                }
            }
            Ref(is_mut, ty) => Type::Reference(*is_mut, Box::new(self.translate_type(&*ty))),
            Fun(args, result) => Type::Fun(
                self.translate_types(&args),
                Box::new(self.translate_type(&*result)),
            ),
            Unit => Type::Tuple(vec![]),
            Multiple(vst) => Type::Tuple(self.translate_types(vst)),
            UnresolvedError => Type::Error,
        }
    }

    /// Translates a slice of single types.
    pub fn translate_types(&mut self, tys: &[EA::Type]) -> Vec<Type> {
        tys.iter().map(|t| self.translate_type(t)).collect()
    }

    /// Translates option a slice of single types.
    pub fn translate_types_opt(&mut self, tys_opt: &Option<Vec<EA::Type>>) -> Vec<Type> {
        tys_opt
            .as_deref()
            .map(|tys| self.translate_types(tys))
            .unwrap_or_else(Vec::new)
    }
}

/// # Expression Translation

impl<'env, 'translator, 'module_translator> ExpTranslator<'env, 'translator, 'module_translator> {
    /// Translates an expression representing a modify target
    pub fn translate_modify_target(&mut self, exp: &EA::Exp) -> ExpData {
        let loc = self.to_loc(&exp.loc);
        let (_, exp) = self.translate_exp_free(exp);
        match &exp {
            ExpData::Call(_, Operation::Global(_), _) => exp,
            _ => {
                self.error(&loc, "global resource access expected");
                self.new_error_exp()
            }
        }
    }

    /// Translates an expression, with given expected type, which might be a type variable.
    pub fn translate_exp(&mut self, exp: &EA::Exp, expected_type: &Type) -> ExpData {
        let loc = self.to_loc(&exp.loc);
        let make_value = |et: &mut ExpTranslator, val: Value, ty: Type| {
            let rty = et.check_type(&loc, &ty, expected_type, "in expression");
            let id = et.new_node_id_with_type_loc(&rty, &loc);
            ExpData::Value(id, val)
        };
        match &exp.value {
            EA::Exp_::Value(v) => {
                if let Some((v, ty)) = self.translate_value(v) {
                    make_value(self, v, ty)
                } else {
                    self.new_error_exp()
                }
            }
            EA::Exp_::Name(maccess, type_params) => {
                self.translate_name(&loc, maccess, type_params.as_deref(), expected_type)
            }
            EA::Exp_::Call(maccess, type_params, args) => {
                // Need to make a &[&Exp] out of args.
                let args = args.value.iter().collect_vec();
                self.translate_fun_call(
                    expected_type,
                    &loc,
                    &maccess,
                    type_params.as_deref(),
                    &args,
                )
            }
            EA::Exp_::Pack(maccess, generics, fields) => {
                self.translate_pack(&loc, maccess, generics, fields, expected_type)
            }
            EA::Exp_::IfElse(cond, then, else_) => {
                let then = self.translate_exp(&*then, expected_type);
                let else_ = self.translate_exp(&*else_, expected_type);
                let cond = self.translate_exp(&*cond, &Type::new_prim(PrimitiveType::Bool));
                let id = self.new_node_id_with_type_loc(expected_type, &loc);
                ExpData::IfElse(id, cond.into(), then.into_exp(), else_.into_exp())
            }
            EA::Exp_::Block(seq) => self.translate_seq(&loc, seq, expected_type),
            EA::Exp_::Lambda(bindings, exp) => {
                self.translate_lambda(&loc, bindings, exp, expected_type)
            }
            EA::Exp_::Quant(kind, ranges, triggers, condition, body) => self.translate_quant(
                &loc,
                *kind,
                ranges,
                triggers,
                condition,
                body,
                expected_type,
            ),
            EA::Exp_::BinopExp(l, op, r) => {
                let args = vec![l.as_ref(), r.as_ref()];
                let QualifiedSymbol {
                    module_name,
                    symbol,
                } = self.parent.parent.bin_op_symbol(&op.value);
                self.translate_call(&loc, &Some(module_name), symbol, None, &args, expected_type)
            }
            EA::Exp_::UnaryExp(op, exp) => {
                let args = vec![exp.as_ref()];
                let QualifiedSymbol {
                    module_name,
                    symbol,
                } = self.parent.parent.unary_op_symbol(&op.value);
                self.translate_call(&loc, &Some(module_name), symbol, None, &args, expected_type)
            }
            EA::Exp_::ExpDotted(dotted) => self.translate_dotted(dotted, expected_type),
            EA::Exp_::Index(target, index) => {
                self.translate_index(&loc, target, index, expected_type)
            }
            EA::Exp_::ExpList(exps) => {
                let mut types = vec![];
                let exps = exps
                    .iter()
                    .map(|exp| {
                        let (ty, exp) = self.translate_exp_free(exp);
                        types.push(ty);
                        exp.into_exp()
                    })
                    .collect_vec();
                let ty = self.check_type(
                    &loc,
                    &Type::Tuple(types),
                    expected_type,
                    "in expression list",
                );
                let id = self.new_node_id_with_type_loc(&ty, &loc);
                ExpData::Call(id, Operation::Tuple, exps)
            }
            EA::Exp_::Unit { .. } => {
                let ty = self.check_type(
                    &loc,
                    &Type::Tuple(vec![]),
                    expected_type,
                    "in unit expression",
                );
                let id = self.new_node_id_with_type_loc(&ty, &loc);
                ExpData::Call(id, Operation::Tuple, vec![])
            }
            EA::Exp_::Assign(..) => {
                self.error(&loc, "assignment only allowed in spec var updates");
                self.new_error_exp()
            }
            EA::Exp_::Dereference(exp) | EA::Exp_::Borrow(_, exp) => {
                if self.translating_fun_as_spec_fun {
                    self.translate_exp(exp, expected_type)
                } else {
                    self.error(&loc, "expression construct not supported in specifications");
                    self.new_error_exp()
                }
            }
            _ => {
                self.error(&loc, "expression construct not supported in specifications");
                self.new_error_exp()
            }
        }
    }

    pub fn translate_value(&mut self, v: &EA::Value) -> Option<(Value, Type)> {
        let loc = self.to_loc(&v.loc);
        match &v.value {
            EA::Value_::Address(addr) => {
                let addr_bytes = self.parent.parent.resolve_address(&loc, addr);
                let value = Value::Address(BigUint::from_bytes_be(&addr_bytes.into_bytes()));
                Some((value, Type::new_prim(PrimitiveType::Address)))
            }
            EA::Value_::U8(x) => Some((
                Value::Number(BigInt::from_u8(*x).unwrap()),
                Type::new_prim(PrimitiveType::U8),
            )),
            EA::Value_::U64(x) => Some((
                Value::Number(BigInt::from_u64(*x).unwrap()),
                Type::new_prim(PrimitiveType::U64),
            )),
            EA::Value_::InferredNum(x) | EA::Value_::U128(x) => Some((
                Value::Number(BigInt::from_u128(*x).unwrap()),
                Type::new_prim(PrimitiveType::U128),
            )),
            EA::Value_::Bool(x) => Some((Value::Bool(*x), Type::new_prim(PrimitiveType::Bool))),
            EA::Value_::Bytearray(x) => {
                let ty = Type::Vector(Box::new(Type::new_prim(PrimitiveType::U8)));
                Some((Value::ByteArray(x.clone()), ty))
            }
        }
    }

    fn translate_fun_call(
        &mut self,
        expected_type: &Type,
        loc: &Loc,
        maccess: &Spanned<EA::ModuleAccess_>,
        generics: Option<&[EA::Type]>,
        args: &[&EA::Exp],
    ) -> ExpData {
        // First check for builtin functions.
        if let EA::ModuleAccess_::Name(n) = &maccess.value {
            if n.value == "update_field" {
                return self.translate_update_field(expected_type, loc, generics, args);
            }
        }
        // First check whether this is an Invoke on a function value.
        if let EA::ModuleAccess_::Name(n) = &maccess.value {
            let sym = self.symbol_pool().make(&n.value);
            if let Some(entry) = self.lookup_local(sym, false) {
                // Check whether the local has the expected function type.
                let sym_ty = entry.type_.clone();
                let (arg_types, args) = self.translate_exp_list(args, false);
                let fun_t = Type::Fun(arg_types, Box::new(expected_type.clone()));
                let sym_ty = self.check_type(&loc, &sym_ty, &fun_t, "in expression");
                let local_id = self.new_node_id_with_type_loc(&sym_ty, &self.to_loc(&n.loc));
                let local_var = ExpData::LocalVar(local_id, sym);
                let id = self.new_node_id_with_type_loc(expected_type, &loc);
                return ExpData::Invoke(id, local_var.into_exp(), args);
            }
        }
        // Next treat this as a call to a global function.
        let (module_name, name) = self.parent.module_access_to_parts(maccess);

        // Ignore assert statement.
        if name == self.parent.parent.assert_symbol() {
            return ExpData::Call(
                self.new_node_id_with_type_loc(expected_type, &self.to_loc(&maccess.loc)),
                Operation::NoOp,
                vec![],
            );
        }

        let is_old = module_name.is_none() && name == self.parent.parent.old_symbol();
        if is_old {
            match self.old_status {
                OldExpStatus::NotSupported => {
                    self.error(&loc, "`old(..)` expression not allowed in this context");
                }
                OldExpStatus::InsideOld => {
                    self.error(&loc, "`old(..old(..)..)` not allowed");
                }
                OldExpStatus::OutsideOld => {
                    self.old_status = OldExpStatus::InsideOld;
                }
            }
        }
        let result = self.translate_call(&loc, &module_name, name, generics, args, expected_type);
        if is_old && self.old_status == OldExpStatus::InsideOld {
            self.old_status = OldExpStatus::OutsideOld;
        }
        result
    }

    /// Translates an expression without any known type expectation. This creates a fresh type
    /// variable and passes this in as expected type, then returns a pair of this type and the
    /// translated expression.
    pub fn translate_exp_free(&mut self, exp: &EA::Exp) -> (Type, ExpData) {
        let tvar = self.fresh_type_var();
        let exp = self.translate_exp(exp, &tvar);
        (self.subs.specialize(&tvar), exp)
    }

    /// Translates a sequence expression.
    pub fn translate_seq(
        &mut self,
        loc: &Loc,
        seq: &EA::Sequence,
        expected_type: &Type,
    ) -> ExpData {
        let n = seq.len();
        if n == 0 {
            self.error(loc, "block sequence cannot be empty");
            return self.new_error_exp();
        }
        // Process all items before the last one, which must be bindings, and accumulate
        // declarations for them.
        let mut decls = vec![];
        let seq = seq.iter().collect_vec();
        for item in &seq[0..seq.len() - 1] {
            match &item.value {
                EA::SequenceItem_::Bind(list, exp) => {
                    let (t, e) = self.translate_exp_free(exp);
                    if list.value.len() != 1 {
                        self.error(
                            &self.to_loc(&list.loc),
                            "[current restriction] tuples not supported in let",
                        );
                        return ExpData::Invalid(self.new_node_id());
                    }
                    let bind_loc = self.to_loc(&list.value[0].loc);
                    match &list.value[0].value {
                        EA::LValue_::Var(maccess, _) => {
                            let name = match &maccess.value {
                                EA::ModuleAccess_::Name(n) => n,
                                EA::ModuleAccess_::ModuleAccess(_, n) => n,
                            };
                            // Define the local. Currently we mimic
                            // Rust/ML semantics here, allowing to shadow with each let,
                            // thus entering a new scope.
                            self.enter_scope();
                            let name = self.symbol_pool().make(&name.value);
                            self.define_local(&bind_loc, name, t.clone(), None, None);
                            let id = self.new_node_id_with_type_loc(&t, &bind_loc);
                            decls.push(LocalVarDecl {
                                id,
                                name,
                                binding: Some(e.into_exp()),
                            });
                        }
                        EA::LValue_::Unpack(..) => {
                            self.error(
                                &bind_loc,
                                "[current restriction] unpack not supported in let",
                            );
                            return ExpData::Invalid(self.new_node_id());
                        }
                    }
                }
                EA::SequenceItem_::Seq(e) => {
                    let translated = self.translate_exp(e, expected_type);
                    match translated {
                        ExpData::Call(_, Operation::NoOp, _) => { /* allow assert statement */ }
                        _ => self.error(
                            &self.to_loc(&item.loc),
                            "only binding `let p = e; ...` allowed here",
                        ),
                    }
                }
                _ => self.error(
                    &self.to_loc(&item.loc),
                    "only binding `let p = e; ...` allowed here",
                ),
            }
        }

        // Process the last element, which must be an Exp item.
        let last = match &seq[n - 1].value {
            EA::SequenceItem_::Seq(e) => self.translate_exp(e, expected_type),
            _ => {
                self.error(
                    &self.to_loc(&seq[n - 1].loc),
                    "expected an expression as the last element of the block",
                );
                self.new_error_exp()
            }
        };

        // Exit the scopes for variable bindings
        for _ in 0..decls.len() {
            self.exit_scope();
        }

        let id = self.new_node_id_with_type_loc(expected_type, loc);
        ExpData::Block(id, decls, last.into_exp())
    }

    /// Translates a name. Reports an error if the name is not found.
    fn translate_name(
        &mut self,
        loc: &Loc,
        maccess: &EA::ModuleAccess,
        type_args: Option<&[EA::Type]>,
        expected_type: &Type,
    ) -> ExpData {
        let global_var_sym = match &maccess.value {
            EA::ModuleAccess_::ModuleAccess(..) => self.parent.module_access_to_qualified(maccess),
            EA::ModuleAccess_::Name(name) => {
                // First try to resolve simple name as local.
                let sym = self.symbol_pool().make(name.value.as_str());
                if let Some(exp) = self.resolve_local(
                    loc,
                    sym,
                    self.old_status == OldExpStatus::InsideOld,
                    expected_type,
                ) {
                    return exp;
                }

                // If not found, try to resolve as builtin constant.
                let builtin_sym = self.parent.parent.builtin_qualified_symbol(&name.value);
                if let Some(entry) = self.parent.parent.const_table.get(&builtin_sym).cloned() {
                    return self.translate_constant(loc, entry, expected_type);
                }
                // If not found, treat as global var in this module.
                self.parent.qualified_by_module(sym)
            }
        };
        if let Some(entry) = self.parent.parent.const_table.get(&global_var_sym).cloned() {
            return self.translate_constant(loc, entry, expected_type);
        }

        if let Some(entry) = self.parent.parent.spec_var_table.get(&global_var_sym) {
            let type_args = type_args.unwrap_or(&[]);
            if entry.type_params.len() != type_args.len() {
                self.error(
                    loc,
                    &format!(
                        "generic count mismatch (expected {} but found {})",
                        entry.type_params.len(),
                        type_args.len()
                    ),
                );
                return self.new_error_exp();
            }
            let ty = entry.type_.clone();
            let module_id = entry.module_id;
            let var_id = entry.var_id;
            let instantiation = self.translate_types(type_args);
            let ty = ty.instantiate(&instantiation);
            let ty = self.check_type(loc, &ty, expected_type, "in spec var expression");
            let id = self.new_node_id_with_type_loc(&ty, loc);
            // Remember the instantiation as an attribute on the expression node.
            self.set_node_instantiation(id, instantiation);
            return ExpData::SpecVar(id, module_id, var_id, None);
        }

        self.error(
            loc,
            &format!(
                "undeclared `{}`",
                global_var_sym.display(self.symbol_pool())
            ),
        );
        self.new_error_exp()
    }

    /// Creates an expression for a constant, checking the expected type.
    fn translate_constant(
        &mut self,
        loc: &Loc,
        entry: ConstEntry,
        expected_type: &Type,
    ) -> ExpData {
        let ConstEntry { ty, value, .. } = entry;
        let ty = self.check_type(loc, &ty, expected_type, "in const expression");
        let id = self.new_node_id_with_type_loc(&ty, loc);
        ExpData::Value(id, value)
    }

    fn resolve_local(
        &mut self,
        loc: &Loc,
        sym: Symbol,
        in_old: bool,
        expected_type: &Type,
    ) -> Option<ExpData> {
        if let Some(entry) = self.lookup_local(sym, in_old) {
            // Make copies of some fields to avoid borrowing issues.
            let oper_opt = entry.operation.clone();
            let index_opt = entry.temp_index;
            let ty = entry.type_.clone();
            let ty = self.check_type(loc, &ty, expected_type, "in name expression");
            let id = self.new_node_id_with_type_loc(&ty, loc);
            if let Some(oper) = oper_opt {
                Some(ExpData::Call(id, oper, vec![]))
            } else if let Some(index) = index_opt.filter(|_| !self.translating_fun_as_spec_fun) {
                // Only create a temporary if we are not currently translating a move function as
                // a spec function, or a let. In this case, the LocalVarEntry has a bytecode index, but
                // we do not want to use this if interpreted as a spec fun.
                Some(ExpData::Temporary(id, index))
            } else {
                Some(ExpData::LocalVar(id, sym))
            }
        } else {
            None
        }
    }

    #[allow(unused)]
    pub fn make_context_local_name(&self, name: Symbol, in_old: bool) -> Symbol {
        if in_old {
            self.symbol_pool()
                .make(&format!("{}_$old", name.display(self.symbol_pool())))
        } else {
            name
        }
    }

    /// Translate an Index expression.
    fn translate_index(
        &mut self,
        loc: &Loc,
        target: &EA::Exp,
        index: &EA::Exp,
        expected_type: &Type,
    ) -> ExpData {
        // We must concretize the type of index to decide whether this is a slice
        // or not. This is not compatible with full type inference, so we may
        // try to actually represent slicing explicitly in the syntax to fix this.
        // Alternatively, we could leave it to the backend to figure (after full
        // type inference) whether this is slice or index.
        let elem_ty = self.fresh_type_var();
        let vector_ty = Type::Vector(Box::new(elem_ty.clone()));
        let vector_exp = self.translate_exp(target, &vector_ty);
        let (index_ty, ie) = self.translate_exp_free(index);
        let index_ty = self.subs.specialize(&index_ty);
        let (result_t, oper) = if let Type::Primitive(PrimitiveType::Range) = &index_ty {
            (vector_ty, Operation::Slice)
        } else {
            // If this is not (known to be) a range, assume its an index.
            self.check_type(
                &loc,
                &index_ty,
                &Type::new_prim(PrimitiveType::Num),
                "in index expression",
            );
            (elem_ty, Operation::Index)
        };
        let result_t = self.check_type(loc, &result_t, expected_type, "in index expression");
        let id = self.new_node_id_with_type_loc(&result_t, &loc);
        ExpData::Call(id, oper, vec![vector_exp.into_exp(), ie.into_exp()])
    }

    /// Translate a Dotted expression.
    fn translate_dotted(&mut self, dotted: &EA::ExpDotted, expected_type: &Type) -> ExpData {
        match &dotted.value {
            EA::ExpDotted_::Exp(e) => self.translate_exp(e, expected_type),
            EA::ExpDotted_::Dot(e, n) => {
                let loc = self.to_loc(&dotted.loc);
                let ty = self.fresh_type_var();
                let exp = self.translate_dotted(e.as_ref(), &ty);
                if let Some((struct_id, field_id, field_ty)) = self.lookup_field(&loc, &ty, n) {
                    self.check_type(&loc, &field_ty, expected_type, "in field selection");
                    let id = self.new_node_id_with_type_loc(&field_ty, &loc);
                    ExpData::Call(
                        id,
                        Operation::Select(struct_id.module_id, struct_id.id, field_id),
                        vec![exp.into_exp()],
                    )
                } else {
                    self.new_error_exp()
                }
            }
        }
    }

    /// Translate the builtin function `update_field<generics>(args)`. The first arg must
    /// be a field name, the second the expression to assign the field.
    fn translate_update_field(
        &mut self,
        expected_type: &Type,
        loc: &Loc,
        generics: Option<&[EA::Type]>,
        args: &[&EA::Exp],
    ) -> ExpData {
        if generics.is_some() {
            self.error(loc, "`update_field` cannot have type parameters");
            return self.new_error_exp();
        }
        if args.len() != 3 {
            self.error(loc, "`update_field` requires 3 arguments");
            return self.new_error_exp();
        }
        let struct_exp = self.translate_exp(&args[0], expected_type);
        let expected_type = &self.subs.specialize(expected_type);
        if let EA::Exp_::Name(
            Spanned {
                value: EA::ModuleAccess_::Name(name),
                ..
            },
            None,
        ) = &args[1].value
        {
            if let Some((struct_id, field_id, field_type)) =
                self.lookup_field(loc, &expected_type, name)
            {
                // Translate the new value with the field type as the expected type.
                let value_exp = self.translate_exp(&args[2], &self.subs.specialize(&field_type));
                let id = self.new_node_id_with_type_loc(&expected_type, loc);
                self.set_node_instantiation(id, vec![expected_type.clone()]);
                ExpData::Call(
                    id,
                    Operation::UpdateField(struct_id.module_id, struct_id.id, field_id),
                    vec![struct_exp.into_exp(), value_exp.into_exp()],
                )
            } else {
                // Error reported
                self.new_error_exp()
            }
        } else {
            self.error(
                loc,
                "second argument of `update_field` must be a field name",
            );
            self.new_error_exp()
        }
    }

    /// Loops up a field in a struct. Returns field information or None after reporting errors.
    fn lookup_field(
        &mut self,
        loc: &Loc,
        struct_ty: &Type,
        name: &Name,
    ) -> Option<(QualifiedId<StructId>, FieldId, Type)> {
        // Similar as with Index, we must concretize the type of the expression on which
        // field selection is performed, violating pure type inference rules, so we can actually
        // check and retrieve the field. To avoid this, we would need to introduce the concept
        // of a type constraint to type unification, where the constraint would be
        // 'type var X where X has field F'. This makes unification significant more complex,
        // so lets see how far we get without this.
        let struct_ty = self.subs.specialize(&struct_ty);
        let field_name = self.symbol_pool().make(&name.value);
        if let Type::Struct(mid, sid, targs) = &struct_ty {
            // Lookup the StructEntry in the build. It must be defined for valid
            // Type::Struct instances.
            let struct_name = self
                .parent
                .parent
                .reverse_struct_table
                .get(&(*mid, *sid))
                .expect("invalid Type::Struct");
            let entry = self
                .parent
                .parent
                .struct_table
                .get(struct_name)
                .expect("invalid Type::Struct");
            // Lookup the field in the struct.
            if let Some(fields) = &entry.fields {
                if let Some((_, field_ty)) = fields.get(&field_name) {
                    // We must instantiate the field type by the provided type args.
                    let field_ty = field_ty.instantiate(targs);
                    Some((
                        entry.module_id.qualified(entry.struct_id),
                        FieldId::new(field_name),
                        field_ty,
                    ))
                } else {
                    self.error(
                        &loc,
                        &format!(
                            "field `{}` not declared in struct `{}`",
                            field_name.display(self.symbol_pool()),
                            struct_name.display(self.symbol_pool())
                        ),
                    );
                    None
                }
            } else {
                self.error(
                    &loc,
                    &format!(
                        "struct `{}` is native and does not support field selection",
                        struct_name.display(self.symbol_pool())
                    ),
                );
                None
            }
        } else {
            self.error(
                &loc,
                &format!(
                    "type `{}` cannot be resolved as a struct",
                    struct_ty.display(&self.type_display_context()),
                ),
            );
            None
        }
    }

    /// Translates a call, performing overload resolution. Reports an error if the function cannot be found.
    /// This is used to resolve both calls to user spec functions and builtin operators.
    fn translate_call(
        &mut self,
        loc: &Loc,
        module: &Option<ModuleName>,
        name: Symbol,
        generics: Option<&[EA::Type]>,
        args: &[&EA::Exp],
        expected_type: &Type,
    ) -> ExpData {
        // Translate generic arguments, if any.
        let generics = generics.as_ref().map(|ts| self.translate_types(&ts));
        // Translate arguments. Skip any lambda expressions; they are resolved after the overload
        // is identified to avoid restrictions with type inference.
        let (arg_types, mut translated_args) = self.translate_exp_list(args, true);
        let args_have_errors = arg_types.iter().any(|t| t == &Type::Error);
        // Lookup candidates.
        let cand_modules = if let Some(m) = module {
            vec![m.clone()]
        } else {
            // For an unqualified name, resolve it both in this and in the builtin pseudo module.
            vec![
                self.parent.module_name.clone(),
                self.parent.parent.builtin_module(),
            ]
        };
        let mut cands = vec![];
        for module_name in cand_modules {
            let full_name = QualifiedSymbol {
                module_name,
                symbol: name,
            };
            if let Some(list) = self.parent.parent.spec_fun_table.get(&full_name) {
                cands.extend_from_slice(list);
            }
        }
        if cands.is_empty() {
            let display = self.display_call_target(module, name);
            self.error(loc, &format!("no function named `{}` found", display));
            return self.new_error_exp();
        }
        // Partition candidates in those which matched and which have been outruled.
        let mut outruled = vec![];
        let mut matching = vec![];
        for cand in &cands {
            if cand.arg_types.len() != translated_args.len() {
                outruled.push((
                    cand,
                    format!(
                        "argument count mismatch (expected {} but found {})",
                        cand.arg_types.len(),
                        translated_args.len()
                    ),
                ));
                continue;
            }
            let (instantiation, diag) =
                self.make_instantiation(cand.type_params.len(), vec![], generics.clone());
            if let Some(msg) = diag {
                outruled.push((cand, msg));
                continue;
            }
            // Clone the current substitution, then unify arguments against parameter types.
            let mut subs = self.subs.clone();
            let mut success = true;
            for (i, arg_ty) in arg_types.iter().enumerate() {
                let instantiated = cand.arg_types[i].instantiate(&instantiation);
                if let Err(err) = subs.unify(Variance::Allow, arg_ty, &instantiated) {
                    outruled.push((
                        cand,
                        format!(
                            "{} for argument {}",
                            err.message(&self.type_display_context()),
                            i + 1
                        ),
                    ));
                    success = false;
                    break;
                }
            }
            if success {
                matching.push((cand, subs, instantiation));
            }
        }
        // Deliver results, reporting errors if there are no or ambiguous matches.
        match matching.len() {
            0 => {
                // Only report error if args had no errors.
                if !args_have_errors {
                    let display = self.display_call_target(module, name);
                    let notes = outruled
                        .iter()
                        .map(|(cand, msg)| {
                            format!(
                                "outruled candidate `{}` ({})",
                                self.display_call_cand(module, name, cand),
                                msg
                            )
                        })
                        .collect_vec();
                    self.parent.parent.env.error_with_notes(
                        loc,
                        &format!("no matching declaration of `{}`", display),
                        notes,
                    );
                }
                self.new_error_exp()
            }
            1 => {
                let (cand, subs, instantiation) = matching.remove(0);
                // Commit the candidate substitution to this expression build.
                self.subs = subs;
                // Now translate lambda-based arguments passing expected type to aid type inference.
                for i in 0..translated_args.len() {
                    let e = args[i];
                    if matches!(e.value, EA::Exp_::Lambda(..)) {
                        let expected_type = self.subs.specialize(&arg_types[i]);
                        translated_args[i] = self.translate_exp(e, &expected_type).into_exp();
                    }
                }
                // Check result type against expected type.
                let ty = self.check_type(
                    loc,
                    &cand.result_type.instantiate(&instantiation),
                    expected_type,
                    "in expression",
                );
                // Construct result.
                let id = self.new_node_id_with_type_loc(&ty, loc);
                self.set_node_instantiation(id, instantiation);

                if let Operation::Function(module_id, spec_fun_id, None) = cand.oper {
                    if !self.translating_fun_as_spec_fun {
                        // Record the usage of spec function in specs, used later
                        // in spec build.
                        self.parent
                            .parent
                            .add_used_spec_fun(module_id.qualified(spec_fun_id));
                    }
                    let module_name = match module {
                        Some(m) => m,
                        _ => &self.parent.module_name,
                    }
                    .clone();
                    let qsym = QualifiedSymbol {
                        module_name,
                        symbol: name,
                    };
                    // If the spec function called is from a Move function,
                    // error if it is not pure.
                    if let Some(entry) = self.parent.parent.fun_table.get(&qsym) {
                        if !entry.is_pure {
                            if self.translating_fun_as_spec_fun {
                                // The Move function is calling another impure Move function,
                                // so it should be considered impure.
                                if module_id.to_usize() < self.parent.module_id.to_usize() {
                                    self.error(loc, "Move function calls impure Move function");
                                    return self.new_error_exp();
                                }
                            } else {
                                let display = self.display_call_target(module, name);
                                let notes = vec![format!(
                                    "impure function `{}`",
                                    self.display_call_cand(module, name, cand),
                                )];
                                self.parent.parent.env.error_with_notes(
                                    loc,
                                    &format!(
                                        "calling impure function `{}` is not allowed",
                                        display
                                    ),
                                    notes,
                                );
                                return self.new_error_exp();
                            }
                        }
                    }
                    self.called_spec_funs.insert((module_id, spec_fun_id));
                }
                ExpData::Call(id, cand.oper.clone(), translated_args)
            }
            _ => {
                // Only report error if args had no errors.
                if !args_have_errors {
                    let display = self.display_call_target(module, name);
                    let notes = matching
                        .iter()
                        .map(|(cand, _, _)| {
                            format!(
                                "matching candidate `{}`",
                                self.display_call_cand(module, name, cand)
                            )
                        })
                        .collect_vec();
                    self.parent.parent.env.error_with_notes(
                        loc,
                        &format!("ambiguous application of `{}`", display),
                        notes,
                    );
                }
                self.new_error_exp()
            }
        }
    }

    /// Translate a list of expressions and deliver them together with their types.
    fn translate_exp_list(
        &mut self,
        exps: &[&EA::Exp],
        skip_lambda: bool,
    ) -> (Vec<Type>, Vec<Exp>) {
        let mut types = vec![];
        let exps = exps
            .iter()
            .map(|e| {
                let (t, e) = if !skip_lambda || !matches!(e.value, EA::Exp_::Lambda(..)) {
                    let (ty, exp) = self.translate_exp_free(e);
                    (ty, exp.into_exp())
                } else {
                    // In skip-lambda mode, just create a fresh type variable. We translate
                    // the expression in a second pass, once the expected type is known.
                    (
                        self.fresh_type_var(),
                        ExpData::Invalid(NodeId::new(0)).into_exp(),
                    )
                };
                types.push(t);
                e
            })
            .collect_vec();
        (types, exps)
    }

    /// Creates a type instantiation based on provided actual type parameters.
    fn make_instantiation(
        &mut self,
        param_count: usize,
        context_args: Vec<Type>,
        user_args: Option<Vec<Type>>,
    ) -> (Vec<Type>, Option<String>) {
        let mut args = context_args;
        let expected_user_count = param_count - args.len();
        if let Some(types) = user_args {
            let n = types.len();
            args.extend(types.into_iter());
            if n != expected_user_count {
                (
                    args,
                    Some(format!(
                        "generic count mismatch (expected {} but found {})",
                        expected_user_count, n,
                    )),
                )
            } else {
                (args, None)
            }
        } else {
            // Create fresh type variables for user args
            for _ in 0..expected_user_count {
                args.push(self.fresh_type_var());
            }
            (args, None)
        }
    }

    fn translate_pack(
        &mut self,
        loc: &Loc,
        maccess: &EA::ModuleAccess,
        generics: &Option<Vec<EA::Type>>,
        fields: &EA::Fields<EA::Exp>,
        expected_type: &Type,
    ) -> ExpData {
        let struct_name = self.parent.module_access_to_qualified(maccess);
        let struct_name_loc = self.to_loc(&maccess.loc);
        let generics = generics.as_ref().map(|ts| self.translate_types(&ts));
        if let Some(entry) = self.parent.parent.struct_table.get(&struct_name) {
            let entry = entry.clone();
            let (instantiation, diag) =
                self.make_instantiation(entry.type_params.len(), vec![], generics);
            if let Some(msg) = diag {
                self.error(loc, &msg);
                return self.new_error_exp();
            }
            if let Some(field_decls) = &entry.fields {
                let mut fields_not_covered: BTreeSet<Symbol> = BTreeSet::new();
                fields_not_covered.extend(field_decls.keys());
                let mut args = BTreeMap::new();
                for (name_loc, name_, (_, exp)) in fields.iter() {
                    let field_name = self.symbol_pool().make(&name_);
                    if let Some((idx, field_ty)) = field_decls.get(&field_name) {
                        let exp = self.translate_exp(exp, &field_ty.instantiate(&instantiation));
                        fields_not_covered.remove(&field_name);
                        args.insert(idx, exp);
                    } else {
                        self.error(
                            &self.to_loc(&name_loc),
                            &format!(
                                "field `{}` not declared in struct `{}`",
                                field_name.display(self.symbol_pool()),
                                struct_name.display(self.symbol_pool())
                            ),
                        );
                    }
                }
                if !fields_not_covered.is_empty() {
                    self.error(
                        loc,
                        &format!(
                            "missing fields {}",
                            fields_not_covered
                                .iter()
                                .map(|n| format!("`{}`", n.display(self.symbol_pool())))
                                .join(", ")
                        ),
                    );
                    self.new_error_exp()
                } else {
                    let struct_ty =
                        Type::Struct(entry.module_id, entry.struct_id, instantiation.clone());
                    let struct_ty =
                        self.check_type(loc, &struct_ty, expected_type, "in pack expression");
                    let mut args = args
                        .into_iter()
                        .sorted_by_key(|(i, _)| *i)
                        .map(|(_, e)| e.into_exp())
                        .collect_vec();
                    if args.is_empty() {
                        // The move compiler inserts a dummy field with the value of false
                        // for structs with no fields. This is also what we find in the
                        // Model metadata (i.e. a field `dummy_field`). We simulate this here
                        // for now, though it would be better to remove it everywhere as it
                        // can be confusing to users. However, its currently hard to do this,
                        // because a user could also have defined the `dummy_field`.
                        let id = self.new_node_id_with_type_loc(&BOOL_TYPE, loc);
                        args.push(ExpData::Value(id, Value::Bool(false)).into_exp());
                    }
                    let id = self.new_node_id_with_type_loc(&struct_ty, loc);
                    self.set_node_instantiation(id, instantiation);
                    ExpData::Call(id, Operation::Pack(entry.module_id, entry.struct_id), args)
                }
            } else {
                self.error(
                    &struct_name_loc,
                    &format!(
                        "native struct `{}` cannot be packed",
                        struct_name.display(self.symbol_pool())
                    ),
                );
                self.new_error_exp()
            }
        } else {
            self.error(
                &struct_name_loc,
                &format!(
                    "undeclared struct `{}`",
                    struct_name.display(self.symbol_pool())
                ),
            );
            self.new_error_exp()
        }
    }

    fn translate_lambda(
        &mut self,
        loc: &Loc,
        bindings: &EA::LValueList,
        body: &EA::Exp,
        expected_type: &Type,
    ) -> ExpData {
        // Enter the lambda variables into a new local scope and collect their declarations.
        self.enter_scope();
        let mut decls = vec![];
        let mut arg_types = vec![];
        for bind in &bindings.value {
            let loc = self.to_loc(&bind.loc);
            match &bind.value {
                EA::LValue_::Var(
                    Spanned {
                        value: EA::ModuleAccess_::Name(n),
                        ..
                    },
                    _,
                ) => {
                    let name = self.symbol_pool().make(&n.value);
                    let ty = self.fresh_type_var();
                    let id = self.new_node_id_with_type_loc(&ty, &loc);
                    self.define_local(&loc, name, ty.clone(), None, None);
                    arg_types.push(ty);
                    decls.push(LocalVarDecl {
                        id,
                        name,
                        binding: None,
                    });
                }
                EA::LValue_::Unpack(..) | EA::LValue_::Var(..) => {
                    self.error(&loc, "[current restriction] tuples not supported in lambda")
                }
            }
        }
        // Create a fresh type variable for the body and check expected type before analyzing
        // body. This aids type inference for the lambda parameters.
        let ty = self.fresh_type_var();
        let rty = self.check_type(
            loc,
            &Type::Fun(arg_types, Box::new(ty.clone())),
            expected_type,
            "in lambda",
        );
        let rbody = self.translate_exp(body, &ty);
        self.exit_scope();
        let id = self.new_node_id_with_type_loc(&rty, loc);
        ExpData::Lambda(id, decls, rbody.into_exp())
    }

    fn translate_quant(
        &mut self,
        loc: &Loc,
        kind: PA::QuantKind,
        ranges: &EA::LValueWithRangeList,
        triggers: &[Vec<EA::Exp>],
        condition: &Option<Box<EA::Exp>>,
        body: &EA::Exp,
        expected_type: &Type,
    ) -> ExpData {
        let rkind = match kind.value {
            PA::QuantKind_::Forall => QuantKind::Forall,
            PA::QuantKind_::Exists => QuantKind::Exists,
            PA::QuantKind_::Choose => QuantKind::Choose,
            PA::QuantKind_::ChooseMin => QuantKind::ChooseMin,
        };

        // Enter the quantifier variables into a new local scope and collect their declarations.
        self.enter_scope();
        let mut rranges = vec![];
        for range in &ranges.value {
            // The quantified variable and its domain expression.
            let (bind, exp) = &range.value;
            let loc = self.to_loc(&bind.loc);
            let (exp_ty, rexp) = self.translate_exp_free(exp);
            let ty = self.fresh_type_var();
            let exp_ty = self.subs.specialize(&exp_ty);
            match &exp_ty {
                Type::Vector(..) => {
                    self.check_type(
                        &loc,
                        &exp_ty,
                        &Type::Vector(Box::new(ty.clone())),
                        "in quantification over vector",
                    );
                }
                Type::TypeDomain(..) => {
                    self.check_type(
                        &loc,
                        &exp_ty,
                        &Type::TypeDomain(Box::new(ty.clone())),
                        "in quantification over domain",
                    );
                }
                Type::Primitive(PrimitiveType::Range) => {
                    self.check_type(
                        &loc,
                        &ty,
                        &Type::Primitive(PrimitiveType::Num),
                        "in quantification over range",
                    );
                }
                _ => {
                    self.error(&loc, "quantified variables must range over a vector, a type domain, or a number range");
                    return self.new_error_exp();
                }
            }
            match &bind.value {
                EA::LValue_::Var(
                    Spanned {
                        value: EA::ModuleAccess_::Name(n),
                        ..
                    },
                    _,
                ) => {
                    let name = self.symbol_pool().make(&n.value);
                    let id = self.new_node_id_with_type_loc(&ty, &loc);
                    self.define_local(&loc, name, ty.clone(), None, None);
                    let rbind = LocalVarDecl {
                        id,
                        name,
                        binding: None,
                    };
                    rranges.push((rbind, rexp.into_exp()));
                }
                EA::LValue_::Unpack(..) | EA::LValue_::Var(..) => self.error(
                    &loc,
                    "[current restriction] tuples not supported in quantifiers",
                ),
            }
        }
        let rtriggers = triggers
            .iter()
            .map(|trigger| {
                trigger
                    .iter()
                    .map(|e| self.translate_exp_free(e).1.into_exp())
                    .collect()
            })
            .collect();
        let rbody = self.translate_exp(body, &BOOL_TYPE);
        let rcondition = condition
            .as_ref()
            .map(|cond| self.translate_exp(cond, &BOOL_TYPE).into_exp());
        self.exit_scope();
        let quant_ty = if rkind.is_choice() {
            self.parent.parent.env.get_node_type(rranges[0].0.id)
        } else {
            BOOL_TYPE.clone()
        };
        self.check_type(loc, &quant_ty, expected_type, "in quantifier expression");
        let id = self.new_node_id_with_type_loc(&quant_ty, loc);
        ExpData::Quant(id, rkind, rranges, rtriggers, rcondition, rbody.into_exp())
    }

    pub fn check_type(&mut self, loc: &Loc, ty: &Type, expected: &Type, context_msg: &str) -> Type {
        // Because of Rust borrow semantics, we must temporarily detach the substitution from
        // the build. This is because we also need to inherently borrow self via the
        // type_display_context which is passed into unification.
        let mut subs = std::mem::replace(&mut self.subs, Substitution::new());
        let result = match subs.unify(Variance::Shallow, ty, expected) {
            Ok(t) => t,
            Err(err) => {
                self.error(
                    &loc,
                    &format!(
                        "{} {}",
                        err.message(&self.type_display_context()),
                        context_msg
                    ),
                );
                Type::Error
            }
        };
        self.subs = subs;
        result
    }

    pub fn translate_from_move_value(&self, loc: &Loc, value: &MoveValue) -> Value {
        match value {
            MoveValue::U8(n) => Value::Number(BigInt::from_u8(*n).unwrap()),
            MoveValue::U64(n) => Value::Number(BigInt::from_u64(*n).unwrap()),
            MoveValue::U128(n) => Value::Number(BigInt::from_u128(*n).unwrap()),
            MoveValue::Bool(b) => Value::Bool(*b),
            MoveValue::Address(a) => Value::Address(crate::addr_to_big_uint(a)),
            MoveValue::Signer(a) => Value::Address(crate::addr_to_big_uint(a)),
            MoveValue::Vector(vs) => {
                let b = vs
                    .iter()
                    .filter_map(|v| match v {
                        MoveValue::U8(n) => Some(*n),
                        _ => {
                            self.error(
                                loc,
                                &format!("Not yet supported constant vector value: {:?}", v),
                            );
                            None
                        }
                    })
                    .collect::<Vec<u8>>();
                Value::ByteArray(b)
            }
            _ => {
                self.error(
                    loc,
                    &format!("Not yet supported constant value: {:?}", value),
                );
                Value::Bool(false)
            }
        }
    }
}
