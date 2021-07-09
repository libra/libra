// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    context::{CompiledDependency, Context, MaterializedPools, TABLE_MAX_SIZE},
    errors::*,
};
use anyhow::{bail, format_err, Result};
use bytecode_source_map::source_map::SourceMap;
use move_binary_format::{
    check_bounds::BoundsChecker,
    errors::Location as VMErrorLocation,
    file_format::{
        Ability, AbilitySet, Bytecode, CodeOffset, CodeUnit, CompiledModule, CompiledScript,
        Constant, FieldDefinition, FunctionDefinition, FunctionSignature, ModuleHandle, Signature,
        SignatureToken, StructDefinition, StructDefinitionIndex, StructFieldInformation,
        StructHandleIndex, StructTypeParameter, TableIndex, TypeParameterIndex, TypeSignature,
        Visibility,
    },
    file_format_common::VERSION_MAX,
};
use move_core_types::{
    account_address::AccountAddress,
    value::{MoveTypeLayout, MoveValue},
};
use move_ir_types::{
    ast::{self, Bytecode as IRBytecode, Bytecode_ as IRBytecode_, *},
    location::*,
    sp,
};
use std::{
    clone::Clone,
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        BTreeSet, HashMap, VecDeque,
    },
};

macro_rules! record_src_loc {
    (local: $context:expr, $var:expr) => {{
        let source_name = ($var.value.clone().into_inner(), $var.loc);
        $context
            .source_map
            .add_local_mapping($context.current_function_definition_index(), source_name)?;
    }};
    (parameter: $context:expr, $var:expr) => {{
        let source_name = ($var.value.clone().into_inner(), $var.loc);
        $context
            .source_map
            .add_parameter_mapping($context.current_function_definition_index(), source_name)?;
    }};
    (field: $context:expr, $idx: expr, $field:expr) => {{
        $context
            .source_map
            .add_struct_field_mapping($idx, $field.loc)?;
    }};
    (function_type_formals: $context:expr, $var:expr) => {
        for (ty_var, _) in $var.iter() {
            let source_name = (ty_var.value.clone().into_inner(), ty_var.loc);
            $context.source_map.add_function_type_parameter_mapping(
                $context.current_function_definition_index(),
                source_name,
            )?;
        }
    };
    (function_decl: $context:expr, $location:expr, $function_index:expr) => {{
        $context.set_function_index($function_index as TableIndex);
        $context.source_map.add_top_level_function_mapping(
            $context.current_function_definition_index(),
            $location,
        )?;
    }};
    (struct_type_formals: $context:expr, $var:expr) => {
        for (_, ty_var, _) in $var.iter() {
            let source_name = (ty_var.value.clone().into_inner(), ty_var.loc);
            $context.source_map.add_struct_type_parameter_mapping(
                $context.current_struct_definition_index(),
                source_name,
            )?;
        }
    };
    (struct_decl: $context:expr, $location:expr) => {
        $context
            .source_map
            .add_top_level_struct_mapping($context.current_struct_definition_index(), $location)?;
    };
    (const_decl: $context:expr, $const_index:expr, $name:expr) => {
        $context.source_map.add_const_mapping($const_index, $name)?;
    };
}

macro_rules! make_push_instr {
    ($context:ident, $code:ident) => {
        macro_rules! push_instr {
            ($loc:expr, $instr:expr) => {{
                let code_offset = $code.len() as CodeOffset;
                $context.source_map.add_code_mapping(
                    $context.current_function_definition_index(),
                    code_offset,
                    $loc,
                )?;
                $code.push($instr);
            }};
        }
    };
}

macro_rules! make_record_nop_label {
    ($context:ident, $code:ident) => {
        macro_rules! record_nop_label {
            ($label:expr) => {{
                let code_offset = $code.len() as CodeOffset;
                $context.source_map.add_nop_mapping(
                    $context.current_function_definition_index(),
                    $label,
                    code_offset,
                )?;
            }};
        }
    };
}

#[derive(Debug, Default)]
struct LoopInfo {
    start_loc: usize,
    breaks: Vec<usize>,
}

// Ideally, we should capture all of this info into a CFG, but as we only have structured control
// flow currently, it would be a bit overkill. It will be a necessity if we add arbitrary branches
// in the IR, as is expressible in the bytecode
struct ControlFlowInfo {
    // A `break` is reachable iff it was used before a terminal node
    reachable_break: bool,
    // A terminal node is an infinite loop or a path that always returns
    terminal_node: bool,
}

impl ControlFlowInfo {
    fn join(f1: ControlFlowInfo, f2: ControlFlowInfo) -> ControlFlowInfo {
        ControlFlowInfo {
            reachable_break: f1.reachable_break || f2.reachable_break,
            terminal_node: f1.terminal_node && f2.terminal_node,
        }
    }
    fn successor(prev: ControlFlowInfo, next: ControlFlowInfo) -> ControlFlowInfo {
        if prev.terminal_node {
            prev
        } else {
            ControlFlowInfo {
                reachable_break: prev.reachable_break || next.reachable_break,
                terminal_node: next.terminal_node,
            }
        }
    }
}

// Inferred representation of SignatureToken's
// In essence, it's a signature token with a "bottom" type added
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum InferredType {
    // Result of the compiler failing to infer the type of an expression
    // Not translatable to a signature token
    Anything,

    // Signature tokens
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<InferredType>),
    Struct(StructHandleIndex, Vec<InferredType>),
    Reference(Box<InferredType>),
    MutableReference(Box<InferredType>),
    TypeParameter(String),
}

impl InferredType {
    fn from_signature_token_with_subst(
        subst: &HashMap<TypeParameterIndex, InferredType>,
        sig_token: &SignatureToken,
    ) -> Self {
        use InferredType as I;
        use SignatureToken as S;
        match sig_token {
            S::Bool => I::Bool,
            S::U8 => I::U8,
            S::U64 => I::U64,
            S::U128 => I::U128,
            S::Address => I::Address,
            S::Signer => I::Signer,
            S::Vector(s_inner) => I::Vector(Box::new(Self::from_signature_token_with_subst(
                subst, s_inner,
            ))),
            S::Struct(si) => {
                let tys = Self::from_signature_tokens_with_subst(subst, &[]);
                I::Struct(*si, tys)
            }
            S::StructInstantiation(si, sig_tys) => {
                let tys = Self::from_signature_tokens_with_subst(subst, sig_tys);
                I::Struct(*si, tys)
            }
            S::Reference(s_inner) => {
                let i_inner = Self::from_signature_token_with_subst(subst, s_inner);
                I::Reference(Box::new(i_inner))
            }
            S::MutableReference(s_inner) => {
                let i_inner = Self::from_signature_token_with_subst(subst, s_inner);
                I::MutableReference(Box::new(i_inner))
            }
            S::TypeParameter(tp) => match subst.get(tp) {
                Some(bound_type) => bound_type.clone(),
                None => I::TypeParameter(tp.to_string()),
            },
        }
    }

    fn from_signature_tokens_with_subst(
        subst: &HashMap<TypeParameterIndex, InferredType>,
        sig_tokens: &[SignatureToken],
    ) -> Vec<Self> {
        sig_tokens
            .iter()
            .map(|sig_ty| Self::from_signature_token_with_subst(subst, sig_ty))
            .collect()
    }

    fn from_signature_token(sig_token: &SignatureToken) -> Self {
        Self::from_signature_token_with_subst(&HashMap::new(), sig_token)
    }

    fn from_signature_tokens(sig_tokens: &[SignatureToken]) -> Vec<Self> {
        Self::from_signature_tokens_with_subst(&HashMap::new(), sig_tokens)
    }

    fn get_struct_handle(&self) -> Result<(StructHandleIndex, &Vec<InferredType>)> {
        match self {
            InferredType::Anything => bail!("could not infer struct type"),
            InferredType::Bool => bail!("no struct type for Bool"),
            InferredType::U8 => bail!("no struct type for U8"),
            InferredType::U64 => bail!("no struct type for U64"),
            InferredType::U128 => bail!("no struct type for U128"),
            InferredType::Address => bail!("no struct type for Address"),
            InferredType::Signer => bail!("no struct type for Signer"),
            InferredType::Vector(_) => bail!("no struct type for vector"),
            InferredType::Reference(inner) | InferredType::MutableReference(inner) => {
                inner.get_struct_handle()
            }
            InferredType::Struct(idx, tys) => Ok((*idx, tys)),
            InferredType::TypeParameter(_) => bail!("no struct type for type parameter"),
        }
    }

    fn to_signature_token(ty: &Self) -> Result<SignatureToken> {
        use InferredType as I;
        use SignatureToken as S;
        Ok(match ty {
            I::Bool => S::Bool,
            I::U8 => S::U8,
            I::U64 => S::U64,
            I::U128 => S::U128,
            I::Address => S::Address,
            I::Signer => S::Signer,
            I::Vector(inner) => S::Vector(Box::new(Self::to_signature_token(inner)?)),
            I::Struct(si, tys) if tys.is_empty() => S::Struct(*si),
            I::Struct(si, tys) => S::StructInstantiation(*si, Self::build_signature_tokens(tys)?),
            I::Reference(inner) => S::Reference(Box::new(Self::to_signature_token(inner)?)),
            I::MutableReference(inner) => {
                S::MutableReference(Box::new(Self::to_signature_token(inner)?))
            }
            I::TypeParameter(s) => match s.parse::<TableIndex>() {
                Ok(idx) => S::TypeParameter(idx),
                Err(_) => bail!(
                    "ICE unsubstituted type parameter when converting back to signature tokens"
                ),
            },
            I::Anything => bail!("Could not infer type"),
        })
    }

    fn build_signature_tokens(tys: &[InferredType]) -> Result<Vec<SignatureToken>> {
        tys.iter()
            .map(|sig_ty| Self::to_signature_token(sig_ty))
            .collect()
    }
}

// Holds information about a function being compiled.
#[derive(Debug)]
struct FunctionFrame {
    locals: HashMap<Var_, u8>,
    local_types: Signature,
    // i64 to allow the bytecode verifier to catch errors of
    // - negative stack sizes
    // - excessivley large stack sizes
    // The max stack depth of the file_format is set as u16.
    // Theoretically, we could use a BigInt here, but that is probably overkill for any testing
    max_stack_depth: i64,
    cur_stack_depth: i64,
    type_parameters: HashMap<TypeVar_, TypeParameterIndex>,
    loops: Vec<LoopInfo>,
}

impl FunctionFrame {
    fn new(type_parameters: HashMap<TypeVar_, TypeParameterIndex>) -> FunctionFrame {
        FunctionFrame {
            locals: HashMap::new(),
            local_types: Signature(vec![]),
            max_stack_depth: 0,
            cur_stack_depth: 0,
            loops: vec![],
            type_parameters,
        }
    }

    // Manage the stack info for the function
    fn push(&mut self) -> Result<()> {
        if self.cur_stack_depth == i64::max_value() {
            bail!("ICE Stack depth accounting overflow. The compiler can only support a maximum stack depth of up to i64::max_value")
        }
        self.cur_stack_depth += 1;
        self.max_stack_depth = std::cmp::max(self.max_stack_depth, self.cur_stack_depth);
        Ok(())
    }

    fn pop(&mut self) -> Result<()> {
        if self.cur_stack_depth == i64::min_value() {
            bail!("ICE Stack depth accounting underflow. The compiler can only support a minimum stack depth of up to i64::min_value")
        }
        self.cur_stack_depth -= 1;
        Ok(())
    }

    fn get_local(&self, var: &Var_) -> Result<u8> {
        match self.locals.get(var) {
            None => bail!("variable {} undefined", var),
            Some(idx) => Ok(*idx),
        }
    }

    fn get_local_type(&self, idx: u8) -> Result<&SignatureToken> {
        self.local_types
            .0
            .get(idx as usize)
            .ok_or_else(|| format_err!("variable {} undefined", idx))
    }

    fn define_local(&mut self, var: &Var_, type_: SignatureToken) -> Result<u8> {
        if self.locals.len() >= TABLE_MAX_SIZE {
            bail!("Max number of locals reached");
        }

        let cur_loc_idx = self.locals.len() as u8;
        let loc = var.clone();
        let entry = self.locals.entry(loc);
        match entry {
            Occupied(_) => bail!("variable redefinition {}", var),
            Vacant(e) => {
                e.insert(cur_loc_idx);
                self.local_types.0.push(type_);
            }
        }
        Ok(cur_loc_idx)
    }

    fn push_loop(&mut self, start_loc: usize) {
        self.loops.push(LoopInfo {
            start_loc,
            breaks: Vec::new(),
        });
    }

    fn pop_loop(&mut self) -> Result<()> {
        match self.loops.pop() {
            Some(_) => Ok(()),
            None => bail!("Impossible: failed to pop loop!"),
        }
    }

    fn get_loop_start(&self) -> Result<usize> {
        match self.loops.last() {
            Some(loop_) => Ok(loop_.start_loc),
            None => bail!("continue outside loop"),
        }
    }

    fn push_loop_break(&mut self, loc: usize) -> Result<()> {
        match self.loops.last_mut() {
            Some(loop_) => {
                loop_.breaks.push(loc);
                Ok(())
            }
            None => bail!("break outside loop"),
        }
    }

    fn get_loop_breaks(&self) -> Result<&Vec<usize>> {
        match self.loops.last() {
            Some(loop_) => Ok(&loop_.breaks),
            None => bail!("Impossible: failed to get loop breaks (no loops in stack)"),
        }
    }

    fn type_parameters(&self) -> &HashMap<TypeVar_, TypeParameterIndex> {
        &self.type_parameters
    }
}

/// Compile a transaction script.
pub fn compile_script<'a>(
    address: Option<AccountAddress>,
    script: Script,
    dependencies: impl IntoIterator<Item = &'a CompiledModule>,
) -> Result<(CompiledScript, SourceMap<Loc>)> {
    let mut context = Context::new(HashMap::new(), None)?;
    for dep in dependencies {
        context.add_compiled_dependency(dep)?;
    }

    compile_imports(&mut context, address, script.imports.clone())?;
    // Add explicit handles/dependency declarations to `dependencies`
    compile_explicit_dependency_declarations(
        &mut context,
        None,
        script.imports,
        script.explicit_dependency_declarations,
    )?;

    for ir_constant in script.constants {
        let constant = compile_constant(&mut context, ir_constant.signature, ir_constant.value)?;
        context.declare_constant(ir_constant.name.clone(), constant.clone())?;
        let const_idx = context.constant_index(constant)?;
        record_src_loc!(const_decl: context, const_idx, ir_constant.name);
    }

    let function = script.main;

    let sig = function_signature(&mut context, &function.value.signature)?;
    let parameters_sig_idx = context.signature_index(Signature(sig.parameters))?;

    record_src_loc!(function_decl: context, function.loc, 0);
    record_src_loc!(
        function_type_formals: context,
        &function.value.signature.type_formals
    );
    let code = compile_function_body_impl(&mut context, function.value)?.unwrap();

    let (
        MaterializedPools {
            module_handles,
            struct_handles,
            function_handles,
            signatures,
            identifiers,
            address_identifiers,
            constant_pool,
            function_instantiations,
            ..
        },
        _compiled_deps,
        source_map,
    ) = context.materialize_pools();
    let script = CompiledScript {
        version: VERSION_MAX,
        module_handles,
        struct_handles,
        function_handles,
        function_instantiations,
        signatures,
        identifiers,
        address_identifiers,
        constant_pool,

        type_parameters: sig.type_parameters,
        parameters: parameters_sig_idx,
        code,
    };
    match BoundsChecker::verify_script(&script) {
        Ok(()) => Ok((script, source_map)),
        Err(e) => Err(InternalCompilerError::BoundsCheckErrors(
            e.finish(VMErrorLocation::Undefined),
        )
        .into()),
    }
}

/// Compile a module.
pub fn compile_module<'a>(
    address: AccountAddress,
    module: ModuleDefinition,
    dependencies: impl IntoIterator<Item = &'a CompiledModule>,
) -> Result<(CompiledModule, SourceMap<Loc>)> {
    let current_module = QualifiedModuleIdent {
        address,
        name: module.name,
    };
    let mut context = Context::new(HashMap::new(), Some(current_module.clone()))?;
    for dep in dependencies {
        context.add_compiled_dependency(dep)?;
    }

    // Compile friends
    let friend_decls = compile_friends(&mut context, Some(address), module.friends)?;

    // Compile imports
    let self_name = ModuleName::new(ModuleName::self_name().into());
    let self_module_handle_idx = context.declare_import(current_module, self_name.clone())?;
    // Explicitly declare all imports as they will be included even if not used
    compile_imports(&mut context, Some(address), module.imports.clone())?;

    // Add explicit handles/dependency declarations to `dependencies`
    compile_explicit_dependency_declarations(
        &mut context,
        Some(address),
        module.imports,
        module.explicit_dependency_declarations,
    )?;

    // Explicitly declare all structs as they will be included even if not used
    for s in &module.structs {
        let abilities = abilities(&s.value.abilities);
        let ident = QualifiedStructIdent {
            module: self_name.clone(),
            name: s.value.name.clone(),
        };
        let type_parameters = struct_type_parameters(&s.value.type_formals);
        context.declare_struct_handle_index(ident, abilities, type_parameters)?;
    }

    for ir_constant in module.constants {
        let constant = compile_constant(&mut context, ir_constant.signature, ir_constant.value)?;
        context.declare_constant(ir_constant.name.clone(), constant.clone())?;
        let const_idx = context.constant_index(constant)?;
        record_src_loc!(const_decl: context, const_idx, ir_constant.name);
    }

    for (name, function) in &module.functions {
        let sig = function_signature(&mut context, &function.value.signature)?;
        context.declare_function(self_name.clone(), name.clone(), sig)?;
    }

    // Compile definitions
    let struct_defs = compile_structs(&mut context, &self_name, module.structs)?;
    let function_defs = compile_functions(&mut context, &self_name, module.functions)?;

    let (
        MaterializedPools {
            module_handles,
            struct_handles,
            function_handles,
            field_handles,
            signatures,
            identifiers,
            address_identifiers,
            constant_pool,
            function_instantiations,
            struct_def_instantiations,
            field_instantiations,
        },
        _compiled_deps,
        source_map,
    ) = context.materialize_pools();
    CompiledModule {
        version: VERSION_MAX,
        module_handles,
        self_module_handle_idx,
        struct_handles,
        function_handles,
        field_handles,
        friend_decls,
        struct_def_instantiations,
        function_instantiations,
        field_instantiations,
        signatures,
        identifiers,
        address_identifiers,
        constant_pool,
        struct_defs,
        function_defs,
    }
    .freeze()
    .map_err(|e| {
        InternalCompilerError::BoundsCheckErrors(e.finish(VMErrorLocation::Undefined)).into()
    })
    .map(|frozen_module| (frozen_module, source_map))
}

// Note: DO NOT try to recover from this function as it zeros out the `outer_contexts` dependencies
// and sets them after a successful result
// Any `Error` should stop compilation in the caller
fn compile_explicit_dependency_declarations(
    outer_context: &mut Context,
    address_opt: Option<AccountAddress>,
    imports: Vec<ImportDefinition>,
    dependencies: Vec<ModuleDependency>,
) -> Result<()> {
    let mut dependencies_acc = outer_context.take_dependencies();
    for dependency in dependencies {
        let ModuleDependency {
            name: mname,
            structs,
            functions,
        } = dependency;
        let current_module = outer_context.module_ident(&mname)?;
        let mut context = Context::new(dependencies_acc, Some(current_module.clone()))?;
        compile_imports(&mut context, address_opt, imports.clone())?;
        let self_module_handle_idx = context.module_handle_index(&mname)?;
        for struct_dep in structs {
            let StructDependency {
                abilities: abs,
                name,
                type_formals: tys,
            } = struct_dep;
            let sname = QualifiedStructIdent::new(mname.clone(), name);
            let ability_set = abilities(&abs);
            let kinds = struct_type_parameters(&tys);
            context.declare_struct_handle_index(sname, ability_set, kinds)?;
        }
        for function_dep in functions {
            let FunctionDependency { name, signature } = function_dep;
            let sig = function_signature(&mut context, &signature)?;
            context.declare_function(mname.clone(), name, sig)?;
        }

        let (
            MaterializedPools {
                module_handles,
                struct_handles,
                function_handles,
                field_handles,
                signatures,
                identifiers,
                address_identifiers,
                constant_pool,
                function_instantiations,
                struct_def_instantiations,
                field_instantiations,
            },
            compiled_deps,
            _source_map,
        ) = context.materialize_pools();
        let compiled_module = CompiledModule {
            version: VERSION_MAX,
            module_handles,
            self_module_handle_idx,
            struct_handles,
            function_handles,
            field_handles,
            friend_decls: vec![],
            struct_def_instantiations,
            function_instantiations,
            field_instantiations,
            signatures,
            identifiers,
            address_identifiers,
            constant_pool,
            struct_defs: vec![],
            function_defs: vec![],
        }
        .freeze()
        .map_err(|e| {
            InternalCompilerError::BoundsCheckErrors(e.finish(VMErrorLocation::Undefined))
        })?;
        dependencies_acc = compiled_deps;
        dependencies_acc.insert(
            current_module.clone(),
            CompiledDependency::stored(compiled_module)?,
        );
    }
    outer_context.restore_dependencies(dependencies_acc);
    Ok(())
}

fn compile_friends(
    context: &mut Context,
    address_opt: Option<AccountAddress>,
    friends: Vec<ast::ModuleIdent>,
) -> Result<Vec<ModuleHandle>> {
    let mut friend_decls = vec![];
    for friend in friends {
        let ident = match (address_opt, friend) {
            (Some(address), ModuleIdent::Transaction(name)) => {
                QualifiedModuleIdent { name, address }
            }
            (None, ModuleIdent::Transaction(name)) => bail!(
                "Invalid friend '{}'. No address specified for script so cannot resolve friend",
                name
            ),
            (_, ModuleIdent::Qualified(id)) => id,
        };
        let handle = context.declare_friend(ident)?;
        friend_decls.push(handle);
    }
    Ok(friend_decls)
}

fn compile_imports(
    context: &mut Context,
    address_opt: Option<AccountAddress>,
    imports: Vec<ImportDefinition>,
) -> Result<()> {
    for import in imports {
        let ident = match (address_opt, import.ident) {
            (Some(address), ModuleIdent::Transaction(name)) => {
                QualifiedModuleIdent { name, address }
            }
            (None, ModuleIdent::Transaction(name)) => bail!(
                "Invalid import '{}'. No address specified for script so cannot resolve import",
                name
            ),
            (_, ModuleIdent::Qualified(id)) => id,
        };
        context.declare_import(ident, import.alias)?;
    }
    Ok(())
}

fn type_parameter_indexes<'a>(
    ast_tys: impl IntoIterator<Item = &'a TypeVar>,
) -> Result<HashMap<TypeVar_, TypeParameterIndex>> {
    let mut m = HashMap::new();
    for (idx, ty_var) in ast_tys.into_iter().enumerate() {
        if idx > TABLE_MAX_SIZE {
            bail!("Too many type parameters")
        }
        let old = m.insert(ty_var.value.clone(), idx as TypeParameterIndex);
        if old.is_some() {
            bail!("Type formal '{}'' already bound", ty_var)
        }
    }
    Ok(m)
}

fn make_type_argument_subst(
    tokens: &[InferredType],
) -> Result<HashMap<TypeParameterIndex, InferredType>> {
    let mut subst = HashMap::new();
    for (idx, token) in tokens.iter().enumerate() {
        if idx > TABLE_MAX_SIZE {
            bail!("Too many type arguments")
        }
        subst.insert(idx as TypeParameterIndex, token.clone());
    }
    Ok(subst)
}

fn struct_type_parameters(ast_tys: &[ast::StructTypeParameter]) -> Vec<StructTypeParameter> {
    ast_tys
        .iter()
        .map(|(is_phantom, _, abs)| StructTypeParameter {
            constraints: abilities(abs),
            is_phantom: *is_phantom,
        })
        .collect()
}

fn abilities(abilities: &BTreeSet<ast::Ability>) -> AbilitySet {
    abilities
        .iter()
        .map(|a| ability(a))
        .fold(AbilitySet::EMPTY, |acc, a| acc | a)
}

fn ability(ab: &ast::Ability) -> Ability {
    match ab {
        ast::Ability::Copy => Ability::Copy,
        ast::Ability::Drop => Ability::Drop,
        ast::Ability::Store => Ability::Store,
        ast::Ability::Key => Ability::Key,
    }
}

fn compile_types(
    context: &mut Context,
    type_parameters: &HashMap<TypeVar_, TypeParameterIndex>,
    tys: &[Type],
) -> Result<Vec<SignatureToken>> {
    tys.iter()
        .map(|ty| compile_type(context, type_parameters, ty))
        .collect::<Result<_>>()
}

fn compile_type(
    context: &mut Context,
    type_parameters: &HashMap<TypeVar_, TypeParameterIndex>,
    ty: &Type,
) -> Result<SignatureToken> {
    Ok(match ty {
        Type::Address => SignatureToken::Address,
        Type::Signer => SignatureToken::Signer,
        Type::U8 => SignatureToken::U8,
        Type::U64 => SignatureToken::U64,
        Type::U128 => SignatureToken::U128,
        Type::Bool => SignatureToken::Bool,
        Type::Vector(inner_type) => SignatureToken::Vector(Box::new(compile_type(
            context,
            type_parameters,
            inner_type,
        )?)),
        Type::Reference(is_mutable, inner_type) => {
            let inner_token = Box::new(compile_type(context, type_parameters, inner_type)?);
            if *is_mutable {
                SignatureToken::MutableReference(inner_token)
            } else {
                SignatureToken::Reference(inner_token)
            }
        }
        Type::Struct(ident, tys) => {
            let sh_idx = context.struct_handle_index(ident.clone())?;

            if tys.is_empty() {
                SignatureToken::Struct(sh_idx)
            } else {
                let tokens = compile_types(context, type_parameters, tys)?;
                SignatureToken::StructInstantiation(sh_idx, tokens)
            }
        }
        Type::TypeParameter(ty_var) => {
            let idx = match type_parameters.get(&ty_var) {
                None => bail!("Unbound type parameter {}", ty_var),
                Some(idx) => *idx,
            };
            SignatureToken::TypeParameter(idx)
        }
    })
}

fn function_signature(
    context: &mut Context,
    f: &ast::FunctionSignature,
) -> Result<FunctionSignature> {
    let m = type_parameter_indexes(f.type_formals.iter().map(|formal| &formal.0))?;
    let return_ = compile_types(context, &m, &f.return_type)?;
    let parameters = f
        .formals
        .iter()
        .map(|(_, ty)| compile_type(context, &m, ty))
        .collect::<Result<_>>()?;
    let type_parameters = f
        .type_formals
        .iter()
        .map(|(_, abs)| abilities(abs))
        .collect();
    Ok(move_binary_format::file_format::FunctionSignature {
        return_,
        parameters,
        type_parameters,
    })
}

fn compile_structs(
    context: &mut Context,
    self_name: &ModuleName,
    structs: Vec<ast::StructDefinition>,
) -> Result<Vec<StructDefinition>> {
    let mut struct_defs = vec![];
    for s in structs {
        let sident = QualifiedStructIdent {
            module: self_name.clone(),
            name: s.value.name.clone(),
        };
        let sh_idx = context.struct_handle_index(sident.clone())?;
        record_src_loc!(struct_decl: context, s.loc);
        record_src_loc!(struct_type_formals: context, &s.value.type_formals);
        let m = type_parameter_indexes(s.value.type_formals.iter().map(|formal| &formal.1))?;
        let sd_idx = context.declare_struct_definition_index(s.value.name)?;
        let field_information = compile_fields(context, &m, sh_idx, sd_idx, s.value.fields)?;
        struct_defs.push(StructDefinition {
            struct_handle: sh_idx,
            field_information,
        });
    }
    Ok(struct_defs)
}

fn compile_fields(
    context: &mut Context,
    type_parameters: &HashMap<TypeVar_, TypeParameterIndex>,
    sh_idx: StructHandleIndex,
    sd_idx: StructDefinitionIndex,
    sfields: StructDefinitionFields,
) -> Result<StructFieldInformation> {
    Ok(match sfields {
        StructDefinitionFields::Native => StructFieldInformation::Native,
        StructDefinitionFields::Move { fields } => {
            let mut decl_fields = vec![];
            for (decl_order, (f, ty)) in fields.into_iter().enumerate() {
                let name = context.identifier_index(f.value.as_inner())?;
                record_src_loc!(field: context, sd_idx, f);
                let sig_token = compile_type(context, type_parameters, &ty)?;
                context.declare_field(sh_idx, sd_idx, f.value, sig_token.clone(), decl_order);
                decl_fields.push(FieldDefinition {
                    name,
                    signature: TypeSignature(sig_token),
                });
            }
            StructFieldInformation::Declared(decl_fields)
        }
    })
}

fn compile_functions(
    context: &mut Context,
    self_name: &ModuleName,
    functions: Vec<(FunctionName, Function)>,
) -> Result<Vec<FunctionDefinition>> {
    functions
        .into_iter()
        .enumerate()
        .map(|(func_index, (name, ast_function))| {
            compile_function(context, self_name, name, ast_function, func_index)
        })
        .collect()
}

fn compile_function_body_impl(
    context: &mut Context,
    ast_function: Function_,
) -> Result<Option<CodeUnit>> {
    Ok(match ast_function.body {
        FunctionBody::Move { locals, code } => {
            let m = type_parameter_indexes(
                ast_function
                    .signature
                    .type_formals
                    .iter()
                    .map(|formal| &formal.0),
            )?;
            Some(compile_function_body(
                context,
                m,
                ast_function.signature.formals,
                locals,
                code,
            )?)
        }
        FunctionBody::Bytecode { locals, code } => {
            let m = type_parameter_indexes(
                ast_function
                    .signature
                    .type_formals
                    .iter()
                    .map(|formal| &formal.0),
            )?;
            Some(compile_function_body_bytecode(
                context,
                m,
                ast_function.signature.formals,
                locals,
                code,
            )?)
        }

        FunctionBody::Native => {
            for (var, _) in ast_function.signature.formals.into_iter() {
                record_src_loc!(parameter: context, var)
            }
            None
        }
    })
}

fn compile_function(
    context: &mut Context,
    self_name: &ModuleName,
    name: FunctionName,
    ast_function: Function,
    function_index: usize,
) -> Result<FunctionDefinition> {
    record_src_loc!(function_decl: context, ast_function.loc, function_index);
    record_src_loc!(
        function_type_formals: context,
        &ast_function.value.signature.type_formals
    );
    let fh_idx = context.function_handle(self_name.clone(), name)?.1;

    let ast_function = ast_function.value;

    let visibility = match ast_function.visibility {
        FunctionVisibility::Public => Visibility::Public,
        FunctionVisibility::Script => Visibility::Script,
        FunctionVisibility::Friend => Visibility::Friend,
        FunctionVisibility::Internal => Visibility::Private,
    };
    let acquires_global_resources = ast_function
        .acquires
        .iter()
        .map(|name| context.struct_definition_index(name))
        .collect::<Result<_>>()?;

    let code = compile_function_body_impl(context, ast_function)?;

    Ok(FunctionDefinition {
        function: fh_idx,
        visibility,
        acquires_global_resources,
        code,
    })
}

fn compile_function_body(
    context: &mut Context,
    type_parameters: HashMap<TypeVar_, TypeParameterIndex>,
    formals: Vec<(Var, Type)>,
    locals: Vec<(Var, Type)>,
    block: Block_,
) -> Result<CodeUnit> {
    let mut function_frame = FunctionFrame::new(type_parameters);
    let mut locals_signature = Signature(vec![]);
    for (var, t) in formals {
        let sig = compile_type(context, function_frame.type_parameters(), &t)?;
        function_frame.define_local(&var.value, sig.clone())?;
        record_src_loc!(parameter: context, var);
    }

    for (var_, t) in locals {
        let sig = compile_type(context, function_frame.type_parameters(), &t)?;
        function_frame.define_local(&var_.value, sig.clone())?;
        locals_signature.0.push(sig);
        record_src_loc!(local: context, var_);
    }
    let sig_idx = context.signature_index(locals_signature)?;

    let mut code = vec![];
    compile_block(context, &mut function_frame, &mut code, block)?;
    Ok(CodeUnit {
        locals: sig_idx,
        code,
    })
}

fn compile_block(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    block: Block_,
) -> Result<ControlFlowInfo> {
    let mut cf_info = ControlFlowInfo {
        reachable_break: false,
        terminal_node: false,
    };
    for stmt in block.stmts {
        let stmt_info = match stmt {
            Statement::CommandStatement(command) => {
                compile_command(context, function_frame, code, command)?
            }
            Statement::WhileStatement(while_) => {
                // always assume the loop might not be taken
                compile_while(context, function_frame, code, while_)?
            }
            Statement::LoopStatement(loop_) => compile_loop(context, function_frame, code, loop_)?,
            Statement::IfElseStatement(if_else) => {
                compile_if_else(context, function_frame, code, if_else)?
            }
            Statement::EmptyStatement => continue,
        };
        cf_info = ControlFlowInfo::successor(cf_info, stmt_info);
    }
    Ok(cf_info)
}

fn compile_if_else(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    if_else: IfElse,
) -> Result<ControlFlowInfo> {
    make_push_instr!(context, code);
    let cond_span = if_else.cond.loc;
    compile_expression(context, function_frame, code, if_else.cond)?;

    let brfalse_ins_loc = code.len();
    // placeholder, final branch target replaced later
    push_instr!(cond_span, Bytecode::BrFalse(0));
    function_frame.pop()?;
    let if_cf_info = compile_block(context, function_frame, code, if_else.if_block.value)?;

    let mut else_block_location = code.len();

    let else_cf_info = match if_else.else_block {
        None => ControlFlowInfo {
            reachable_break: false,
            terminal_node: false,
        },
        Some(else_block) => {
            let branch_ins_loc = code.len();
            if !if_cf_info.terminal_node {
                // placeholder, final branch target replaced later
                push_instr!(else_block.loc, Bytecode::Branch(0));
                else_block_location += 1;
            }
            let else_cf_info = compile_block(context, function_frame, code, else_block.value)?;
            if !if_cf_info.terminal_node {
                code[branch_ins_loc] = Bytecode::Branch(code.len() as u16);
            }
            else_cf_info
        }
    };

    code[brfalse_ins_loc] = Bytecode::BrFalse(else_block_location as u16);

    let cf_info = ControlFlowInfo::join(if_cf_info, else_cf_info);
    Ok(cf_info)
}

fn compile_while(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    while_: While,
) -> Result<ControlFlowInfo> {
    make_push_instr!(context, code);
    let cond_span = while_.cond.loc;
    let loop_start_loc = code.len();
    function_frame.push_loop(loop_start_loc);
    compile_expression(context, function_frame, code, while_.cond)?;

    let brfalse_loc = code.len();

    // placeholder, final branch target replaced later
    push_instr!(cond_span, Bytecode::BrFalse(0));
    function_frame.pop()?;

    compile_block(context, function_frame, code, while_.block.value)?;
    push_instr!(while_.block.loc, Bytecode::Branch(loop_start_loc as u16));

    let loop_end_loc = code.len() as u16;
    code[brfalse_loc] = Bytecode::BrFalse(loop_end_loc);
    let breaks = function_frame.get_loop_breaks()?;
    for i in breaks {
        code[*i] = Bytecode::Branch(loop_end_loc);
    }

    function_frame.pop_loop()?;
    Ok(ControlFlowInfo {
        // this `reachable_break` break is for any outer loop
        // not the loop that was just compiled
        reachable_break: false,
        // While always has the ability to break.
        // Conceptually we treat
        //   `while (cond) { body }`
        // as `
        //   `loop { if (cond) { body; continue; } else { break; } }`
        // So a `break` is always reachable
        terminal_node: false,
    })
}

fn compile_loop(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    loop_: Loop,
) -> Result<ControlFlowInfo> {
    make_push_instr!(context, code);
    let loop_start_loc = code.len();
    function_frame.push_loop(loop_start_loc);

    let body_cf_info = compile_block(context, function_frame, code, loop_.block.value)?;
    push_instr!(loop_.block.loc, Bytecode::Branch(loop_start_loc as u16));

    let loop_end_loc = code.len() as u16;
    let breaks = function_frame.get_loop_breaks()?;
    for i in breaks {
        code[*i] = Bytecode::Branch(loop_end_loc);
    }

    function_frame.pop_loop()?;
    // this `reachable_break` break is for any outer loop
    // not the loop that was just compiled
    let reachable_break = false;
    // If the body of the loop does not have a break, it will loop forever
    // and thus is a terminal node
    let terminal_node = !body_cf_info.reachable_break;
    Ok(ControlFlowInfo {
        reachable_break,
        terminal_node,
    })
}

fn compile_command(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    cmd: Cmd,
) -> Result<ControlFlowInfo> {
    make_push_instr!(context, code);
    let (reachable_break, terminal_node) = match &cmd.value {
            // If we are in a loop, `continue` makes a terminal node
            // Conceptually we treat
            //   `while (cond) { body }`
            // as `
            //   `loop { if (cond) { body; continue; } else { break; } }`
            Cmd_::Continue |
            // `return` and `abort` alway makes a terminal node
            Cmd_::Abort(_) |
            Cmd_::Return(_) => (false, true),
            Cmd_::Break => (true, false),
            _ => (false, false),
        };
    match cmd.value {
        Cmd_::Return(exps) => {
            compile_expression(context, function_frame, code, *exps)?;
            push_instr!(cmd.loc, Bytecode::Ret);
        }
        Cmd_::Abort(exp_opt) => {
            if let Some(exp) = exp_opt {
                compile_expression(context, function_frame, code, *exp)?;
            }
            push_instr!(cmd.loc, Bytecode::Abort);
            function_frame.pop()?;
        }
        Cmd_::Assign(lvalues, rhs_expressions) => {
            compile_expression(context, function_frame, code, rhs_expressions)?;
            compile_lvalues(context, function_frame, code, lvalues)?;
        }
        Cmd_::Unpack(name, tys, bindings, e) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);

            compile_expression(context, function_frame, code, *e)?;

            let def_idx = context.struct_definition_index(&name)?;
            if tys.is_empty() {
                push_instr!(cmd.loc, Bytecode::Unpack(def_idx));
            } else {
                let type_parameters_id = context.signature_index(tokens)?;
                let si_idx = context.struct_instantiation_index(def_idx, type_parameters_id)?;
                push_instr!(cmd.loc, Bytecode::UnpackGeneric(si_idx));
            }
            function_frame.pop()?;

            for (field_, lhs_variable) in bindings.iter().rev() {
                let loc_idx = function_frame.get_local(&lhs_variable.value)?;
                let st_loc = Bytecode::StLoc(loc_idx);
                push_instr!(field_.loc, st_loc);
            }
        }
        Cmd_::Continue => {
            let loc = function_frame.get_loop_start()?;
            push_instr!(cmd.loc, Bytecode::Branch(loc as u16));
        }
        Cmd_::Break => {
            function_frame.push_loop_break(code.len())?;
            // placeholder, to be replaced when the enclosing while is compiled
            push_instr!(cmd.loc, Bytecode::Branch(0));
        }
        Cmd_::Exp(e) => {
            compile_expression(context, function_frame, code, *e)?;
        }
    }
    Ok(ControlFlowInfo {
        reachable_break,
        terminal_node,
    })
}

fn compile_lvalues(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    lvalues: Vec<LValue>,
) -> Result<()> {
    make_push_instr!(context, code);
    for lvalue_ in lvalues.into_iter().rev() {
        match lvalue_.value {
            LValue_::Var(v) => {
                let loc_idx = function_frame.get_local(&v.value)?;
                push_instr!(lvalue_.loc, Bytecode::StLoc(loc_idx));
                function_frame.pop()?;
            }
            LValue_::Mutate(e) => {
                compile_expression(context, function_frame, code, e)?;
                push_instr!(lvalue_.loc, Bytecode::WriteRef);
                function_frame.pop()?;
                function_frame.pop()?;
            }
            LValue_::Pop => {
                push_instr!(lvalue_.loc, Bytecode::Pop);
                function_frame.pop()?;
            }
        }
    }
    Ok(())
}

macro_rules! vec_deque {
    ($($x:expr),*) => {
        VecDeque::from(vec![$($x),*])
    }
}

fn infer_int_bin_op_result_ty(
    tys1: &VecDeque<InferredType>,
    tys2: &VecDeque<InferredType>,
) -> InferredType {
    use InferredType as I;
    if tys1.len() != 1 || tys2.len() != 1 {
        return I::Anything;
    }
    match (&tys1[0], &tys2[0]) {
        (I::U8, I::U8) => I::U8,
        (I::U64, I::U64) => I::U64,
        (I::U128, I::U128) => I::U128,
        _ => I::Anything,
    }
}

fn compile_expression(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    exp: Exp,
) -> Result<VecDeque<InferredType>> {
    make_push_instr!(context, code);
    Ok(match exp.value {
        Exp_::Move(v) => {
            let loc_idx = function_frame.get_local(&v.value)?;
            let load_loc = Bytecode::MoveLoc(loc_idx);
            push_instr!(exp.loc, load_loc);
            function_frame.push()?;
            let loc_type = function_frame.get_local_type(loc_idx)?;
            vec_deque![InferredType::from_signature_token(loc_type)]
        }
        Exp_::Copy(v) => {
            let loc_idx = function_frame.get_local(&v.value)?;
            let load_loc = Bytecode::CopyLoc(loc_idx);
            push_instr!(exp.loc, load_loc);
            function_frame.push()?;
            let loc_type = function_frame.get_local_type(loc_idx)?;
            vec_deque![InferredType::from_signature_token(loc_type)]
        }
        Exp_::BorrowLocal(is_mutable, v) => {
            let loc_idx = function_frame.get_local(&v.value)?;
            let loc_type = function_frame.get_local_type(loc_idx)?;
            let inner_token = Box::new(InferredType::from_signature_token(loc_type));
            if is_mutable {
                push_instr!(exp.loc, Bytecode::MutBorrowLoc(loc_idx));
                function_frame.push()?;
                vec_deque![InferredType::MutableReference(inner_token)]
            } else {
                push_instr!(exp.loc, Bytecode::ImmBorrowLoc(loc_idx));
                function_frame.push()?;
                vec_deque![InferredType::Reference(inner_token)]
            }
        }
        Exp_::Value(cv) => match cv.value {
            CopyableVal_::Address(address) => {
                let address_value = MoveValue::Address(address);
                let constant = compile_constant(context, Type::Address, address_value)?;
                let idx = context.constant_index(constant)?;
                push_instr!(exp.loc, Bytecode::LdConst(idx));
                function_frame.push()?;
                vec_deque![InferredType::Address]
            }
            CopyableVal_::U8(i) => {
                push_instr!(exp.loc, Bytecode::LdU8(i));
                function_frame.push()?;
                vec_deque![InferredType::U8]
            }
            CopyableVal_::U64(i) => {
                push_instr!(exp.loc, Bytecode::LdU64(i));
                function_frame.push()?;
                vec_deque![InferredType::U64]
            }
            CopyableVal_::U128(i) => {
                push_instr!(exp.loc, Bytecode::LdU128(i));
                function_frame.push()?;
                vec_deque![InferredType::U128]
            }
            CopyableVal_::ByteArray(buf) => {
                let vec_value = MoveValue::vector_u8(buf);
                let ty = Type::Vector(Box::new(Type::U8));
                let constant = compile_constant(context, ty, vec_value)?;
                let idx = context.constant_index(constant)?;
                push_instr!(exp.loc, Bytecode::LdConst(idx));
                function_frame.push()?;
                vec_deque![InferredType::Vector(Box::new(InferredType::U8))]
            }
            CopyableVal_::Bool(b) => {
                push_instr! {exp.loc,
                    if b {
                        Bytecode::LdTrue
                    } else {
                        Bytecode::LdFalse
                    }
                };
                function_frame.push()?;
                vec_deque![InferredType::Bool]
            }
        },
        Exp_::Pack(name, ast_tys, fields) => {
            let sig_tys = compile_types(context, function_frame.type_parameters(), &ast_tys)?;
            let tys = InferredType::from_signature_tokens(&sig_tys);
            let tokens = Signature(sig_tys);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&name)?;

            let self_name = ModuleName::new(ModuleName::self_name().into());
            let ident = QualifiedStructIdent {
                module: self_name,
                name: name.clone(),
            };
            let sh_idx = context.struct_handle_index(ident)?;

            let num_fields = fields.len();
            for (field_order, (field, e)) in fields.into_iter().enumerate() {
                // Check that the fields are specified in order matching the definition.
                let (_, _, decl_order) = context.field(sh_idx, field.value.clone())?;
                if field_order != decl_order {
                    bail!("Field {} defined out of order for struct {}", field, name);
                }

                compile_expression(context, function_frame, code, e)?;
            }
            if tys.is_empty() {
                push_instr!(exp.loc, Bytecode::Pack(def_idx));
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                push_instr!(exp.loc, Bytecode::PackGeneric(si_idx));
            }
            for _ in 0..num_fields {
                function_frame.pop()?;
            }
            function_frame.push()?;

            vec_deque![InferredType::Struct(sh_idx, tys)]
        }
        Exp_::UnaryExp(op, e) => {
            compile_expression(context, function_frame, code, *e)?;
            match op {
                UnaryOp::Not => {
                    push_instr!(exp.loc, Bytecode::Not);
                    vec_deque![InferredType::Bool]
                }
            }
        }
        Exp_::BinopExp(e1, op, e2) => {
            let tys1 = compile_expression(context, function_frame, code, *e1)?;
            let tys2 = compile_expression(context, function_frame, code, *e2)?;

            function_frame.pop()?;
            match op {
                BinOp::Add => {
                    push_instr!(exp.loc, Bytecode::Add);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::Sub => {
                    push_instr!(exp.loc, Bytecode::Sub);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::Mul => {
                    push_instr!(exp.loc, Bytecode::Mul);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::Mod => {
                    push_instr!(exp.loc, Bytecode::Mod);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::Div => {
                    push_instr!(exp.loc, Bytecode::Div);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::BitOr => {
                    push_instr!(exp.loc, Bytecode::BitOr);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::BitAnd => {
                    push_instr!(exp.loc, Bytecode::BitAnd);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::Xor => {
                    push_instr!(exp.loc, Bytecode::Xor);
                    vec_deque![infer_int_bin_op_result_ty(&tys1, &tys2)]
                }
                BinOp::Shl => {
                    push_instr!(exp.loc, Bytecode::Shl);
                    tys1
                }
                BinOp::Shr => {
                    push_instr!(exp.loc, Bytecode::Shr);
                    tys1
                }
                BinOp::Or => {
                    push_instr!(exp.loc, Bytecode::Or);
                    vec_deque![InferredType::Bool]
                }
                BinOp::And => {
                    push_instr!(exp.loc, Bytecode::And);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Eq => {
                    push_instr!(exp.loc, Bytecode::Eq);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Neq => {
                    push_instr!(exp.loc, Bytecode::Neq);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Lt => {
                    push_instr!(exp.loc, Bytecode::Lt);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Gt => {
                    push_instr!(exp.loc, Bytecode::Gt);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Le => {
                    push_instr!(exp.loc, Bytecode::Le);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Ge => {
                    push_instr!(exp.loc, Bytecode::Ge);
                    vec_deque![InferredType::Bool]
                }
                BinOp::Subrange => {
                    unreachable!("Subrange operators should only appear in specification ASTs.");
                }
            }
        }
        Exp_::Dereference(e) => {
            let loc_type = compile_expression(context, function_frame, code, *e)?.pop_front();
            push_instr!(exp.loc, Bytecode::ReadRef);
            match loc_type {
                Some(InferredType::MutableReference(sig_ref_token)) => vec_deque![*sig_ref_token],
                Some(InferredType::Reference(sig_ref_token)) => vec_deque![*sig_ref_token],
                _ => vec_deque![InferredType::Anything],
            }
        }
        Exp_::Borrow {
            is_mutable,
            exp: inner_exp,
            field,
        } => {
            let loc_type_opt =
                compile_expression(context, function_frame, code, *inner_exp)?.pop_front();
            let loc_type =
                loc_type_opt.ok_or_else(|| format_err!("Impossible no expression to borrow"))?;
            let (sh_idx, tys) = loc_type.get_struct_handle()?;
            let subst = make_type_argument_subst(tys)?;
            let (def_idx, field_type, field_offset) = context.field(sh_idx, field)?;

            function_frame.pop()?;
            let inner_token = Box::new(InferredType::from_signature_token_with_subst(
                &subst,
                &field_type,
            ));

            let fh_idx = context.field_handle_index(def_idx, field_offset as u16)?;
            if tys.is_empty() {
                if is_mutable {
                    push_instr!(exp.loc, Bytecode::MutBorrowField(fh_idx));
                } else {
                    push_instr!(exp.loc, Bytecode::ImmBorrowField(fh_idx));
                }
            } else {
                let inst = InferredType::build_signature_tokens(tys)?;
                let inst_idx = context.signature_index(Signature(inst))?;
                let field_inst_idx = context.field_instantiation_index(fh_idx, inst_idx)?;
                if is_mutable {
                    push_instr!(exp.loc, Bytecode::MutBorrowFieldGeneric(field_inst_idx));
                } else {
                    push_instr!(exp.loc, Bytecode::ImmBorrowFieldGeneric(field_inst_idx));
                }
            };
            function_frame.push()?;
            if is_mutable {
                vec_deque![InferredType::MutableReference(inner_token)]
            } else {
                vec_deque![InferredType::Reference(inner_token)]
            }
        }
        Exp_::FunctionCall(f, exps) => {
            let mut actuals_tys = vec_deque![];
            for types in compile_expression(context, function_frame, code, *exps)? {
                actuals_tys.push_back(types);
            }
            compile_call(context, function_frame, code, f, actuals_tys)?
        }
        Exp_::ExprList(exps) => {
            let mut result = vec_deque![];
            for e in exps {
                result.append(&mut compile_expression(context, function_frame, code, e)?);
            }
            result
        }
    })
}

fn compile_call(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    call: FunctionCall,
    mut argument_types: VecDeque<InferredType>,
) -> Result<VecDeque<InferredType>> {
    make_push_instr!(context, code);
    Ok(match call.value {
        FunctionCall_::Builtin(function) => {
            match function {
                Builtin::Exists(name, tys) => {
                    let tokens = Signature(compile_types(
                        context,
                        function_frame.type_parameters(),
                        &tys,
                    )?);
                    let type_actuals_id = context.signature_index(tokens)?;
                    let def_idx = context.struct_definition_index(&name)?;
                    if tys.is_empty() {
                        push_instr!(call.loc, Bytecode::Exists(def_idx));
                    } else {
                        let si_idx =
                            context.struct_instantiation_index(def_idx, type_actuals_id)?;
                        push_instr!(call.loc, Bytecode::ExistsGeneric(si_idx));
                    }
                    function_frame.pop()?;
                    function_frame.push()?;
                    vec_deque![InferredType::Bool]
                }
                Builtin::BorrowGlobal(mut_, name, ast_tys) => {
                    let sig_tys =
                        compile_types(context, function_frame.type_parameters(), &ast_tys)?;
                    let tys = InferredType::from_signature_tokens(&sig_tys);
                    let tokens = Signature(sig_tys);
                    let type_actuals_id = context.signature_index(tokens)?;
                    let def_idx = context.struct_definition_index(&name)?;
                    if tys.is_empty() {
                        push_instr! {call.loc,
                            if mut_ {
                                Bytecode::MutBorrowGlobal(def_idx)
                            } else {
                                Bytecode::ImmBorrowGlobal(def_idx)
                            }
                        };
                    } else {
                        let si_idx =
                            context.struct_instantiation_index(def_idx, type_actuals_id)?;
                        push_instr! {call.loc,
                            if mut_ {
                                Bytecode::MutBorrowGlobalGeneric(si_idx)
                            } else {
                                Bytecode::ImmBorrowGlobalGeneric(si_idx)
                            }
                        };
                    }
                    function_frame.pop()?;
                    function_frame.push()?;

                    let self_name = ModuleName::new(ModuleName::self_name().into());
                    let ident = QualifiedStructIdent {
                        module: self_name,
                        name,
                    };
                    let sh_idx = context.struct_handle_index(ident)?;
                    let inner = Box::new(InferredType::Struct(sh_idx, tys));
                    vec_deque![if mut_ {
                        InferredType::MutableReference(inner)
                    } else {
                        InferredType::Reference(inner)
                    }]
                }
                Builtin::MoveFrom(name, ast_tys) => {
                    let sig_tys =
                        compile_types(context, function_frame.type_parameters(), &ast_tys)?;
                    let tys = InferredType::from_signature_tokens(&sig_tys);
                    let tokens = Signature(sig_tys);
                    let type_actuals_id = context.signature_index(tokens)?;
                    let def_idx = context.struct_definition_index(&name)?;
                    if tys.is_empty() {
                        push_instr!(call.loc, Bytecode::MoveFrom(def_idx));
                    } else {
                        let si_idx =
                            context.struct_instantiation_index(def_idx, type_actuals_id)?;
                        push_instr!(call.loc, Bytecode::MoveFromGeneric(si_idx));
                    }
                    function_frame.pop()?; // pop the address
                    function_frame.push()?; // push the return value

                    let self_name = ModuleName::new(ModuleName::self_name().into());
                    let ident = QualifiedStructIdent {
                        module: self_name,
                        name,
                    };
                    let sh_idx = context.struct_handle_index(ident)?;
                    vec_deque![InferredType::Struct(sh_idx, tys)]
                }
                Builtin::MoveTo(name, tys) => {
                    let tokens = Signature(compile_types(
                        context,
                        function_frame.type_parameters(),
                        &tys,
                    )?);
                    let type_actuals_id = context.signature_index(tokens)?;
                    let def_idx = context.struct_definition_index(&name)?;
                    if tys.is_empty() {
                        push_instr!(call.loc, Bytecode::MoveTo(def_idx));
                    } else {
                        let si_idx =
                            context.struct_instantiation_index(def_idx, type_actuals_id)?;
                        push_instr!(call.loc, Bytecode::MoveToGeneric(si_idx));
                    }
                    function_frame.push()?;
                    vec_deque![]
                }
                Builtin::Freeze => {
                    push_instr!(call.loc, Bytecode::FreezeRef);
                    function_frame.pop()?; // pop mut ref
                    function_frame.push()?; // push imm ref
                    let inner_token = match argument_types.pop_front() {
                        Some(InferredType::Reference(inner_token))
                        | Some(InferredType::MutableReference(inner_token)) => inner_token,
                        // Incorrect call
                        _ => Box::new(InferredType::Anything),
                    };
                    vec_deque![InferredType::Reference(inner_token)]
                }
                Builtin::ToU8 => {
                    push_instr!(call.loc, Bytecode::CastU8);
                    function_frame.pop()?;
                    function_frame.push()?;
                    vec_deque![InferredType::U8]
                }
                Builtin::ToU64 => {
                    push_instr!(call.loc, Bytecode::CastU64);
                    function_frame.pop()?;
                    function_frame.push()?;
                    vec_deque![InferredType::U64]
                }
                Builtin::ToU128 => {
                    push_instr!(call.loc, Bytecode::CastU128);
                    function_frame.pop()?;
                    function_frame.push()?;
                    vec_deque![InferredType::U128]
                }
            }
        }
        FunctionCall_::ModuleFunctionCall {
            module,
            name,
            type_actuals,
        } => {
            let ty_arg_tokens =
                compile_types(context, function_frame.type_parameters(), &type_actuals)?;
            let ty_args = ty_arg_tokens
                .iter()
                .map(|t| InferredType::from_signature_token(t))
                .collect::<Vec<_>>();
            let subst = &make_type_argument_subst(&ty_args)?;
            let tokens = Signature(ty_arg_tokens);
            let type_actuals_id = context.signature_index(tokens)?;
            let fh_idx = context.function_handle(module.clone(), name.clone())?.1;
            let fcall = if type_actuals.is_empty() {
                Bytecode::Call(fh_idx)
            } else {
                let fi_idx = context.function_instantiation_index(fh_idx, type_actuals_id)?;
                Bytecode::CallGeneric(fi_idx)
            };
            push_instr!(call.loc, fcall);
            for _ in 0..argument_types.len() {
                function_frame.pop()?;
            }
            // Return value of current function is pushed onto the stack.
            function_frame.push()?;
            let signature = context.function_signature(module, name)?;
            signature
                .return_
                .iter()
                .map(|t| InferredType::from_signature_token_with_subst(subst, t))
                .collect()
        }
    })
}

fn compile_constant(_context: &mut Context, ty: Type, value: MoveValue) -> Result<Constant> {
    fn type_layout(ty: Type) -> Result<MoveTypeLayout> {
        Ok(match ty {
            Type::Address => MoveTypeLayout::Address,
            Type::Signer => MoveTypeLayout::Signer,
            Type::U8 => MoveTypeLayout::U8,
            Type::U64 => MoveTypeLayout::U64,
            Type::U128 => MoveTypeLayout::U128,
            Type::Bool => MoveTypeLayout::Bool,
            Type::Vector(inner_type) => MoveTypeLayout::Vector(Box::new(type_layout(*inner_type)?)),
            Type::Reference(_, _) => bail!("References are not supported in constant type layouts"),
            Type::TypeParameter(_) => {
                bail!("Type parameters are not supported in constant type layouts")
            }
            Type::Struct(_ident, _tys) => {
                bail!("TODO Structs are not *yet* supported in constant type layouts")
            }
        })
    }

    Constant::serialize_constant(&type_layout(ty)?, &value)
        .ok_or_else(|| format_err!("Could not serialize constant"))
}

//**************************************************************************************************
// Bytecode
//**************************************************************************************************

fn compile_function_body_bytecode(
    context: &mut Context,
    type_parameters: HashMap<TypeVar_, TypeParameterIndex>,
    formals: Vec<(Var, Type)>,
    locals: Vec<(Var, Type)>,
    blocks: BytecodeBlocks,
) -> Result<CodeUnit> {
    let mut function_frame = FunctionFrame::new(type_parameters);
    let mut locals_signature = Signature(vec![]);
    for (var, t) in formals {
        let sig = compile_type(context, function_frame.type_parameters(), &t)?;
        function_frame.define_local(&var.value, sig.clone())?;
        record_src_loc!(parameter: context, var);
    }
    for (var_, t) in locals {
        let sig = compile_type(context, function_frame.type_parameters(), &t)?;
        function_frame.define_local(&var_.value, sig.clone())?;
        locals_signature.0.push(sig);
        record_src_loc!(local: context, var_);
    }
    let sig_idx = context.signature_index(locals_signature)?;

    let mut code = vec![];
    let mut label_to_index: HashMap<BlockLabel, u16> = HashMap::new();
    for (label, block) in blocks {
        label_to_index.insert(label.clone(), code.len() as u16);
        context.label_index(label)?;
        compile_bytecode_block(context, &mut function_frame, &mut code, block)?;
    }
    let fake_to_actual = context.build_index_remapping(label_to_index);
    remap_branch_offsets(&mut code, &fake_to_actual);
    Ok(CodeUnit {
        locals: sig_idx,
        code,
    })
}

fn compile_bytecode_block(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    block: BytecodeBlock,
) -> Result<()> {
    for instr in block {
        compile_bytecode(context, function_frame, code, instr)?
    }
    Ok(())
}

fn compile_bytecode(
    context: &mut Context,
    function_frame: &mut FunctionFrame,
    code: &mut Vec<Bytecode>,
    sp!(loc, instr_): IRBytecode,
) -> Result<()> {
    make_push_instr!(context, code);
    make_record_nop_label!(context, code);
    let ff_instr = match instr_ {
        IRBytecode_::Pop => Bytecode::Pop,
        IRBytecode_::Ret => Bytecode::Ret,
        IRBytecode_::Nop(None) => Bytecode::Nop,
        IRBytecode_::Nop(Some(lbl)) => {
            record_nop_label!(lbl);
            Bytecode::Nop
        }
        IRBytecode_::BrTrue(lbl) => Bytecode::BrTrue(context.label_index(lbl)?),
        IRBytecode_::BrFalse(lbl) => Bytecode::BrFalse(context.label_index(lbl)?),
        IRBytecode_::Branch(lbl) => Bytecode::Branch(context.label_index(lbl)?),
        IRBytecode_::LdU8(u) => Bytecode::LdU8(u),
        IRBytecode_::LdU64(u) => Bytecode::LdU64(u),
        IRBytecode_::LdU128(u) => Bytecode::LdU128(u),
        IRBytecode_::CastU8 => Bytecode::CastU8,
        IRBytecode_::CastU64 => Bytecode::CastU64,
        IRBytecode_::CastU128 => Bytecode::CastU128,
        IRBytecode_::LdByteArray(b) => {
            let vec_value = MoveValue::vector_u8(b);
            let ty = Type::Vector(Box::new(Type::U8));
            let constant = compile_constant(context, ty, vec_value)?;
            Bytecode::LdConst(context.constant_index(constant)?)
        }
        IRBytecode_::LdAddr(a) => {
            let address_value = MoveValue::Address(a);
            let constant = compile_constant(context, Type::Address, address_value)?;
            Bytecode::LdConst(context.constant_index(constant)?)
        }
        IRBytecode_::LdTrue => Bytecode::LdTrue,
        IRBytecode_::LdFalse => Bytecode::LdFalse,
        IRBytecode_::LdConst(c) => Bytecode::LdConst(context.named_constant_index(&c)?),
        IRBytecode_::CopyLoc(sp!(_, v_)) => Bytecode::CopyLoc(function_frame.get_local(&v_)?),
        IRBytecode_::MoveLoc(sp!(_, v_)) => Bytecode::MoveLoc(function_frame.get_local(&v_)?),
        IRBytecode_::StLoc(sp!(_, v_)) => Bytecode::StLoc(function_frame.get_local(&v_)?),
        IRBytecode_::Call(m, n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let fh_idx = context.function_handle(m, n)?.1;
            if tys.is_empty() {
                Bytecode::Call(fh_idx)
            } else {
                let fi_idx = context.function_instantiation_index(fh_idx, type_actuals_id)?;
                Bytecode::CallGeneric(fi_idx)
            }
        }
        IRBytecode_::Pack(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::Pack(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::PackGeneric(si_idx)
            }
        }
        IRBytecode_::Unpack(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::Unpack(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::UnpackGeneric(si_idx)
            }
        }
        IRBytecode_::ReadRef => Bytecode::ReadRef,
        IRBytecode_::WriteRef => Bytecode::WriteRef,
        IRBytecode_::FreezeRef => Bytecode::FreezeRef,
        IRBytecode_::MutBorrowLoc(sp!(_, v_)) => {
            Bytecode::MutBorrowLoc(function_frame.get_local(&v_)?)
        }
        IRBytecode_::ImmBorrowLoc(sp!(_, v_)) => {
            Bytecode::ImmBorrowLoc(function_frame.get_local(&v_)?)
        }
        IRBytecode_::MutBorrowField(name, tys, sp!(_, field_)) => {
            let qualified_struct_name = QualifiedStructIdent {
                module: ModuleName::module_self(),
                name,
            };
            let sh_idx = context.struct_handle_index(qualified_struct_name)?;
            let (def_idx, _, field_offset) = context.field(sh_idx, field_)?;

            let fh_idx = context.field_handle_index(def_idx, field_offset as u16)?;
            if tys.is_empty() {
                Bytecode::MutBorrowField(fh_idx)
            } else {
                let tokens = Signature(compile_types(
                    context,
                    function_frame.type_parameters(),
                    &tys,
                )?);
                let type_actuals_id = context.signature_index(tokens)?;
                let fi_idx = context.field_instantiation_index(fh_idx, type_actuals_id)?;
                Bytecode::MutBorrowFieldGeneric(fi_idx)
            }
        }
        IRBytecode_::ImmBorrowField(name, tys, sp!(_, field_)) => {
            let qualified_struct_name = QualifiedStructIdent {
                module: ModuleName::module_self(),
                name,
            };
            let sh_idx = context.struct_handle_index(qualified_struct_name)?;
            let (def_idx, _, field_offset) = context.field(sh_idx, field_)?;

            let fh_idx = context.field_handle_index(def_idx, field_offset as u16)?;
            if tys.is_empty() {
                Bytecode::ImmBorrowField(fh_idx)
            } else {
                let tokens = Signature(compile_types(
                    context,
                    function_frame.type_parameters(),
                    &tys,
                )?);
                let type_actuals_id = context.signature_index(tokens)?;
                let fi_idx = context.field_instantiation_index(fh_idx, type_actuals_id)?;
                Bytecode::ImmBorrowFieldGeneric(fi_idx)
            }
        }
        IRBytecode_::MutBorrowGlobal(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::MutBorrowGlobal(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::MutBorrowGlobalGeneric(si_idx)
            }
        }
        IRBytecode_::ImmBorrowGlobal(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::ImmBorrowGlobal(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::ImmBorrowGlobalGeneric(si_idx)
            }
        }
        IRBytecode_::Add => Bytecode::Add,
        IRBytecode_::Sub => Bytecode::Sub,
        IRBytecode_::Mul => Bytecode::Mul,
        IRBytecode_::Mod => Bytecode::Mod,
        IRBytecode_::Div => Bytecode::Div,
        IRBytecode_::BitOr => Bytecode::BitOr,
        IRBytecode_::BitAnd => Bytecode::BitAnd,
        IRBytecode_::Xor => Bytecode::Xor,
        IRBytecode_::Or => Bytecode::Or,
        IRBytecode_::And => Bytecode::And,
        IRBytecode_::Not => Bytecode::Not,
        IRBytecode_::Eq => Bytecode::Eq,
        IRBytecode_::Neq => Bytecode::Neq,
        IRBytecode_::Lt => Bytecode::Lt,
        IRBytecode_::Gt => Bytecode::Gt,
        IRBytecode_::Le => Bytecode::Le,
        IRBytecode_::Ge => Bytecode::Ge,
        IRBytecode_::Abort => Bytecode::Abort,
        IRBytecode_::Exists(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::Exists(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::ExistsGeneric(si_idx)
            }
        }
        IRBytecode_::MoveFrom(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::MoveFrom(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::MoveFromGeneric(si_idx)
            }
        }
        IRBytecode_::MoveTo(n, tys) => {
            let tokens = Signature(compile_types(
                context,
                function_frame.type_parameters(),
                &tys,
            )?);
            let type_actuals_id = context.signature_index(tokens)?;
            let def_idx = context.struct_definition_index(&n)?;
            if tys.is_empty() {
                Bytecode::MoveTo(def_idx)
            } else {
                let si_idx = context.struct_instantiation_index(def_idx, type_actuals_id)?;
                Bytecode::MoveToGeneric(si_idx)
            }
        }
        IRBytecode_::Shl => Bytecode::Shl,
        IRBytecode_::Shr => Bytecode::Shr,
    };
    push_instr!(loc, ff_instr);
    Ok(())
}

fn remap_branch_offsets(code: &mut Vec<Bytecode>, fake_to_actual: &HashMap<u16, u16>) {
    for instr in code {
        match instr {
            Bytecode::BrTrue(offset) | Bytecode::BrFalse(offset) | Bytecode::Branch(offset) => {
                *offset = fake_to_actual[offset]
            }
            _ => (),
        }
    }
}
