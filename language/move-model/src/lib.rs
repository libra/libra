// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use codespan_reporting::diagnostic::{Diagnostic, Label};
use itertools::Itertools;
#[allow(unused_imports)]
use log::warn;
use std::collections::BTreeSet;

use builder::module_builder::ModuleBuilder;
use move_binary_format::{
    access::ModuleAccess,
    check_bounds::BoundsChecker,
    file_format::{
        self_module_name, AddressIdentifierIndex, CompiledModule, CompiledScript,
        FunctionDefinition, FunctionDefinitionIndex, FunctionHandle, FunctionHandleIndex,
        IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        StructDefinitionIndex, Visibility,
    },
};
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use move_ir_types::location::sp;
use move_lang::{
    self,
    compiled_unit::{self, CompiledUnit},
    errors::Errors,
    expansion::ast::{self as E, Address, ModuleDefinition, ModuleIdent, ModuleIdent_},
    parser::ast::{self as P, ModuleName as ParserModuleName},
    shared::{unique_map::UniqueMap, AddressBytes},
    Compiler, Flags, PASS_COMPILATION, PASS_EXPANSION, PASS_PARSER,
};
use num::{BigUint, Num};

use crate::{
    ast::{ModuleName, Spec},
    builder::model_builder::ModelBuilder,
    model::{FunId, FunctionData, GlobalEnv, Loc, ModuleData, ModuleId, StructId},
};

pub mod ast;
mod builder;
pub mod code_writer;
pub mod exp_generator;
pub mod exp_rewriter;
pub mod model;
pub mod native;
pub mod pragmas;
pub mod spec_translator;
pub mod symbol;
pub mod ty;

// =================================================================================================
// Entry Point

/// Build the move model with default compilation flags.
/// This collects transitive dependencies for move sources from the provided directory list.
pub fn run_model_builder(
    move_sources: &[String],
    deps_dir: &[String],
) -> anyhow::Result<GlobalEnv> {
    run_model_builder_with_compilation_flags(move_sources, deps_dir, Flags::empty())
}

/// Build the move model with supplied compilation flags.
/// This collects transitive dependencies for move sources from the provided directory list.
pub fn run_model_builder_with_compilation_flags(
    move_sources: &[String],
    deps_dir: &[String],
    flags: Flags,
) -> anyhow::Result<GlobalEnv> {
    let mut env = GlobalEnv::new();

    // Step 1: parse the program to get comments and a separation of targets and dependencies.
    let (files, comments_and_compiler_res) = Compiler::new(move_sources, deps_dir)
        .set_flags(flags)
        .run::<PASS_PARSER>()?;
    let (comment_map, compiler) = match comments_and_compiler_res {
        Err(errors) => {
            // Add source files so that the env knows how to translate locations of parse errors
            for fname in files.keys().sorted() {
                let fsrc = &files[fname];
                env.add_source(fname, fsrc, /* is_dep */ false);
            }
            add_move_lang_errors(&mut env, errors);
            return Ok(env);
        }
        Ok(res) => res,
    };
    let (compiler, parsed_prog) = compiler.into_ast();
    // Add source files for targets and dependencies
    let dep_files: BTreeSet<_> = parsed_prog
        .lib_definitions
        .iter()
        .map(|def| def.file())
        .collect();
    for fname in files.keys().sorted() {
        let fsrc = &files[fname];
        env.add_source(fname, fsrc, dep_files.contains(fname));
    }

    // Add any documentation comments found by the Move compiler to the env.
    for (fname, documentation) in comment_map {
        let file_id = env.get_file_id(fname).expect("file name defined");
        env.add_documentation(file_id, documentation);
    }

    // Step 2: run the compiler up to expansion
    let parsed_prog = {
        let P::Program {
            mut source_definitions,
            lib_definitions,
        } = parsed_prog;
        source_definitions.extend(lib_definitions);
        P::Program {
            source_definitions,
            lib_definitions: vec![],
        }
    };
    let (compiler, expansion_ast) = match compiler.at_parser(parsed_prog).run::<PASS_EXPANSION>() {
        Err(errors) => {
            add_move_lang_errors(&mut env, errors);
            return Ok(env);
        }
        Ok(compiler) => compiler.into_ast(),
    };
    // Extract the module/script closure
    let mut visited_addresses = BTreeSet::new();
    let mut visited_modules = BTreeSet::new();
    for (_, mident, mdef) in &expansion_ast.modules {
        let src_file = mdef.loc.file();
        if !dep_files.contains(src_file) {
            collect_related_modules_recursive(
                mident,
                &expansion_ast.modules,
                &mut visited_addresses,
                &mut visited_modules,
            );
        }
    }
    for sdef in expansion_ast.scripts.values() {
        let src_file = sdef.loc.file();
        if !dep_files.contains(src_file) {
            for (_, mident, _neighbor) in &sdef.immediate_neighbors {
                collect_related_modules_recursive(
                    mident,
                    &expansion_ast.modules,
                    &mut visited_addresses,
                    &mut visited_modules,
                );
            }
            for addr in &sdef.used_addresses {
                if let Address::Named(n) = &addr {
                    visited_addresses.insert(&n.value);
                }
            }
        }
    }

    // Step 3: selective compilation.
    let expansion_ast = {
        let addresses = expansion_ast
            .addresses
            .filter_map(|n, val| visited_addresses.contains(n.value.as_str()).then(|| val));
        let E::Program {
            addresses: _,
            modules,
            scripts,
        } = expansion_ast;
        let modules = modules.filter_map(|mident, mut mdef| {
            visited_modules.contains(&mident.value).then(|| {
                mdef.is_source_module = true;
                mdef
            })
        });
        E::Program {
            addresses,
            modules,
            scripts,
        }
    };
    // Run the compiler fully to the compiled units
    let units = match compiler
        .at_expansion(expansion_ast.clone())
        .run::<PASS_COMPILATION>()
    {
        Err(errors) => {
            add_move_lang_errors(&mut env, errors);
            return Ok(env);
        }
        Ok(compiler) => compiler.into_compiled_units(),
    };
    // Check for bytecode verifier errors (there should not be any)
    let (verified_units, errors) = compiled_unit::verify_units(units);
    if !errors.is_empty() {
        add_move_lang_errors(&mut env, errors);
        return Ok(env);
    }

    // Now that it is known that the program has no errors, run the spec checker on verified units
    // plus expanded AST. This will populate the environment including any errors.
    run_spec_checker(&mut env, verified_units, expansion_ast);
    Ok(env)
}

fn collect_used_addresses<'a>(
    used_addresses: &'a BTreeSet<Address>,
    visited_addresses: &mut BTreeSet<&'a str>,
) {
    for addr in used_addresses {
        if let Address::Named(n) = &addr {
            visited_addresses.insert(&n.value);
        }
    }
}

fn collect_related_modules_recursive<'a>(
    mident: &'a ModuleIdent_,
    modules: &'a UniqueMap<ModuleIdent, ModuleDefinition>,
    visited_addresses: &mut BTreeSet<&'a str>,
    visited_modules: &mut BTreeSet<ModuleIdent_>,
) {
    if visited_modules.contains(&mident) {
        return;
    }
    let mdef = modules.get_(mident).unwrap();
    if let Address::Named(n) = &mident.address {
        visited_addresses.insert(&n.value);
    }
    collect_used_addresses(&mdef.used_addresses, visited_addresses);
    visited_modules.insert(mident.clone());
    for (_, next_mident, _) in &mdef.immediate_neighbors {
        collect_related_modules_recursive(next_mident, modules, visited_addresses, visited_modules);
    }
}

/// Build a `GlobalEnv` from a collection of `CompiledModule`'s. The `modules` list must be
/// topologically sorted by the dependency relation (i.e., a child node in the dependency graph
/// should appear earlier in the vector than its parents).
pub fn run_bytecode_model_builder<'a>(
    modules: impl IntoIterator<Item = &'a CompiledModule>,
) -> anyhow::Result<GlobalEnv> {
    let mut env = GlobalEnv::new();
    for (i, m) in modules.into_iter().enumerate() {
        let id = m.self_id();
        let addr = addr_to_big_uint(id.address());
        let module_name = ModuleName::new(addr, env.symbol_pool().make(id.name().as_str()));
        let module_id = ModuleId::new(i);
        let mut module_data = ModuleData::stub(module_name.clone(), module_id, m.clone());

        // add functions
        for (i, def) in m.function_defs().iter().enumerate() {
            let def_idx = FunctionDefinitionIndex(i as u16);
            let name = m.identifier_at(m.function_handle_at(def.function).name);
            let symbol = env.symbol_pool().make(name.as_str());
            let fun_id = FunId::new(symbol);
            let data = FunctionData::stub(symbol, def_idx, def.function);
            module_data.function_data.insert(fun_id, data);
            module_data.function_idx_to_id.insert(def_idx, fun_id);
        }

        // add structs
        for (i, def) in m.struct_defs().iter().enumerate() {
            let def_idx = StructDefinitionIndex(i as u16);
            let name = m.identifier_at(m.struct_handle_at(def.struct_handle).name);
            let symbol = env.symbol_pool().make(name.as_str());
            let struct_id = StructId::new(symbol);
            let data = env.create_struct_data(&m, def_idx, symbol, Loc::default(), Spec::default());
            module_data.struct_data.insert(struct_id, data);
            module_data.struct_idx_to_id.insert(def_idx, struct_id);
        }

        env.module_data.push(module_data);
    }
    Ok(env)
}

fn add_move_lang_errors(env: &mut GlobalEnv, errors: Errors) {
    let mk_label = |env: &mut GlobalEnv, err: (move_ir_types::location::Loc, String)| {
        let loc = env.to_loc(&err.0);
        Label::new(loc.file_id(), loc.span(), err.1)
    };
    #[allow(deprecated)]
    for mut labels in errors.into_vec() {
        let primary = labels.remove(0);
        let diag = Diagnostic::new_error("", mk_label(env, primary))
            .with_secondary_labels(labels.into_iter().map(|e| mk_label(env, e)));
        env.add_diag(diag);
    }
}

#[allow(deprecated)]
fn script_into_module(compiled_script: CompiledScript) -> CompiledModule {
    let mut script = compiled_script;

    // Add the "<SELF>" identifier if it isn't present.
    //
    // Note: When adding an element to the table, in theory it is possible for the index
    // to overflow. This will not be a problem if we get rid of the script/module conversion.
    let self_ident_idx = match script
        .identifiers
        .iter()
        .position(|ident| ident.as_ident_str() == self_module_name())
    {
        Some(idx) => IdentifierIndex::new(idx as u16),
        None => {
            let idx = IdentifierIndex::new(script.identifiers.len() as u16);
            script
                .identifiers
                .push(Identifier::new(self_module_name().to_string()).unwrap());
            idx
        }
    };

    // Add a dummy adress if none exists.
    let dummy_addr = AccountAddress::new([0xff; AccountAddress::LENGTH]);
    let dummy_addr_idx = match script
        .address_identifiers
        .iter()
        .position(|addr| addr == &dummy_addr)
    {
        Some(idx) => AddressIdentifierIndex::new(idx as u16),
        None => {
            let idx = AddressIdentifierIndex::new(script.address_identifiers.len() as u16);
            script.address_identifiers.push(dummy_addr);
            idx
        }
    };

    // Add a self module handle.
    let self_module_handle_idx = match script
        .module_handles
        .iter()
        .position(|handle| handle.address == dummy_addr_idx && handle.name == self_ident_idx)
    {
        Some(idx) => ModuleHandleIndex::new(idx as u16),
        None => {
            let idx = ModuleHandleIndex::new(script.module_handles.len() as u16);
            script.module_handles.push(ModuleHandle {
                address: dummy_addr_idx,
                name: self_ident_idx,
            });
            idx
        }
    };

    // Find the index to the empty signature [].
    // Create one if it doesn't exist.
    let return_sig_idx = match script.signatures.iter().position(|sig| sig.0.is_empty()) {
        Some(idx) => SignatureIndex::new(idx as u16),
        None => {
            let idx = SignatureIndex::new(script.signatures.len() as u16);
            script.signatures.push(Signature(vec![]));
            idx
        }
    };

    // Create a function handle for the main function.
    let main_handle_idx = FunctionHandleIndex::new(script.function_handles.len() as u16);
    script.function_handles.push(FunctionHandle {
        module: self_module_handle_idx,
        name: self_ident_idx,
        parameters: script.parameters,
        return_: return_sig_idx,
        type_parameters: script.type_parameters,
    });

    // Create a function definition for the main function.
    let main_def = FunctionDefinition {
        function: main_handle_idx,
        visibility: Visibility::Script,
        acquires_global_resources: vec![],
        code: Some(script.code),
    };

    let module = CompiledModule {
        version: script.version,
        module_handles: script.module_handles,
        self_module_handle_idx,
        struct_handles: script.struct_handles,
        function_handles: script.function_handles,
        field_handles: vec![],
        friend_decls: vec![],

        struct_def_instantiations: vec![],
        function_instantiations: script.function_instantiations,
        field_instantiations: vec![],

        signatures: script.signatures,

        identifiers: script.identifiers,
        address_identifiers: script.address_identifiers,
        constant_pool: script.constant_pool,

        struct_defs: vec![],
        function_defs: vec![main_def],
    };
    BoundsChecker::verify_module(&module).expect("invalid bounds in module");
    module
}

#[allow(deprecated)]
fn run_spec_checker(env: &mut GlobalEnv, units: Vec<CompiledUnit>, mut eprog: E::Program) {
    let named_address_mapping = eprog
        .addresses
        .iter()
        .filter_map(|(_, n, addr_bytes_opt)| addr_bytes_opt.map(|ab| (n.clone(), ab.value)))
        .collect();
    let mut builder = ModelBuilder::new(env, named_address_mapping);
    // Merge the compiled units with the expanded program, preserving the order of the compiled
    // units which is topological w.r.t. use relation.
    let modules = units
        .into_iter()
        .flat_map(|unit| {
            Some(match unit {
                CompiledUnit::Module {
                    ident,
                    module,
                    source_map,
                    function_infos,
                } => {
                    let module_ident = ident.into_module_ident();
                    let expanded_module = match eprog.modules.remove(&module_ident) {
                        Some(m) => m,
                        None => {
                            warn!(
                                "[internal] cannot associate bytecode module `{}` with AST",
                                module_ident
                            );
                            return None;
                        }
                    };
                    (
                        module_ident,
                        expanded_module,
                        module,
                        source_map,
                        function_infos,
                    )
                }
                CompiledUnit::Script {
                    loc: _loc,
                    key,
                    script,
                    source_map,
                    function_info,
                } => {
                    let move_lang::expansion::ast::Script {
                        attributes,
                        loc,
                        immediate_neighbors,
                        used_addresses,
                        function_name,
                        constants,
                        function,
                        specs,
                    } = match eprog.scripts.remove(&key) {
                        Some(s) => s,
                        None => {
                            warn!(
                                "[internal] cannot associate bytecode script `{}` with AST",
                                key
                            );
                            return None;
                        }
                    };
                    // Convert the script into a module.
                    let address = Address::Anonymous(sp(loc, AddressBytes::DEFAULT_ERROR_BYTES));
                    let ident = sp(
                        loc,
                        ModuleIdent_::new(address, ParserModuleName(function_name.0.clone())),
                    );
                    let mut function_infos = UniqueMap::new();
                    function_infos
                        .add(function_name.clone(), function_info)
                        .unwrap();
                    // Construct a pseudo module definition.
                    let mut functions = UniqueMap::new();
                    functions.add(function_name, function).unwrap();
                    let expanded_module = ModuleDefinition {
                        attributes,
                        loc,
                        dependency_order: usize::MAX,
                        immediate_neighbors,
                        used_addresses,
                        is_source_module: true,
                        friends: UniqueMap::new(),
                        structs: UniqueMap::new(),
                        constants,
                        functions,
                        specs,
                    };
                    let module = script_into_module(script);
                    (ident, expanded_module, module, source_map, function_infos)
                }
            })
        })
        .enumerate();
    for (module_count, (module_id, expanded_module, compiled_module, source_map, function_infos)) in
        modules
    {
        let loc = builder.to_loc(&expanded_module.loc);
        let addr_bytes = builder.resolve_address(&loc, &module_id.value.address);
        let module_name = ModuleName::from_address_bytes_and_name(
            addr_bytes,
            builder
                .env
                .symbol_pool()
                .make(&module_id.value.module.0.value),
        );
        let module_id = ModuleId::new(module_count);
        let mut module_translator = ModuleBuilder::new(&mut builder, module_id, module_name);
        module_translator.translate(
            loc,
            expanded_module,
            compiled_module,
            source_map,
            function_infos,
        );
    }
    // After all specs have been processed, warn about any unused schemas.
    builder.warn_unused_schemas();
}

// =================================================================================================
// Helpers

/// Converts an address identifier to a number representing the address.
pub fn addr_to_big_uint(addr: &AccountAddress) -> BigUint {
    BigUint::from_str_radix(&addr.to_string(), 16).unwrap()
}

/// Converts a biguint into an account address
pub fn big_uint_to_addr(i: &BigUint) -> AccountAddress {
    // TODO: do this in more efficient way (e.g., i.to_le_bytes() and pad out the resulting Vec<u8>
    // to ADDRESS_LENGTH
    AccountAddress::from_hex_literal(&format!("{:#x}", i)).unwrap()
}

// =================================================================================================
// Crate Helpers

/// Helper to project the 1st element from a vector of pairs.
pub(crate) fn project_1st<T: Clone, R>(v: &[(T, R)]) -> Vec<T> {
    v.iter().map(|(x, _)| x.clone()).collect()
}

/// Helper to project the 2nd element from a vector of pairs.
pub(crate) fn project_2nd<T, R: Clone>(v: &[(T, R)]) -> Vec<R> {
    v.iter().map(|(_, x)| x.clone()).collect()
}
