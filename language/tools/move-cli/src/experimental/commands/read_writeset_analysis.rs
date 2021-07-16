// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::sandbox::utils::on_disk_state_view::OnDiskStateView;
use move_binary_format::file_format::CompiledModule;
use move_bytecode_utils::Modules;
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::TypeTag,
    transaction_argument::{convert_txn_args, TransactionArgument},
};

use crate::ConcretizeMode;
use anyhow::{anyhow, Result};
use std::fs;

pub fn analyze_read_write_set(
    state: &OnDiskStateView,
    module_file: &str,
    function: &str,
    signers: &[String],
    txn_args: &[TransactionArgument],
    type_args: &[TypeTag],
    concretize: ConcretizeMode,
    verbose: bool,
) -> Result<()> {
    let module_id = CompiledModule::deserialize(&fs::read(module_file)?)
        .map_err(|e| anyhow!("Error deserializing module: {:?}", e))?
        .self_id();
    let fun_id = Identifier::new(function.to_string())?;
    let all_modules = state.get_all_modules()?;
    let code_cache = Modules::new(&all_modules);
    let dep_graph = code_cache.compute_dependency_graph();
    if verbose {
        println!(
            "Inferring read/write set for {:?} module(s)",
            all_modules.len(),
        )
    }
    let modules = dep_graph.compute_topological_order()?;
    let rw = read_write_set::analyze(modules)?;
    if let Some(fenv) = rw.get_function_env(&module_id, &fun_id) {
        let signer_addresses = signers
            .iter()
            .map(|s| AccountAddress::from_hex_literal(&s))
            .collect::<Result<Vec<AccountAddress>, _>>()?;
        // TODO: parse Value's directly instead of going through the indirection of TransactionArgument?
        let script_args: Vec<Vec<u8>> = convert_txn_args(&txn_args);
        // substitute given script arguments + blockchain state into abstract r/w set
        match concretize {
            ConcretizeMode::Paths => {
                let results = rw.get_concretized_summary(
                    &module_id,
                    &fun_id,
                    &signer_addresses,
                    &script_args,
                    type_args,
                    state,
                )?;
                println!("{}", results.display(&fenv))
            }
            ConcretizeMode::Reads => {
                let results = rw.get_keys_read(
                    &module_id,
                    &fun_id,
                    &signer_addresses,
                    &script_args,
                    &type_args,
                    state,
                )?;
                for key in results {
                    println!("{}", key)
                }
            }
            ConcretizeMode::Writes => {
                let results = rw.get_keys_written(
                    &module_id,
                    &fun_id,
                    &signer_addresses,
                    &script_args,
                    &type_args,
                    state,
                )?;
                for key in results {
                    println!("{}", key)
                }
            }
            ConcretizeMode::Dont => {
                // don't try try to concretize; just print the R/W set
                // safe to unwrap here because every function must be analyzed
                let results = rw.get_summary(&module_id, &fun_id).expect(
                    "Invariant violation: couldn't resolve R/W set summary for defined function",
                );
                println!("{}", results.display(&fenv))
            }
        }
    } else {
        println!("Function {} not found in {}", function, module_file)
    }
    Ok(())
}
