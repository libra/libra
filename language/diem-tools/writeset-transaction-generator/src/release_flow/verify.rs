// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::release_flow::{
    create::create_release_from_artifact, hash_for_modules, load_latest_artifact,
};
use anyhow::{bail, Result};
use bytecode_verifier::verify_module;
use diem_transaction_replay::DiemDebugger;
use diem_types::{
    access_path::Path,
    chain_id::ChainId,
    transaction::{TransactionStatus, Version, WriteSetPayload},
    write_set::WriteOp,
};
use diem_validator_interface::{DiemValidatorInterface, JsonRpcDebuggerInterface};
use move_binary_format::CompiledModule;
use move_core_types::vm_status::KeptVMStatus;
use std::collections::BTreeMap;

pub fn verify_release(
    // ChainID to distinguish the diem network. e.g: PREMAINNET
    chain_id: ChainId,
    // Public JSON-rpc endpoint URL
    url: String,
    // Path to the serialized bytes of WriteSet
    writeset_payload: &WriteSetPayload,
    remote_modules: &[(Vec<u8>, CompiledModule)],
    // If set to true, will verify the release payload against the latest blockchain height instead of the height recorded in the artifact file. This would be needed when the height is already pruned.
    use_latest_version: bool,
) -> Result<()> {
    for (_, module) in remote_modules {
        verify_module(&module).expect("invalid remote module");
    }

    let artifact = load_latest_artifact(&chain_id)?;
    if artifact.chain_id != chain_id {
        bail!("Unexpected ChainId");
    }
    if artifact.stdlib_hash
        != hash_for_modules(
            remote_modules
                .iter()
                .map(|(bytes, module)| (module.self_id(), bytes)),
        )?
    {
        bail!("Build artifact doesn't match local stdlib hash");
    }
    let remote = Box::new(JsonRpcDebuggerInterface::new(url.as_str())?);
    let override_version = if use_latest_version {
        Some(remote.get_latest_version()?)
    } else {
        Some(artifact.version)
    };

    let generated_payload =
        create_release_from_artifact(&artifact, url.as_str(), remote_modules, override_version)?;
    if &generated_payload != writeset_payload {
        bail!("Payload generated from the artifact doesn't match with input file");
    }
    verify_payload_change(
        remote,
        override_version,
        &writeset_payload,
        remote_modules.iter().map(|(_bytes, m)| m),
    )
}
/// Make sure that given a remote state, applying the `payload` will make sure the new on-chain
/// states contains the exact same Diem Framework modules as the locally compiled stdlib.
pub(crate) fn verify_payload_change<'a>(
    validator: Box<dyn DiemValidatorInterface>,
    block_height_opt: Option<Version>,
    payload: &WriteSetPayload,
    remote_modules: impl IntoIterator<Item = &'a CompiledModule>,
) -> Result<()> {
    let block_height = match block_height_opt {
        Some(h) => h,
        None => validator.get_latest_version()?,
    };

    // Applying this writeset should make Diem framework equal to its on-disk status
    let mut old_modules = validator
        .get_diem_framework_modules_by_version(block_height)?
        .into_iter()
        .map(|m| (m.self_id(), m))
        .collect::<BTreeMap<_, _>>();

    let output = {
        let txn_replay = DiemDebugger::new(validator);
        txn_replay.execute_writeset_at_version(block_height, payload, false)?
    };

    if output.status() != &TransactionStatus::Keep(KeptVMStatus::Executed) {
        bail!("Unexpected transaction status from running WriteSetPayload")
    }

    // Should contain a reconfiguration event
    let new_epoch_event_key = diem_types::on_chain_config::new_epoch_event_key();
    if !output
        .events()
        .iter()
        .any(|e| *e.key() == new_epoch_event_key)
    {
        bail!("Output WriteSet won't trigger a reconfiguration")
    }

    for (access_path, write_op) in output.write_set() {
        let path = bcs::from_bytes::<Path>(access_path.path.as_slice())?;
        if let Path::Code(module_id) = path {
            match write_op {
                WriteOp::Deletion => {
                    println!("Deleting deprecated module: {:?}", module_id);
                    if old_modules.remove(&module_id).is_none() {
                        bail!("Removing non-existent module")
                    }
                }
                WriteOp::Value(v) => {
                    let updated_module = match CompiledModule::deserialize(v.as_slice()) {
                        Ok(m) => m,
                        Err(e) => bail!("Unexpected module deserialize error {:?}", e),
                    };

                    match old_modules.insert(module_id.clone(), updated_module.clone()) {
                        Some(_) => println!("Updating existing module: {:?}", module_id),
                        None => println!("Adding new module: {:?}", module_id),
                    }
                }
            }
        }
    }

    let local_modules = remote_modules
        .into_iter()
        .map(|m| (m.self_id(), m.clone()))
        .collect::<BTreeMap<_, _>>();
    if local_modules.len() != old_modules.len() {
        bail!(
            "Found {:?} modules locally but {:?} in remote storage",
            local_modules.len(),
            old_modules.len()
        )
    }
    for (remote, local) in old_modules.values().zip(local_modules.values()) {
        if remote != local {
            bail!("Applying writeset onto the state causes module {:?} diverge from the on disk files", local.self_id())
        }
    }
    Ok(())
}
