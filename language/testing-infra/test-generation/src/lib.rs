// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod abstract_state;
pub mod borrow_graph;
pub mod bytecode_generator;
pub mod config;
pub mod control_flow_graph;
pub mod error;
pub mod summaries;
pub mod transitions;

#[macro_use]
extern crate mirai_annotations;

use crate::config::{Args, EXECUTE_UNVERIFIED_MODULE, RUN_ON_VM};
use bytecode_generator::BytecodeGenerator;
use bytecode_verifier::verify_module;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use getrandom::getrandom;
use module_generation::generate_module;
use move_binary_format::{
    access::ModuleAccess,
    file_format::{
        AbilitySet, CompiledModule, FunctionDefinitionIndex, SignatureToken, StructHandleIndex,
    },
};
use move_core_types::{
    account_address::AccountAddress,
    effects::ChangeSet,
    language_storage::TypeTag,
    value::MoveValue,
    vm_status::{StatusCode, VMStatus},
};
use move_lang::{compiled_unit::CompiledUnit, Compiler};
use move_vm_runtime::{data_cache::MoveStorage, move_vm::MoveVM};
use move_vm_test_utils::{DeltaStorage, InMemoryStorage};
use move_vm_types::gas_schedule::GasStatus;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{fs, io::Write, panic, thread};
use tracing::{debug, error, info};

/// This function calls the Bytecode verifier to test it
fn run_verifier(module: CompiledModule) -> Result<CompiledModule, String> {
    match panic::catch_unwind(|| verify_module(&module)) {
        Ok(res) => match res {
            Ok(_) => Ok(module),
            Err(err) => Err(format!("Module verification failed: {:#?}", err)),
        },
        Err(err) => Err(format!("Verifier panic: {:#?}", err)),
    }
}

static STORAGE_WITH_MOVE_STDLIB: Lazy<InMemoryStorage> = Lazy::new(|| {
    let mut storage = InMemoryStorage::new();
    let (_, compiled_units) = Compiler::new(&move_stdlib::move_stdlib_files(), &[])
        .build_and_report()
        .unwrap();
    let compiled_modules = compiled_units.into_iter().map(|unit| match unit {
        CompiledUnit::Module { module, .. } => module,
        CompiledUnit::Script { .. } => panic!("Unexpected Script in stdlib"),
    });
    for module in compiled_modules {
        let mut blob = vec![];
        module.serialize(&mut blob).unwrap();
        storage.publish_or_overwrite_module(module.self_id(), blob);
    }
    storage
});

/// This function runs a verified module in the VM runtime
fn run_vm(module: CompiledModule) -> Result<(), VMStatus> {
    // By convention the 0'th index function definition is the entrypoint to the module (i.e. that
    // will contain only simply-typed arguments).
    let entry_idx = FunctionDefinitionIndex::new(0);
    let function_signature = {
        let handle = module.function_def_at(entry_idx).function;
        let sig_idx = module.function_handle_at(handle).parameters;
        module.signature_at(sig_idx).clone()
    };
    let main_args: Vec<Vec<u8>> = function_signature
        .0
        .iter()
        .map(|sig_tok| match sig_tok {
            SignatureToken::Address => MoveValue::Address(AccountAddress::ZERO)
                .simple_serialize()
                .unwrap(),
            SignatureToken::U64 => MoveValue::U64(0).simple_serialize().unwrap(),
            SignatureToken::Bool => MoveValue::Bool(true).simple_serialize().unwrap(),
            SignatureToken::Vector(inner_tok) if **inner_tok == SignatureToken::U8 => {
                MoveValue::Vector(vec![]).simple_serialize().unwrap()
            }
            _ => unimplemented!("Unsupported argument type: {:#?}", sig_tok),
        })
        .collect();

    execute_function_in_module(
        module,
        entry_idx,
        vec![],
        main_args,
        &*STORAGE_WITH_MOVE_STDLIB,
    )
}

/// Execute the first function in a module
fn execute_function_in_module(
    module: CompiledModule,
    idx: FunctionDefinitionIndex,
    ty_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
    storage: &impl MoveStorage,
) -> Result<(), VMStatus> {
    let module_id = module.self_id();
    let entry_name = {
        let entry_func_idx = module.function_def_at(idx).function;
        let entry_name_idx = module.function_handle_at(entry_func_idx).name;
        module.identifier_at(entry_name_idx)
    };
    {
        let vm = MoveVM::new(move_stdlib::natives::all_natives(
            AccountAddress::from_hex_literal("0x1").unwrap(),
        ))
        .unwrap();

        let mut changeset = ChangeSet::new();
        let mut blob = vec![];
        module.serialize(&mut blob).unwrap();
        changeset.publish_or_overwrite_module(module_id.clone(), blob);
        let delta_storage = DeltaStorage::new(storage, &changeset);
        let mut sess = vm.new_session(&delta_storage);

        let mut gas_status = GasStatus::new_unmetered();
        sess.execute_function(&module_id, entry_name, ty_args, args, &mut gas_status)?;

        Ok(())
    }
}

/// Serialize a module to `path` if `output_path` is `Some(path)`. If `output_path` is `None`
/// print the module out as debug output.
fn output_error_case(module: CompiledModule, output_path: Option<String>, case_id: u64, tid: u64) {
    match output_path {
        Some(path) => {
            let mut out = vec![];
            module
                .serialize(&mut out)
                .expect("Unable to serialize module");
            let output_file = format!("{}/case{}_{}.module", path, tid, case_id);
            let mut f = fs::File::create(&output_file)
                .unwrap_or_else(|err| panic!("Unable to open output file {}: {}", &path, err));
            f.write_all(&out)
                .unwrap_or_else(|err| panic!("Unable to write to output file {}: {}", &path, err));
        }
        None => {
            debug!("{:#?}", module);
        }
    }
}

fn seed(seed: Option<String>) -> [u8; 32] {
    let mut array = [0u8; 32];
    match seed {
        Some(string) => {
            let vec = hex::decode(string).unwrap();
            if vec.len() != 32 {
                panic!("Invalid seed supplied, the length must be 32.");
            }
            for (i, byte) in vec.into_iter().enumerate() {
                array[i] = byte;
            }
        }
        None => {
            getrandom(&mut array).unwrap();
        }
    };
    array
}

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    VerificationFailure,
    ExecutionFailure,
    Valid,
}

fn bytecode_module(rng: &mut StdRng, module: CompiledModule) -> CompiledModule {
    let mut generated_module = BytecodeGenerator::new(rng).generate_module(module.clone());
    // Module generation can retry under certain circumstances
    while generated_module.is_none() {
        generated_module = BytecodeGenerator::new(rng).generate_module(module.clone());
    }
    generated_module.unwrap()
}

pub fn module_frame_generation(
    num_iters: Option<u64>,
    seed: [u8; 32],
    sender: Sender<CompiledModule>,
    stats: Receiver<Status>,
) {
    let mut verification_failures: u128 = 0;
    let mut execution_failures: u128 = 0;
    let mut generated: u128 = 1;

    let generation_options = config::module_generation_settings();
    let mut rng = StdRng::from_seed(seed);
    let mut module = generate_module(&mut rng, generation_options.clone());
    // Either get the number of iterations provided by the user, or iterate "infinitely"--up to
    // u128::MAX number of times.
    let iters = num_iters
        .map(|x| x as u128)
        .unwrap_or_else(|| std::u128::MAX);

    while generated < iters && sender.send(module).is_ok() {
        module = generate_module(&mut rng, generation_options.clone());
        generated += 1;
        while let Ok(stat) = stats.try_recv() {
            match stat {
                Status::VerificationFailure => verification_failures += 1,
                Status::ExecutionFailure => execution_failures += 1,
                _ => (),
            };
        }

        if generated > 0 && generated % 100 == 0 {
            info!(
                "Generated: {} Verified: {} Executed: {}",
                generated,
                (generated - verification_failures),
                (generated - execution_failures)
            );
        }
    }

    // Drop the sender channel to signal to the consumers that they should expect no more modules,
    // and should finish up.
    drop(sender);

    // Gather final stats from the consumers.
    while let Ok(stat) = stats.recv() {
        match stat {
            Status::VerificationFailure => verification_failures += 1,
            Status::ExecutionFailure => execution_failures += 1,
            _ => (),
        };
    }
    info!(
        "Final stats: Generated: {} Verified: {} Executed: {}",
        generated,
        (generated - verification_failures),
        (generated - execution_failures)
    );
}

pub fn bytecode_generation(
    output_path: Option<String>,
    tid: u64,
    mut rng: StdRng,
    receiver: Receiver<CompiledModule>,
    stats: Sender<Status>,
) {
    while let Ok(module) = receiver.recv() {
        let mut status = Status::VerificationFailure;
        debug!("Generating module");
        let module = bytecode_module(&mut rng, module);

        debug!("Done...Running module on verifier...");
        let verified_module = match run_verifier(module.clone()) {
            Ok(verified_module) => {
                status = Status::ExecutionFailure;
                Some(verified_module)
            }
            Err(e) => {
                error!("{}", e);
                let uid = rng.gen::<u64>();
                output_error_case(module.clone(), output_path.clone(), uid, tid);
                if EXECUTE_UNVERIFIED_MODULE {
                    Some(module.clone())
                } else {
                    None
                }
            }
        };

        if let Some(verified_module) = verified_module {
            if RUN_ON_VM {
                debug!("Done...Running module on VM...");
                let execution_result = panic::catch_unwind(|| run_vm(verified_module));
                match execution_result {
                    Ok(execution_result) => match execution_result {
                        Ok(_) => {
                            status = Status::Valid;
                        }
                        Err(e) => match e.status_code() {
                            StatusCode::ARITHMETIC_ERROR | StatusCode::OUT_OF_GAS => {
                                status = Status::Valid;
                            }
                            _ => {
                                error!("{}", e);
                                let uid = rng.gen::<u64>();
                                output_error_case(module.clone(), output_path.clone(), uid, tid);
                            }
                        },
                    },
                    Err(_) => {
                        // Save modules that cause the VM runtime to panic
                        let uid = rng.gen::<u64>();
                        output_error_case(module.clone(), output_path.clone(), uid, tid);
                    }
                }
            } else {
                status = Status::Valid;
            }
        };
        stats.send(status).unwrap();
    }

    drop(stats);
}

/// Run generate_bytecode for the range passed in and test each generated module
/// on the bytecode verifier.
pub fn run_generation(args: Args) {
    let num_threads = if let Some(num_threads) = args.num_threads {
        num_threads as usize
    } else {
        num_cpus::get()
    };
    assert!(
        num_threads > 0,
        "Number of worker threads must be greater than 0"
    );

    let (sender, receiver) = bounded(num_threads);
    let (stats_sender, stats_reciever) = unbounded();
    let seed = seed(args.seed);

    let mut threads = Vec::new();
    for tid in 0..num_threads {
        let receiver = receiver.clone();
        let stats_sender = stats_sender.clone();
        let rng = StdRng::from_seed(seed);
        let output_path = args.output_path.clone();
        threads.push(thread::spawn(move || {
            bytecode_generation(output_path, tid as u64, rng, receiver, stats_sender)
        }));
    }

    // Need to drop this channel otherwise we'll get infinite blocking since the other channels are
    // cloned; this one will remain open unless we close it and other threads are going to block
    // waiting for more stats.
    drop(stats_sender);

    let num_iters = args.num_iterations;
    threads.push(thread::spawn(move || {
        module_frame_generation(num_iters, seed, sender, stats_reciever)
    }));

    for thread in threads {
        thread.join().unwrap();
    }
}

pub(crate) fn substitute(token: &SignatureToken, tys: &[SignatureToken]) -> SignatureToken {
    use SignatureToken::*;

    match token {
        Bool => Bool,
        U8 => U8,
        U64 => U64,
        U128 => U128,
        Address => Address,
        Signer => Signer,
        Vector(ty) => Vector(Box::new(substitute(ty, tys))),
        Struct(idx) => Struct(*idx),
        StructInstantiation(idx, type_params) => StructInstantiation(
            *idx,
            type_params.iter().map(|ty| substitute(ty, tys)).collect(),
        ),
        Reference(ty) => Reference(Box::new(substitute(ty, tys))),
        MutableReference(ty) => MutableReference(Box::new(substitute(ty, tys))),
        TypeParameter(idx) => {
            // Assume that the caller has previously parsed and verified the structure of the
            // file and that this guarantees that type parameter indices are always in bounds.
            assume!((*idx as usize) < tys.len());
            tys[*idx as usize].clone()
        }
    }
}

pub fn abilities(
    module: &impl ModuleAccess,
    ty: &SignatureToken,
    constraints: &[AbilitySet],
) -> AbilitySet {
    use SignatureToken::*;

    match ty {
        Bool | U8 | U64 | U128 | Address => AbilitySet::PRIMITIVES,

        Reference(_) | MutableReference(_) => AbilitySet::REFERENCES,
        Signer => AbilitySet::SIGNER,
        TypeParameter(idx) => constraints[*idx as usize],
        Vector(ty) => AbilitySet::polymorphic_abilities(
            AbilitySet::VECTOR,
            vec![false],
            vec![abilities(module, ty, constraints)],
        )
        .unwrap(),
        Struct(idx) => {
            let sh = module.struct_handle_at(*idx);
            sh.abilities
        }
        StructInstantiation(idx, type_args) => {
            let sh = module.struct_handle_at(*idx);
            let declared_abilities = sh.abilities;
            let declared_phantom_parameters =
                sh.type_parameters.iter().map(|param| param.is_phantom);
            let type_arguments = type_args
                .iter()
                .map(|arg| abilities(module, arg, constraints));
            AbilitySet::polymorphic_abilities(
                declared_abilities,
                declared_phantom_parameters,
                type_arguments,
            )
            .unwrap()
        }
    }
}

pub(crate) fn get_struct_handle_from_reference(
    reference_signature: &SignatureToken,
) -> Option<StructHandleIndex> {
    match reference_signature {
        SignatureToken::Reference(signature) => match **signature {
            SignatureToken::StructInstantiation(idx, _) | SignatureToken::Struct(idx) => Some(idx),
            _ => None,
        },
        SignatureToken::MutableReference(signature) => match **signature {
            SignatureToken::StructInstantiation(idx, _) | SignatureToken::Struct(idx) => Some(idx),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn get_type_actuals_from_reference(
    token: &SignatureToken,
) -> Option<Vec<SignatureToken>> {
    use SignatureToken::*;

    match token {
        Reference(box_) | MutableReference(box_) => match &**box_ {
            StructInstantiation(_, tys) => Some(tys.clone()),
            Struct(_) => Some(vec![]),
            _ => None,
        },
        _ => None,
    }
}
