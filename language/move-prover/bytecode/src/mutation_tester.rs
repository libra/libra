// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Transformation which mutates code for mutation testing in various ways
//!
//! This transformation should run after code is translated to bytecode, but before any
//!  other bytecode modification
//! It emits instructions in bytecode format, but with changes made
//! Note that this mutation does nothing if mutation flags are not enabled

use crate::{
    function_data_builder::FunctionDataBuilder,
    function_target::FunctionData,
    function_target_pipeline::{FunctionTargetProcessor, FunctionTargetsHolder},
    stackless_bytecode::{Bytecode, Operation},
    options::ProverOptions,
};

use move_model::{exp_generator::ExpGenerator, model::FunctionEnv, model::GlobalEnv};

pub struct MutationTester {}

pub struct MutationManager {
    pub mutated : bool,
    add_sub : usize
}

impl MutationTester {
    pub fn new() -> Box<Self> {
        Box::new(Self {})
    }
}

impl FunctionTargetProcessor for MutationTester {
    fn initialize(&self, global_env: &GlobalEnv, _targets: &mut FunctionTargetsHolder) {
        let options = ProverOptions::get(global_env);
        global_env.set_extension(MutationManager{mutated : false, add_sub : options.mutation_add_sub});
    }

    fn process(
        &self,
        _targets: &mut FunctionTargetsHolder,
        fun_env: &FunctionEnv<'_>,
        data: FunctionData,
    ) -> FunctionData {
        use Bytecode::*;

        if fun_env.is_native() {
            // Nothing to do
            return data;
        }

        let mut builder = FunctionDataBuilder::new(fun_env, data);
        let code = std::mem::take(&mut builder.data.code);

        builder.set_loc(builder.fun_env.get_loc().at_start());
        let global_env = fun_env.module_env.env;
        let m = global_env.get_extension::<MutationManager>().unwrap();

        for bc in code {
            match bc {
                Call(ref attrid, ref indices, Operation::Add, 
                        ref srcs, ref dests) => {
                    let mv = m.add_sub;
                    if mv == 1 {
                        builder.emit(Call((*attrid).clone(), (*indices).clone(), Operation::Sub, 
                            (*srcs).clone(), (*dests).clone()));
                        global_env.set_extension(MutationManager{mutated : true, add_sub : mv-1});
                    } else {
                        builder.emit(bc);
                    }
                    if mv > 0 {
                        global_env.set_extension(MutationManager{add_sub : mv-1, mutated : m.mutated});
                    }
                }
                _ => {
                    builder.emit(bc);
                }
            }
        }

        builder.data
    }

    fn name(&self) -> String {
        "mutation_tester".to_string()
    }
}
