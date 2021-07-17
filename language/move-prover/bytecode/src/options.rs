// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use codespan_reporting::diagnostic::Severity;
use move_model::model::{GlobalEnv, VerificationScope};
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum AutoTraceLevel {
    Off,
    VerifiedFunction,
    AllFunctions,
}

impl AutoTraceLevel {
    pub fn verified_functions(self) -> bool {
        use AutoTraceLevel::*;
        matches!(self, VerifiedFunction | AllFunctions)
    }
    pub fn functions(self) -> bool {
        use AutoTraceLevel::*;
        matches!(self, AllFunctions)
    }
    pub fn invariants(self) -> bool {
        use AutoTraceLevel::*;
        matches!(self, VerifiedFunction | AllFunctions)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProverOptions {
    /// Whether to only generate backend code.
    pub generate_only: bool,
    /// Whether to generate stubs for native functions.
    pub native_stubs: bool,
    /// Whether to minimize execution traces in errors.
    pub minimize_execution_trace: bool,
    /// Whether to omit debug information in generated model.
    pub omit_model_debug: bool,
    /// Whether output for e.g. diagnosis shall be stable/redacted so it can be used in test
    /// output.
    pub stable_test_output: bool,
    /// Scope of what functions to verify.
    pub verify_scope: VerificationScope,
    /// [deprecated] Whether to emit global axiom that resources are well-formed.
    pub resource_wellformed_axiom: bool,
    /// Whether to assume wellformedness when elements are read from memory, instead of on
    /// function entry.
    pub assume_wellformed_on_access: bool,
    /// Indicates that we should do any mutations
    pub mutation: bool,
    /// Indicates that we should use the add-subtract mutation on the given block
    pub mutation_add_sub: usize,
    /// Whether to assume a global invariant when the related memory
    /// is accessed, instead of on function entry. This is currently known to be slower
    /// if one than off, so off by default.
    pub assume_invariant_on_access: bool,
    /// Whether pack/unpack should recurse over the structure.
    pub deep_pack_unpack: bool,
    /// Auto trace level.
    pub auto_trace_level: AutoTraceLevel,
    /// Minimal severity level for diagnostics to be reported.
    pub report_severity: Severity,
    /// Whether to dump the transformed stackless bytecode to a file
    pub dump_bytecode: bool,
    /// Whether to dump the control-flow graphs (in dot format) to files, one per each function
    pub dump_cfg: bool,
    /// Number of Boogie instances to be run concurrently.
    pub num_instances: usize,
    /// Whether to run Boogie instances sequentially.
    pub sequential_task: bool,
    /// Whether to check the inconsistency
    pub check_inconsistency: bool,
    /// Whether to use exclusively weak edges in borrow analysis
    pub weak_edges: bool,
    /// Whether to run monomorphization analysis & transformation
    pub run_mono: bool,
    /// Whether to use new global invariant checking
    pub invariants_v2: bool,
    /// Whether to run the transformation passes for concrete interpretation (instead of proving)
    pub for_interpretation: bool,
}

impl Default for ProverOptions {
    fn default() -> Self {
        Self {
            generate_only: false,
            native_stubs: false,
            minimize_execution_trace: true,
            omit_model_debug: false,
            stable_test_output: false,
            verify_scope: VerificationScope::All,
            resource_wellformed_axiom: false,
            assume_wellformed_on_access: false,
            mutation: false,
            mutation_add_sub: 0,
            deep_pack_unpack: false,
            auto_trace_level: AutoTraceLevel::Off,
            report_severity: Severity::Warning,
            assume_invariant_on_access: false,
            dump_bytecode: false,
            dump_cfg: false,
            num_instances: 1,
            sequential_task: false,
            check_inconsistency: false,
            weak_edges: false,
            run_mono: true,
            invariants_v2: true,
            for_interpretation: false,
        }
    }
}

impl ProverOptions {
    pub fn get(env: &GlobalEnv) -> Rc<ProverOptions> {
        if !env.has_extension::<ProverOptions>() {
            env.set_extension(ProverOptions::default())
        }
        env.get_extension::<ProverOptions>().unwrap()
    }

    pub fn set(env: &GlobalEnv, options: ProverOptions) {
        env.set_extension::<ProverOptions>(options);
    }
}
