// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Transformation which injects global invariants into the bytecode.

#[allow(unused_imports)]
use log::{debug, info, log, warn};

use crate::{
    function_data_builder::FunctionDataBuilder,
    function_target::FunctionData,
    function_target_pipeline::{FunctionTargetProcessor, FunctionTargetsHolder},
    stackless_bytecode::{BorrowNode, Bytecode, Operation, PropKind},
    usage_analysis,
    verification_analysis_v2::InvariantAnalysisData,
};

use crate::options::ProverOptions;
use move_model::{
    ast::{ConditionKind, Exp},
    exp_generator::ExpGenerator,
    model::{FunId, FunctionEnv, GlobalEnv, GlobalId, Loc, QualifiedId, QualifiedInstId, StructId},
    pragmas::CONDITION_ISOLATED_PROP,
    spec_translator::{SpecTranslator, TranslatedSpec},
};
use std::collections::{BTreeMap, BTreeSet};

const GLOBAL_INVARIANT_FAILS_MESSAGE: &str = "global memory invariant does not hold";

pub struct GlobalInvariantInstrumentationProcessorV2 {}

impl GlobalInvariantInstrumentationProcessorV2 {
    pub fn new() -> Box<Self> {
        Box::new(Self {})
    }
}

impl FunctionTargetProcessor for GlobalInvariantInstrumentationProcessorV2 {
    fn process(
        &self,
        _targets: &mut FunctionTargetsHolder,
        fun_env: &FunctionEnv<'_>,
        data: FunctionData,
    ) -> FunctionData {
        if fun_env.is_native() || fun_env.is_intrinsic() {
            // Nothing to do.
            return data;
        }

        if !data.variant.is_verified() {
            // Only need to instrument if this is a verification variant
            return data;
        }

        Instrumenter::run(fun_env, data)
    }

    fn name(&self) -> String {
        "global_invariant_instrumenter_v2".to_string()
    }
}

struct Instrumenter<'a> {
    options: &'a ProverOptions,
    builder: FunctionDataBuilder<'a>,
    saved_from_before_instr_or_call: Option<(TranslatedSpec, BTreeSet<GlobalId>)>,
}

impl<'a> Instrumenter<'a> {
    fn run(fun_env: &FunctionEnv<'a>, data: FunctionData) -> FunctionData {
        let global_env = fun_env.module_env.env;
        let options = ProverOptions::get(global_env);
        let builder = FunctionDataBuilder::new(fun_env, data);
        let mut instrumenter = Instrumenter {
            options: options.as_ref(),
            builder,
            saved_from_before_instr_or_call: None,
        };
        instrumenter.instrument(global_env);
        instrumenter.builder.data
    }

    fn instrument(&mut self, global_env: &GlobalEnv) {
        // Extract and clear current code
        let old_code = std::mem::take(&mut self.builder.data.code);
        let fun_env = self.builder.fun_env;
        let inv_ana_data = global_env.get_extension::<InvariantAnalysisData>().unwrap();
        let disabled_inv_fun_set = &inv_ana_data.disabled_inv_fun_set;
        let target_invariants = &inv_ana_data.target_invariants;

        // Emit entrypoint assumptions if this is a verification variant.
        if self.builder.data.variant.is_verified() {
            let fun_id = fun_env.get_qualified_id();

            let entrypoint_invariants = self.compute_entrypoint_invariants();
            let xlated_spec = SpecTranslator::translate_invariants_by_id(
                self.options.auto_trace_level.invariants(),
                &mut self.builder,
                &entrypoint_invariants,
            );
            self.assert_or_assume_translated_invariants(
                &xlated_spec.invariants,
                &entrypoint_invariants,
                PropKind::Assume,
            );

            // In addition to the entrypoint invariants assumed just above, it is necessary
            // to assume more invariants in a special case.  When invariants are disabled in
            // this function but not in callers, we will later assert those invariants just
            // before return instructions.
            // We need to assume those invariants at the beginning of the function in order
            // to prove them later. They aren't necessarily entrypoint invariants if we are
            // verifying a function in a strict dependency, or in a friend module that does not
            // have the target module in its dependencies.
            // So, the next code finds the set of target invariants (which will be assumed on return)
            // and assumes those that are not entrypoint invariants.
            if disabled_inv_fun_set.contains(&fun_id) {
                // Separate the update invariants, because we never want to assume them.
                let (global_target_invs, _update_target_invs) =
                    self.separate_update_invariants(&target_invariants);
                let return_invariants: BTreeSet<GlobalId> = global_target_invs
                    .difference(&entrypoint_invariants)
                    .cloned()
                    .collect();
                let xlated_spec = SpecTranslator::translate_invariants_by_id(
                    self.options.auto_trace_level.invariants(),
                    &mut self.builder,
                    &return_invariants,
                );
                self.assert_or_assume_translated_invariants(
                    &xlated_spec.invariants,
                    &return_invariants,
                    PropKind::Assume,
                );
            }
            // Generate new instrumented code.
            for bc in old_code {
                self.instrument_bytecode(bc, fun_id, &inv_ana_data, &entrypoint_invariants);
            }
        } else {
            // just re-emit the bytecode without additional instrumentation
            for bc in old_code {
                self.builder.emit(bc);
            }
        }
    }

    /// Returns list of invariant ids to be assumed at the beginning of the current function.
    fn compute_entrypoint_invariants(&mut self) -> BTreeSet<GlobalId> {
        // Emit an assume of each invariant over memory touched by this function, and which
        // are declared in this module or transitively dependent modules.
        //
        // Excludes global invariants (a) those which are marked by the user
        // explicitly as `[isolated]` (b) those which are not declared
        // in dependent modules of the module defining the function
        // (which may not be the target module) and upon which the
        // code should therefore not depend, apart from the update
        // itself. Also excludes "update" invariants.
        let env = self.builder.global_env();
        // Invariants with types that are read or written by the function
        let mut invariants_for_used_memory = BTreeSet::new();
        // Invariants with types that are written by the function
        let mut invariants_for_modified_memory = BTreeSet::new();
        // get memory (list of structs) read or written by the function target,
        // then find all invariants in loaded modules that refer to that memory.
        for mem in usage_analysis::get_used_memory_inst(&self.builder.get_target()).iter() {
            invariants_for_used_memory.extend(env.get_global_invariants_for_memory(mem));
        }
        // get memory (list of structs) written by function, find the invariants referring to that memory.
        // Also called "invariants updated by the function"
        for mem in usage_analysis::get_modified_memory_inst(&self.builder.get_target()).iter() {
            invariants_for_modified_memory.extend(env.get_global_invariants_for_memory(mem));
        }
        let module_env = &self.builder.fun_env.module_env;
        invariants_for_used_memory
            .iter()
            .filter_map(|id| {
                env.get_global_invariant(*id).filter(|inv| {
                    inv.kind == ConditionKind::Invariant  // excludes "update invariants"
                        && module_env.is_transitive_dependency(inv.declaring_module)
                        && !module_env.env.is_property_true(
                            &inv.properties,
                            CONDITION_ISOLATED_PROP)
                        .unwrap_or(false)
                })
            })
            .map(|inv| inv.id)
            .collect()
    }

    fn instrument_bytecode(
        &mut self,
        bc: Bytecode,
        fun_id: QualifiedId<FunId>,
        inv_ana_data: &InvariantAnalysisData,
        entrypoint_invariants: &BTreeSet<GlobalId>,
    ) {
        use BorrowNode::*;
        use Bytecode::*;
        use Operation::*;
        let target_invariants = &inv_ana_data.target_invariants;
        let disabled_inv_fun_set = &inv_ana_data.disabled_inv_fun_set;
        match &bc {
            Call(_, _, WriteBack(GlobalRoot(mem), ..), ..) => {
                self.emit_invariants_for_bytecode(
                    &bc,
                    &fun_id,
                    inv_ana_data,
                    mem,
                    entrypoint_invariants,
                );
            }
            Call(_, _, MoveTo(mid, sid, inst), ..) | Call(_, _, MoveFrom(mid, sid, inst), ..) => {
                let mem = mid.qualified_inst(*sid, inst.to_owned());
                self.emit_invariants_for_bytecode(
                    &bc,
                    &fun_id,
                    inv_ana_data,
                    &mem,
                    entrypoint_invariants,
                );
            }
            // Emit assumes before procedure calls.  This also deals with saves for update invariants.
            Call(_, _, OpaqueCallBegin(module_id, id, _), _, _) => {
                self.assume_invariants_for_opaque_begin(
                    module_id.qualified(*id),
                    entrypoint_invariants,
                    inv_ana_data,
                );
                // Then emit the call instruction.
                self.builder.emit(bc);
            }
            // Emit asserts after procedure calls
            Call(_, _, OpaqueCallEnd(module_id, id, _), _, _) => {
                // First, emit the call instruction.
                self.builder.emit(bc.clone());
                self.assert_invariants_for_opaque_end(module_id.qualified(*id), inv_ana_data)
            }
            // When invariants are disabled in the body of this function but not in its
            // callers, assert them just before a return instruction (the caller will be
            // assuming they hold).
            Ret(_, _) => {
                let (global_target_invs, _update_target_invs) =
                    self.separate_update_invariants(&target_invariants);
                if disabled_inv_fun_set.contains(&fun_id) {
                    let xlated_spec = SpecTranslator::translate_invariants_by_id(
                        self.options.auto_trace_level.invariants(),
                        &mut self.builder,
                        &global_target_invs,
                    );
                    self.assert_or_assume_translated_invariants(
                        &xlated_spec.invariants,
                        &global_target_invs,
                        PropKind::Assert,
                    );
                }
                self.builder.emit(bc);
            }
            _ => self.builder.emit(bc),
        }
    }

    /// Emit invariants and saves for call to OpaqueCallBegin in the
    /// special case where the invariants are not checked in the
    /// called function.
    fn assume_invariants_for_opaque_begin(
        &mut self,
        called_fun_id: QualifiedId<FunId>,
        entrypoint_invariants: &BTreeSet<GlobalId>,
        inv_ana_data: &InvariantAnalysisData,
    ) {
        let target_invariants = &inv_ana_data.target_invariants;
        let disabled_inv_fun_set = &inv_ana_data.disabled_inv_fun_set;
        let non_inv_fun_set = &inv_ana_data.non_inv_fun_set;
        let funs_that_modify_inv = &inv_ana_data.funs_that_modify_inv;
        // Normally, invariants would be assumed and asserted in
        // a called function, and so there would be no need to assume
        // the invariant before the call.
        // When invariants are not disabled in the current function
        // but the called function doesn't check them, we are going to
        // need to assert the invariant when the call returns (at the
        // matching OpaqueCallEnd instruction). So, we assume the
        // invariant here, before the OpaqueCallBegin, so that we have
        // a hope of proving it later.
        // Remove invariants that were already assumed at the beginning
        // of this function to avoid redundant assumption.
        // This also emits state saves for update invariants (for "old"
        // state values).
        let fun_id = self.builder.fun_env.get_qualified_id();
        if !disabled_inv_fun_set.contains(&fun_id)
            && !non_inv_fun_set.contains(&fun_id)
            && non_inv_fun_set.contains(&called_fun_id)
        {
            // remove invariants that were already assumed at function entry
            let invs_to_assume = target_invariants
                .difference(entrypoint_invariants)
                .cloned()
                .collect();
            // assert the invariants that are modified by the called function
            let modified_invs =
                self.get_invs_modified_by_fun(&invs_to_assume, called_fun_id, funs_that_modify_inv);
            self.emit_assumes_and_saves_before_bytecode(modified_invs, entrypoint_invariants);
        }
    }

    /// Called when invariants need to be checked, but an opaque called function
    /// doesn't check them.
    fn assert_invariants_for_opaque_end(
        &mut self,
        called_fun_id: QualifiedId<FunId>,
        inv_ana_data: &InvariantAnalysisData,
    ) {
        let disabled_inv_fun_set = &inv_ana_data.disabled_inv_fun_set;
        let non_inv_fun_set = &inv_ana_data.non_inv_fun_set;

        // Add invariant assertions after function call when invariant holds in the
        // body of the current function, but the called function does not assert
        // invariants.
        // The asserted invariant ensures the the invariant
        // holds in the body of the current function, as is required.
        let fun_id = self.builder.fun_env.get_qualified_id();
        if !disabled_inv_fun_set.contains(&fun_id)
            && !non_inv_fun_set.contains(&fun_id)
            && non_inv_fun_set.contains(&called_fun_id)
        {
            self.emit_asserts_after_bytecode();
        }
    }

    /// emit assumes before, and asserts after, a bytecode
    fn emit_invariants_for_bytecode(
        &mut self,
        bc: &Bytecode,
        fun_id: &QualifiedId<FunId>,
        inv_ana_data: &InvariantAnalysisData,
        mem: &QualifiedInstId<StructId>,
        entrypoint_invariants: &BTreeSet<GlobalId>,
    ) {
        // When invariants are enabled during the body of the current function, add asserts after
        // the writeback for each invariant that the writeback could modify.
        let target_invariants = &inv_ana_data.target_invariants;
        let disabled_inv_fun_set = &inv_ana_data.disabled_inv_fun_set;
        let non_inv_fun_set = &inv_ana_data.non_inv_fun_set;
        if !disabled_inv_fun_set.contains(&fun_id) && !non_inv_fun_set.contains(&fun_id) {
            // consider only the invariants that are modified by instruction
            let modified_invariants = self
                .builder
                .global_env()
                .get_subset_invariants_for_memory(mem.clone(), target_invariants);
            self.emit_assumes_and_saves_before_bytecode(modified_invariants, entrypoint_invariants);
            // put out the modifying instruction byte code.
            self.builder.emit(bc.clone());
            self.emit_asserts_after_bytecode();
        } else {
            self.builder.emit(bc.clone());
        }
    }

    // emit assumptions for invariants that were not assumed on entry and saves for types that are embedded
    // in "old" in update invariants.
    fn emit_assumes_and_saves_before_bytecode(
        &mut self,
        modified_invs: BTreeSet<GlobalId>,
        entrypoint_invariants: &BTreeSet<GlobalId>,
    ) {
        // translate all the invariants. Some were already translated at the entrypoint, but
        // that's ok because entrypoint invariants are global invariants that don't have "old",
        // so redundant state tags are not going to be a problem.
        // TODO: Several changes need to be made in this code: (1) don't check update
        // invariants across opaque calls, (2) separate global & update invariants earlier,
        // (3) eliminate redundant refactoring.  However, these are tricky and require significant
        // refactorings, so not doing it now.
        let mut xlated_invs = SpecTranslator::translate_invariants_by_id(
            self.options.auto_trace_level.invariants(),
            &mut self.builder,
            &modified_invs,
        );
        // separate out the update invariants, which need to be handled differently from global invs.
        // Specifically, update invariants are not assumed, but need consistent save tags.
        let (global_assumes, _update_invs) = self.separate_update_invariants(&modified_invs);

        // remove entrypoint invariants so we don't assume them again here.
        let modified_assumes: BTreeSet<GlobalId> = global_assumes
            .difference(entrypoint_invariants)
            .cloned()
            .collect();
        // assume the global invariants that weren't assumed at entrypoint
        self.assert_or_assume_translated_invariants(
            &xlated_invs.invariants,
            &modified_assumes,
            PropKind::Assume,
        );
        // emit the instructions to save state in the state tags assigned in the previous step
        self.emit_state_saves_for_update_invs(&mut xlated_invs);
        // Save the translated invariants for use in asserts after instruction or opaque call end
        if self.saved_from_before_instr_or_call.is_none() {
            self.saved_from_before_instr_or_call = Some((xlated_invs, modified_invs));
        } else {
            panic!("self.saved_from_pre should be None");
        }
    }

    fn emit_asserts_after_bytecode(&mut self) {
        // assert the global and update invariants that instruction modifies, regardless of where they
        // were assumed
        if let Some((xlated_invs, modified_invs)) =
            std::mem::take(&mut self.saved_from_before_instr_or_call)
        {
            self.assert_or_assume_translated_invariants(
                &xlated_invs.invariants,
                &modified_invs,
                PropKind::Assert,
            );
        } else {
            // This should never happen
            panic!("saved_from_pre should be Some");
        }
    }

    /// Given a set of invariants, return a pair of sets: global invariants and update invariants
    fn separate_update_invariants(
        &self,
        invariants: &BTreeSet<GlobalId>,
    ) -> (BTreeSet<GlobalId>, BTreeSet<GlobalId>) {
        let global_env = self.builder.fun_env.module_env.env;
        let mut global_invs: BTreeSet<GlobalId> = BTreeSet::new();
        let mut update_invs: BTreeSet<GlobalId> = BTreeSet::new();
        for inv_id in invariants {
            let inv = global_env.get_global_invariant(*inv_id).unwrap();
            if inv.kind == ConditionKind::InvariantUpdate {
                update_invs.insert(*inv_id);
            } else {
                global_invs.insert(*inv_id);
            }
        }
        (global_invs, update_invs)
    }

    /// Returns the set of invariants modified by a function
    fn get_invs_modified_by_fun(
        &mut self,
        inv_set: &BTreeSet<GlobalId>,
        fun_id: QualifiedId<FunId>,
        funs_that_modify_inv: &BTreeMap<GlobalId, BTreeSet<QualifiedId<FunId>>>,
    ) -> BTreeSet<GlobalId> {
        let mut modified_inv_set: BTreeSet<GlobalId> = BTreeSet::new();
        for inv_id in inv_set {
            if let Some(fun_id_set) = funs_that_modify_inv.get(inv_id) {
                if fun_id_set.contains(&fun_id) {
                    modified_inv_set.insert(*inv_id);
                }
            }
        }
        modified_inv_set
    }

    /// Update invariants contain "old" expressions, so it is necessary to save any types in the
    /// state that appear in the old expressions.  "update_invs" argument must contain only update
    /// invariants (not checked).
    fn emit_state_saves_for_update_invs(&mut self, xlated_spec: &mut TranslatedSpec) {
        // Emit all necessary state saves
        self.builder
            .set_next_debug_comment("state save for global update invariants".to_string());
        for (mem, label) in std::mem::take(&mut xlated_spec.saved_memory) {
            self.builder
                .emit_with(|id| Bytecode::SaveMem(id, label, mem));
        }
        for (var, label) in std::mem::take(&mut xlated_spec.saved_spec_vars) {
            self.builder
                .emit_with(|id| Bytecode::SaveSpecVar(id, label, var));
        }
        self.builder.clear_next_debug_comment();
    }

    /// emit asserts or assumes (depending on prop_kind argument) for the invariants in
    /// xlated_invariants that is also in inv_set at the current location,
    fn assert_or_assume_translated_invariants(
        &mut self,
        xlated_invariants: &[(Loc, GlobalId, Exp)],
        inv_set: &BTreeSet<GlobalId>,
        prop_kind: PropKind,
    ) {
        let global_env = self.builder.global_env();
        for (loc, mid, cond) in xlated_invariants {
            if inv_set.contains(mid) {
                // Check for hard-to-debug coding error (this is not a user error)
                if inv_set.contains(mid)
                    && matches!(prop_kind, PropKind::Assume)
                    && matches!(
                        global_env.get_global_invariant(*mid).unwrap().kind,
                        ConditionKind::InvariantUpdate
                    )
                {
                    panic!("Not allowed to assume update invariant");
                }
                self.emit_invariant(loc, cond, prop_kind);
            }
        }
    }

    /// Emit an assert for one invariant, give location and expression for the property
    fn emit_invariant(&mut self, loc: &Loc, cond: &Exp, prop_kind: PropKind) {
        self.builder.set_next_debug_comment(format!(
            "global invariant {}",
            loc.display(self.builder.global_env())
        ));
        // No error messages on assumes
        if prop_kind == PropKind::Assert {
            self.builder
                .set_loc_and_vc_info(loc.clone(), GLOBAL_INVARIANT_FAILS_MESSAGE);
        }
        self.builder
            .emit_with(|id| Bytecode::Prop(id, prop_kind, cond.clone()));
    }
}
