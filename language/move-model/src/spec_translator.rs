// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module supports translations of specifications as found in the move-model to
//! expressions which can be used in assumes/asserts in bytecode.

use std::collections::{BTreeMap, BTreeSet};

use itertools::Itertools;

use crate::{
    ast::{
        Condition, ConditionKind, Exp, ExpData, GlobalInvariant, LocalVarDecl, MemoryLabel,
        Operation, Spec, TempIndex,
    },
    exp_generator::ExpGenerator,
    exp_rewriter::ExpRewriterFunctions,
    model::{FunctionEnv, GlobalId, Loc, ModuleId, NodeId, QualifiedInstId, SpecVarId, StructId},
    pragmas::{
        ABORTS_IF_IS_STRICT_PRAGMA, CONDITION_ABSTRACT_PROP, CONDITION_CONCRETE_PROP,
        CONDITION_EXPORT_PROP, CONDITION_INJECTED_PROP,
    },
    symbol::Symbol,
    ty::{PrimitiveType, Type},
};
use codespan_reporting::diagnostic::Severity;

/// A helper which reduces specification conditions to assume/assert statements.
pub struct SpecTranslator<'a, 'b, T: ExpGenerator<'a>> {
    /// Whether we should autogenerate TRACE calls for top-level expressions of the VC.
    auto_trace: bool,
    /// The builder for the function we are currently translating.
    /// Note this is not necessarily the same as the function for which we translate specs.
    /// The builder must implement the expression generation trait.
    builder: &'b mut T,
    /// The function for which we translate specifications.
    fun_env: &'b FunctionEnv<'a>,
    /// The type instantiation of the function.
    type_args: &'b [Type],
    /// An optional substitution for parameters of the above function.
    param_substitution: Option<&'b [TempIndex]>,
    /// Whether we translate the expression in a post state.
    in_post_state: bool,
    /// An optional substitution for return vales.
    ret_locals: &'b [TempIndex],
    /// A set of locals which are declared by outer block, lambda, or quant expressions.
    shadowed: Vec<BTreeSet<Symbol>>,
    /// A map from let symbols to temporaries allocated for them.
    let_locals: BTreeMap<Symbol, TempIndex>,
    /// The translated spec.
    result: TranslatedSpec,
    /// Whether we are in "old" (pre-state) context
    in_old: bool,
}

/// Represents a translated spec.
#[derive(Default)]
pub struct TranslatedSpec {
    pub saved_memory: BTreeMap<QualifiedInstId<StructId>, MemoryLabel>,
    pub saved_spec_vars: BTreeMap<QualifiedInstId<SpecVarId>, MemoryLabel>,
    pub saved_params: BTreeMap<TempIndex, TempIndex>,
    pub debug_traces: Vec<(NodeId, Exp)>,
    pub pre: Vec<(Loc, Exp)>,
    pub post: Vec<(Loc, Exp)>,
    pub aborts: Vec<(Loc, Exp, Option<Exp>)>,
    pub aborts_with: Vec<(Loc, Vec<Exp>)>,
    pub emits: Vec<(Loc, Exp, Exp, Option<Exp>)>,
    pub modifies: Vec<(Loc, Exp)>,
    pub invariants: Vec<(Loc, GlobalId, Exp)>,
    pub lets: Vec<(Loc, bool, TempIndex, Exp)>,
}

impl TranslatedSpec {
    /// Creates a boolean expression which describes the overall abort condition. This is
    /// a disjunction of the individual abort conditions.
    pub fn aborts_condition<'a, T: ExpGenerator<'a>>(&self, builder: &T) -> Option<Exp> {
        builder.mk_join_bool(Operation::Or, self.aborts.iter().map(|(_, e, _)| e.clone()))
    }

    /// Creates a boolean expression which describes the overall condition which constraints
    /// the abort code.
    ///
    /// Let (P1, C1)..(Pj, Cj) be aborts_if with a code, Pk..Pl aborts_if without a code, and the
    /// Cm..Cn standalone aborts codes from an aborts_with:
    ///
    ///  ```notrust
    ///   P1 && abort_code == C1 || .. || Pj && abort_code == Cj
    ///       || Pk || .. || Pl
    ///       || abort_code == Cm || .. || abort_code == Cn
    /// ```
    ///
    /// This characterizes the allowed value of the code. In the presence of aborts_if with code,
    /// whenever the aborts condition is true, the code must also be the specified ones. Notice
    /// that still allows any other member of the disjunction to make the overall condition true.
    /// Specifically, if someone specifies `aborts_if P with C1; aborts_with C2`, then even if
    /// P is true, C2 is allowed as an abort code.
    pub fn aborts_code_condition<'a, T: ExpGenerator<'a>>(
        &self,
        builder: &T,
        actual_code: &Exp,
    ) -> Option<Exp> {
        let eq_code = |e: &Exp| builder.mk_eq(e.clone(), actual_code.clone());
        builder.mk_join_bool(
            Operation::Or,
            self.aborts
                .iter()
                .map(|(_, exp, code)| {
                    builder
                        .mk_join_opt_bool(
                            Operation::And,
                            Some(exp.clone()),
                            code.as_ref().map(|c| eq_code(c)),
                        )
                        .unwrap()
                })
                .chain(
                    self.aborts_with
                        .iter()
                        .map(|(_, codes)| codes.iter())
                        .flatten()
                        .map(|c| eq_code(c)),
                ),
        )
    }

    /// Returns true if there are any specs about the abort code.
    pub fn has_aborts_code_specs(&self) -> bool {
        !self.aborts_with.is_empty() || self.aborts.iter().any(|(_, _, c)| c.is_some())
    }

    /// Return an iterator of effective pre conditions.
    pub fn pre_conditions<'a, T: ExpGenerator<'a>>(
        &self,
        _builder: &T,
    ) -> impl Iterator<Item = (Loc, Exp)> + '_ {
        self.pre.iter().cloned()
    }

    /// Returns a sequence of EventStoreIncludes expressions which verify the `emits` clauses of a
    /// function spec. While logically we could generate a single EventStoreIncludes, for better
    /// error reporting we construct incrementally multiple EventStoreIncludes expressions with some
    /// redundancy for each individual `emits, so we the see the exact failure at the right
    /// emit condition.
    pub fn emits_conditions<'a, T: ExpGenerator<'a>>(&self, builder: &T) -> Vec<(Loc, Exp)> {
        let es_ty = Type::Primitive(PrimitiveType::EventStore);
        let mut result = vec![];
        for i in 0..self.emits.len() {
            let loc = self.emits[i].0.clone();
            let es = self.build_event_store(
                builder,
                builder.mk_call(&es_ty, Operation::EmptyEventStore, vec![]),
                &self.emits[0..i + 1],
            );
            result.push((
                loc,
                builder.mk_bool_call(Operation::EventStoreIncludes, vec![es]),
            ));
        }
        result
    }

    pub fn emits_completeness_condition<'a, T: ExpGenerator<'a>>(&self, builder: &T) -> Exp {
        let es_ty = Type::Primitive(PrimitiveType::EventStore);
        let es = self.build_event_store(
            builder,
            builder.mk_call(&es_ty, Operation::EmptyEventStore, vec![]),
            &self.emits,
        );
        builder.mk_bool_call(Operation::EventStoreIncludedIn, vec![es])
    }

    fn build_event_store<'a, T: ExpGenerator<'a>>(
        &self,
        builder: &T,
        es: Exp,
        emits: &[(Loc, Exp, Exp, Option<Exp>)],
    ) -> Exp {
        if emits.is_empty() {
            es
        } else {
            let (_, event, handle, cond) = &emits[0];
            let mut args = vec![es, event.clone(), handle.clone()];
            if let Some(c) = cond {
                args.push(c.clone())
            }
            let es_ty = Type::Primitive(PrimitiveType::EventStore);
            let extend_exp = builder.mk_call(&es_ty, Operation::ExtendEventStore, args);
            self.build_event_store(builder, extend_exp, &emits[1..])
        }
    }
}

impl<'a, 'b, T: ExpGenerator<'a>> SpecTranslator<'a, 'b, T> {
    /// Translates the specification of function `fun_env`. This can happen for a call of the
    /// function or for its definition (parameter `for_call`). This will process all the
    /// conditions found in the spec block of the function, dealing with references to `old(..)`,
    /// and creating respective memory/spec var saves. If `for_call` is true, abort conditions
    /// will be translated for the current state, otherwise they will be treated as in an `old`.
    /// and creating respective memory/spec var saves. It also allows to provide type arguments
    /// with which the specifications are instantiated, as well as a substitution for temporaries.
    /// The later two parameters are used to instantiate a function specification for a given
    /// call context.
    pub fn translate_fun_spec(
        auto_trace: bool,
        for_call: bool,
        builder: &'b mut T,
        fun_env: &'b FunctionEnv<'a>,
        type_args: &[Type],
        param_substitution: Option<&'b [TempIndex]>,
        ret_locals: &'b [TempIndex],
    ) -> TranslatedSpec {
        let mut translator = SpecTranslator {
            auto_trace,
            builder,
            fun_env,
            type_args,
            param_substitution,
            ret_locals,
            in_post_state: false,
            shadowed: Default::default(),
            result: Default::default(),
            let_locals: Default::default(),
            in_old: false,
        };
        translator.translate_spec(for_call);
        translator.result
    }

    /// Translates a set of invariants. If there are any references to `old(...)` they
    /// will be rewritten and respective memory/spec var saves will be generated.
    pub fn translate_invariants(
        auto_trace: bool,
        builder: &'b mut T,
        type_args: &'b [Type],
        invariants: impl Iterator<Item = &'b GlobalInvariant>,
    ) -> TranslatedSpec {
        let fun_env = builder.function_env().clone();
        let mut translator = SpecTranslator {
            auto_trace,
            builder,
            fun_env: &fun_env,
            type_args,
            param_substitution: Default::default(),
            ret_locals: Default::default(),
            in_post_state: false,
            shadowed: Default::default(),
            result: Default::default(),
            let_locals: Default::default(),
            in_old: false,
        };
        for inv in invariants {
            let exp = translator.translate_exp(&translator.auto_trace(&inv.loc, &inv.cond), false);
            translator
                .result
                .invariants
                .push((inv.loc.clone(), inv.id, exp));
        }
        translator.result
    }

    /// Translate one inline property. If there are any references to `old(...)` they
    /// will be rewritten and respective memory/spec var saves will be generated.
    pub fn translate_inline_property(builder: &'b mut T, prop: &Exp) -> (TranslatedSpec, Exp) {
        let fun_env = builder.function_env().clone();
        let mut translator = SpecTranslator {
            auto_trace: false,
            builder,
            fun_env: &fun_env,
            type_args: &[],
            param_substitution: Default::default(),
            ret_locals: Default::default(),
            in_post_state: false,
            shadowed: Default::default(),
            result: Default::default(),
            let_locals: Default::default(),
            in_old: false,
        };
        let exp = translator.translate_exp(prop, false);
        (translator.result, exp)
    }

    pub fn translate_invariants_by_id(
        auto_trace: bool,
        builder: &'b mut T,
        type_args: &'b [Type],
        inv_id_set: &BTreeSet<GlobalId>,
    ) -> TranslatedSpec {
        let global_env = builder.global_env();
        let invariants = inv_id_set
            .iter()
            .map(|inv_id| global_env.get_global_invariant(*inv_id).unwrap());
        SpecTranslator::translate_invariants(auto_trace, builder, type_args, invariants)
    }

    fn translate_spec(&mut self, for_call: bool) {
        let fun_env = self.fun_env;
        let env = fun_env.module_env.env;
        let spec = fun_env.get_spec();

        // A function which determines whether a condition is applicable in the context, which
        // is `for_call` for the function being called, and `!for_call` if its verified.
        // If a condition has the `[abstract]` property, it will only be included for calls,
        // and if it has the `[concrete]` property only for verification. Also, conditions
        // which are injected from a schema are only included on call site if they are also
        // exported.
        let is_applicable = |cond: &&Condition| {
            let abstract_ = env
                .is_property_true(&cond.properties, CONDITION_ABSTRACT_PROP)
                .unwrap_or(false);
            let concrete = env
                .is_property_true(&cond.properties, CONDITION_CONCRETE_PROP)
                .unwrap_or(false);
            let injected = env
                .is_property_true(&cond.properties, CONDITION_INJECTED_PROP)
                .unwrap_or(false);
            let exported = env
                .is_property_true(&cond.properties, CONDITION_EXPORT_PROP)
                .unwrap_or(false);
            if for_call {
                (!injected || exported) && (abstract_ || !concrete)
            } else {
                concrete || !abstract_
            }
        };

        // First process `let` so subsequently expressions can refer to them.
        self.translate_lets(false, spec);

        // Next process requires
        for cond in spec
            .filter_kind(ConditionKind::Requires)
            .filter(is_applicable)
        {
            self.in_post_state = false;
            let exp = self.translate_exp(&self.auto_trace(&cond.loc, &cond.exp), false);
            self.result.pre.push((cond.loc.clone(), exp));
        }

        // Aborts conditions are translated in post state when they aren't handled for a call
        // but for a definition. Otherwise, they are translated for a call of an opaque function
        // and are evaluated in pre state.
        self.in_post_state = !for_call;
        for cond in spec
            .filter_kind(ConditionKind::AbortsIf)
            .filter(is_applicable)
        {
            let code_opt = if cond.additional_exps.is_empty() {
                None
            } else {
                Some(self.translate_exp(&cond.additional_exps[0], self.in_post_state))
            };
            let exp =
                self.translate_exp(&self.auto_trace(&cond.loc, &cond.exp), self.in_post_state);
            self.result.aborts.push((cond.loc.clone(), exp, code_opt));
        }

        for cond in spec
            .filter_kind(ConditionKind::AbortsWith)
            .filter(is_applicable)
        {
            let codes = cond
                .all_exps()
                .map(|e| self.translate_exp(&self.auto_trace_no_loc(e), self.in_post_state))
                .collect_vec();
            self.result.aborts_with.push((cond.loc.clone(), codes));
        }

        // If there are no aborts_if and aborts_with, and the pragma `aborts_if_is_strict` is set,
        // add an implicit aborts_if false.
        if self.result.aborts.is_empty()
            && self.result.aborts_with.is_empty()
            && self
                .fun_env
                .is_pragma_true(ABORTS_IF_IS_STRICT_PRAGMA, || false)
        {
            self.result.aborts.push((
                self.fun_env.get_loc().at_end(),
                self.builder.mk_bool_const(false),
                None,
            ));
        }

        // Translate modifies.
        for cond in spec
            .filter_kind(ConditionKind::Modifies)
            .filter(is_applicable)
        {
            self.in_post_state = false;
            for exp in cond.all_exps() {
                // Auto trace the inner address expression.
                let exp = match exp.as_ref() {
                    ExpData::Call(id, oper, args) if args.len() == 1 => ExpData::Call(
                        *id,
                        oper.clone(),
                        vec![self.auto_trace(&cond.loc, &args[0])],
                    )
                    .into_exp(),
                    _ => cond.exp.to_owned(),
                };
                let exp = self.translate_exp(&exp, false);
                self.result.modifies.push((cond.loc.clone(), exp));
            }
        }

        // Now translate `let update` which are evaluated in post state.
        self.translate_lets(true, spec);

        // Translate ensures.
        for cond in spec
            .filter_kind(ConditionKind::Ensures)
            .filter(is_applicable)
        {
            self.in_post_state = true;
            let exp = self.translate_exp(&self.auto_trace(&cond.loc, &cond.exp), false);
            self.result.post.push((cond.loc.clone(), exp));
        }

        // Translate emits.
        for cond in spec.filter_kind(ConditionKind::Emits).filter(is_applicable) {
            self.in_post_state = true;
            let event_exp = self.translate_exp(&self.auto_trace(&cond.loc, &cond.exp), false);
            let handle_exp =
                self.translate_exp(&self.auto_trace_no_loc(&cond.additional_exps[0]), false);
            let cond_exp = if cond.additional_exps.len() > 1 {
                Some(self.translate_exp(&self.auto_trace_no_loc(&cond.additional_exps[1]), false))
            } else {
                None
            };
            self.result
                .emits
                .push((cond.loc.clone(), event_exp, handle_exp, cond_exp));
        }
    }

    fn translate_lets(&mut self, post_state: bool, spec: &Spec) {
        for cond in &spec.conditions {
            let sym = match &cond.kind {
                ConditionKind::LetPost(sym) if post_state => sym,
                ConditionKind::LetPre(sym) if !post_state => sym,
                _ => continue,
            };
            let exp = self.translate_exp(&self.auto_trace(&cond.loc, &cond.exp), false);
            let ty = self.builder.global_env().get_node_type(exp.node_id());
            let temp = self.builder.add_local(ty.skip_reference().clone());
            self.let_locals.insert(*sym, temp);
            self.result
                .lets
                .push((cond.loc.clone(), post_state, temp, exp));
        }
    }

    fn auto_trace(&self, loc: &Loc, exp: &Exp) -> Exp {
        if self.auto_trace {
            let env = self.builder.global_env();
            let id = exp.node_id();
            let ty = env.get_node_type(id);
            let new_id = env.new_node(loc.clone(), ty.clone());
            env.set_node_instantiation(new_id, vec![ty]);
            ExpData::Call(new_id, Operation::Trace, vec![exp.to_owned()]).into_exp()
        } else {
            exp.to_owned()
        }
    }

    fn auto_trace_no_loc(&self, exp: &Exp) -> Exp {
        self.auto_trace(&self.builder.global_env().get_node_loc(exp.node_id()), exp)
    }

    fn translate_exp(&mut self, exp: &Exp, in_old: bool) -> Exp {
        self.in_old = in_old;
        self.rewrite_exp(exp.to_owned())
    }

    fn is_shadowed(&self, sym: Symbol) -> bool {
        self.shadowed.iter().any(|bs| bs.contains(&sym))
    }

    /// Apply parameter substitution if present.
    fn apply_param_substitution(&self, idx: TempIndex) -> TempIndex {
        if let Some(map) = self.param_substitution {
            map[idx]
        } else {
            idx
        }
    }

    fn save_spec_var(&mut self, qid: QualifiedInstId<SpecVarId>) -> MemoryLabel {
        let builder = &mut self.builder;
        *self
            .result
            .saved_spec_vars
            .entry(qid)
            .or_insert_with(|| builder.global_env().new_global_id())
    }

    fn save_memory(&mut self, qid: QualifiedInstId<StructId>) -> MemoryLabel {
        let builder = &mut self.builder;
        *self
            .result
            .saved_memory
            .entry(qid)
            .or_insert_with(|| builder.global_env().new_global_id())
    }

    fn save_param(&mut self, idx: TempIndex) -> TempIndex {
        if let Some(saved) = self.result.saved_params.get(&idx) {
            *saved
        } else {
            let saved = self
                .builder
                .new_temp(self.builder.get_local_type(idx).skip_reference().clone());
            self.result.saved_params.insert(idx, saved);
            saved
        }
    }
}

impl<'a, 'b, T: ExpGenerator<'a>> ExpRewriterFunctions for SpecTranslator<'a, 'b, T> {
    fn rewrite_exp(&mut self, exp: Exp) -> Exp {
        // Do some pre-processing of the expression before actual rewrite, reporting
        // errors.
        let env = self.builder.global_env();
        let mut is_old = false;
        match exp.as_ref() {
            ExpData::Call(id, Operation::Old, args) => {
                is_old = true;
                // Generate an error if an `old` function is applied to a pure expression.
                let arg = &args[0];
                if arg.is_pure(self.builder.global_env()) {
                    let loc = self.builder.global_env().get_node_loc(*id);
                    // Compute labels for any sub-expressions which are included into this
                    // expression via substitution (from schema inclusion, for example). This
                    // is done via checking the location of the sub-expression. We also try
                    // to avoid to report a sub-expression which is a sub-expression of an
                    // already reported one.
                    let mut labels = vec![];
                    let loc_contained = |loc: &Loc, cont: &Loc| {
                        loc.file_id() == cont.file_id()
                            && cont.span().start() >= loc.span().start()
                            && cont.span().end() <= loc.span().end()
                    };
                    arg.visit_pre_post(&mut |up: bool, e: &ExpData| {
                        let sub_loc = self.builder.global_env().get_node_loc(e.node_id());
                        if !up
                            && !loc_contained(&loc, &sub_loc)
                            && !labels.iter().any(|(l, _)| loc_contained(l, &sub_loc))
                        {
                            labels.push((sub_loc, "substituted sub-expression".to_owned()))
                        }
                    });
                    self.builder.global_env().diag_with_labels(
                        Severity::Error,
                        &loc,
                        "`old(..)` applied to expression which does not depend on state",
                        labels,
                    )
                }
            }
            ExpData::Call(id, Operation::Trace, args) => {
                // Generate an error if a TRACE is applied to an expression where it is not
                // allowed, i.e. if there are free LocalVar terms, excluding locals from lets.
                let loc = env.get_node_loc(*id);
                let has_free_vars = args[0]
                    .free_vars(env)
                    .iter()
                    .any(|(s, _)| !self.let_locals.contains_key(s));
                if has_free_vars {
                    env.error(
                        &loc,
                        "`TRACE(..)` function cannot be used for expressions depending \
                             on quantified variables or spec function parameters",
                    )
                }
            }
            _ => {}
        }
        if is_old {
            self.in_old = true;
        }
        let exp = self.rewrite_exp_descent(exp);
        if is_old {
            self.in_old = false;
        }
        exp
    }

    fn rewrite_local_var(&mut self, id: NodeId, sym: Symbol) -> Option<Exp> {
        if !self.is_shadowed(sym) {
            if let Some(temp) = self.let_locals.get(&sym) {
                // Need to create new node id since the replacement `temp` may
                // differ w.r.t. references.
                let env = self.builder.global_env();
                let new_node_id =
                    env.new_node(env.get_node_loc(id), self.builder.get_local_type(*temp));
                return Some(ExpData::Temporary(new_node_id, *temp).into_exp());
            }
        }
        None
    }

    fn rewrite_temporary(&mut self, id: NodeId, idx: TempIndex) -> Option<Exp> {
        // Compute the effective index.
        let local_type = if idx < self.fun_env.get_parameter_count() {
            // if the idx is a function argument, get its original type
            self.fun_env.get_local_type(idx)
        } else {
            // otherwise, get type from the builder
            self.builder.get_local_type(idx)
        };
        let is_mut = local_type.is_mutable_reference();
        let effective_idx = if self.in_old || self.in_post_state && !is_mut {
            // We access a param inside of old context, or a value which might have been
            // mutated as we are in the post state. We need to create a temporary
            // to save their value at function entry, and deliver this temporary here.
            //
            // Notice that a redundant copy of a value (i.e. one which is not mutated)
            // is removed by copy propagation, so we do not need to
            // care about optimizing this here.
            self.save_param(self.apply_param_substitution(idx))
        } else {
            self.apply_param_substitution(idx)
        };
        if effective_idx != idx {
            // The type of this temporary might be different than the node's type w.r.t.
            // references. Create a new node id with the effective type.
            let effective_type = self
                .builder
                .get_local_type(effective_idx)
                .instantiate(self.type_args);
            let loc = self.builder.global_env().get_node_loc(id);
            let new_id = self.builder.global_env().new_node(loc, effective_type);
            Some(ExpData::Temporary(new_id, effective_idx).into_exp())
        } else {
            None
        }
    }

    fn rewrite_spec_var(
        &mut self,
        id: NodeId,
        mid: ModuleId,
        vid: SpecVarId,
        label: &Option<MemoryLabel>,
    ) -> Option<Exp> {
        if self.in_old && label.is_none() {
            let inst = self.builder.global_env().get_node_instantiation(id);
            Some(
                ExpData::SpecVar(
                    id,
                    mid,
                    vid,
                    Some(self.save_spec_var(mid.qualified_inst(vid, inst))),
                )
                .into_exp(),
            )
        } else {
            None
        }
    }

    fn rewrite_call(&mut self, id: NodeId, oper: &Operation, args: &[Exp]) -> Option<Exp> {
        use ExpData::*;
        use Operation::*;
        match oper {
            Global(None) if self.in_old => Some(
                Call(
                    id,
                    Global(Some(self.save_memory(self.builder.get_memory_of_node(id)))),
                    args.to_owned(),
                )
                .into_exp(),
            ),
            Exists(None) if self.in_old => Some(
                Call(
                    id,
                    Exists(Some(self.save_memory(self.builder.get_memory_of_node(id)))),
                    args.to_owned(),
                )
                .into_exp(),
            ),
            Function(mid, fid, None) if self.in_old => {
                let (used_memory, used_spec_vars) = {
                    let module_env = self.builder.global_env().get_module(*mid);
                    let decl = module_env.get_spec_fun(*fid);
                    // Unfortunately, the below clones are necessary, as we cannot borrow decl
                    // and at the same time mutate self later.
                    (decl.used_memory.clone(), decl.used_spec_vars.clone())
                };
                let inst = self.builder.global_env().get_node_instantiation(id);
                let mut labels = vec![];
                for mem in used_memory {
                    let mem = mem.instantiate(&inst);
                    labels.push(self.save_memory(mem));
                }
                for var in used_spec_vars {
                    let var = var.instantiate(&inst);
                    labels.push(self.save_spec_var(var));
                }
                Some(Call(id, Function(*mid, *fid, Some(labels)), args.to_owned()).into_exp())
            }
            Old => Some(args[0].to_owned()),
            Result(n) => {
                self.builder.set_loc_from_node(id);
                Some(self.builder.mk_temporary(self.ret_locals[*n]))
            }
            Trace => {
                let exp = args[0].to_owned();
                let env = self.builder.global_env();
                let loc = env.get_node_loc(id);
                let trace_id = env.new_node(loc, env.get_node_type(exp.node_id()));
                self.result.debug_traces.push((trace_id, exp.clone()));
                Some(exp)
            }
            _ => None,
        }
    }

    fn rewrite_node_id(&mut self, id: NodeId) -> Option<NodeId> {
        if self.type_args.is_empty() {
            None
        } else {
            ExpData::instantiate_node(self.builder.global_env(), id, self.type_args)
        }
    }

    fn rewrite_enter_scope<'c>(&mut self, decls: impl Iterator<Item = &'c LocalVarDecl>) {
        self.shadowed.push(decls.map(|d| d.name).collect())
    }

    fn rewrite_exit_scope(&mut self) {
        self.shadowed.pop();
    }
}
