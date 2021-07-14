// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Analysis which computes information needed in backends for monomorphization. This
//! computes the distinct type instantiations in the model for structs and inlined functions.
//! It also eliminates type quantification (`forall coin_type: type:: P`).

use crate::verification_analysis_v2::InvariantAnalysisData;
use crate::{
    function_data_builder::FunctionDataBuilder,
    function_target::{FunctionData, FunctionTarget},
    function_target_pipeline::{FunctionTargetProcessor, FunctionTargetsHolder, FunctionVariant},
    mono_analysis,
    mut_ref_instrumentation::{FunctionEnv, Loc},
    stackless_bytecode::{Bytecode, Bytecode::SaveMem, Operation},
    usage_analysis,
};
use itertools::Itertools;
use move_model::pragmas::DISABLE_INVARIANTS_IN_BODY_PRAGMA;
use move_model::ty::{Substitution, Variance};
use move_model::{
    ast,
    ast::{Condition, ConditionKind, Exp, ExpData, LocalVarDecl, MemoryLabel, QuantKind},
    exp_generator::ExpGenerator,
    model::{
        FunId, GlobalEnv, ModuleId, NodeId, QualifiedId, QualifiedInstId, SpecFunId, SpecVarId,
        StructEnv, StructId,
    },
    symbol::Symbol,
    ty::{PrimitiveType, Type, TypeDisplayContext},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
    rc::Rc,
};

/// The environment extension computed by this analysis.
#[derive(Clone, Default, Debug)]
pub struct MonoInfo {
    pub structs: BTreeMap<QualifiedId<StructId>, BTreeSet<Vec<Type>>>,
    pub verified_funs: BTreeMap<QualifiedId<FunId>, BTreeSet<Vec<Type>>>,
    pub inlined_funs: BTreeMap<QualifiedId<FunId>, BTreeSet<Vec<Type>>>,
    pub spec_funs: BTreeMap<QualifiedId<SpecFunId>, BTreeSet<Vec<Type>>>,
    pub spec_vars: BTreeMap<QualifiedId<SpecVarId>, BTreeSet<Vec<Type>>>,
    pub type_params: BTreeSet<u16>,
    pub vec_inst: BTreeSet<Type>,
    pub native_inst: BTreeMap<ModuleId, BTreeSet<Vec<Type>>>,
    pub axioms: Vec<Condition>,
}

/// Get the information computed by this analysis.
pub fn get_info(env: &GlobalEnv) -> Rc<MonoInfo> {
    env.get_extension::<MonoInfo>()
        .unwrap_or_else(|| Rc::new(MonoInfo::default()))
}

pub struct MonoAnalysisProcessor();

impl MonoAnalysisProcessor {
    pub fn new() -> Box<Self> {
        Box::new(Self())
    }
}

/// A marker stored as an environment extension to tell the finalize method that
/// the analysis needs to be re-run because new instances have been introduced
/// by type quantifier elimination.
struct RunAnalysisAgain();

/// This processor does the following.
/// 1. During `initialize`, it performs an analysis of all instantiations in
///    the program, setting the `MonoInfo` data in the environment.
/// 2. It then processes each function, eliminating potential quantifiers over
///    types by substituting those types with instantiations found in the program.
/// 3. If (2) has added new types, it runs the mono analysis a second time.
impl FunctionTargetProcessor for MonoAnalysisProcessor {
    fn process(
        &self,
        _targets: &mut FunctionTargetsHolder,
        fun_env: &FunctionEnv<'_>,
        mut data: FunctionData,
    ) -> FunctionData {
        // Eliminate a quantification over type variable `name` by collecting all instantiations
        // of constructors using `name` inside of the quantifiers `body`, and then expanding
        // the body into a conjunction or disjunction. For example, given the expression
        // `forall t: type :: P[TypeCtor<u64, t>]`, and the program context containing
        // instantiations `TypeCtor<u64, A>` and `TypeCtor<address, B>`, we will generate
        // `P[TypeCtor<u64, A>] && P[TypeCtor<address, B>]`.
        let code = std::mem::take(&mut data.code);
        let builder = FunctionDataBuilder::new(fun_env, data);
        let mut rewriter = TypeQuantRewriter {
            generator: builder,
            instantiated_memory: Default::default(),
            quants_eliminated: false,
            marker: PhantomData::default(),
        };
        for bc in code {
            if let Bytecode::Prop(id, kind, exp) = bc {
                let exp = rewriter.rewrite_type_quant(exp);
                rewriter.generator.emit(Bytecode::Prop(id, kind, exp));
            } else {
                rewriter.generator.emit(bc);
            }
        }
        if rewriter.quants_eliminated {
            // We need to go a second time over the code to expand `SaveMem` instructions.
            // Where we previous had `SaveMem<R<type_var>>` we need to create one SaveMem
            // for every instance.
            let code = std::mem::take(&mut rewriter.generator.data.code);
            for bc in code {
                match bc {
                    Bytecode::SaveMem(id, label, mem) => {
                        if rewriter.instantiated_memory.contains_key(&label) {
                            for inst in rewriter.instantiated_memory.get(&label).unwrap() {
                                rewriter.generator.emit(Bytecode::SaveMem(
                                    id,
                                    label,
                                    inst.to_owned(),
                                ));
                            }
                        } else if !mem
                            .inst
                            .iter()
                            .any(|ty| ty.contains(&|t| matches!(t, Type::TypeLocal(_))))
                        {
                            // Only retain the SaveMem if it does not contain type locals.
                            // Such SaveMem's can result from zero expansions during quantifier
                            // elimination, and they are dead.
                            rewriter.generator.emit(SaveMem(id, label, mem));
                        }
                    }
                    _ => rewriter.generator.emit(bc),
                }
            }
            rewriter
                .generator
                .global_env()
                .set_extension(RunAnalysisAgain());
        }
        rewriter.generator.data
    }

    fn name(&self) -> String {
        "mono_analysis".to_owned()
    }

    fn initialize(&self, env: &GlobalEnv, targets: &mut FunctionTargetsHolder) {
        self.analyze(env, None, targets);
    }

    fn finalize(&self, env: &GlobalEnv, targets: &mut FunctionTargetsHolder) {
        // Run type quantifier elimination on axioms
        let mut new_axioms = vec![];
        let mut axioms_rewritten = false;
        for module_env in env.get_modules() {
            for axiom in module_env.get_spec().filter_kind(ConditionKind::Axiom) {
                let mut rewriter = TypeQuantRewriter {
                    generator: EnvGenerator {
                        env,
                        current_loc: env.unknown_loc(),
                    },
                    quants_eliminated: false,
                    instantiated_memory: Default::default(),
                    marker: Default::default(),
                };
                let new_axiom = Condition {
                    kind: axiom.kind.clone(),
                    loc: axiom.loc.clone(),
                    properties: axiom.properties.clone(),
                    exp: rewriter.rewrite_type_quant(axiom.exp.clone()),
                    additional_exps: vec![],
                };
                new_axioms.push(new_axiom);
                axioms_rewritten = axioms_rewritten || rewriter.quants_eliminated;
            }
        }
        if axioms_rewritten || env.has_extension::<RunAnalysisAgain>() {
            self.analyze(env, Some(&new_axioms), targets);
        }
        if !new_axioms.is_empty() {
            env.update_extension(move |info: &mut MonoInfo| {
                info.axioms = new_axioms;
            });
        }
    }

    fn dump_result(
        &self,
        f: &mut fmt::Formatter,
        env: &GlobalEnv,
        _targets: &FunctionTargetsHolder,
    ) -> fmt::Result {
        writeln!(f, "\n\n==== mono-analysis result ====\n")?;
        let info = env
            .get_extension::<MonoInfo>()
            .expect("monomorphization analysis not run");
        let tctx = TypeDisplayContext::WithEnv {
            env,
            type_param_names: None,
        };
        let display_inst = |tys: &[Type]| {
            tys.iter()
                .map(|ty| ty.display(&tctx).to_string())
                .join(", ")
        };
        for (sid, insts) in &info.structs {
            let sname = env.get_struct(*sid).get_full_name_str();
            writeln!(f, "struct {} = {{", sname)?;
            for inst in insts {
                writeln!(f, "  <{}>", display_inst(inst))?;
            }
            writeln!(f, "}}")?;
        }
        for (fid, insts) in &info.inlined_funs {
            let fname = env.get_function(*fid).get_full_name_str();
            writeln!(f, "fun {} = {{", fname)?;
            for inst in insts {
                writeln!(f, "  <{}>", display_inst(inst))?;
            }
            writeln!(f, "}}")?;
        }
        for (fid, insts) in &info.spec_funs {
            let module_env = env.get_module(fid.module_id);
            let decl = module_env.get_spec_fun(fid.id);
            let mname = module_env.get_full_name_str();
            let fname = decl.name.display(env.symbol_pool());
            writeln!(f, "spec fun {}::{} = {{", mname, fname)?;
            for inst in insts {
                writeln!(f, "  <{}>", display_inst(inst))?;
            }
            writeln!(f, "}}")?;
        }

        Ok(())
    }
}

// Instantiation Analysis
// ======================

impl MonoAnalysisProcessor {
    fn analyze<'a>(
        &self,
        env: &'a GlobalEnv,
        rewritten_axioms: Option<&[Condition]>,
        targets: &'a FunctionTargetsHolder,
    ) {
        let mut analyzer = Analyzer {
            env,
            targets,
            info: MonoInfo::default(),
            todo_funs: vec![],
            done_funs: BTreeSet::new(),
            todo_spec_funs: vec![],
            done_spec_funs: BTreeSet::new(),
            done_types: BTreeSet::new(),
            inst_opt: None,
        };
        if let Some(axioms) = rewritten_axioms {
            // Analyze newly rewritten axioms.
            for axiom in axioms {
                analyzer.analyze_exp(&axiom.exp)
            }
        } else {
            // Analyze axioms found in modules.
            for module_env in env.get_modules() {
                for axiom in module_env.get_spec().filter_kind(ConditionKind::Axiom) {
                    analyzer.analyze_exp(&axiom.exp)
                }
            }
        }
        analyzer.analyze_funs();
        let Analyzer { info, .. } = analyzer;
        env.set_extension(info);
    }
}

struct Analyzer<'a> {
    env: &'a GlobalEnv,
    targets: &'a FunctionTargetsHolder,
    info: MonoInfo,
    todo_funs: Vec<(QualifiedId<FunId>, Vec<Type>)>,
    done_funs: BTreeSet<(QualifiedId<FunId>, Vec<Type>)>,
    todo_spec_funs: Vec<(QualifiedId<SpecFunId>, Vec<Type>)>,
    done_spec_funs: BTreeSet<(QualifiedId<SpecFunId>, Vec<Type>)>,
    done_types: BTreeSet<Type>,
    inst_opt: Option<Vec<Type>>,
}

impl<'a> Analyzer<'a> {
    fn analyze_funs(&mut self) {
        // Analyze top-level, verified functions. Any functions they call will be queued
        // in self.todo_targets for later analysis.
        for module in self.env.get_modules() {
            for fun in module.get_functions() {
                for (variant, ref target) in self.targets.get_targets(&fun) {
                    if variant.is_primary_verified() {
                        // Analyze for all instantiations which need verification.
                        for inst in self.compute_verification_instances(target) {
                            // Add instantiation.
                            self.info
                                .verified_funs
                                .entry(target.func_env.get_qualified_id())
                                .or_default()
                                .insert(inst.clone());

                            // Analyze.
                            self.inst_opt = Some(inst);
                            self.analyze_fun(target.clone());

                            // We also need to analyze all modify targets because they are not
                            // included in the bytecode.
                            for (_, exps) in target.get_modify_ids_and_exps() {
                                for exp in exps {
                                    self.analyze_exp(exp);
                                }
                            }
                        }
                    }
                }
            }
        }
        // Now incrementally work todo lists until they are done, while self.inst_opt
        // contains the specific instantiation. We can first do regular functions,
        // then the spec functions; the later can never add new regular functions.
        while !self.todo_funs.is_empty() {
            let (fun, inst) = self.todo_funs.pop().unwrap();
            self.inst_opt = Some(inst);
            self.analyze_fun(
                self.targets
                    .get_target(&self.env.get_function(fun), &FunctionVariant::Baseline),
            );
            let inst = std::mem::take(&mut self.inst_opt).unwrap();
            // Insert it into final analysis result.
            self.info
                .inlined_funs
                .entry(fun)
                .or_default()
                .insert(inst.clone());
            self.done_funs.insert((fun, inst));
        }
        while !self.todo_spec_funs.is_empty() {
            let (fun, inst) = self.todo_spec_funs.pop().unwrap();
            self.inst_opt = Some(inst);
            self.analyze_spec_fun(fun);
            let inst = std::mem::take(&mut self.inst_opt).unwrap();
            // Insert it into final analysis result.
            self.info
                .spec_funs
                .entry(fun)
                .or_default()
                .insert(inst.clone());
            self.done_spec_funs.insert((fun, inst));
        }
    }

    /// Computes the type instantiations which need to be verified for the given function.
    /// By default, the uninstantiated function is included. We also must include
    /// all instantiations which update memory which is constraint by global invariants. Suppose
    /// we have a function `f<T>(a: address) { modify<R<T>>(a) }` and an invariant
    /// `invariant forall a: address where exists<R<u64>>: global<R<u64>>.value > 0`.
    /// We need to verify `f<u64>` so the given invariant is verified for this instance.
    /// Note that in this example, the function `f<u64>` has no way to satisfy the invariant
    /// as it does not known about it's type instantiations. In such a case, the user will
    /// have to mark this function as having invariants disabled, and they will be verified at
    /// caller side. In other cases, verification may succeed, so disabling invariants
    /// for generic functions is a user choice.
    fn compute_verification_instances(&self, target: &FunctionTarget<'_>) -> BTreeSet<Vec<Type>> {
        let mut result = BTreeSet::new();
        result.insert(vec![]);
        let type_params = target
            .get_type_parameters()
            .into_iter()
            .map(|p| p.0)
            .collect_vec();
        if type_params.is_empty() {
            // Shortcut
            return result;
        }
        if target
            .func_env
            .is_pragma_true(DISABLE_INVARIANTS_IN_BODY_PRAGMA, || false)
        {
            // No invariant verification for this function.
            return result;
        }

        let invariant_data = match self.env.get_extension::<InvariantAnalysisData>() {
            Some(data) => data,
            None => {
                // We need verification_analysis_v2, so need to bail out if it is not available.
                return result;
            }
        };

        // All the memory accessed by global invariants which are target of verification.
        let invariant_memory = &invariant_data.target_memory;

        // All the memory  modified transitively by this function.
        let modified_memory_inst = usage_analysis::get_modified_memory_inst(target);

        for inv_mem in invariant_memory {
            let inv_mem_ty = inv_mem.to_type();
            for mod_memory in modified_memory_inst.iter() {
                if inv_mem.to_qualified_id() != mod_memory.to_qualified_id() {
                    // Distinct memory.
                    continue;
                }
                // We are going to type-unify the modified memory (e.g. `R<T>`) with invariant memory
                // (e.g. `R<u64>`). The resulting substitution is than applied to create an
                // instantiation of the function (e.g. `f<T>` is instantiated as `f<u64>`).

                // First create type variables for function's type parameters and use them to
                // instantiate the modified memory,
                let inst = (0..type_params.len())
                    .map(|i| Type::Var(i as u16))
                    .collect_vec();
                let mod_memory = mod_memory.to_owned().instantiate(&inst);

                // Now unify mod_memory with inv_mem
                let mod_memory_ty = mod_memory.to_type();
                let mut subs = Substitution::new();
                match subs.unify(
                    &self.env.type_display_context(),
                    Variance::Disallow,
                    &inv_mem_ty,
                    &mod_memory_ty,
                ) {
                    Ok(_) => {
                        // Compute the unified instantiation and collect it in the result.
                        let unified_inst = inst
                            .into_iter()
                            .map(|ty| subs.specialize(&ty))
                            .collect_vec();
                        result.insert(unified_inst);
                    }
                    Err(_) => {
                        // Unification did not succeed implies this modified memory cannot depend
                        // on this invariant. For example, an invariant over `R<u64>` cannot
                        // have an effect on a modified memory `R<S<u64>>`,
                    }
                }
            }
        }
        result
    }

    fn analyze_fun(&mut self, target: FunctionTarget<'_>) {
        // Analyze function locals and return value types.
        for idx in 0..target.get_local_count() {
            self.add_type_root(target.get_local_type(idx));
        }
        for ty in target.get_return_types().iter() {
            self.add_type_root(ty);
        }
        // Analyze code.
        if !target.func_env.is_native_or_intrinsic() {
            for bc in target.get_bytecode() {
                self.analyze_bytecode(&target, bc);
            }
        }
    }

    fn analyze_bytecode(&mut self, _target: &FunctionTarget<'_>, bc: &Bytecode) {
        use Bytecode::*;
        use Operation::*;
        // We only need to analyze function calls, not `pack` or other instructions
        // because the types those are using are reflected in locals which are analyzed
        // elsewhere.
        match bc {
            Call(_, _, Function(mid, fid, targs), ..) => {
                let callee = &self.env.get_module(*mid).into_function(*fid);
                let actuals = self.instantiate_vec(targs);
                if callee.is_native_or_intrinsic() && !actuals.is_empty() {
                    // Mark the associated module to be instantiated with the given actuals.
                    // This will instantiate all functions in the module with matching number
                    // of type parameters.
                    self.info
                        .native_inst
                        .entry(callee.module_env.get_id())
                        .or_default()
                        .insert(actuals);
                } else if !callee.is_opaque() {
                    // This call needs to be inlined, with targs instantiated by self.inst_opt.
                    // Schedule for later processing if this instance has not been processed yet.
                    let entry = (mid.qualified(*fid), actuals);
                    if !self.done_funs.contains(&entry) {
                        self.todo_funs.push(entry);
                    }
                }
            }
            Prop(_, _, exp) => self.analyze_exp(exp),
            SaveMem(_, _, mem) => {
                let mem = self.instantiate_mem(mem.to_owned());
                let struct_env = self.env.get_struct_qid(mem.to_qualified_id());
                self.add_struct(struct_env, &mem.inst);
            }
            _ => {}
        }
    }

    fn instantiate_vec(&self, targs: &[Type]) -> Vec<Type> {
        if let Some(inst) = &self.inst_opt {
            Type::instantiate_slice(targs, inst)
        } else {
            targs.to_owned()
        }
    }

    fn instantiate_mem(&self, mem: QualifiedInstId<StructId>) -> QualifiedInstId<StructId> {
        if let Some(inst) = &self.inst_opt {
            mem.instantiate(inst)
        } else {
            mem
        }
    }

    // Expression and Spec Fun Analysis
    // --------------------------------

    fn analyze_spec_fun(&mut self, fun: QualifiedId<SpecFunId>) {
        let module_env = self.env.get_module(fun.module_id);
        let decl = module_env.get_spec_fun(fun.id);
        for (_, ty) in &decl.params {
            self.add_type_root(ty)
        }
        self.add_type_root(&decl.result_type);
        if let Some(exp) = &decl.body {
            self.analyze_exp(exp)
        }
    }

    fn analyze_exp(&mut self, exp: &ExpData) {
        exp.visit(&mut |e| {
            let node_id = e.node_id();
            self.add_type_root(&self.env.get_node_type(node_id));
            for ref ty in self.env.get_node_instantiation(node_id) {
                self.add_type_root(ty);
            }
            match e {
                ExpData::Call(node_id, ast::Operation::Function(mid, fid, _), _) => {
                    let actuals = self.instantiate_vec(&self.env.get_node_instantiation(*node_id));
                    // Only if this call has not been processed yet, queue it for future processing.
                    let module = self.env.get_module(*mid);
                    let spec_fun = module.get_spec_fun(*fid);
                    if spec_fun.is_native && !actuals.is_empty() {
                        // Add module to native modules
                        self.info
                            .native_inst
                            .entry(module.get_id())
                            .or_default()
                            .insert(actuals);
                    } else {
                        let entry = (mid.qualified(*fid), actuals);
                        if !self.done_spec_funs.contains(&entry) {
                            self.todo_spec_funs.push(entry);
                        }
                    }
                }
                ExpData::SpecVar(node_id, mid, sid, _) => {
                    let actuals = self.instantiate_vec(&self.env.get_node_instantiation(*node_id));
                    let qid = mid.qualified(*sid);
                    self.info.spec_vars.entry(qid).or_default().insert(actuals);
                }
                _ => {}
            }
        });
    }

    // Type Analysis
    // -------------

    fn add_type_root(&mut self, ty: &Type) {
        if let Some(inst) = &self.inst_opt {
            let ty = ty.instantiate(inst);
            self.add_type(&ty)
        } else {
            self.add_type(ty)
        }
    }

    fn add_type(&mut self, ty: &Type) {
        if !self.done_types.insert(ty.to_owned()) {
            return;
        }
        ty.visit(&mut |t| match t {
            Type::Vector(et) => {
                self.info.vec_inst.insert(et.as_ref().clone());
            }
            Type::Struct(mid, sid, targs) => {
                self.add_struct(self.env.get_module(*mid).into_struct(*sid), targs)
            }
            Type::TypeParameter(idx) => {
                self.info.type_params.insert(*idx);
            }
            _ => {}
        });
    }

    fn add_struct(&mut self, struct_: StructEnv<'_>, targs: &[Type]) {
        if targs
            .iter()
            .any(|ty| ty.contains(&|t| matches!(t, Type::TypeLocal(..))))
        {
            // Do not add instantiations based on type locals. They will be eliminated by
            // the backend.
            return;
        }
        if struct_.is_native_or_intrinsic() && !targs.is_empty() {
            self.info
                .native_inst
                .entry(struct_.module_env.get_id())
                .or_default()
                .insert(targs.to_owned());
        } else {
            self.info
                .structs
                .entry(struct_.get_qualified_id())
                .or_default()
                .insert(targs.to_owned());
            for field in struct_.get_fields() {
                self.add_type(&field.get_type().instantiate(targs));
            }
        }
    }
}

// Type Quantifier Elimination
// ===========================

struct TypeQuantRewriter<'e, G>
where
    G: ExpGenerator<'e>,
{
    generator: G,
    quants_eliminated: bool,
    // A map from memory label accessed from within the body of the quantifier
    // which needs to be specialized to the given instances in SaveMem instructions.
    instantiated_memory: BTreeMap<MemoryLabel, BTreeSet<QualifiedInstId<StructId>>>,
    marker: PhantomData<&'e G>,
}

impl<'e, G: ExpGenerator<'e>> TypeQuantRewriter<'e, G> {
    fn rewrite_type_quant(&mut self, exp: Exp) -> Exp {
        let env = self.generator.global_env();
        ExpData::rewrite(exp, &mut |e| {
            if let ExpData::Quant(node_id, kind, ranges, triggers, condition, body) = e.as_ref() {
                for (i, (var, range)) in ranges.iter().enumerate() {
                    let ty = env.get_node_type(range.node_id());
                    if let Type::TypeDomain(bt) = ty.skip_reference() {
                        self.quants_eliminated = true;
                        if matches!(bt.as_ref(), Type::Primitive(PrimitiveType::TypeValue)) {
                            if !triggers.is_empty() {
                                env.error(
                                    &env.get_node_loc(*node_id),
                                    "Cannot have triggers with type value ranges",
                                );
                                return Err(e);
                            }
                            if kind.is_choice() {
                                env.error(
                                    &env.get_node_loc(*node_id),
                                    "Type quantification cannot be used with a choice operator",
                                );
                                return Err(e);
                            }
                            let mut remaining_ranges = ranges.clone();
                            remaining_ranges.remove(i);
                            return Ok(self.eliminate_type_quant(
                                *node_id,
                                *kind,
                                var.name,
                                remaining_ranges,
                                condition.clone(),
                                body.clone(),
                            ));
                        }
                    }
                }
            }
            Err(e)
        })
    }

    fn eliminate_type_quant(
        &mut self,
        node_id: NodeId,
        kind: QuantKind,
        name: Symbol,
        ranges: Vec<(LocalVarDecl, Exp)>,
        condition: Option<Exp>,
        body: Exp,
    ) -> Exp {
        let env = self.generator.global_env();

        // Create the effective condition of the eliminated quantifier.
        let body = if !ranges.is_empty() {
            ExpData::Quant(node_id, kind, ranges, vec![], condition, body).into_exp()
        } else {
            match condition {
                Some(c) => match kind {
                    QuantKind::Forall => {
                        ExpData::Call(node_id, ast::Operation::Implies, vec![c, body]).into_exp()
                    }
                    QuantKind::Exists => {
                        ExpData::Call(node_id, ast::Operation::And, vec![c, body]).into_exp()
                    }
                    _ => unreachable!(),
                },
                _ => body,
            }
        };

        // Collect all instantiations in which the type name appears.
        let mono_info = mono_analysis::get_info(env);
        let mut collected = BTreeSet::new();
        let empty = &BTreeSet::new();
        body.visit(&mut |e| {
            let node_id = e.node_id();
            self.collect_type_local_insts(
                mono_info.as_ref(),
                &mut collected,
                name,
                &env.get_node_type(node_id),
            );
            let type_inst = env.get_node_instantiation(node_id);
            for ty in &type_inst {
                self.collect_type_local_insts(mono_info.as_ref(), &mut collected, name, ty);
            }
            match e {
                ExpData::LocalVar(_, n) => {
                    if *n == name {
                        env.error(
                            &env.get_node_loc(node_id),
                            &format!(
                                "type value `{}` can only be used in type constructor",
                                name.display(env.symbol_pool())
                            ),
                        )
                    }
                }
                ExpData::Call(_, ast::Operation::Function(mid, fid, _), ..) => {
                    // Collect instantiations of this function for `name`.
                    self.collect_instances(
                        &mut collected,
                        name,
                        &type_inst,
                        mono_info
                            .spec_funs
                            .get(&mid.qualified(*fid))
                            .unwrap_or(empty),
                    );
                }
                _ => {}
            }
        });

        // For each of the instantiations, expand the body, with the instantiation substituted.
        let expanded = collected
            .into_iter()
            .map(|ty| {
                let mut node_rewriter = |id: NodeId| {
                    let node_ty = env.get_node_type(id);
                    let new_node_ty = node_ty.replace_type_local(name, ty.clone());
                    let node_inst = env.get_node_instantiation_opt(id);
                    let new_node_inst = node_inst.clone().map(|i| {
                        i.iter()
                            .map(|t| t.replace_type_local(name, ty.clone()))
                            .collect_vec()
                    });
                    if node_ty != new_node_ty || node_inst != new_node_inst {
                        let loc = env.get_node_loc(id);
                        let new_id = env.new_node(loc, new_node_ty);
                        if let Some(inst) = new_node_inst {
                            env.set_node_instantiation(new_id, inst);
                        }
                        Some(new_id)
                    } else {
                        None
                    }
                };
                let body = ExpData::rewrite_node_id(body.clone(), &mut node_rewriter);
                // Collect memory used by the expanded body. We need to rewrite SaveMem
                // instructions to point to the instantiated memory.
                body.visit(&mut |e| {
                    use ast::Operation::*;
                    use ExpData::*;
                    match e {
                        Call(id, Global(Some(label)), _) | Call(id, Exists(Some(label)), _) => {
                            let inst = env.get_node_instantiation(*id);
                            let ty = &inst[0];
                            let (mid, sid, inst) = ty.require_struct();
                            self.instantiated_memory
                                .entry(*label)
                                .or_default()
                                .insert(mid.qualified_inst(sid, inst.to_owned()));
                        }
                        Call(id, Function(mid, fid, Some(labels)), _) => {
                            let inst = &env.get_node_instantiation(*id);
                            let module_env = env.get_module(*mid);
                            let fun = module_env.get_spec_fun(*fid);
                            for (i, mem) in fun.used_memory.iter().enumerate() {
                                let mem = mem.to_owned().instantiate(inst);
                                self.instantiated_memory
                                    .entry(labels[i])
                                    .or_default()
                                    .insert(mem);
                            }
                        }
                        _ => {}
                    }
                });
                body
            })
            .collect_vec();

        // Compose the resulting list of expansions into a conjunction or disjunction.
        self.generator.set_loc(env.get_node_loc(node_id));
        match kind {
            QuantKind::Forall => self
                .generator
                .mk_join_bool(ast::Operation::And, expanded.into_iter())
                .unwrap_or_else(|| self.generator.mk_bool_const(true)),
            QuantKind::Exists => self
                .generator
                .mk_join_bool(ast::Operation::Or, expanded.into_iter())
                .unwrap_or_else(|| self.generator.mk_bool_const(false)),
            _ => unreachable!(),
        }
    }

    /// In the given type, collect all concrete instantiations in `mono_info` of structs or
    /// vectors which are instantiated with  the type local `name`.
    fn collect_type_local_insts(
        &self,
        mono_info: &MonoInfo,
        collected: &mut BTreeSet<Type>,
        name: Symbol,
        ty: &Type,
    ) {
        let type_local = &Type::TypeLocal(name);
        let empty = &BTreeSet::new();
        ty.visit(&mut |ty| {
            use Type::*;
            match ty {
                Struct(mid, sid, inst) => {
                    self.collect_instances(
                        collected,
                        name,
                        inst,
                        mono_info.structs.get(&mid.qualified(*sid)).unwrap_or(empty),
                    );
                }
                Vector(et) => {
                    if et.as_ref() == type_local {
                        collected.extend(mono_info.vec_inst.iter().cloned())
                    }
                }
                _ => {}
            }
        })
    }

    fn collect_instances(
        &self,
        collected: &mut BTreeSet<Type>,
        name: Symbol,
        inst: &[Type],
        insts_in_prog: &BTreeSet<Vec<Type>>,
    ) {
        let type_local = &Type::TypeLocal(name);
        for (i, ity) in inst.iter().enumerate() {
            if ity == type_local {
                collected.extend(insts_in_prog.iter().filter_map(|tys| {
                    let ty = &tys[i];
                    if matches!(ty, Type::TypeLocal(..)) {
                        None
                    } else {
                        Some(ty.clone())
                    }
                }));
            }
        }
    }
}

struct EnvGenerator<'e> {
    env: &'e GlobalEnv,
    current_loc: Loc,
}

impl<'e> ExpGenerator<'e> for EnvGenerator<'e> {
    fn function_env(&self) -> &FunctionEnv<'e> {
        // TODO: remove this from ExpGenerator. We should be able to generate exps without.
        unimplemented!()
    }

    fn global_env(&self) -> &'e GlobalEnv {
        self.env
    }

    fn get_current_loc(&self) -> Loc {
        self.current_loc.clone()
    }

    fn set_loc(&mut self, loc: Loc) {
        self.current_loc = loc;
    }

    fn add_local(&mut self, _ty: Type) -> usize {
        // TODO: remove this from ExpGenerator. We should be able to generate exps without.
        unimplemented!()
    }

    fn get_local_type(&self, _temp: usize) -> Type {
        // TODO: remove this from ExpGenerator. We should be able to generate exps without.
        unimplemented!()
    }
}
