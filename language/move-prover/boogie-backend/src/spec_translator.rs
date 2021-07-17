// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module translates specification conditions to Boogie code.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use itertools::Itertools;
#[allow(unused_imports)]
use log::{debug, info, warn};

use move_model::{
    ast::{ExpData, LocalVarDecl, Operation, Value},
    code_writer::CodeWriter,
    emit, emitln,
    model::{FieldId, GlobalEnv, Loc, ModuleEnv, ModuleId, NodeId, SpecFunId, StructId},
    symbol::Symbol,
    ty::{PrimitiveType, Type},
};

use crate::{
    boogie_helpers::{
        boogie_byte_blob, boogie_choice_fun_name, boogie_declare_global, boogie_field_sel,
        boogie_global_declarator, boogie_inst_suffix, boogie_modifies_memory_name,
        boogie_resource_memory_name, boogie_spec_fun_name, boogie_spec_var_name,
        boogie_struct_name, boogie_type, boogie_type_suffix, boogie_well_formed_expr,
    },
    options::BoogieOptions,
};
use bytecode::mono_analysis::MonoInfo;
use codespan_reporting::diagnostic::Severity;
use move_model::{
    ast::{Exp, MemoryLabel, QuantKind, SpecFunDecl, SpecVarDecl, TempIndex},
    model::{QualifiedInstId, SpecVarId},
};
use std::cell::RefCell;

#[derive(Clone)]
pub struct SpecTranslator<'env> {
    /// The global environment.
    env: &'env GlobalEnv,
    /// Options passed into the translator.
    options: &'env BoogieOptions,
    /// The code writer.
    writer: &'env CodeWriter,
    /// If we are translating in the context of a type instantiation, the type arguments.
    type_inst: Vec<Type>,
    /// Counter for creating new variables.
    fresh_var_count: RefCell<usize>,
    /// Information about lifted choice expressions. Each choice expression in the
    /// original program is uniquely identified by the node id. This allows us to capture
    /// duplication of expressions and map them to the same uninterpreted choice
    /// function. If an expression is duplicated and then later specialized by a type
    /// instantiation, it will have a different node id, but again the same instantiations
    /// map to the same node id, which is the desired semantics.
    lifted_choice_infos: RefCell<BTreeMap<NodeId, LiftedChoiceInfo>>,
}

/// A struct which contains information about a lifted choice expression (like `some x:int: p(x)`).
/// Those expressions are replaced by a call to an axiomatized function which is generated from
/// this info at the end of translation.
#[derive(Clone)]
struct LiftedChoiceInfo {
    id: usize,
    node_id: NodeId,
    kind: QuantKind,
    free_vars: Vec<(Symbol, Type)>,
    used_temps: Vec<(TempIndex, Type)>,
    used_memory: Vec<(QualifiedInstId<StructId>, Option<MemoryLabel>)>,
    var: Symbol,
    range: Exp,
    condition: Exp,
}

impl<'env> SpecTranslator<'env> {
    /// Creates a translator.
    pub fn new(
        writer: &'env CodeWriter,
        env: &'env GlobalEnv,
        options: &'env BoogieOptions,
    ) -> Self {
        Self {
            env,
            options,
            writer,
            type_inst: vec![],
            fresh_var_count: Default::default(),
            lifted_choice_infos: Default::default(),
        }
    }

    /// Emits a translation error.
    pub fn error(&self, loc: &Loc, msg: &str) {
        self.env.error(loc, &format!("[boogie translator] {}", msg));
    }

    /// Sets the location of the code writer from node id.
    fn set_writer_location(&self, node_id: NodeId) {
        self.writer.set_location(&self.env.get_node_loc(node_id));
    }

    /// Generates a fresh variable name.
    fn fresh_var_name(&self, prefix: &str) -> String {
        let mut fvc_ref = self.fresh_var_count.borrow_mut();
        let name_str = format!("${}_{}", prefix, *fvc_ref);
        *fvc_ref = usize::saturating_add(*fvc_ref, 1);
        name_str
    }

    /// Translates a sequence of items separated by `sep`.
    fn translate_seq<T, F>(&self, items: impl Iterator<Item = T>, sep: &str, f: F)
    where
        F: Fn(T),
    {
        let mut first = true;
        for item in items {
            if first {
                first = false;
            } else {
                emit!(self.writer, sep);
            }
            f(item);
        }
    }
}

// Axioms
// ======

impl<'env> SpecTranslator<'env> {
    pub fn translate_axioms(&self, env: &GlobalEnv, mono_info: &MonoInfo) {
        for axiom in &mono_info.axioms {
            self.writer.set_location(&axiom.loc);
            emitln!(self.writer, "// axiom {}", axiom.loc.display(env));
            emit!(self.writer, "axiom ");
            self.translate_exp(&axiom.exp);
            emitln!(self.writer, ";\n");
        }
    }
}

// Specification Variables
// =======================

impl<'env> SpecTranslator<'env> {
    pub fn translate_spec_vars(&self, module_env: &ModuleEnv<'_>, mono_info: &MonoInfo) {
        let empty = &BTreeSet::new();
        let mut translated = BTreeSet::new();
        for (id, var) in module_env.get_spec_vars() {
            for type_inst in mono_info
                .spec_vars
                .get(&module_env.get_id().qualified(*id))
                .unwrap_or(empty)
                .to_owned()
            {
                let name = boogie_spec_var_name(
                    module_env,
                    module_env.get_spec_var(*id).name,
                    &type_inst,
                    &None,
                );
                if !translated.insert(name) {
                    continue;
                }
                if type_inst.is_empty() {
                    self.translate_spec_var(module_env, *id, var);
                } else {
                    SpecTranslator {
                        type_inst,
                        ..self.clone()
                    }
                    .translate_spec_var(module_env, *id, var);
                }
            }
        }
    }

    pub fn translate_spec_var(
        &self,
        module_env: &ModuleEnv<'_>,
        _id: SpecVarId,
        var: &SpecVarDecl,
    ) {
        emitln!(self.writer, "// spec var {}", var.loc.display(self.env));
        let boogie_name = boogie_spec_var_name(module_env, var.name, &self.type_inst, &None);
        emitln!(
            self.writer,
            &boogie_declare_global(self.env, &boogie_name, &self.inst(&var.type_))
        );
    }
}

// Specification Functions
// =======================

impl<'env> SpecTranslator<'env> {
    pub fn translate_spec_funs(&self, module_env: &ModuleEnv<'_>, mono_info: &MonoInfo) {
        let empty = &BTreeSet::new();
        let mut translated = BTreeSet::new();
        for (id, fun) in module_env.get_spec_funs() {
            for type_inst in mono_info
                .spec_funs
                .get(&module_env.get_id().qualified(*id))
                .unwrap_or(empty)
                .to_owned()
            {
                let name = boogie_spec_fun_name(module_env, *id, &type_inst);
                if !translated.insert(name) {
                    continue;
                }
                if type_inst.is_empty() {
                    self.translate_spec_fun(module_env, *id, fun);
                } else {
                    SpecTranslator {
                        type_inst,
                        ..self.clone()
                    }
                    .translate_spec_fun(module_env, *id, fun);
                }
            }
        }
    }

    fn translate_spec_fun(&self, module_env: &ModuleEnv, id: SpecFunId, fun: &SpecFunDecl) {
        if fun.body.is_none() && !fun.uninterpreted {
            // This function is native and expected to be found in the prelude.
            return;
        }
        if fun.is_move_fun && fun.is_native {
            // This function is a native Move function and its spec version is
            // expected to be found in the prelude.
            return;
        }
        if fun.is_move_fun && !module_env.spec_fun_is_used(id) {
            // This function is a pure Move function but is never used,
            // so we don't need to translate it.
            return;
        }
        if let Type::Tuple(..) | Type::Fun(..) = fun.result_type {
            self.error(&fun.loc, "function or tuple result type not yet supported");
            return;
        }
        emitln!(self.writer, "// spec fun {}", fun.loc.display(self.env));
        let result_type = boogie_type(self.env, &self.inst(&fun.result_type));
        let spec_var_params = fun.used_spec_vars.iter().map(|spec_var| {
            let spec_var = &spec_var.to_owned().instantiate(&self.type_inst);
            let declaring_module = self.env.get_module(spec_var.module_id);
            let decl = declaring_module.get_spec_var(spec_var.id);
            let boogie_name =
                boogie_spec_var_name(&declaring_module, decl.name, &spec_var.inst, &None);
            boogie_global_declarator(
                declaring_module.env,
                &boogie_name,
                decl.type_params.len(),
                &self.inst(&decl.type_),
            )
        });
        // it is possible that the spec fun may refer to the same memory after monomorphization,
        // (e.g., one via concrete type and the other via type parameter being instantiated).
        // In this case, we mark the other parameter as unused
        let mut mem_inst_seen = BTreeSet::new();
        let mem_params = fun.used_memory.iter().map(|memory| {
            let memory = memory.to_owned().instantiate(&self.type_inst);
            let struct_env = &self.env.get_struct_qid(memory.to_qualified_id());
            let param_repr = format!(
                "{}: $Memory {}",
                boogie_resource_memory_name(self.env, &memory, &None),
                boogie_struct_name(struct_env, &memory.inst)
            );
            if mem_inst_seen.insert(memory) {
                param_repr
            } else {
                format!("__unused_{}", param_repr)
            }
        });
        let params = fun.params.iter().map(|(name, ty)| {
            format!(
                "{}: {}",
                name.display(module_env.symbol_pool()),
                boogie_type(self.env, &self.inst(ty))
            )
        });
        self.writer.set_location(&fun.loc);
        let boogie_name = boogie_spec_fun_name(&module_env, id, &self.type_inst);
        let param_list = mem_params.chain(spec_var_params).chain(params).join(", ");
        emit!(
            self.writer,
            "function {{:inline}} {}({}): {}",
            boogie_name,
            param_list,
            result_type
        );
        if fun.uninterpreted {
            // Uninterpreted function has no body.
            emitln!(self.writer, ";");
            // Emit axiom about return type. Notice we don't need to process spec_var or memory
            // parameters because an interpreted functions does not have those.
            let call = format!(
                "{}({})",
                boogie_name,
                fun.params
                    .iter()
                    .map(|(n, _)| { format!("{}", n.display(module_env.symbol_pool())) })
                    .join(", ")
            );
            let type_check =
                boogie_well_formed_expr(self.env, "$$res", &self.inst(&fun.result_type));
            if !type_check.is_empty() {
                if !param_list.is_empty() {
                    emitln!(
                        self.writer,
                        "axiom (forall {} ::\n(var $$res := {};\n{}));",
                        param_list,
                        call,
                        type_check
                    );
                } else {
                    emitln!(
                        self.writer,
                        "axiom (var $$res := {};\n{});",
                        call,
                        type_check
                    );
                }
            }
            emitln!(self.writer);
        } else {
            emitln!(self.writer, " {");
            self.writer.indent();
            self.translate_exp(fun.body.as_ref().unwrap());
            emitln!(self.writer);
            self.writer.unindent();
            emitln!(self.writer, "}");
            emitln!(self.writer);
        }
    }
}

// Emit any finalization items
// ============================

impl<'env> SpecTranslator<'env> {
    pub(crate) fn finalize(&self) {
        self.translate_choice_functions();
    }

    /// Translate lifted functions for choice expressions.
    fn translate_choice_functions(&self) {
        let env = self.env;
        let infos = self.lifted_choice_infos.borrow();
        for (_, info) in infos.iter() {
            let fun_name = boogie_choice_fun_name(info.id);
            let result_ty = &env.get_node_type(info.node_id);
            let exp_loc = env.get_node_loc(info.node_id);
            let var_name = info.var.display(env.symbol_pool()).to_string();
            self.writer.set_location(&exp_loc);
            // Pairs of context parameter names and boogie types
            let param_decls = info
                .free_vars
                .iter()
                .map(|(s, ty)| {
                    (
                        s.display(env.symbol_pool()).to_string(),
                        boogie_type(env, ty),
                    )
                })
                .chain(
                    info.used_temps
                        .iter()
                        .map(|(t, ty)| (format!("$t{}", t), boogie_type(env, ty))),
                )
                .chain(info.used_memory.iter().map(|(m, l)| {
                    let struct_env = &env.get_struct(m.to_qualified_id());
                    (
                        boogie_resource_memory_name(env, m, l),
                        format!("$Memory {}", boogie_struct_name(struct_env, &m.inst)),
                    )
                }))
                .collect_vec();
            // Pair of choice variable name and type.
            let var_decl = (var_name, boogie_type(env, result_ty));

            // Helper functions
            let mk_decl = |(n, t): &(String, String)| format!("{}: {}", n, t);
            let mk_arg = |(n, _): &(String, String)| n.to_owned();
            let emit_valid = |n: &str, ty: &Type| {
                let suffix = boogie_type_suffix(env, ty);
                emit!(self.writer, "$IsValid'{}'({})", suffix, n);
            };
            let mk_temp = |t: TempIndex| format!("$t{}", t);

            emitln!(
                self.writer,
                "// choice expression {}",
                exp_loc.display(self.env)
            );

            // Emit predicate function characterizing the choice.
            emitln!(
                self.writer,
                "function {{:inline}} {}_pred({}): bool {{",
                fun_name,
                vec![&var_decl]
                    .into_iter()
                    .chain(param_decls.iter())
                    .map(mk_decl)
                    .join(", ")
            );
            self.writer.indent();
            emit_valid(&var_decl.0, result_ty);
            match env.get_node_type(info.range.node_id()) {
                Type::Vector(..) => {
                    emit!(self.writer, " && InRangeVec(");
                    self.translate_exp(&info.range);
                    emit!(self.writer, ", {})", &var_decl.0);
                }
                Type::Primitive(PrimitiveType::Range) => {
                    emit!(self.writer, " && $InRange(");
                    self.translate_exp(&info.range);
                    emit!(self.writer, ", {})", &var_decl.0);
                }
                _ => {}
            }
            emitln!(self.writer, " &&");
            self.translate_exp(&info.condition);
            self.writer.unindent();
            emitln!(self.writer, "\n}");
            // Create call to predicate
            let predicate = format!(
                "{}_pred({})",
                fun_name,
                vec![&var_decl]
                    .into_iter()
                    .chain(param_decls.iter())
                    .map(mk_arg)
                    .join(", ")
            );

            // Emit choice function
            emitln!(
                self.writer,
                "function {}({}): {};",
                fun_name,
                param_decls.iter().map(mk_decl).join(", "),
                boogie_type(env, result_ty)
            );
            // Create call to choice function
            let choice = format!(
                "{}({})",
                fun_name,
                param_decls.iter().map(mk_arg).join(", ")
            );

            // Emit choice axiom
            if !param_decls.is_empty() {
                emit!(
                    self.writer,
                    "axiom (forall {}:: ",
                    param_decls.iter().map(mk_decl).join(", ")
                );
                if !info.free_vars.is_empty() || !info.used_temps.is_empty() {
                    // TODO: IsValid for memory?
                    let mut sep = "";
                    for (s, ty) in &info.free_vars {
                        emit!(self.writer, sep);
                        emit_valid(env.symbol_pool().string(*s).as_ref(), ty);
                        sep = " && ";
                    }
                    for (t, ty) in &info.used_temps {
                        emit!(self.writer, sep);
                        emit_valid(&mk_temp(*t), ty);
                        sep = " && ";
                    }
                    emitln!(self.writer, " ==>");
                }
            } else {
                emitln!(self.writer, "axiom");
            }
            self.writer.indent();
            emitln!(
                self.writer,
                "(exists {}:: {}) ==> ",
                mk_decl(&var_decl),
                predicate
            );
            emitln!(
                self.writer,
                "(var {} := {}; {}",
                &var_decl.0,
                choice,
                predicate
            );

            // Emit min constraint
            if info.kind == QuantKind::ChooseMin {
                // Check whether we support min on the range type.
                if !result_ty.is_number() && !result_ty.is_signer_or_address() {
                    env.error(
                        &env.get_node_loc(info.node_id),
                        "The min choice can only be applied to numbers, addresses, or signers",
                    )
                }
                // Add the condition that there does not exist a smaller satisfying value.
                emit!(self.writer, " && (var $$c := {}; ", &var_decl.0);
                emit!(
                    self.writer,
                    "(forall {}:: {} < $$c ==> !{}))",
                    mk_decl(&var_decl),
                    &var_decl.0,
                    predicate
                );
            }
            self.writer.unindent();
            if !param_decls.is_empty() {
                emit!(self.writer, ")");
            }
            emitln!(self.writer, ");\n");
        }
    }
}

// Expressions
// ===========

impl<'env> SpecTranslator<'env> {
    pub(crate) fn translate(&self, exp: &Exp, type_inst: &[Type]) {
        *self.fresh_var_count.borrow_mut() = 0;
        if type_inst.is_empty() {
            self.translate_exp(exp)
        } else {
            // Use a clone with the given type instantiation.
            let mut trans = self.clone();
            trans.type_inst = type_inst.to_owned();
            trans.translate_exp(exp)
        }
    }

    fn inst(&self, ty: &Type) -> Type {
        ty.instantiate(&self.type_inst)
    }

    fn inst_slice(&self, tys: &[Type]) -> Vec<Type> {
        Type::instantiate_slice(tys, &self.type_inst)
    }

    fn get_node_type(&self, id: NodeId) -> Type {
        self.inst(&self.env.get_node_type(id))
    }

    fn get_node_instantiation(&self, id: NodeId) -> Vec<Type> {
        self.inst_slice(&self.env.get_node_instantiation(id))
    }

    fn translate_exp(&self, exp: &Exp) {
        match exp.as_ref() {
            ExpData::Value(node_id, val) => {
                self.set_writer_location(*node_id);
                self.translate_value(*node_id, val);
            }
            ExpData::LocalVar(node_id, name) => {
                self.set_writer_location(*node_id);
                self.translate_local_var(*node_id, *name);
            }
            ExpData::Temporary(node_id, idx) => {
                self.set_writer_location(*node_id);
                self.translate_temporary(*node_id, *idx);
            }
            ExpData::SpecVar(node_id, module_id, var_id, mem_label) => {
                let inst = &self.get_node_instantiation(*node_id);
                self.set_writer_location(*node_id);
                let module_env = self.env.get_module(*module_id);
                let spec_var = module_env.get_spec_var(*var_id);
                emit!(
                    self.writer,
                    &boogie_spec_var_name(&module_env, spec_var.name, inst, mem_label)
                );
            }
            ExpData::Call(node_id, oper, args) => {
                self.set_writer_location(*node_id);
                self.translate_call(*node_id, oper, args);
            }
            ExpData::Invoke(node_id, ..) => {
                self.error(&self.env.get_node_loc(*node_id), "Invoke not yet supported")
            }
            ExpData::Lambda(node_id, ..) => self.error(
                &self.env.get_node_loc(*node_id),
                "`|x|e` (lambda) currently only supported as argument for `all` or `any`",
            ),
            ExpData::Quant(node_id, kind, ranges, _, _, exp) if kind.is_choice() => {
                // The parser ensures that len(ranges) = 1 and triggers and condition are
                // not present.
                self.set_writer_location(*node_id);
                self.translate_choice(*node_id, *kind, &ranges[0], exp)
            }
            ExpData::Quant(node_id, kind, ranges, triggers, condition, exp) => {
                self.set_writer_location(*node_id);
                self.translate_quant(*node_id, *kind, ranges, triggers, condition, exp)
            }
            ExpData::Block(node_id, vars, scope) => {
                self.set_writer_location(*node_id);
                self.translate_block(*node_id, vars, scope)
            }
            ExpData::IfElse(node_id, cond, on_true, on_false) => {
                self.set_writer_location(*node_id);
                emit!(self.writer, "if (");
                self.translate_exp(cond);
                emit!(self.writer, ") then ");
                self.translate_exp_parenthesised(on_true);
                emit!(self.writer, " else ");
                self.translate_exp_parenthesised(on_false);
            }
            ExpData::Invalid(_) => panic!("unexpected error expression"),
        }
    }

    fn translate_exp_parenthesised(&self, exp: &Exp) {
        emit!(self.writer, "(");
        self.translate_exp(exp);
        emit!(self.writer, ")");
    }

    fn translate_value(&self, _node_id: NodeId, val: &Value) {
        match val {
            Value::Address(addr) => emit!(self.writer, "{}", addr),
            Value::Number(val) => emit!(self.writer, "{}", val),
            Value::Bool(val) => emit!(self.writer, "{}", val),
            Value::ByteArray(val) => emit!(self.writer, &boogie_byte_blob(self.options, val)),
        }
    }

    fn translate_local_var(&self, _node_id: NodeId, name: Symbol) {
        emit!(self.writer, "{}", name.display(self.env.symbol_pool()));
    }

    fn translate_temporary(&self, node_id: NodeId, idx: TempIndex) {
        let ty = self.get_node_type(node_id);
        let mut_ref = ty.is_mutable_reference();
        if mut_ref {
            emit!(self.writer, "$Dereference(");
        }
        emit!(self.writer, "$t{}", idx);
        if mut_ref {
            emit!(self.writer, ")")
        }
    }

    fn translate_block(&self, node_id: NodeId, vars: &[LocalVarDecl], exp: &Exp) {
        if vars.is_empty() {
            return self.translate_exp(exp);
        }
        let loc = self.env.get_node_loc(node_id);
        if let [var] = vars {
            let name_str = self.env.symbol_pool().string(var.name);
            emit!(self.writer, "(var {} := ", name_str);
            self.translate_exp(var.binding.as_ref().expect("binding"));
            emit!(self.writer, "; ");
            self.translate_exp(exp);
            emit!(self.writer, ")");
        } else {
            self.error(&loc, "currently only single variable binding supported");
        }
    }

    fn translate_call(&self, node_id: NodeId, oper: &Operation, args: &[Exp]) {
        let loc = self.env.get_node_loc(node_id);
        match oper {
            // Operators we introduced in the top level public entry `SpecTranslator::translate`,
            // mapping between Boogies single value domain and our typed world.
            Operation::BoxValue | Operation::UnboxValue => panic!("unexpected box/unbox"),

            // Internal operators for event stores.
            Operation::EmptyEventStore => emit!(self.writer, "$EmptyEventStore"),
            Operation::ExtendEventStore => self.translate_extend_event_store(args),
            Operation::EventStoreIncludes => self.translate_event_store_includes(args),
            Operation::EventStoreIncludedIn => self.translate_event_store_included_in(args),

            // Regular expressions
            Operation::Function(module_id, fun_id, memory_labels) => {
                self.translate_spec_fun_call(node_id, *module_id, *fun_id, args, memory_labels)
            }
            Operation::Pack(mid, sid) => self.translate_pack(node_id, *mid, *sid, args),
            Operation::Tuple => self.error(&loc, "Tuple not yet supported"),
            Operation::Select(module_id, struct_id, field_id) => {
                self.translate_select(node_id, *module_id, *struct_id, *field_id, args)
            }
            Operation::UpdateField(module_id, struct_id, field_id) => {
                self.translate_update_field(node_id, *module_id, *struct_id, *field_id, args)
            }
            Operation::Result(pos) => {
                emit!(self.writer, "$ret{}", pos);
            }
            Operation::Index => self.translate_primitive_call("ReadVec", args),
            Operation::Slice => self.translate_primitive_call("$SliceVecByRange", args),
            Operation::Range => self.translate_primitive_call("$Range", args),

            // Binary operators
            Operation::Add => self.translate_arith_op("+", args),
            Operation::Sub => self.translate_arith_op("-", args),
            Operation::Mul => self.translate_arith_op("*", args),
            Operation::Mod => self.translate_arith_op("mod", args),
            Operation::Div => self.translate_arith_op("div", args),
            Operation::BitOr => self.translate_arith_op("|", args),
            Operation::BitAnd => self.translate_arith_op("&", args),
            Operation::Xor => self.translate_arith_op("^", args),
            Operation::Shl => self.translate_primitive_call("$shl", args),
            Operation::Shr => self.translate_primitive_call("$shr", args),
            Operation::Implies => self.translate_logical_op("==>", args),
            Operation::Iff => self.translate_logical_op("<==>", args),
            Operation::And => self.translate_logical_op("&&", args),
            Operation::Or => self.translate_logical_op("||", args),
            Operation::Lt => self.translate_rel_op("<", args),
            Operation::Le => self.translate_rel_op("<=", args),
            Operation::Gt => self.translate_rel_op(">", args),
            Operation::Ge => self.translate_rel_op(">=", args),
            Operation::Identical => self.translate_identical(args),
            Operation::Eq => self.translate_eq_neq("$IsEqual", args),
            Operation::Neq => self.translate_eq_neq("!$IsEqual", args),

            // Unary operators
            Operation::Not => self.translate_logical_unary_op("!", args),

            // Builtin functions
            Operation::Global(memory_label) => {
                self.translate_resource_access(node_id, args, memory_label)
            }
            Operation::Exists(memory_label) => {
                self.translate_resource_exists(node_id, args, memory_label)
            }
            Operation::CanModify => self.translate_can_modify(node_id, args),
            Operation::Len => self.translate_primitive_call("LenVec", args),
            Operation::TypeValue => self.translate_type_value(node_id),
            Operation::TypeDomain | Operation::ResourceDomain => self.error(
                &loc,
                "domain functions can only be used as the range of a quantifier",
            ),
            Operation::UpdateVec => self.translate_primitive_call("UpdateVec", args),
            Operation::ConcatVec => self.translate_primitive_call("ConcatVec", args),
            Operation::EmptyVec => self.translate_primitive_inst_call(node_id, "$EmptyVec", args),
            Operation::SingleVec => self.translate_primitive_call("MakeVec1", args),
            Operation::IndexOfVec => {
                self.translate_primitive_inst_call(node_id, "$IndexOfVec", args)
            }
            Operation::ContainsVec => {
                self.translate_primitive_inst_call(node_id, "$ContainsVec", args)
            }
            Operation::RangeVec => self.translate_primitive_call("$RangeVec", args),
            Operation::InRangeVec => self.translate_primitive_call("InRangeVec", args),
            Operation::InRangeRange => self.translate_primitive_call("$InRange", args),
            Operation::MaxU8 => emit!(self.writer, "$MAX_U8"),
            Operation::MaxU64 => emit!(self.writer, "$MAX_U64"),
            Operation::MaxU128 => emit!(self.writer, "$MAX_U128"),
            Operation::WellFormed => self.translate_well_formed(&args[0]),
            Operation::AbortCode => emit!(self.writer, "$abort_code"),
            Operation::AbortFlag => emit!(self.writer, "$abort_flag"),
            Operation::NoOp => { /* do nothing. */ }
            Operation::Trace => {
                // An unreduced trace means it has been used in a spec fun or let.
                // Create an error about this.
                self.env.error(
                    &loc,
                    "currently `TRACE(..)` cannot be used in spec functions or in lets",
                )
            }
            Operation::Old => panic!("operation unexpected: {:?}", oper),
        }
    }

    fn translate_event_store_includes(&self, args: &[Exp]) {
        emit!(
            self.writer,
            "(var actual := $EventStore__subtract($es, old($es)); "
        );
        emit!(self.writer, "(var expected := ");
        self.translate_exp(&args[0]);
        emit!(self.writer, "; $EventStore__is_subset(expected, actual)))");
    }

    fn translate_event_store_included_in(&self, args: &[Exp]) {
        emit!(
            self.writer,
            "(var actual := $EventStore__subtract($es, old($es)); "
        );
        emit!(self.writer, "(var expected := ");
        self.translate_exp(&args[0]);
        emit!(self.writer, "; $EventStore__is_subset(actual, expected)))");
    }

    fn translate_extend_event_store(&self, args: &[Exp]) {
        let suffix = boogie_type_suffix(self.env, &self.get_node_type(args[1].node_id()));
        let with_cond = args.len() == 4;
        if with_cond {
            emit!(self.writer, "$CondExtendEventStore'{}'(", suffix)
        } else {
            emit!(self.writer, "$ExtendEventStore'{}'(", suffix)
        }
        self.translate_exp(&args[0]); // event store
        emit!(self.writer, ", ");
        // Next expected argument is the handle.
        self.translate_exp(&args[2]);
        emit!(self.writer, ", ");
        // Next comes the event.
        self.translate_exp(&args[1]);
        // Next comes the optional condition
        if with_cond {
            emit!(self.writer, ", ");
            self.translate_exp(&args[3]);
        }
        emit!(self.writer, ")");
    }

    fn translate_pack(&self, node_id: NodeId, mid: ModuleId, sid: StructId, args: &[Exp]) {
        let struct_env = &self.env.get_module(mid).into_struct(sid);
        let inst = &self.get_node_instantiation(node_id);
        emit!(self.writer, "{}(", boogie_struct_name(struct_env, inst));
        let mut sep = "";
        for arg in args {
            emit!(self.writer, sep);
            self.translate_exp(arg);
            sep = ", ";
        }
        emit!(self.writer, ")");
    }

    fn translate_spec_fun_call(
        &self,
        node_id: NodeId,
        module_id: ModuleId,
        fun_id: SpecFunId,
        args: &[Exp],
        memory_labels: &Option<Vec<MemoryLabel>>,
    ) {
        let inst = &self.get_node_instantiation(node_id);
        let module_env = &self.env.get_module(module_id);
        let fun_decl = module_env.get_spec_fun(fun_id);
        let name = boogie_spec_fun_name(&module_env, fun_id, inst);
        emit!(self.writer, "{}(", name);
        let mut first = true;
        let mut maybe_comma = || {
            if first {
                first = false;
            } else {
                emit!(self.writer, ", ");
            }
        };
        let label_at = |i| memory_labels.as_ref().map(|labels| labels[i]);
        let mut i = 0;
        for memory in &fun_decl.used_memory {
            let memory = &memory.to_owned().instantiate(inst);
            maybe_comma();
            let memory = boogie_resource_memory_name(self.env, memory, &label_at(i));
            emit!(self.writer, &memory);
            i = usize::saturating_add(i, 1);
        }
        for spec_var in &fun_decl.used_spec_vars {
            let spec_var = spec_var.to_owned().instantiate(inst);
            maybe_comma();
            let declaring_module = self.env.get_module(spec_var.module_id);
            let var_decl = declaring_module.get_spec_var(spec_var.id);
            emit!(
                self.writer,
                &boogie_spec_var_name(
                    &declaring_module,
                    var_decl.name,
                    &spec_var.inst,
                    &label_at(i)
                )
            );
            i = usize::saturating_add(i, 1);
        }
        for exp in args {
            maybe_comma();
            self.translate_exp(exp);
        }
        emit!(self.writer, ")");
    }

    fn translate_select(
        &self,
        node_id: NodeId,
        module_id: ModuleId,
        struct_id: StructId,
        field_id: FieldId,
        args: &[Exp],
    ) {
        let struct_env = self.env.get_module(module_id).into_struct(struct_id);
        if struct_env.is_native_or_intrinsic() {
            self.env.error(
                &self.env.get_node_loc(node_id),
                "cannot select field of intrinsic struct",
            );
        }
        let struct_type = &self.get_node_type(args[0].node_id());
        let (_, _, inst) = struct_type.skip_reference().require_struct();
        let field_env = struct_env.get_field(field_id);
        emit!(self.writer, "{}(", boogie_field_sel(&field_env, inst));
        self.translate_exp(&args[0]);
        emit!(self.writer, ")");
    }

    fn translate_update_field(
        &self,
        node_id: NodeId,
        module_id: ModuleId,
        struct_id: StructId,
        field_id: FieldId,
        args: &[Exp],
    ) {
        let struct_env = &self.env.get_module(module_id).into_struct(struct_id);
        let field_env = struct_env.get_field(field_id);
        let suffix = boogie_inst_suffix(self.env, &self.get_node_instantiation(node_id));
        emit!(
            self.writer,
            "$Update{}_{}(",
            suffix,
            field_env.get_name().display(self.env.symbol_pool())
        );
        self.translate_exp(&args[0]);
        emit!(self.writer, ", ");
        self.translate_exp(&args[1]);
        emit!(self.writer, ")");
    }

    fn translate_type_value(&self, node_id: NodeId) {
        let loc = &self.env.get_node_loc(node_id);
        self.env
            .error(loc, "type values not supported by this backend");
    }

    fn translate_resource_access(
        &self,
        node_id: NodeId,
        args: &[Exp],
        memory_label: &Option<MemoryLabel>,
    ) {
        let memory = &self.get_memory_inst_from_node(node_id);
        emit!(
            self.writer,
            "$ResourceValue({}, ",
            boogie_resource_memory_name(self.env, memory, memory_label),
        );
        self.translate_exp(&args[0]);
        emit!(self.writer, ")");
    }

    fn get_memory_inst_from_node(&self, node_id: NodeId) -> QualifiedInstId<StructId> {
        let mem_ty = &self.get_node_instantiation(node_id)[0];
        let (mid, sid, inst) = mem_ty.require_struct();
        mid.qualified_inst(sid, inst.to_owned())
    }

    fn translate_resource_exists(
        &self,
        node_id: NodeId,
        args: &[Exp],
        memory_label: &Option<MemoryLabel>,
    ) {
        let memory = &self.get_memory_inst_from_node(node_id);
        emit!(
            self.writer,
            "$ResourceExists({}, ",
            boogie_resource_memory_name(self.env, memory, memory_label),
        );
        self.translate_exp(&args[0]);
        emit!(self.writer, ")");
    }

    fn translate_can_modify(&self, node_id: NodeId, args: &[Exp]) {
        let memory = &self.get_memory_inst_from_node(node_id);
        let resource_name = boogie_modifies_memory_name(self.env, memory);
        emit!(self.writer, "{}[", resource_name);
        self.translate_exp(&args[0]);
        emit!(self.writer, "]");
    }

    fn with_range_selector_assignments<F>(
        &self,
        ranges: &[(LocalVarDecl, Exp)],
        range_tmps: &HashMap<Symbol, String>,
        quant_vars: &HashMap<Symbol, String>,
        resource_vars: &HashMap<Symbol, String>,
        f: F,
    ) where
        F: Fn(),
    {
        // Translate range selectors.
        for (var, range) in ranges {
            let var_name = self.env.symbol_pool().string(var.name);
            let quant_ty = self.get_node_type(range.node_id());
            match quant_ty.skip_reference() {
                Type::Vector(_) => {
                    let range_tmp = range_tmps.get(&var.name).unwrap();
                    let quant_var = quant_vars.get(&var.name).unwrap();
                    emit!(
                        self.writer,
                        "(var {} := ReadVec({}, {});\n",
                        var_name,
                        range_tmp,
                        quant_var,
                    );
                }
                Type::Primitive(PrimitiveType::Range) => {
                    let quant_var = quant_vars.get(&var.name).unwrap();
                    emit!(self.writer, "(var {} := {};\n", var_name, quant_var);
                }
                Type::ResourceDomain(mid, sid, inst_opt) => {
                    let memory =
                        &mid.qualified_inst(*sid, inst_opt.to_owned().unwrap_or_else(Vec::new));
                    let addr_var = resource_vars.get(&var.name).unwrap();
                    let resource_name = boogie_resource_memory_name(self.env, memory, &None);
                    emit!(
                        self.writer,
                        "(var {} := $ResourceValue({}, {});\n",
                        var_name,
                        resource_name,
                        addr_var
                    );
                }
                _ => (),
            }
        }
        f();
        emit!(
            self.writer,
            &std::iter::repeat(")")
                .take(usize::checked_add(range_tmps.len(), resource_vars.len()).unwrap())
                .collect::<String>()
        );
    }

    fn translate_quant(
        &self,
        node_id: NodeId,
        kind: QuantKind,
        ranges: &[(LocalVarDecl, Exp)],
        triggers: &[Vec<Exp>],
        condition: &Option<Exp>,
        body: &Exp,
    ) {
        assert!(!kind.is_choice());
        // Translate range expressions. While doing, check for currently unsupported
        // type quantification
        let mut range_tmps = HashMap::new();
        for (var, range) in ranges {
            match self.get_node_type(range.node_id()).skip_reference() {
                Type::Vector(..) | Type::Primitive(PrimitiveType::Range) => {
                    let range_tmp = self.fresh_var_name("range");
                    emit!(self.writer, "(var {} := ", range_tmp);
                    self.translate_exp(&range);
                    emit!(self.writer, "; ");
                    range_tmps.insert(var.name, range_tmp);
                }
                Type::TypeDomain(bt) => {
                    if matches!(bt.as_ref(), Type::Primitive(PrimitiveType::TypeValue)) {
                        self.env.diag(
                            Severity::Error,
                            &self.env.get_node_loc(node_id),
                            "Type quantification not supported by this backend.",
                        );
                        emitln!(self.writer, "true");
                        return;
                    }
                }
                _ => {}
            }
        }
        // Translate quantified variables.
        emit!(self.writer, "({} ", kind);
        let mut quant_vars = HashMap::new();
        let mut resource_vars = HashMap::new();
        let mut comma = "";
        for (var, range) in ranges {
            let var_name = self.env.symbol_pool().string(var.name);
            let quant_ty = self.get_node_type(range.node_id());
            match quant_ty.skip_reference() {
                Type::TypeDomain(ty) => {
                    let ty = &self.inst(ty);
                    emit!(
                        self.writer,
                        "{}{}: {}",
                        comma,
                        var_name,
                        boogie_type(self.env, ty)
                    );
                }
                Type::ResourceDomain(..) => {
                    let addr_quant_var = self.fresh_var_name("a");
                    emit!(self.writer, "{}{}: int", comma, addr_quant_var);
                    resource_vars.insert(var.name, addr_quant_var);
                }
                _ => {
                    let quant_var = self.fresh_var_name("i");
                    emit!(self.writer, "{}{}: int", comma, quant_var);
                    quant_vars.insert(var.name, quant_var);
                }
            }
            comma = ", ";
        }
        emit!(self.writer, " :: ");
        // Translate triggers.
        if !triggers.is_empty() {
            for trigger in triggers {
                emit!(self.writer, "{");
                let mut comma = "";
                for p in trigger {
                    emit!(self.writer, "{}", comma);
                    self.with_range_selector_assignments(
                        &ranges,
                        &range_tmps,
                        &quant_vars,
                        &resource_vars,
                        || {
                            self.translate_exp(p);
                        },
                    );
                    comma = ",";
                }
                emit!(self.writer, "}");
            }
        } else {
            // Implicit triggers from ResourceDomain range.
            for (var, range) in ranges {
                let quant_ty = self.get_node_type(range.node_id());
                if let Type::ResourceDomain(mid, sid, inst_opt) = quant_ty.skip_reference() {
                    let addr_var = resource_vars.get(&var.name).unwrap();
                    let inst = self.inst_slice(inst_opt.as_ref().map(Vec::as_slice).unwrap_or(&[]));
                    let resource_name = boogie_resource_memory_name(
                        self.env,
                        &mid.qualified_inst(*sid, inst),
                        &None,
                    );
                    let resource_value = format!("$ResourceValue({}, {})", resource_name, addr_var);
                    emit!(self.writer, "{{{}}}", resource_value);
                }
            }
        }
        // Translate range constraints.
        let connective = match kind {
            QuantKind::Forall => " ==> ",
            QuantKind::Exists => " && ",
            _ => unreachable!(),
        };
        let mut separator = "";
        for (var, range) in ranges {
            let var_name = self.env.symbol_pool().string(var.name);
            let quant_ty = self.get_node_type(range.node_id());
            match quant_ty.skip_reference() {
                Type::TypeDomain(domain_ty) => {
                    let mut type_check = boogie_well_formed_expr(self.env, &var_name, &domain_ty);
                    if type_check.is_empty() {
                        type_check = "true".to_string();
                    }
                    emit!(self.writer, "{}{}", separator, type_check);
                }
                Type::ResourceDomain(..) => {
                    // currently does not generate a constraint
                    continue;
                }
                Type::Vector(..) => {
                    let range_tmp = range_tmps.get(&var.name).unwrap();
                    let quant_var = quant_vars.get(&var.name).unwrap();
                    emit!(
                        self.writer,
                        "{}InRangeVec({}, {})",
                        separator,
                        range_tmp,
                        quant_var,
                    );
                }
                Type::Primitive(PrimitiveType::Range) => {
                    let range_tmp = range_tmps.get(&var.name).unwrap();
                    let quant_var = quant_vars.get(&var.name).unwrap();
                    emit!(
                        self.writer,
                        "{}$InRange({}, {})",
                        separator,
                        range_tmp,
                        quant_var,
                    );
                }
                _ => panic!("unexpected type"),
            }
            separator = connective;
        }
        emit!(self.writer, "{}", separator);
        self.with_range_selector_assignments(
            &ranges,
            &range_tmps,
            &quant_vars,
            &resource_vars,
            || {
                // Translate body and "where" condition.
                if let Some(cond) = condition {
                    emit!(self.writer, "(");
                    self.translate_exp(cond);
                    emit!(self.writer, ") {}", connective);
                }
                emit!(self.writer, "(");
                self.translate_exp(body);
                emit!(self.writer, ")");
            },
        );
        emit!(
            self.writer,
            &std::iter::repeat(")")
                .take(range_tmps.len().checked_add(1).unwrap())
                .collect::<String>()
        );
    }

    /// Translate a `some x: T: P[x]` expression. This saves information about the axiomatized
    /// function representing this expression, to be generated later, and replaces the expression by
    /// a call to this function.
    fn translate_choice(
        &self,
        node_id: NodeId,
        kind: QuantKind,
        range: &(LocalVarDecl, Exp),
        body: &Exp,
    ) {
        let mut choice_infos = self.lifted_choice_infos.borrow_mut();
        let choice_count = choice_infos.len();
        let info = choice_infos.entry(node_id).or_insert_with(|| {
            let some_var = range.0.name;
            let free_vars = body
                .free_vars(self.env)
                .into_iter()
                .filter(|(s, _)| *s != some_var)
                .collect_vec();
            let used_temps = body.temporaries(self.env).into_iter().collect_vec();
            let used_memory = body.used_memory(self.env).into_iter().collect_vec();
            LiftedChoiceInfo {
                id: choice_count,
                node_id,
                kind,
                free_vars,
                used_temps,
                used_memory,
                var: some_var,
                range: range.1.clone(),
                condition: body.clone(),
            }
        });
        let fun_name = boogie_choice_fun_name(info.id);
        let args = info
            .free_vars
            .iter()
            .map(|(s, _)| s.display(self.env.symbol_pool()).to_string())
            .chain(info.used_temps.iter().map(|(t, _)| format!("$t{}", t)))
            .chain(
                info.used_memory
                    .iter()
                    .map(|(m, l)| boogie_resource_memory_name(self.env, m, l)),
            )
            .join(", ");
        emit!(self.writer, "{}({})", fun_name, args);
    }

    fn translate_eq_neq(&self, boogie_val_fun: &str, args: &[Exp]) {
        let suffix = boogie_type_suffix(
            self.env,
            &self.get_node_type(args[0].node_id()).skip_reference(),
        );
        emit!(self.writer, "{}'{}'(", boogie_val_fun, suffix);
        self.translate_exp(&args[0]);
        emit!(self.writer, ", ");
        self.translate_exp(&args[1]);
        emit!(self.writer, ")");
    }

    fn translate_identical(&self, args: &[Exp]) {
        use ExpData::*;
        // If both arguments are &mut temporaries, we just directly make them equal. This allows
        // a more efficient representation of equality between $Mutation objects. Otherwise
        // we translate it the default way with automatic reference removal.
        match (&args[0].as_ref(), &args[1].as_ref()) {
            (Temporary(id1, idx1), Temporary(id2, idx2))
                if self.get_node_type(*id1).is_reference()
                    && self.get_node_type(*id2).is_reference() =>
            {
                emit!(self.writer, "$t{} == $t{}", idx1, idx2);
            }
            _ => self.translate_rel_op("==", args),
        }
    }

    fn translate_arith_op(&self, boogie_op: &str, args: &[Exp]) {
        emit!(self.writer, "(");
        self.translate_exp(&args[0]);
        emit!(self.writer, " {} ", boogie_op);
        self.translate_exp(&args[1]);
        emit!(self.writer, ")");
    }

    fn translate_rel_op(&self, boogie_op: &str, args: &[Exp]) {
        emit!(self.writer, "(");
        self.translate_exp(&args[0]);
        emit!(self.writer, " {} ", boogie_op);
        self.translate_exp(&args[1]);
        emit!(self.writer, ")");
    }

    fn translate_logical_op(&self, boogie_op: &str, args: &[Exp]) {
        emit!(self.writer, "(");
        self.translate_exp(&args[0]);
        emit!(self.writer, " {} ", boogie_op);
        self.translate_exp(&args[1]);
        emit!(self.writer, ")");
    }

    fn translate_logical_unary_op(&self, boogie_op: &str, args: &[Exp]) {
        emit!(self.writer, "{}", boogie_op);
        self.translate_exp(&args[0]);
    }

    fn translate_primitive_call(&self, fun: &str, args: &[Exp]) {
        emit!(self.writer, "{}(", fun);
        self.translate_seq(args.iter(), ", ", |e| self.translate_exp(e));
        emit!(self.writer, ")");
    }

    fn translate_primitive_inst_call(&self, node_id: NodeId, fun: &str, args: &[Exp]) {
        let suffix = boogie_inst_suffix(self.env, &self.get_node_instantiation(node_id));
        emit!(self.writer, "{}{}(", fun, suffix);
        self.translate_seq(args.iter(), ", ", |e| self.translate_exp(e));
        emit!(self.writer, ")");
    }

    fn translate_well_formed(&self, exp: &Exp) {
        let ty = self.get_node_type(exp.node_id());
        match exp.as_ref() {
            ExpData::Temporary(_, idx) => {
                // For the special case of a temporary which can represent a
                // &mut, skip the normal translation of `exp` which would do automatic
                // dereferencing. Instead let boogie_well_formed_expr handle the
                // the dereferencing as part of its logic.
                let check = boogie_well_formed_expr(self.env, &format!("$t{}", idx), &ty);
                if !check.is_empty() {
                    emit!(self.writer, &check);
                } else {
                    emit!(self.writer, "true");
                }
            }
            ExpData::LocalVar(_, sym) => {
                // For specification locals (which never can be references) directly emit them.
                let check = boogie_well_formed_expr(
                    self.env,
                    self.env.symbol_pool().string(*sym).as_str(),
                    &ty,
                );
                emit!(self.writer, &check);
            }
            _ => {
                let check = boogie_well_formed_expr(self.env, "$val", ty.skip_reference());
                emit!(self.writer, "(var $val := ");
                self.translate_exp(exp);
                emit!(self.writer, "; {})", check);
            }
        }
    }
}
