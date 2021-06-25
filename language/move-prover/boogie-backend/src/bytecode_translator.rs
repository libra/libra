// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module translates the bytecode of a module to Boogie code.

use std::collections::{BTreeMap, BTreeSet};

use itertools::Itertools;
#[allow(unused_imports)]
use log::{debug, info, log, warn, Level};

use bytecode::{
    function_target::FunctionTarget,
    function_target_pipeline::{FunctionTargetsHolder, VerificationFlavor},
    mono_analysis,
    stackless_bytecode::{BorrowEdge, BorrowNode, Bytecode, Constant, HavocKind, Operation},
};
use move_model::{
    code_writer::CodeWriter,
    emit, emitln,
    model::{GlobalEnv, StructEnv},
    pragmas::{ADDITION_OVERFLOW_UNCHECKED_PRAGMA, SEED_PRAGMA, TIMEOUT_PRAGMA},
    ty::{PrimitiveType, Type},
};

use crate::{
    boogie_helpers::{
        boogie_byte_blob, boogie_debug_track_abort, boogie_debug_track_local,
        boogie_debug_track_return, boogie_equality_for_type, boogie_field_sel, boogie_field_update,
        boogie_function_name, boogie_make_vec_from_strings, boogie_modifies_memory_name,
        boogie_resource_memory_name, boogie_struct_name, boogie_temp, boogie_type,
        boogie_type_param, boogie_type_suffix, boogie_type_suffix_for_struct,
        boogie_well_formed_check, boogie_well_formed_expr,
    },
    options::BoogieOptions,
    spec_translator::SpecTranslator,
};
use bytecode::{
    function_target_pipeline::FunctionVariant,
    stackless_bytecode::{AbortAction, PropKind},
};
use codespan::LineIndex;
use move_model::{
    ast::TempIndex,
    model::{Loc, NodeId},
    ty::BOOL_TYPE,
};

pub struct BoogieTranslator<'env> {
    env: &'env GlobalEnv,
    options: &'env BoogieOptions,
    writer: &'env CodeWriter,
    spec_translator: SpecTranslator<'env>,
    targets: &'env FunctionTargetsHolder,
}

pub struct FunctionTranslator<'env> {
    parent: &'env BoogieTranslator<'env>,
    fun_target: &'env FunctionTarget<'env>,
    type_inst: &'env [Type],
}

pub struct StructTranslator<'env> {
    parent: &'env BoogieTranslator<'env>,
    struct_env: &'env StructEnv<'env>,
    type_inst: &'env [Type],
}

impl<'env> BoogieTranslator<'env> {
    pub fn new(
        env: &'env GlobalEnv,
        options: &'env BoogieOptions,
        targets: &'env FunctionTargetsHolder,
        writer: &'env CodeWriter,
    ) -> Self {
        Self {
            env,
            options,
            targets,
            writer,
            spec_translator: SpecTranslator::new(writer, env, options),
        }
    }

    pub fn translate(&mut self) {
        let writer = self.writer;
        let env = self.env;
        let spec_translator = &self.spec_translator;

        let mono_info = mono_analysis::get_info(self.env);
        let empty = &BTreeSet::new();

        emitln!(
            writer,
            "\n\n//==================================\n// Begin Translation\n"
        );
        // Add given type declarations for type parameters.
        emitln!(writer, "\n\n// Given Types for Type Parameters\n");
        for idx in &mono_info.type_params {
            let param_type = boogie_type_param(env, *idx);
            let suffix = boogie_type_suffix(env, &Type::TypeParameter(*idx));
            emitln!(writer, "type {};", param_type);
            emitln!(
                writer,
                "function {{:inline}} $IsEqual'{}'(x1: {}, x2: {}): bool {{ x1 == x2 }}",
                suffix,
                param_type,
                param_type
            );
            emitln!(
                writer,
                "function {{:inline}} $IsValid'{}'(x: {}): bool {{ true }}",
                suffix,
                param_type,
            );
        }
        emitln!(writer);

        self.spec_translator
            .translate_axioms(env, mono_info.as_ref());

        let mut translated_types = BTreeSet::new();
        let mut translated_funs = BTreeSet::new();
        for module_env in self.env.get_modules() {
            log!(
                if !module_env.is_target() {
                    Level::Debug
                } else {
                    Level::Info
                },
                "translating module {}",
                module_env.get_name().display(module_env.symbol_pool())
            );
            self.writer.set_location(&module_env.env.internal_loc());

            spec_translator.translate_spec_vars(&module_env, mono_info.as_ref());
            spec_translator.translate_spec_funs(&module_env, mono_info.as_ref());

            for ref struct_env in module_env.get_structs() {
                if struct_env.is_native_or_intrinsic() {
                    continue;
                }
                for type_inst in mono_info
                    .structs
                    .get(&struct_env.get_qualified_id())
                    .unwrap_or(empty)
                {
                    let struct_name = boogie_struct_name(struct_env, type_inst);
                    if !translated_types.insert(struct_name) {
                        continue;
                    }
                    StructTranslator {
                        parent: self,
                        struct_env,
                        type_inst: type_inst.as_slice(),
                    }
                    .translate();
                }
            }

            for ref fun_env in module_env.get_functions() {
                if fun_env.is_native_or_intrinsic() {
                    continue;
                }
                for (variant, ref fun_target) in self.targets.get_targets(fun_env) {
                    if variant.is_verified() {
                        // Verified functions are translated with an empty instantiation, as they
                        // are the top-level entry points for a VC.
                        FunctionTranslator {
                            parent: self,
                            fun_target,
                            type_inst: &[],
                        }
                        .translate();
                    } else {
                        // This variant is inlined, so translate for all type instantiations.
                        for type_inst in mono_info
                            .funs
                            .get(&fun_target.func_env.get_qualified_id())
                            .unwrap_or(empty)
                        {
                            let fun_name = boogie_function_name(fun_env, type_inst);
                            if !translated_funs.insert(fun_name) {
                                continue;
                            }
                            FunctionTranslator {
                                parent: self,
                                fun_target,
                                type_inst,
                            }
                            .translate();
                        }
                    }
                }
            }
        }
        // Emit any finalization items required by spec translation.
        self.spec_translator.finalize();
    }
}

// =================================================================================================
// Struct Translation

impl<'env> StructTranslator<'env> {
    fn inst(&self, ty: &Type) -> Type {
        ty.instantiate(self.type_inst)
    }

    /// Translates the given struct.
    fn translate(&self) {
        let writer = self.parent.writer;
        let struct_env = self.struct_env;
        let env = struct_env.module_env.env;

        let qid = struct_env
            .get_qualified_id()
            .instantiate(self.type_inst.to_owned());
        emitln!(
            writer,
            "// struct {} {}",
            env.display(&qid),
            struct_env.get_loc().display(env)
        );

        // Set the location to internal as default.
        writer.set_location(&env.internal_loc());

        // Emit data type
        let struct_name = boogie_struct_name(struct_env, self.type_inst);
        emitln!(writer, "type {{:datatype}} {};", struct_name);

        // Emit constructor
        let fields = struct_env
            .get_fields()
            .map(|field| {
                format!(
                    "${}: {}",
                    field.get_name().display(env.symbol_pool()),
                    boogie_type(env, &self.inst(&field.get_type()))
                )
            })
            .join(", ");
        emitln!(
            writer,
            "function {{:constructor}} {}({}): {};",
            struct_name,
            fields,
            struct_name
        );

        let suffix = boogie_type_suffix_for_struct(struct_env, self.type_inst);

        // Emit $UpdateField functions.
        let fields = struct_env.get_fields().collect_vec();
        for (pos, field_env) in fields.iter().enumerate() {
            let field_name = field_env.get_name().display(env.symbol_pool()).to_string();
            self.emit_function(
                &format!(
                    "$Update'{}'_{}(s: {}, x: {}): {}",
                    suffix,
                    field_name,
                    struct_name,
                    boogie_type(env, &self.inst(&field_env.get_type())),
                    struct_name
                ),
                || {
                    let args = fields
                        .iter()
                        .enumerate()
                        .map(|(p, f)| {
                            if p == pos {
                                "x".to_string()
                            } else {
                                format!("{}(s)", boogie_field_sel(f, self.type_inst))
                            }
                        })
                        .join(", ");
                    emitln!(writer, "{}({})", struct_name, args);
                },
            );
        }

        // Emit $IsValid function.
        self.emit_function_with_attr(
            "", // not inlined!
            &format!("$IsValid'{}'(s: {}): bool", suffix, struct_name),
            || {
                if struct_env.is_native_or_intrinsic() {
                    emitln!(writer, "true")
                } else {
                    let mut sep = "";
                    for field in struct_env.get_fields() {
                        let sel = format!("{}({})", boogie_field_sel(&field, self.type_inst), "s");
                        let ty = &field.get_type().instantiate(self.type_inst);
                        emitln!(writer, "{}{}", sep, boogie_well_formed_expr(env, &sel, ty));
                        sep = "  && ";
                    }
                }
            },
        );

        // Emit equality
        self.emit_function(
            &format!(
                "$IsEqual'{}'(s1: {}, s2: {}): bool",
                suffix, struct_name, struct_name
            ),
            || {
                if struct_has_native_equality(struct_env, self.type_inst, self.parent.options) {
                    emitln!(writer, "s1 == s2")
                } else {
                    let mut sep = "";
                    for field in &fields {
                        let sel_fun = boogie_field_sel(field, self.type_inst);
                        let field_suffix = boogie_type_suffix(env, &self.inst(&field.get_type()));
                        emit!(
                            writer,
                            "{}$IsEqual'{}'({}(s1), {}(s2))",
                            sep,
                            field_suffix,
                            sel_fun,
                            sel_fun,
                        );
                        sep = "\n&& ";
                    }
                }
            },
        );

        if struct_env.has_memory() {
            // Emit memory variable.
            let memory_name = boogie_resource_memory_name(
                env,
                &struct_env
                    .get_qualified_id()
                    .instantiate(self.type_inst.to_owned()),
                &None,
            );
            emitln!(writer, "var {}: $Memory {};", memory_name, struct_name);
        }

        emitln!(writer);
    }

    fn emit_function(&self, signature: &str, body_fn: impl Fn()) {
        self.emit_function_with_attr("{:inline} ", signature, body_fn)
    }

    fn emit_function_with_attr(&self, attr: &str, signature: &str, body_fn: impl Fn()) {
        let writer = self.parent.writer;
        emitln!(writer, "function {}{} {{", attr, signature);
        writer.indent();
        body_fn();
        writer.unindent();
        emitln!(writer, "}");
    }
}

// =================================================================================================
// Function Translation

impl<'env> FunctionTranslator<'env> {
    fn inst(&self, ty: &Type) -> Type {
        ty.instantiate(self.type_inst)
    }

    fn inst_slice(&self, tys: &[Type]) -> Vec<Type> {
        tys.iter().map(|ty| self.inst(ty)).collect()
    }

    fn get_local_type(&self, idx: TempIndex) -> Type {
        self.fun_target
            .get_local_type(idx)
            .instantiate(self.type_inst)
    }

    /// Translates the given function.
    fn translate(self) {
        let writer = self.parent.writer;
        let fun_target = self.fun_target;
        let env = fun_target.global_env();
        let qid = fun_target
            .func_env
            .get_qualified_id()
            .instantiate(self.type_inst.to_owned());
        emitln!(
            writer,
            "// fun {} [{}] {}",
            env.display(&qid),
            fun_target.data.variant,
            fun_target.get_loc().display(env)
        );
        self.generate_function_sig();
        self.generate_function_body();
        emitln!(self.parent.writer);
    }

    /// Return a string for a boogie procedure header. Use inline attribute and name
    /// suffix as indicated by `entry_point`.
    fn generate_function_sig(&self) {
        let writer = self.parent.writer;
        let options = self.parent.options;
        let fun_target = self.fun_target;
        let (args, rets) = self.generate_function_args_and_returns();

        let (suffix, attribs) = match &fun_target.data.variant {
            FunctionVariant::Baseline => ("".to_string(), "{:inline 1} ".to_string()),
            FunctionVariant::Verification(flavor) => {
                assert!(
                    self.type_inst.is_empty(),
                    "verification variant cannot have an instantiation"
                );
                let timeout = fun_target
                    .func_env
                    .get_num_pragma(TIMEOUT_PRAGMA, || options.vc_timeout);

                let mut attribs = vec![format!("{{:timeLimit {}}} ", timeout)];

                if fun_target.func_env.is_num_pragma_set(SEED_PRAGMA) {
                    let seed = fun_target
                        .func_env
                        .get_num_pragma(SEED_PRAGMA, || options.random_seed);
                    attribs.push(format!("{{:random_seed {}}} ", seed));
                };

                let suffix = match flavor {
                    VerificationFlavor::Regular => "$verify".to_string(),
                    VerificationFlavor::Inconsistency => {
                        attribs.push(format!(
                            "{{:msg_if_verifies \"inconsistency_detected{}\"}} ",
                            self.loc_str(&fun_target.get_loc())
                        ));
                        format!("$verify_{}", flavor)
                    }
                };
                (suffix, attribs.join(""))
            }
        };
        writer.set_location(&fun_target.get_loc());
        emitln!(
            writer,
            "procedure {}{}{}({}) returns ({})",
            attribs,
            boogie_function_name(fun_target.func_env, self.type_inst),
            suffix,
            args,
            rets,
        )
    }

    /// Generate boogie representation of function args and return args.
    fn generate_function_args_and_returns(&self) -> (String, String) {
        let fun_target = self.fun_target;
        let env = fun_target.global_env();
        let args = (0..fun_target.get_parameter_count())
            .map(|i| {
                let ty = self.get_local_type(i);
                // Boogie does not allow to assign to parameters, so we need to proxy them.
                let prefix = if self.parameter_needs_to_be_mutable(fun_target, i) {
                    "_$"
                } else {
                    "$"
                };
                format!("{}t{}: {}", prefix, i, boogie_type(env, &ty))
            })
            .join(", ");
        let mut_ref_inputs = (0..fun_target.get_parameter_count())
            .filter_map(|idx| {
                let ty = self.get_local_type(idx);
                if ty.is_mutable_reference() {
                    Some(ty)
                } else {
                    None
                }
            })
            .collect_vec();
        let rets = fun_target
            .get_return_types()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let s = self.inst(s);
                format!("$ret{}: {}", i, boogie_type(env, &s))
            })
            // Add implicit return parameters for &mut
            .chain(mut_ref_inputs.into_iter().enumerate().map(|(i, ty)| {
                format!(
                    "$ret{}: {}",
                    usize::saturating_add(fun_target.get_return_count(), i),
                    boogie_type(env, &ty)
                )
            }))
            .join(", ");
        (args, rets)
    }

    /// Generates boogie implementation body.
    fn generate_function_body(&self) {
        let writer = self.parent.writer;
        let fun_target = self.fun_target;
        let variant = &fun_target.data.variant;
        let env = fun_target.global_env();

        // Be sure to set back location to the whole function definition as a default.
        writer.set_location(&fun_target.get_loc().at_start());

        emitln!(writer, "{");
        writer.indent();

        // Generate local variable declarations. They need to appear first in boogie.
        emitln!(writer, "// declare local variables");
        let num_args = fun_target.get_parameter_count();
        for i in num_args..fun_target.get_local_count() {
            let local_type = &self.get_local_type(i);
            emitln!(writer, "var $t{}: {};", i, boogie_type(env, local_type));
        }
        // Generate declarations for renamed parameters.
        let proxied_parameters = self.get_mutable_parameters();
        for (idx, ty) in &proxied_parameters {
            emitln!(
                writer,
                "var $t{}: {};",
                idx,
                boogie_type(env, &ty.instantiate(self.type_inst))
            );
        }
        // Generate declarations for modifies condition.
        for qid in fun_target.get_modify_ids() {
            emitln!(
                writer,
                "var {}: {}",
                boogie_modifies_memory_name(
                    fun_target.global_env(),
                    &qid.instantiate(self.type_inst)
                ),
                "[int]bool;"
            );
        }

        // Declare temporaries for debug tracing and other purposes.
        for (_, (ref ty, cnt)) in self.compute_needed_temps() {
            for i in 0..cnt {
                emitln!(
                    writer,
                    "var {}: {};",
                    boogie_temp(env, ty, i),
                    boogie_type(env, ty)
                );
            }
        }

        // Generate memory snapshot variable declarations.
        let code = fun_target.get_bytecode();
        let labels = code
            .iter()
            .filter_map(|bc| {
                use Bytecode::*;
                match bc {
                    SaveMem(_, lab, mem) => Some((lab, mem)),
                    SaveSpecVar(..) => panic!("spec var memory snapshots NYI"),
                    _ => None,
                }
            })
            .collect::<BTreeSet<_>>();
        for (lab, mem) in labels {
            let mem = &mem.to_owned().instantiate(self.type_inst);
            let name = boogie_resource_memory_name(env, mem, &Some(*lab));
            emitln!(
                writer,
                "var {}: $Memory {};",
                name,
                boogie_struct_name(&env.get_struct_qid(mem.to_qualified_id()), &mem.inst)
            );
        }

        // Initialize renamed parameters.
        for (idx, _) in proxied_parameters {
            emitln!(writer, "$t{} := _$t{};", idx, idx);
        }

        // Initialize mutations to have empty paths so $IsParentMutation works correctly.
        for i in num_args..fun_target.get_local_count() {
            if self.get_local_type(i).is_mutable_reference() {
                emitln!(writer, "assume IsEmptyVec(p#$Mutation($t{}));", i);
            }
        }

        // Initial assumptions
        if variant.is_verified() {
            self.translate_verify_entry_assumptions(fun_target);
        }

        // Generate bytecode
        emitln!(writer, "\n// bytecode translation starts here");
        let mut last_tracked_loc = None;
        for bytecode in code.iter() {
            self.translate_bytecode(&mut last_tracked_loc, bytecode);
        }

        writer.unindent();
        emitln!(writer, "}");
    }

    fn get_mutable_parameters(&self) -> Vec<(TempIndex, Type)> {
        let fun_target = self.fun_target;
        (0..fun_target.get_parameter_count())
            .filter_map(|i| {
                if self.parameter_needs_to_be_mutable(fun_target, i) {
                    Some((i, fun_target.get_local_type(i).clone()))
                } else {
                    None
                }
            })
            .collect_vec()
    }

    /// Determines whether the parameter of a function needs to be mutable.
    /// Boogie does not allow to assign to procedure parameters. In some cases
    /// (e.g. for memory instrumentation, but also as a result of copy propagation),
    /// we may need to assign to parameters.
    fn parameter_needs_to_be_mutable(
        &self,
        _fun_target: &FunctionTarget<'_>,
        _idx: TempIndex,
    ) -> bool {
        // For now, we just always say true. This could be optimized because the actual (known
        // so far) sources for mutability are parameters which are used in WriteBack(LocalRoot(p))
        // position.
        true
    }

    fn translate_verify_entry_assumptions(&self, fun_target: &FunctionTarget<'_>) {
        let writer = self.parent.writer;
        emitln!(writer, "\n// verification entrypoint assumptions");

        // Prelude initialization
        emitln!(writer, "call $InitVerification();");

        // Assume reference parameters to be based on the Param(i) Location, ensuring
        // they are disjoint from all other references. This prevents aliasing and is justified as
        // follows:
        // - for mutual references, by their exclusive access in Move.
        // - for immutable references because we have eliminated them
        for i in 0..fun_target.get_parameter_count() {
            let ty = fun_target.get_local_type(i);
            if ty.is_reference() {
                emitln!(writer, "assume l#$Mutation($t{}) == $Param({});", i, i);
            }
        }
    }
}

// =================================================================================================
// Bytecode Translation

impl<'env> FunctionTranslator<'env> {
    /// Translates one bytecode instruction.
    fn translate_bytecode(
        &self,
        last_tracked_loc: &mut Option<(Loc, LineIndex)>,
        bytecode: &Bytecode,
    ) {
        use Bytecode::*;

        let writer = self.parent.writer;
        let spec_translator = &self.parent.spec_translator;
        let options = self.parent.options;
        let fun_target = self.fun_target;
        let env = fun_target.global_env();

        // Set location of this code in the CodeWriter.
        let attr_id = bytecode.get_attr_id();
        let loc = fun_target.get_bytecode_loc(attr_id);
        writer.set_location(&loc);

        // Print location.
        emitln!(
            writer,
            "// {} {}",
            bytecode.display(fun_target, &BTreeMap::default()),
            loc.display(env)
        );

        // Print debug comments.
        if let Some(comment) = fun_target.get_debug_comment(attr_id) {
            emitln!(writer, "// {}", comment);
        }

        // Track location for execution traces.
        if matches!(bytecode, Call(_, _, Operation::TraceAbort, ..)) {
            // Ensure that aborts always has the precise location instead of the
            // line-approximated one
            *last_tracked_loc = None;
        }
        self.track_loc(last_tracked_loc, &loc);

        // Helper function to get a a string for a local
        let str_local = |idx: usize| format!("$t{}", idx);

        // Translate the bytecode instruction.
        match bytecode {
            SaveMem(_, label, mem) => {
                let snapshot = boogie_resource_memory_name(env, mem, &Some(*label));
                let current = boogie_resource_memory_name(env, mem, &None);
                emitln!(writer, "{} := {};", snapshot, current);
            }
            SaveSpecVar(_, _label, _var) => {
                panic!("spec var snapshot NYI")
            }
            Prop(id, kind, exp) => match kind {
                PropKind::Assert => {
                    emit!(writer, "assert ");
                    let info = fun_target
                        .get_vc_info(*id)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown assertion failed");
                    emit!(
                        writer,
                        "{{:msg \"assert_failed{}: {}\"}}\n  ",
                        self.loc_str(&loc),
                        info
                    );
                    spec_translator.translate(exp, self.type_inst);
                    emitln!(writer, ";");
                }
                PropKind::Assume => {
                    emit!(writer, "assume ");
                    spec_translator.translate(exp, self.type_inst);
                    emitln!(writer, ";");
                }
                PropKind::Modifies => {
                    let ty = &self.inst(&env.get_node_type(exp.node_id()));
                    let (mid, sid, inst) = ty.require_struct();
                    let memory = boogie_resource_memory_name(
                        env,
                        &mid.qualified_inst(sid, inst.to_owned()),
                        &None,
                    );
                    let exists_str = boogie_temp(env, &BOOL_TYPE, 0);
                    emitln!(writer, "havoc {};", exists_str);
                    emitln!(writer, "if ({}) {{", exists_str);
                    writer.with_indent(|| {
                        let val_str = boogie_temp(env, ty, 0);
                        emitln!(writer, "havoc {};", val_str);
                        emit!(writer, "{} := $ResourceUpdate({}, ", memory, memory);
                        spec_translator.translate(&exp.call_args()[0], self.type_inst);
                        emitln!(writer, ", {});", val_str);
                    });
                    emitln!(writer, "} else {");
                    writer.with_indent(|| {
                        emit!(writer, "{} := $ResourceRemove({}, ", memory, memory);
                        spec_translator.translate(&exp.call_args()[0], self.type_inst);
                        emitln!(writer, ");");
                    });
                    emitln!(writer, "}");
                }
            },
            Label(_, label) => {
                writer.unindent();
                emitln!(writer, "L{}:", label.as_usize());
                writer.indent();
            }
            Jump(_, target) => emitln!(writer, "goto L{};", target.as_usize()),
            Branch(_, then_target, else_target, idx) => emitln!(
                writer,
                "if ({}) {{ goto L{}; }} else {{ goto L{}; }}",
                str_local(*idx),
                then_target.as_usize(),
                else_target.as_usize(),
            ),
            Assign(_, dest, src, _) => {
                emitln!(writer, "{} := {};", str_local(*dest), str_local(*src));
            }
            Ret(_, rets) => {
                for (i, r) in rets.iter().enumerate() {
                    emitln!(writer, "$ret{} := {};", i, str_local(*r));
                }
                // Also assign input to output $mut parameters
                let mut ret_idx = rets.len();
                for i in 0..fun_target.get_parameter_count() {
                    if self.get_local_type(i).is_mutable_reference() {
                        emitln!(writer, "$ret{} := {};", ret_idx, str_local(i));
                        ret_idx = usize::saturating_add(ret_idx, 1);
                    }
                }
                emitln!(writer, "return;");
            }
            Load(_, dest, c) => {
                let value = match c {
                    Constant::Bool(true) => "true".to_string(),
                    Constant::Bool(false) => "false".to_string(),
                    Constant::U8(num) => num.to_string(),
                    Constant::U64(num) => num.to_string(),
                    Constant::U128(num) => num.to_string(),
                    Constant::Address(val) => val.to_string(),
                    Constant::ByteArray(val) => boogie_byte_blob(options, val),
                };
                let dest_str = str_local(*dest);
                emitln!(writer, "{} := {};", dest_str, value);
                // Insert a WellFormed assumption so the new value gets tagged as u8, ...
                let ty = &self.get_local_type(*dest);
                let check = boogie_well_formed_check(env, &dest_str, ty);
                if !check.is_empty() {
                    emitln!(writer, &check);
                }
            }
            Call(_, dests, oper, srcs, aa) => {
                use Operation::*;
                match oper {
                    FreezeRef => unreachable!(),
                    UnpackRef | UnpackRefDeep | PackRef | PackRefDeep => {
                        // No effect
                    }
                    OpaqueCallBegin(_, _, _) | OpaqueCallEnd(_, _, _) => {
                        // These are just markers.  There is no generated code.
                    }
                    WriteBack(node, edge) => {
                        self.translate_write_back(node, edge, srcs[0]);
                    }
                    IsParent(node, edge) => {
                        if let BorrowNode::Reference(parent) = node {
                            let src_str = str_local(srcs[0]);
                            let edge_pattern = edge
                                .flatten()
                                .into_iter()
                                .filter_map(|e| match e {
                                    BorrowEdge::Field(_, offset) => Some(format!("{}", offset)),
                                    BorrowEdge::Index => Some("-1".to_owned()),
                                    BorrowEdge::Direct => None,
                                    _ => unreachable!(),
                                })
                                .collect_vec();
                            if edge_pattern.len() == 1 {
                                emitln!(
                                    writer,
                                    "{} := $IsParentMutation({}, {}, {});",
                                    str_local(dests[0]),
                                    str_local(*parent),
                                    edge_pattern[0],
                                    src_str
                                );
                            } else {
                                emitln!(
                                    writer,
                                    "{} := $IsParentMutationHyper({}, {}, {});",
                                    str_local(dests[0]),
                                    str_local(*parent),
                                    boogie_make_vec_from_strings(&edge_pattern),
                                    src_str
                                );
                            }
                        } else {
                            panic!("inconsistent IsParent instruction: expected a reference node")
                        }
                    }
                    BorrowLoc => {
                        let src = srcs[0];
                        let dest = dests[0];
                        emitln!(
                            writer,
                            "{} := $Mutation($Local({}), EmptyVec(), {});",
                            str_local(dest),
                            src,
                            str_local(src)
                        );
                    }
                    ReadRef => {
                        let src = srcs[0];
                        let dest = dests[0];
                        emitln!(
                            writer,
                            "{} := $Dereference({});",
                            str_local(dest),
                            str_local(src)
                        );
                    }
                    WriteRef => {
                        let reference = srcs[0];
                        let value = srcs[1];
                        emitln!(
                            writer,
                            "{} := $UpdateMutation({}, {});",
                            str_local(reference),
                            str_local(reference),
                            str_local(value),
                        );
                    }
                    Function(mid, fid, inst) => {
                        let inst = &self.inst_slice(inst);
                        let callee_env = env.get_module(*mid).into_function(*fid);

                        let args_str = srcs.iter().cloned().map(str_local).join(", ");
                        let dest_str = dests
                            .iter()
                            .cloned()
                            .map(str_local)
                            // Add implict dest returns for &mut srcs:
                            //  f(x) --> x := f(x)  if type(x) = &mut_
                            .chain(
                                srcs.iter()
                                    .filter(|idx| self.get_local_type(**idx).is_mutable_reference())
                                    .cloned()
                                    .map(str_local),
                            )
                            .join(",");

                        if dest_str.is_empty() {
                            emitln!(
                                writer,
                                "call {}({});",
                                boogie_function_name(&callee_env, inst),
                                args_str
                            );
                        } else {
                            emitln!(
                                writer,
                                "call {} := {}({});",
                                dest_str,
                                boogie_function_name(&callee_env, inst),
                                args_str
                            );
                        }
                        // Clear the last track location after function call, as the call inserted
                        // location tracks before it returns.
                        *last_tracked_loc = None;
                    }
                    Pack(mid, sid, inst) => {
                        let inst = &self.inst_slice(inst);
                        let struct_env = env.get_module(*mid).into_struct(*sid);
                        let args = srcs.iter().cloned().map(str_local).join(", ");
                        let dest_str = str_local(dests[0]);
                        emitln!(
                            writer,
                            "{} := {}({});",
                            dest_str,
                            boogie_struct_name(&struct_env, inst),
                            args
                        );
                    }
                    Unpack(mid, sid, inst) => {
                        let inst = &self.inst_slice(inst);
                        let struct_env = env.get_module(*mid).into_struct(*sid);
                        for (i, ref field_env) in struct_env.get_fields().enumerate() {
                            let field_sel = format!(
                                "{}({})",
                                boogie_field_sel(field_env, inst),
                                str_local(srcs[0])
                            );
                            emitln!(writer, "{} := {};", str_local(dests[i]), field_sel);
                        }
                    }
                    BorrowField(mid, sid, inst, field_offset) => {
                        let inst = &self.inst_slice(inst);
                        let src_str = str_local(srcs[0]);
                        let dest_str = str_local(dests[0]);
                        let struct_env = env.get_module(*mid).into_struct(*sid);
                        let field_env = &struct_env.get_field_by_offset(*field_offset);
                        let sel_fun = boogie_field_sel(field_env, inst);
                        emitln!(
                            writer,
                            "{} := $ChildMutation({}, {}, {}($Dereference({})));",
                            dest_str,
                            src_str,
                            field_offset,
                            sel_fun,
                            src_str
                        );
                    }
                    GetField(mid, sid, inst, field_offset) => {
                        let inst = &self.inst_slice(inst);
                        let src = srcs[0];
                        let mut src_str = str_local(src);
                        let dest_str = str_local(dests[0]);
                        let struct_env = env.get_module(*mid).into_struct(*sid);
                        let field_env = &struct_env.get_field_by_offset(*field_offset);
                        let sel_fun = boogie_field_sel(field_env, inst);
                        if self.get_local_type(src).is_reference() {
                            src_str = format!("$Dereference({})", src_str);
                        };
                        emitln!(writer, "{} := {}({});", dest_str, sel_fun, src_str);
                    }
                    Exists(mid, sid, inst) => {
                        let inst = self.inst_slice(inst);
                        let addr_str = str_local(srcs[0]);
                        let dest_str = str_local(dests[0]);
                        let memory = boogie_resource_memory_name(
                            env,
                            &mid.qualified_inst(*sid, inst),
                            &None,
                        );
                        emitln!(
                            writer,
                            "{} := $ResourceExists({}, {});",
                            dest_str,
                            memory,
                            addr_str
                        );
                    }
                    BorrowGlobal(mid, sid, inst) => {
                        let inst = self.inst_slice(inst);
                        let addr_str = str_local(srcs[0]);
                        let dest_str = str_local(dests[0]);
                        let memory = boogie_resource_memory_name(
                            env,
                            &mid.qualified_inst(*sid, inst),
                            &None,
                        );
                        emitln!(writer, "if (!$ResourceExists({}, {})) {{", memory, addr_str);
                        writer.with_indent(|| emitln!(writer, "call $ExecFailureAbort();"));
                        emitln!(writer, "} else {");
                        writer.with_indent(|| {
                            emitln!(
                                writer,
                                "{} := $Mutation($Global({}), EmptyVec(), $ResourceValue({}, {}));",
                                dest_str,
                                addr_str,
                                memory,
                                addr_str
                            );
                        });
                        emitln!(writer, "}");
                    }
                    GetGlobal(mid, sid, inst) => {
                        let inst = self.inst_slice(inst);
                        let memory = boogie_resource_memory_name(
                            env,
                            &mid.qualified_inst(*sid, inst),
                            &None,
                        );
                        let addr_str = str_local(srcs[0]);
                        let dest_str = str_local(dests[0]);
                        emitln!(writer, "if (!$ResourceExists({}, {})) {{", memory, addr_str);
                        writer.with_indent(|| emitln!(writer, "call $ExecFailureAbort();"));
                        emitln!(writer, "} else {");
                        writer.with_indent(|| {
                            emitln!(
                                writer,
                                "{} := $ResourceValue({}, {});",
                                dest_str,
                                memory,
                                addr_str
                            );
                        });
                        emitln!(writer, "}");
                    }
                    MoveTo(mid, sid, inst) => {
                        let inst = self.inst_slice(inst);
                        let memory = boogie_resource_memory_name(
                            env,
                            &mid.qualified_inst(*sid, inst),
                            &None,
                        );
                        let value_str = str_local(srcs[0]);
                        let signer_str = str_local(srcs[1]);
                        emitln!(
                            writer,
                            "if ($ResourceExists({}, {})) {{",
                            memory,
                            signer_str
                        );
                        writer.with_indent(|| emitln!(writer, "call $ExecFailureAbort();"));
                        emitln!(writer, "} else {");
                        writer.with_indent(|| {
                            emitln!(
                                writer,
                                "{} := $ResourceUpdate({}, {}, {});",
                                memory,
                                memory,
                                signer_str,
                                value_str
                            );
                        });
                        emitln!(writer, "}");
                    }
                    MoveFrom(mid, sid, inst) => {
                        let inst = &self.inst_slice(inst);
                        let memory = boogie_resource_memory_name(
                            env,
                            &mid.qualified_inst(*sid, inst.to_owned()),
                            &None,
                        );
                        let addr_str = str_local(srcs[0]);
                        let dest_str = str_local(dests[0]);
                        emitln!(writer, "if (!$ResourceExists({}, {})) {{", memory, addr_str);
                        writer.with_indent(|| emitln!(writer, "call $ExecFailureAbort();"));
                        emitln!(writer, "} else {");
                        writer.with_indent(|| {
                            emitln!(
                                writer,
                                "{} := $ResourceValue({}, {});",
                                dest_str,
                                memory,
                                addr_str
                            );
                            emitln!(
                                writer,
                                "{} := $ResourceRemove({}, {});",
                                memory,
                                memory,
                                addr_str
                            );
                        });
                        emitln!(writer, "}");
                    }
                    Havoc(HavocKind::Value) | Havoc(HavocKind::MutationAll) => {
                        let src_str = str_local(srcs[0]);
                        emitln!(writer, "havoc {};", src_str);
                        // Insert a WellFormed check
                        let ty = &self.get_local_type(srcs[0]);
                        let check = boogie_well_formed_check(env, &src_str, ty);
                        if !check.is_empty() {
                            emitln!(writer, &check);
                        }
                    }
                    Havoc(HavocKind::MutationValue) => {
                        let ty = &self.get_local_type(srcs[0]);
                        let src_str = str_local(srcs[0]);
                        let temp_str = boogie_temp(env, ty.skip_reference(), 0);
                        emitln!(writer, "havoc {};", temp_str);
                        emitln!(
                            writer,
                            "{} := $UpdateMutation({}, {});",
                            src_str,
                            src_str,
                            temp_str
                        );
                        // Insert a WellFormed check
                        let check = boogie_well_formed_check(env, &src_str, ty);
                        if !check.is_empty() {
                            emitln!(writer, &check);
                        }
                    }
                    Stop => {
                        // the two statements combined terminate any execution trace that reaches it
                        emitln!(writer, "assume false;");
                        emitln!(writer, "return;");
                    }
                    CastU8 => {
                        let src = srcs[0];
                        let dest = dests[0];
                        emitln!(
                            writer,
                            "call {} := $CastU8({});",
                            str_local(dest),
                            str_local(src)
                        );
                    }
                    CastU64 => {
                        let src = srcs[0];
                        let dest = dests[0];
                        emitln!(
                            writer,
                            "call {} := $CastU64({});",
                            str_local(dest),
                            str_local(src)
                        );
                    }
                    CastU128 => {
                        let src = srcs[0];
                        let dest = dests[0];
                        emitln!(
                            writer,
                            "call {} := $CastU128({});",
                            str_local(dest),
                            str_local(src)
                        );
                    }
                    Not => {
                        let src = srcs[0];
                        let dest = dests[0];
                        emitln!(
                            writer,
                            "call {} := $Not({});",
                            str_local(dest),
                            str_local(src)
                        );
                    }
                    Add => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        let unchecked = if fun_target
                            .is_pragma_true(ADDITION_OVERFLOW_UNCHECKED_PRAGMA, || false)
                        {
                            "_unchecked"
                        } else {
                            ""
                        };
                        let add_type = match &self.get_local_type(dest) {
                            Type::Primitive(PrimitiveType::U8) => "U8".to_string(),
                            Type::Primitive(PrimitiveType::U64) => format!("U64{}", unchecked),
                            Type::Primitive(PrimitiveType::U128) => format!("U128{}", unchecked),
                            _ => unreachable!(),
                        };
                        emitln!(
                            writer,
                            "call {} := $Add{}({}, {});",
                            str_local(dest),
                            add_type,
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Sub => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Sub({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Mul => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        let mul_type = match &self.get_local_type(dest) {
                            Type::Primitive(PrimitiveType::U8) => "U8",
                            Type::Primitive(PrimitiveType::U64) => "U64",
                            Type::Primitive(PrimitiveType::U128) => "U128",
                            _ => unreachable!(),
                        };
                        emitln!(
                            writer,
                            "call {} := $Mul{}({}, {});",
                            str_local(dest),
                            mul_type,
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Div => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Div({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Mod => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Mod({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Shl => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Shl({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Shr => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Shr({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Lt => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Lt({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Gt => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Gt({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Le => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Le({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Ge => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Ge({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Or => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $Or({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    And => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        emitln!(
                            writer,
                            "call {} := $And({}, {});",
                            str_local(dest),
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    Eq | Neq => {
                        let dest = dests[0];
                        let op1 = srcs[0];
                        let op2 = srcs[1];
                        let oper =
                            boogie_equality_for_type(env, oper == &Eq, &self.get_local_type(op1));
                        emitln!(
                            writer,
                            "{} := {}({}, {});",
                            str_local(dest),
                            oper,
                            str_local(op1),
                            str_local(op2)
                        );
                    }
                    BitOr | BitAnd | Xor => {
                        emitln!(
                            writer,
                            "// bit operation not supported: {:?}\nassert false;",
                            bytecode
                        );
                    }
                    Destroy => {}
                    TraceLocal(idx) => {
                        self.track_local(*idx, srcs[0]);
                    }
                    TraceReturn(i) => {
                        self.track_return(*i, srcs[0]);
                    }
                    TraceAbort => self.track_abort(&str_local(srcs[0])),
                    TraceExp(node_id) => self.track_exp(*node_id, srcs[0]),
                    EmitEvent => {
                        let msg = srcs[0];
                        let handle = srcs[1];
                        let translate_local = |idx: usize| {
                            let ty = &self.get_local_type(idx);
                            if ty.is_mutable_reference() {
                                format!("$Dereference({})", str_local(idx))
                            } else {
                                str_local(idx)
                            }
                        };
                        let suffix = boogie_type_suffix(env, &self.get_local_type(msg));
                        emit!(
                            writer,
                            "$es := ${}ExtendEventStore'{}'($es, ",
                            if srcs.len() > 2 { "Cond" } else { "" },
                            suffix
                        );
                        emit!(writer, "{}, {}", translate_local(handle), str_local(msg));
                        if srcs.len() > 2 {
                            emit!(writer, ", {}", str_local(srcs[2]));
                        }
                        emitln!(writer, ");");
                    }
                    EventStoreDiverge => {
                        emitln!(writer, "call $es := $EventStore__diverge($es);");
                    }
                }
                if let Some(AbortAction(target, code)) = aa {
                    emitln!(writer, "if ($abort_flag) {");
                    writer.indent();
                    *last_tracked_loc = None;
                    self.track_loc(last_tracked_loc, &loc);
                    let code_str = str_local(*code);
                    emitln!(writer, "{} := $abort_code;", code_str);
                    self.track_abort(&code_str);
                    emitln!(writer, "goto L{};", target.as_usize());
                    writer.unindent();
                    emitln!(writer, "}");
                }
            }
            Abort(_, src) => {
                emitln!(writer, "$abort_code := {};", str_local(*src));
                emitln!(writer, "$abort_flag := true;");
                emitln!(writer, "return;")
            }
            Nop(..) => {}
        }
        emitln!(writer);
    }

    fn translate_write_back(&self, dest: &BorrowNode, edge: &BorrowEdge, src: TempIndex) {
        use BorrowNode::*;
        let writer = self.parent.writer;
        let env = self.parent.env;
        let src_str = format!("$t{}", src);
        match dest {
            ReturnPlaceholder(_) => {
                unreachable!("unexpected transient borrow node")
            }
            GlobalRoot(memory) => {
                assert!(matches!(edge, BorrowEdge::Direct));
                let memory = &memory.to_owned().instantiate(self.type_inst);
                let memory_name = boogie_resource_memory_name(env, memory, &None);
                emitln!(
                    writer,
                    "{} := $ResourceUpdate({}, $GlobalLocationAddress({}),\n    \
                                     $Dereference({}));",
                    memory_name,
                    memory_name,
                    src_str,
                    src_str
                );
            }
            LocalRoot(idx) => {
                assert!(matches!(edge, BorrowEdge::Direct));
                emitln!(writer, "$t{} := $Dereference({});", idx, src_str);
            }
            Reference(idx) => {
                let dst_value = format!("$Dereference($t{})", idx);
                let src_value = format!("$Dereference({})", src_str);
                let get_path_index = |offset: usize| {
                    if offset == 0 {
                        format!(
                            "ReadVec(p#$Mutation({}), LenVec(p#$Mutation($t{})))",
                            src_str, idx
                        )
                    } else {
                        format!(
                            "ReadVec(p#$Mutation({}), LenVec(p#$Mutation($t{})) + {})",
                            src_str, idx, offset
                        )
                    }
                };
                let update = if let BorrowEdge::Hyper(edges) = edge {
                    self.translate_write_back_update(
                        &mut || dst_value.clone(),
                        &get_path_index,
                        src_value,
                        edges,
                        0,
                    )
                } else {
                    self.translate_write_back_update(
                        &mut || dst_value.clone(),
                        &get_path_index,
                        src_value,
                        &[edge.to_owned()],
                        0,
                    )
                };
                emitln!(
                    writer,
                    "$t{} := $UpdateMutation($t{}, {});",
                    idx,
                    idx,
                    update
                );
            }
        }
    }

    fn translate_write_back_update(
        &self,
        mk_dest: &mut dyn FnMut() -> String,
        get_path_index: &dyn Fn(usize) -> String,
        src: String,
        edges: &[BorrowEdge],
        at: usize,
    ) -> String {
        if at >= edges.len() {
            src
        } else {
            match &edges[at] {
                BorrowEdge::Direct => {
                    self.translate_write_back_update(mk_dest, get_path_index, src, edges, at + 1)
                }
                BorrowEdge::Field(memory, offset) => {
                    let memory = memory.to_owned().instantiate(self.type_inst);
                    let struct_env = &self.parent.env.get_struct_qid(memory.to_qualified_id());
                    let field_env = &struct_env.get_field_by_offset(*offset);
                    let sel_fun = boogie_field_sel(field_env, &memory.inst);
                    let new_dest = format!("{}({})", sel_fun, (*mk_dest)());
                    let mut new_dest_needed = false;
                    let new_src = self.translate_write_back_update(
                        &mut || {
                            new_dest_needed = true;
                            format!("$$sel{}", at)
                        },
                        get_path_index,
                        src,
                        edges,
                        at + 1,
                    );
                    let update_fun = boogie_field_update(field_env, &memory.inst);
                    if new_dest_needed {
                        format!(
                            "(var $$sel{} := {}; {}({}, {}))",
                            at,
                            new_dest,
                            update_fun,
                            (*mk_dest)(),
                            new_src
                        )
                    } else {
                        format!("{}({}, {})", update_fun, (*mk_dest)(), new_src)
                    }
                }
                BorrowEdge::Index => {
                    // Compute the offset into the path where to retrieve the index.
                    let offset = edges[0..at]
                        .iter()
                        .filter(|e| !matches!(e, BorrowEdge::Direct))
                        .count();
                    let index = (*get_path_index)(offset);
                    let new_dest = format!("ReadVec({}, {})", (*mk_dest)(), index);
                    let mut new_dest_needed = false;
                    let new_src = self.translate_write_back_update(
                        &mut || {
                            new_dest_needed = true;
                            format!("$$sel{}", at)
                        },
                        get_path_index,
                        src,
                        edges,
                        at + 1,
                    );
                    if new_dest_needed {
                        format!(
                            "(var $$sel{} := {}; UpdateVec({}, {}, {}))",
                            at,
                            new_dest,
                            (*mk_dest)(),
                            index,
                            new_src
                        )
                    } else {
                        format!("UpdateVec({}, {}, {})", (*mk_dest)(), index, new_src)
                    }
                }
                BorrowEdge::Hyper(_) => unreachable!("unexpected borrow edge"),
            }
        }
    }

    /// Track location for execution trace, avoiding to track the same line multiple times.
    fn track_loc(&self, last_tracked_loc: &mut Option<(Loc, LineIndex)>, loc: &Loc) {
        let env = self.fun_target.global_env();
        if let Some(l) = env.get_location(loc) {
            if let Some((last_loc, last_line)) = last_tracked_loc {
                if *last_line == l.line {
                    // This line already tracked.
                    return;
                }
                *last_loc = loc.clone();
                *last_line = l.line;
            } else {
                *last_tracked_loc = Some((loc.clone(), l.line));
            }
            emitln!(
                self.parent.writer,
                "assume {{:print \"$at{}\"}} true;",
                self.loc_str(&loc)
            );
        }
    }

    fn track_abort(&self, code_var: &str) {
        emitln!(
            self.parent.writer,
            &boogie_debug_track_abort(self.fun_target, code_var)
        );
    }

    /// Generates an update of the debug information about temporary.
    fn track_local(&self, origin_idx: TempIndex, idx: TempIndex) {
        emitln!(
            self.parent.writer,
            &boogie_debug_track_local(self.fun_target, origin_idx, idx, &self.get_local_type(idx))
        );
    }

    /// Generates an update of the debug information about the return value at given location.
    fn track_return(&self, return_idx: usize, idx: TempIndex) {
        emitln!(
            self.parent.writer,
            &boogie_debug_track_return(self.fun_target, return_idx, idx, &self.get_local_type(idx))
        );
    }

    fn track_exp(&self, node_id: NodeId, temp: TempIndex) {
        let env = self.parent.env;
        let writer = self.parent.writer;
        let ty = self.get_local_type(temp);
        let temp_str = if ty.is_reference() {
            let new_temp = boogie_temp(env, ty.skip_reference(), 0);
            emitln!(writer, "{} := $Dereference($t{});", new_temp, temp);
            new_temp
        } else {
            format!("$t{}", temp)
        };
        emitln!(
            self.parent.writer,
            "assume {{:print \"$track_exp({}):\", {}}} true;",
            node_id.as_usize(),
            temp_str,
        );
    }

    fn loc_str(&self, loc: &Loc) -> String {
        let file_idx = self.fun_target.global_env().file_id_to_idx(loc.file_id());
        format!("({},{},{})", file_idx, loc.span().start(), loc.span().end())
    }

    /// Compute temporaries needed for the compilation of given function. Because boogie does
    /// not allow to declare locals in arbitrary blocks, we need to compute them upfront.
    fn compute_needed_temps(&self) -> BTreeMap<String, (Type, usize)> {
        use Bytecode::*;
        use Operation::*;

        let fun_target = self.fun_target;
        let env = fun_target.global_env();

        let mut res: BTreeMap<String, (Type, usize)> = BTreeMap::new();
        let mut need = |ty: &Type, n: usize| {
            // Index by type suffix, which is more coarse grained then type.
            let ty = ty.skip_reference();
            let suffix = boogie_type_suffix(env, ty);
            let cnt = res.entry(suffix).or_insert_with(|| (ty.to_owned(), 0));
            (*cnt).1 = (*cnt).1.max(n);
        };
        for bc in &fun_target.data.code {
            match bc {
                Call(_, _, oper, srcs, ..) => match oper {
                    TraceExp(id) => need(&self.inst(&env.get_node_type(*id)), 1),
                    TraceReturn(idx) => need(&self.inst(fun_target.get_return_type(*idx)), 1),
                    TraceLocal(_) => need(&self.get_local_type(srcs[0]), 1),
                    Havoc(HavocKind::MutationValue) => need(&self.get_local_type(srcs[0]), 1),
                    _ => {}
                },
                Prop(_, PropKind::Modifies, exp) => {
                    need(&BOOL_TYPE, 1);
                    need(&self.inst(&env.get_node_type(exp.node_id())), 1)
                }
                _ => {}
            }
        }
        res
    }
}

fn struct_has_native_equality(
    struct_env: &StructEnv<'_>,
    inst: &[Type],
    options: &BoogieOptions,
) -> bool {
    if options.native_equality {
        // Everything has native equality
        return true;
    }
    for field in struct_env.get_fields() {
        if !has_native_equality(
            struct_env.module_env.env,
            options,
            &field.get_type().instantiate(inst),
        ) {
            return false;
        }
    }
    true
}

pub fn has_native_equality(env: &GlobalEnv, options: &BoogieOptions, ty: &Type) -> bool {
    if options.native_equality {
        // Everything has native equality
        return true;
    }
    match ty {
        Type::Vector(..) => false,
        Type::Struct(mid, sid, sinst) => {
            struct_has_native_equality(&env.get_struct_qid(mid.qualified(*sid)), sinst, options)
        }
        _ => true,
    }
}
