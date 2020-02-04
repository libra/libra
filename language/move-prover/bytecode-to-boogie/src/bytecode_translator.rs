// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module translates the bytecode of a module to Boogie code.

use std::collections::BTreeSet;

use itertools::Itertools;
use log::info;

use ir_to_bytecode_syntax::ast::Loc;
use libra_types::account_address::AccountAddress;
use libra_types::language_storage::ModuleId;
use stackless_bytecode_generator::{
    stackless_bytecode::StacklessBytecode::{self, *},
    stackless_bytecode_generator::{StacklessFunction, StacklessModuleGenerator},
};

use crate::boogie_helpers::{
    boogie_field_name, boogie_function_name, boogie_local_type, boogie_struct_name,
    boogie_struct_type_value, boogie_type_check, boogie_type_value, boogie_type_values,
};
use crate::code_writer::CodeWriter;
use crate::driver::PSEUDO_PRELUDE_MODULE;
use crate::env::{
    FunctionEnv, GlobalEnv, GlobalType, ModuleEnv, Parameter, StructEnv, TypeParameter,
};
use crate::spec_translator::SpecTranslator;
use codespan::{ByteIndex, ByteOffset};

pub struct BoogieTranslator<'env> {
    env: &'env GlobalEnv,
    writer: &'env CodeWriter,
}

pub struct ModuleTranslator<'env> {
    writer: &'env CodeWriter,
    module_env: ModuleEnv<'env>,
    stackless_bytecode: Vec<StacklessFunction>,
}

/// Returns true if for the module no code should be produced because its already defined
/// in the prelude.
pub fn is_module_provided_by_prelude(id: &ModuleId) -> bool {
    id.name().as_str() == "Vector"
        && *id.address() == AccountAddress::from_hex_literal("0x0").unwrap()
}

impl<'env> BoogieTranslator<'env> {
    pub fn new(env: &'env GlobalEnv, writer: &'env CodeWriter) -> Self {
        Self { env, writer }
    }

    pub fn translate(&mut self) {
        // generate definitions for all modules.
        for module_env in self.env.get_modules() {
            ModuleTranslator::new(self, module_env).translate();
        }
    }
}

impl<'env> ModuleTranslator<'env> {
    /// Creates a new module translator. Calls the stackless bytecode generator and wraps
    /// result into the translator.
    fn new(parent: &'env BoogieTranslator, module: ModuleEnv<'env>) -> Self {
        let stackless_bytecode =
            StacklessModuleGenerator::new(module.get_verified_module().as_inner())
                .generate_module();
        Self {
            writer: parent.writer,
            module_env: module,
            stackless_bytecode,
        }
    }

    /// Translates this module.
    fn translate(&mut self) {
        if !is_module_provided_by_prelude(self.module_env.get_id()) {
            info!("translating module {}", self.module_env.get_id().name());
            self.writer
                .set_location(self.module_env.get_module_idx(), Loc::default());
            self.translate_structs();
            self.translate_functions();
        }
    }

    /// Translates all structs in the module.
    fn translate_structs(&self) {
        emitln!(
            self.writer,
            "\n\n// ** structs of module {}\n",
            self.module_env.get_id().name()
        );
        for struct_env in self.module_env.get_structs() {
            self.writer
                .set_location(self.module_env.get_module_idx(), struct_env.get_loc());
            self.translate_struct_type(&struct_env);
            if !struct_env.is_native() {
                self.translate_struct_accessors(&struct_env);
            }
        }
    }

    /// Translates the given struct.
    fn translate_struct_type(&self, struct_env: &StructEnv<'_>) {
        // Emit TypeName
        let struct_name = boogie_struct_name(&struct_env);
        emitln!(self.writer, "const unique {}: TypeName;", struct_name);

        // Emit FieldNames
        for (i, field_env) in struct_env.get_fields().enumerate() {
            let field_name = boogie_field_name(&field_env);
            emitln!(
                self.writer,
                "const {}: FieldName;\naxiom {} == {};",
                field_name,
                field_name,
                i
            );
        }

        // Emit TypeValue constructor function.
        let type_args = struct_env
            .get_type_parameters()
            .iter()
            .enumerate()
            .map(|(i, _)| format!("tv{}: TypeValue", i))
            .join(", ");
        let mut field_types = String::from("EmptyTypeValueArray");
        for field_env in struct_env.get_fields() {
            field_types = format!(
                "ExtendTypeValueArray({}, {})",
                field_types,
                boogie_type_value(self.module_env.env, &field_env.get_type())
            );
        }
        let type_value = format!("StructType({}, {})", struct_name, field_types);
        if struct_name == "LibraAccount_T" {
            // Special treatment of well-known resource LibraAccount_T. The type_value
            // function is forward-declared in the prelude, here we only add an axiom for
            // it.
            emitln!(
                self.writer,
                "axiom {}_type_value() == {};",
                struct_name,
                type_value
            );
        } else {
            emitln!(
                self.writer,
                "function {}_type_value({}): TypeValue {{\n    {}\n}}",
                struct_name,
                type_args,
                type_value
            );
        }
    }

    /// Translates struct accessors (pack/unpack).
    fn translate_struct_accessors(&self, struct_env: &StructEnv<'_>) {
        // Pack function
        let type_args_str = struct_env
            .get_type_parameters()
            .iter()
            .map(|TypeParameter(ref i, _)| format!("{}: TypeValue", i))
            .join(", ");
        let args_str = struct_env
            .get_fields()
            .map(|field_env| format!("{}: Value", field_env.get_name()))
            .join(", ");
        emitln!(
            self.writer,
            "procedure {{:inline 1}} Pack_{}({}) returns (_struct: Value)\n{{",
            boogie_struct_name(struct_env),
            if !args_str.is_empty() && !type_args_str.is_empty() {
                format!("{}, {}", type_args_str, args_str)
            } else if args_str.is_empty() {
                type_args_str
            } else {
                args_str.clone()
            }
        );
        self.writer.indent();
        let mut fields_str = String::from("EmptyValueArray");
        for field_env in struct_env.get_fields() {
            let type_check = boogie_type_check(
                self.module_env.env,
                field_env.get_name().as_str(),
                &field_env.get_type(),
            );
            emit!(self.writer, &type_check);
            fields_str = format!("ExtendValueArray({}, {})", fields_str, field_env.get_name());
        }
        emitln!(self.writer, "_struct := Vector({});", fields_str);
        self.writer.unindent();
        emitln!(self.writer, "}\n");

        // Unpack function
        emitln!(
            self.writer,
            "procedure {{:inline 1}} Unpack_{}(_struct: Value) returns ({})\n{{",
            boogie_struct_name(struct_env),
            args_str
        );
        self.writer.indent();
        emitln!(self.writer, "assume is#Vector(_struct);");
        for field_env in struct_env.get_fields() {
            emitln!(
                self.writer,
                "{} := SelectField(_struct, {});",
                field_env.get_name(),
                boogie_field_name(&field_env)
            );
            let type_check = boogie_type_check(
                self.module_env.env,
                field_env.get_name().as_str(),
                &field_env.get_type(),
            );
            emit!(self.writer, &type_check);
        }
        self.writer.unindent();
        emitln!(self.writer, "}\n");
    }

    /// Translates all functions in the module.
    fn translate_functions(&self) {
        emitln!(
            self.writer,
            "\n\n// ** functions of module {}\n",
            self.module_env.get_id().name()
        );
        let mut num_fun_specified = 0;
        let mut num_fun = 0;
        for func_env in self.module_env.get_functions() {
            if !func_env.is_native() {
                num_fun += 1;
            }
            if !func_env.get_specification().is_empty() && !func_env.is_native() {
                num_fun_specified += 1;
            }
            self.writer
                .set_location(self.module_env.get_module_idx(), func_env.get_loc());
            self.translate_function(&func_env);
        }
        if num_fun > 0 {
            info!(
                "{} out of {} functions are specified in module {}",
                num_fun_specified,
                num_fun,
                self.module_env.get_id().name()
            );
        }
    }

    /// Translates the given function.
    fn translate_function(&self, func_env: &FunctionEnv<'_>) {
        if func_env.is_native() {
            if self.module_env.env.options.native_stubs {
                self.generate_function_sig(func_env, true);
                emit!(self.writer, ";");
                self.generate_function_spec(func_env);
                emitln!(self.writer);
            }
            return;
        }

        // generate inline function with function body
        self.generate_function_sig(func_env, true); // inlined version of function
        self.generate_function_spec(func_env);
        self.generate_inline_function_body(func_env);
        emitln!(self.writer);

        // generate the _verify version of the function which calls inline version for standalone
        // verification.
        self.generate_function_sig(func_env, false); // no inline
        self.generate_verify_function_body(func_env); // function body just calls inlined version
    }

    /// Translates one bytecode instruction.
    fn translate_bytecode(
        &self,
        func_env: &FunctionEnv<'_>,
        debug_vars: &BTreeSet<(ByteIndex, usize)>,
        offset: u16,
        bytecode: &StacklessBytecode,
        mutual_local_borrows: &BTreeSet<usize>,
    ) {
        // Set location of this code in the CodeWriter.
        let loc = func_env.get_bytecode_loc(offset);
        self.writer
            .set_location(self.module_env.get_module_idx(), loc);
        // emitln!(self.writer, "// {}", loc); // DEBUG

        // Helper functions to update a local including debug information.
        let update_local =
            |idx: usize, value: &str| self.update_local(func_env, debug_vars, loc, idx, value);
        let update_debug_var = |idx: usize, value: &str| {
            self.generate_model_debug_update(func_env, debug_vars, loc, idx, value)
        };

        // Helper function to update debug info for mutual borrows.
        let update_mutual_refs = || {
            for idx in mutual_local_borrows {
                let update = self.generate_model_debug_update(
                    func_env,
                    debug_vars,
                    loc,
                    *idx,
                    &format!("GetLocal(__m, __frame + {})", idx),
                );
                if !update.is_empty() {
                    emitln!(self.writer, &update)
                }
            }
        };

        let propagate_abort = "if (__abort_flag) { goto Label_Abort; }";
        match bytecode {
            Branch(target) => emitln!(self.writer, "goto Label_{};", target),
            BrTrue(target, idx) => emitln!(
                self.writer,
                "__tmp := GetLocal(__m, __frame + {});\nif (b#Boolean(__tmp)) {{ goto Label_{}; }}",
                idx,
                target,
            ),
            BrFalse(target, idx) => emitln!(
                self.writer,
                "__tmp := GetLocal(__m, __frame + {});\nif (!b#Boolean(__tmp)) {{ goto Label_{}; }}",
                idx,
                target,
            ),
            MoveLoc(dest, src) => {
                if self.get_local_type(func_env, *dest).is_reference() {
                    emitln!(
                        self.writer,
                        "call __t{} := CopyOrMoveRef({});",
                        dest,
                        func_env.get_local_name(*src as usize)
                    )
                } else {
                    emitln!(
                        self.writer,
                        "call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + {}));",
                        src
                    );
                    emitln!(self.writer, &update_local(*dest, "__tmp"));
                }
            }
            CopyLoc(dest, src) => {
                if self.get_local_type(func_env, *dest).is_reference() {
                    emitln!(
                        self.writer,
                        "call __t{} := CopyOrMoveRef({});",
                        dest,
                        func_env.get_local_name(*src as usize)
                    )
                } else {
                    emitln!(
                        self.writer,
                        "call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + {}));",
                        src
                    );
                    emitln!(self.writer, &update_local(*dest, "__tmp"));
                }
            }
            StLoc(dest, src) => {
                if self.get_local_type(func_env, *dest as usize).is_reference() {
                    emitln!(
                        self.writer,
                        "call {} := CopyOrMoveRef(__t{});",
                        func_env.get_local_name(*dest as usize),
                        src
                    )
                } else {
                    emitln!(
                        self.writer,
                        "call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + {}));",
                        src
                    );
                    emitln!(self.writer, &update_local(*dest as usize, "__tmp"));
                }
            }
            BorrowLoc(dest, src) => {
                emitln!(
                    self.writer,
                    "call __t{} := BorrowLoc(__frame + {});",
                    dest,
                    src
                );
            }
            ReadRef(dest, src) => {
                emitln!(self.writer, "call __tmp := ReadRef(__t{});", src);
                emit!(
                    self.writer,
                    &boogie_type_check(
                        self.module_env.env,
                        "__tmp",
                        &self.get_local_type(func_env, *dest)
                    )
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            WriteRef(dest, src) => {
                emitln!(
                    self.writer,
                    "call WriteRef(__t{}, GetLocal(__m, __frame + {}));",
                    dest,
                    src
                );
                update_mutual_refs();
            }
            FreezeRef(dest, src) => emitln!(self.writer, "call __t{} := FreezeRef(__t{});", dest, src),
            Call(dests, callee_index, type_actuals, args) => {
                let (callee_module_env, callee_def_idx) =
                    self.module_env.get_callee_info(callee_index);
                let callee_env = callee_module_env.get_function(&callee_def_idx);
                let mut dest_str = String::new();
                let mut args_str = String::new();
                let mut dest_type_assumptions = vec![];
                let mut tmp_assignments = vec![];

                args_str.push_str(&boogie_type_values(
                    func_env.module_env.env,
                    &func_env.module_env.get_type_actuals(*type_actuals),
                ));
                if !args_str.is_empty() && !args.is_empty() {
                    args_str.push_str(", ");
                }
                args_str.push_str(
                    &args
                        .iter()
                        .map(|arg_idx| {
                            if self.get_local_type(func_env, *arg_idx).is_reference() {
                                format!("__t{}", arg_idx)
                            } else {
                                format!("GetLocal(__m, __frame + {})", arg_idx)
                            }
                        })
                        .join(", "),
                );
                dest_str.push_str(
                    &dests
                        .iter()
                        .map(|dest_idx| {
                            let dest = format!("__t{}", dest_idx);
                            let dest_type = &self.get_local_type(func_env, *dest_idx);
                            dest_type_assumptions.push(boogie_type_check(
                                self.module_env.env,
                                &dest,
                                dest_type,
                            ));
                            if !dest_type.is_reference() {
                                tmp_assignments.push(
                                    update_local(*dest_idx, &dest));
                            } else {
                                tmp_assignments.push(update_debug_var(*dest_idx, &dest));
                            }
                            dest
                        })
                        .join(", "),
                );
                if dest_str == "" {
                    emitln!(
                        self.writer,
                        "call {}({});",
                        boogie_function_name(&callee_env),
                        args_str
                    );
                } else {
                    emitln!(
                        self.writer,
                        "call {} := {}({});",
                        dest_str,
                        boogie_function_name(&callee_env),
                        args_str
                    );
                }
                emitln!(self.writer, propagate_abort);
                for s in &dest_type_assumptions {
                    emitln!(self.writer, s);
                }
                for s in &tmp_assignments {
                    emitln!(self.writer, s);
                }
                if callee_env.is_mutating() {
                    update_mutual_refs();
                }
            }
            Pack(dest, struct_def_index, type_actuals, fields) => {
                let struct_env = func_env.module_env.get_struct(struct_def_index);
                let args_str = func_env
                    .module_env
                    .get_type_actuals(*type_actuals)
                    .iter()
                    .map(|s| boogie_type_value(self.module_env.env, s))
                    .chain(
                        fields
                            .iter()
                            .map(|i| format!("GetLocal(__m, __frame + {})", i)),
                    )
                    .join(", ");
                emitln!(
                    self.writer,
                    "call __tmp := Pack_{}({});",
                    boogie_struct_name(&struct_env),
                    args_str
                );

                emitln!(
                    self.writer,
                    &update_local(*dest, "__tmp")
                );
            }
            Unpack(dests, struct_def_index, _, src) => {
                let struct_env = &func_env.module_env.get_struct(struct_def_index);
                let mut dests_str = String::new();
                let mut tmp_assignments = vec![];
                for dest in dests.iter() {
                    if !dests_str.is_empty() {
                        dests_str.push_str(", ");
                    }
                    let dest_str = &format!("__t{}", dest);
                    let dest_type = &self.get_local_type(func_env, *dest);
                    dests_str.push_str(dest_str);
                    if !dest_type.is_reference() {
                        tmp_assignments.push(update_local(*dest, &dest_str));
                    } else {
                        tmp_assignments.push(update_debug_var(*dest, &dest_str));
                    }
                }
                emitln!(
                    self.writer,
                    "call {} := Unpack_{}(GetLocal(__m, __frame + {}));",
                    dests_str,
                    boogie_struct_name(struct_env),
                    src
                );
                for s in &tmp_assignments {
                    emitln!(self.writer, s);
                }
            }
            BorrowField(dest, src, field_def_index) => {
                let struct_env = self.module_env.get_struct_of_field(field_def_index);
                let field_env = &struct_env.get_field(field_def_index);
                emitln!(
                    self.writer,
                    "call __t{} := BorrowField(__t{}, {});",
                    dest,
                    src,
                    boogie_field_name(field_env)
                );
            }
            Exists(dest, addr, struct_def_index, type_actuals) => {
                let resource_type = boogie_struct_type_value(
                    self.module_env.env,
                    self.module_env.get_module_idx(),
                    struct_def_index,
                    &self.module_env.get_type_actuals(*type_actuals),
                );
                emitln!(
                    self.writer,
                    "call __tmp := Exists(GetLocal(__m, __frame + {}), {});",
                    addr,
                    resource_type
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            BorrowGlobal(dest, addr, struct_def_index, type_actuals) => {
                let resource_type = boogie_struct_type_value(
                    self.module_env.env,
                    self.module_env.get_module_idx(),
                    struct_def_index,
                    &self.module_env.get_type_actuals(*type_actuals),
                );
                emitln!(
                    self.writer,
                    "call __t{} := BorrowGlobal(GetLocal(__m, __frame + {}), {});",
                    dest,
                    addr,
                    resource_type,
                );
                emitln!(self.writer, propagate_abort);
            }
            MoveToSender(src, struct_def_index, type_actuals) => {
                let resource_type = boogie_struct_type_value(
                    self.module_env.env,
                    self.module_env.get_module_idx(),
                    struct_def_index,
                    &self.module_env.get_type_actuals(*type_actuals),
                );
                emitln!(
                    self.writer,
                    "call MoveToSender({}, GetLocal(__m, __frame + {}));",
                    resource_type,
                    src,
                );
                emitln!(self.writer, propagate_abort);
            }
            MoveFrom(dest, src, struct_def_index, type_actuals) => {
                let resource_type = boogie_struct_type_value(
                    self.module_env.env,
                    self.module_env.get_module_idx(),
                    struct_def_index,
                    &self.module_env.get_type_actuals(*type_actuals),
                );
                emitln!(
                    self.writer,
                    "call __tmp := MoveFrom(GetLocal(__m, __frame + {}), {});",
                    src,
                    resource_type,
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
                emit!(
                    self.writer,
                    &boogie_type_check(
                        self.module_env.env,
                        &format!("__t{}", dest),
                        &self.get_local_type(func_env, *dest)
                    )
                );
                emitln!(self.writer, propagate_abort);
            }
            Ret(rets) => {
                for (i, r) in rets.iter().enumerate() {
                    if self.get_local_type(func_env, *r).is_reference() {
                        emitln!(self.writer, "__ret{} := __t{};", i, r);
                    } else {
                        emitln!(self.writer, "__ret{} := GetLocal(__m, __frame + {});", i, r);
                    }
                    emitln!(self.writer, &update_debug_var(func_env.get_local_count() + i, &format!("__ret{}", i)));
                }
                emitln!(self.writer, "return;");
            }
            LdTrue(idx) => {
                emitln!(self.writer, "call __tmp := LdTrue();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            LdFalse(idx) => {
                emitln!(self.writer, "call __tmp := LdFalse();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            LdU8(idx, num) => {
                emitln!(self.writer, "call __tmp := LdConst({});", num);
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            LdU64(idx, num) => {
                emitln!(self.writer, "call __tmp := LdConst({});", num);
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            LdU128(idx, num) => {
                emitln!(self.writer, "call __tmp := LdConst({});", num);
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            CastU8(dest, src) => {
                emitln!(
                    self.writer,
                    "call __tmp := CastU8(GetLocal(__m, __frame + {}));",
                    src
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            CastU64(dest, src) => {
                emitln!(
                    self.writer,
                    "call __tmp := CastU64(GetLocal(__m, __frame + {}));",
                    src
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            CastU128(dest, src) => {
                emitln!(
                    self.writer,
                    "call __tmp := CastU128(GetLocal(__m, __frame + {}));",
                    src
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            LdAddr(idx, addr_idx) => {
                let addr_int = self.module_env.get_address(addr_idx);
                emitln!(self.writer, "call __tmp := LdAddr({});", addr_int);
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            Not(dest, operand) => {
                emitln!(
                    self.writer,
                    "call __tmp := Not(GetLocal(__m, __frame + {}));",
                    operand
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Add(dest, op1, op2) => {
                let add_type = match self.get_local_type(func_env, *dest) {
                    GlobalType::U8 => "U8",
                    GlobalType::U64 => "U64",
                    GlobalType::U128 => "U128",
                    _ => unreachable!(),
                };
                emitln!(
                    self.writer,
                    "call __tmp := Add{}(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    add_type,
                    op1,
                    op2
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Sub(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Sub(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Mul(dest, op1, op2) => {
                let mul_type = match self.get_local_type(func_env, *dest) {
                    GlobalType::U8 => "U8",
                    GlobalType::U64 => "U64",
                    GlobalType::U128 => "U128",
                    _ => unreachable!(),
                };
                emitln!(
                    self.writer,
                    "call __tmp := Mul{}(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    mul_type,
                    op1,
                    op2
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Div(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Div(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Mod(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Mod(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, propagate_abort);
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Lt(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Lt(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Gt(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Gt(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Le(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Le(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Ge(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Ge(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Or(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := Or(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            And(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "call __tmp := And(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {}));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Eq(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "__tmp := Boolean(IsEqual(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {})));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            Neq(dest, op1, op2) => {
                emitln!(
                    self.writer,
                    "__tmp := Boolean(!IsEqual(GetLocal(__m, __frame + {}), GetLocal(__m, __frame + {})));",
                    op1,
                    op2
                );
                emitln!(self.writer, &update_local(*dest, "__tmp"));
            }
            BitOr(_, _, _) | BitAnd(_, _, _) | Xor(_, _, _) => {
                emitln!(
                    self.writer,
                    "// bit operation not supported: {:?}",
                    bytecode
                );
            }
            Abort(_) => emitln!(self.writer, "goto Label_Abort;"),
            GetGasRemaining(idx) => {
                emitln!(self.writer, "call __tmp := GetGasRemaining();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            GetTxnSequenceNumber(idx) => {
                emitln!(self.writer, "call __tmp := GetTxnSequenceNumber();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            GetTxnPublicKey(idx) => {
                emitln!(self.writer, "call __tmp := GetTxnPublicKey();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            GetTxnSenderAddress(idx) => {
                emitln!(self.writer, "call __tmp := GetTxnSenderAddress();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            GetTxnMaxGasUnits(idx) => {
                emitln!(self.writer, "call __tmp := GetTxnMaxGasUnits();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            GetTxnGasUnitPrice(idx) => {
                emitln!(self.writer, "call __tmp := GetTxnGasUnitPrice();");
                emitln!(self.writer, &update_local(*idx, "__tmp"));
            }
            _ => emitln!(self.writer, "// unimplemented instruction: {:?}", bytecode),
        }
        emitln!(self.writer);
    }

    /// Return a string for a boogie procedure header.
    /// if inline = true, add the inline attribute and use the plain function name
    /// for the procedure name. Also inject pre/post conditions if defined.
    /// Else, generate the function signature without the ":inline" attribute, and
    /// append _verify to the function name.
    fn generate_function_sig(&self, func_env: &FunctionEnv<'_>, inline: bool) {
        let (args, rets) = self.generate_function_args_and_returns(func_env);
        if inline {
            emit!(
                self.writer,
                "procedure {{:inline 1}} {} ({}) returns ({})",
                boogie_function_name(func_env),
                args,
                rets,
            )
        } else {
            emit!(
                self.writer,
                "procedure {}_verify ({}) returns ({})",
                boogie_function_name(func_env),
                args,
                rets
            )
        }
    }

    /// Generate boogie representation of function args and return args.
    fn generate_function_args_and_returns(&self, func_env: &FunctionEnv<'_>) -> (String, String) {
        let args = func_env
            .get_type_parameters()
            .iter()
            .map(|TypeParameter(ref i, _)| format!("{}: TypeValue", i))
            .chain(
                func_env
                    .get_parameters()
                    .iter()
                    .map(|Parameter(ref i, ref s)| format!("{}: {}", i, boogie_local_type(s))),
            )
            .join(", ");
        let rets = func_env
            .get_return_types()
            .iter()
            .enumerate()
            .map(|(i, ref s)| format!("__ret{}: {}", i, boogie_local_type(s)))
            .join(", ");
        (args, rets)
    }

    /// Return string for the function specification.
    fn generate_function_spec(&self, func_env: &FunctionEnv<'_>) {
        emitln!(self.writer);
        SpecTranslator::new(func_env, self.writer).translate();
    }

    /// Return string for body of verify function, which is just a call to the
    /// inline version of the function.
    fn generate_verify_function_body(&self, func_env: &FunctionEnv<'_>) {
        // Set the location to pseudo module so it won't be counted for execution traces
        self.writer
            .set_location(PSEUDO_PRELUDE_MODULE, Loc::default());

        let args = func_env
            .get_type_parameters()
            .iter()
            .map(|TypeParameter(i, _)| i.as_str().to_string())
            .chain(
                func_env
                    .get_parameters()
                    .iter()
                    .map(|Parameter(i, _)| i.as_str().to_string()),
            )
            .join(", ");
        let rets = (0..func_env.get_return_count())
            .map(|i| format!("__ret{}", i))
            .join(", ");
        let assumptions = "    call InitVerification();\n";
        if rets.is_empty() {
            emit!(
                self.writer,
                "\n{{\n{}    call {}({});\n}}\n\n",
                assumptions,
                boogie_function_name(func_env),
                args
            )
        } else {
            emit!(
                self.writer,
                "\n{{\n{}    call {} := {}({});\n}}\n\n",
                assumptions,
                rets,
                boogie_function_name(func_env),
                args
            )
        }
    }

    /// This generates boogie code for everything after the function signature
    /// The function body is only generated for the "inline" version of the function.
    fn generate_inline_function_body(&self, func_env: &FunctionEnv<'_>) {
        let code = &self.stackless_bytecode[func_env.get_def_idx().0 as usize];

        // Identify all the branching targets so we can insert labels in front of them. Also
        // calculate mutual borrows.
        let mut branching_targets = BTreeSet::new();
        let mut mutual_local_borrows = BTreeSet::new();
        for bytecode in code.code.iter() {
            match bytecode {
                Branch(target) | BrTrue(target, _) | BrFalse(target, _) => {
                    branching_targets.insert(*target as usize);
                }
                BorrowLoc(dst, src) => {
                    if self.get_local_type(func_env, *dst).is_mutual_reference() {
                        mutual_local_borrows.insert(*src as usize);
                    }
                }
                _ => {}
            }
        }

        // Compute the debug variables.
        let mut debug_vars = BTreeSet::new();
        let func_start = func_env.get_loc().start();
        for idx in 0..func_env.get_parameters().len() {
            debug_vars.insert((func_start, idx));
        }
        for (offset, bytecode) in code.code.iter().enumerate() {
            for (pos, idx) in
                &self.compute_debug_vars(func_env, bytecode, offset as u16, &mutual_local_borrows)
            {
                debug_vars.insert((*pos, *idx));
            }
        }

        // Be sure to set back location to the whole function definition as a default, otherwise
        // we may get unassigned code locations associated with condition locations.
        self.writer
            .set_location(self.module_env.get_module_idx(), func_env.get_loc());

        emitln!(self.writer, "{");
        self.writer.indent();

        // Generate local variable declarations. They need to appear first in boogie.
        emitln!(self.writer, "// declare local variables");
        let num_args = func_env.get_parameters().len();
        for i in num_args..code.local_types.len() {
            let local_name = func_env.get_local_name(i);
            let local_type = &self.module_env.globalize_signature(&code.local_types[i]);
            emitln!(
                self.writer,
                "var {}: {}; // {}",
                local_name,
                boogie_local_type(local_type),
                boogie_type_value(self.module_env.env, local_type)
            );
        }
        emitln!(self.writer, "var __tmp: Value;");
        emitln!(self.writer, "var __frame: int;");
        emitln!(self.writer, "var __saved_m: Memory;");
        self.generate_model_debug_declarations(func_env, &debug_vars);

        emitln!(self.writer, "\n// initialize function execution");
        emitln!(self.writer, "assume !__abort_flag;");
        emitln!(self.writer, "__saved_m := __m;");
        emitln!(self.writer, "__frame := __local_counter;");
        emitln!(
            self.writer,
            "__local_counter := __local_counter + {};",
            code.local_types.len()
        );
        self.generate_model_debug_initialization(func_env, &debug_vars);

        emitln!(self.writer, "\n// process and type check arguments");
        for i in 0..num_args {
            let local_name = func_env.get_local_name(i);
            let local_type = &self.module_env.globalize_signature(&code.local_types[i]);
            let type_check = boogie_type_check(self.module_env.env, &local_name, local_type);
            emit!(self.writer, &type_check);
            if !local_type.is_reference() {
                emitln!(
                    self.writer,
                    &self.update_local(func_env, &debug_vars, func_env.get_loc(), i, &local_name)
                );
            } else {
                emitln!(
                    self.writer,
                    &self.generate_model_debug_update(
                        func_env,
                        &debug_vars,
                        func_env.get_loc(),
                        i,
                        &local_name
                    )
                );
            }
        }

        emitln!(self.writer, "\n// bytecode translation starts here");

        // Generate bytecode
        for (offset, bytecode) in code.code.iter().enumerate() {
            // insert labels for branching targets
            if branching_targets.contains(&offset) {
                self.writer.unindent();
                emitln!(self.writer, "Label_{}:", offset);
                self.writer.indent();
            }
            self.translate_bytecode(
                func_env,
                &debug_vars,
                offset as u16,
                bytecode,
                &mutual_local_borrows,
            );
        }

        // Generate abort exit.
        let mut end_loc = func_env.get_loc();
        if end_loc.end().0 > 0 {
            end_loc = Loc::new(end_loc.end() - ByteOffset(1), end_loc.end())
        }
        self.writer
            .set_location(self.module_env.get_module_idx(), end_loc);
        self.writer.unindent();
        emitln!(self.writer, "Label_Abort:");
        self.writer.indent();
        emitln!(self.writer, "__abort_flag := true;");
        emitln!(self.writer, "__m := __saved_m;");
        for (i, sig) in func_env.get_return_types().iter().enumerate() {
            let ret_str = format!("__ret{}", i);
            if sig.is_reference() {
                emitln!(self.writer, "{} := DefaultReference;", &ret_str);
            } else {
                emitln!(self.writer, "{} := DefaultValue;", &ret_str);
            }
            let update =
                self.generate_model_debug_update(func_env, &debug_vars, end_loc, i, &ret_str);
            if !update.is_empty() {
                emitln!(self.writer, &update);
            }
        }
        self.writer.unindent();
        emitln!(self.writer, "}");
    }

    /// Looks up the type of a local in the stackless bytecode representation.
    fn get_local_type(&self, func_env: &FunctionEnv<'_>, local_idx: usize) -> GlobalType {
        self.module_env.globalize_signature(
            &self.stackless_bytecode[func_env.get_def_idx().0 as usize].local_types[local_idx],
        )
    }

    /// Generates variable declarations for model debugging of given function.
    /// This creates an `[Position]Value` array for each named local and for returns.
    fn generate_model_debug_declarations(
        &self,
        func_env: &FunctionEnv<'_>,
        debug_vars: &BTreeSet<(ByteIndex, usize)>,
    ) {
        if self.module_env.env.options.omit_model_debug {
            return;
        }
        for (pos, idx) in debug_vars {
            emitln!(
                self.writer,
                "var {}: Value;",
                self.debug_var_name(func_env, *pos, *idx)
            )
        }
    }

    /// Returns the name of a debug variable.
    fn debug_var_name(&self, func_env: &FunctionEnv<'_>, pos: ByteIndex, idx: usize) -> String {
        let name = if idx as usize >= func_env.get_local_count() {
            "__ret".to_string()
        } else {
            func_env.get_local_name(idx)
        };
        format!(
            "debug#{}#{}#{}#{}#{}",
            func_env.module_env.get_id().name(),
            func_env.get_name(),
            idx,
            name,
            pos
        )
    }

    /// Generates variable initialization for model debugging of given function.
    fn generate_model_debug_initialization(
        &self,
        _func_env: &FunctionEnv<'_>,
        _debug_vars: &BTreeSet<(ByteIndex, usize)>,
    ) {
        // Nothing to do here right now. We are relying on that the model doesn't contain
        // assignments for debug variables for which no assumptions have been made yet. That is, in:
        //
        //     var debug_var: Value;
        //     ... // no use of debug_var
        //     assume debug_var == v
        //
        // ... we expect no mentioning of debug_var in the model until the `assume` is executed.
        // This seems to work (currently!), though it would be sound for the prover to assign
        // a value to debug_var even if the assume statement was never reached.
        //
        // Notice that an alternative representation like the below which seems to be more robust
        // logically does not work:
        //
        //     var debug_var: Value;
        //     debug_var := DefaultValue; // initialization
        //     ... // no use of debug_var
        //     debug_var := v
        //
        // With this usage debug_var will never appear in the model, even if the assignment is
        // reached. Reason seems to be that boogie eliminates unused variables (but not redundant
        // assumptions).
    }

    /// Updates a local, injecting debug information if available.
    fn update_local(
        &self,
        func_env: &FunctionEnv<'_>,
        debug_vars: &BTreeSet<(ByteIndex, usize)>,
        loc: Loc,
        idx: usize,
        value: &str,
    ) -> String {
        let update = format!("__m := UpdateLocal(__m, __frame + {}, {});", idx, value);
        let debug_update = self.generate_model_debug_update(func_env, debug_vars, loc, idx, value);
        if !debug_update.is_empty() {
            format!("{}\n{}", update, debug_update)
        } else {
            update
        }
    }

    /// Generates an update of the model debug variable at given location.
    fn generate_model_debug_update(
        &self,
        func_env: &FunctionEnv<'_>,
        debug_vars: &BTreeSet<(ByteIndex, usize)>,
        loc: Loc,
        idx: usize,
        value: &str,
    ) -> String {
        if self.module_env.env.options.omit_model_debug || !debug_vars.contains(&(loc.start(), idx))
        {
            return "".to_string();
        }
        let sig = if idx < func_env.get_local_count() {
            func_env.get_local_type(idx)
        } else {
            func_env.get_return_types()[idx - func_env.get_local_count()].clone()
        };
        let actual_value = if sig.is_reference() {
            format!("Dereference(__m, {})", value)
        } else {
            value.to_string()
        };
        let debug_var = self.debug_var_name(func_env, loc.start(), idx);
        // format!("{} := {};", debug_var, actual_value)
        format!("assume ({}) == ({});", debug_var, actual_value)
    }

    /// Compute the debug variables (ByteIndex position and local idx) which we want to update at
    /// the given bytecode.
    fn compute_debug_vars(
        &self,
        func_env: &FunctionEnv,
        code: &StacklessBytecode,
        offset: u16,
        mutual_borrows: &BTreeSet<usize>,
    ) -> Vec<(ByteIndex, usize)> {
        let pos = func_env.get_bytecode_loc(offset).start();
        let mkt = |idx: &usize| {
            if *idx < func_env.get_local_count() {
                vec![(pos, *idx)]
            } else {
                vec![]
            }
        };
        let mkr = |idx: &usize| vec![(pos, (func_env.get_local_count() + *idx))];
        let mkl = |idx: &u8| {
            if (*idx as usize) < func_env.get_local_count() {
                vec![(pos, *idx as usize)]
            } else {
                vec![]
            }
        };
        let borrows = || mutual_borrows.iter().map(|idx| (pos, *idx)).collect_vec();
        match code {
            MoveLoc(t, ..)
            | CopyLoc(t, ..)
            | ReadRef(t, ..)
            | Pack(t, ..)
            | Exists(t, ..)
            | BorrowGlobal(t, ..)
            | MoveFrom(t, ..)
            | LdTrue(t)
            | LdFalse(t)
            | LdU8(t, ..)
            | LdU64(t, ..)
            | LdU128(t, ..)
            | CastU8(t, ..)
            | CastU64(t, ..)
            | CastU128(t, ..)
            | LdAddr(t, ..)
            | Not(t, ..)
            | Add(t, ..)
            | Sub(t, ..)
            | Mul(t, ..)
            | Div(t, ..)
            | Mod(t, ..)
            | Lt(t, ..)
            | Gt(t, ..)
            | Le(t, ..)
            | Ge(t, ..)
            | Or(t, ..)
            | And(t, ..)
            | Eq(t, ..)
            | Neq(t, ..)
            | BitOr(t, ..)
            | GetGasRemaining(t)
            | GetTxnSequenceNumber(t)
            | GetTxnPublicKey(t)
            | GetTxnSenderAddress(t)
            | GetTxnMaxGasUnits(t)
            | GetTxnGasUnitPrice(t) => mkt(t),
            StLoc(l, ..) => mkl(l),
            WriteRef(..) => borrows(),
            Call(ts, ..) | Unpack(ts, ..) => {
                let mut rets = ts.iter().map(|t| mkt(t)).flatten().collect_vec();
                rets.extend_from_slice(&borrows());
                rets
            }
            Ret(ts) => (0..ts.len()).map(|i| mkr(&i)).flatten().collect_vec(),
            _ => vec![],
        }
    }
}
