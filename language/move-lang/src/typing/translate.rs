// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    core::{self, Context, Subst},
    expand, globals, infinite_instantiations, recursive_structs,
};
use crate::{
    diag,
    errors::diagnostic_codes::*,
    expansion::ast::{Fields, ModuleIdent, Value_},
    naming::ast::{self as N, TParam, TParamID, Type, TypeName_, Type_},
    parser::ast::{Ability_, BinOp_, ConstantName, Field, FunctionName, StructName, UnaryOp_, Var},
    shared::{unique_map::UniqueMap, *},
    typing::ast as T,
    FullyCompiledProgram,
};
use move_ir_types::location::*;
use std::collections::{BTreeMap, VecDeque};

//**************************************************************************************************
// Entry
//**************************************************************************************************

pub fn program(
    compilation_env: &mut CompilationEnv,
    pre_compiled_lib: Option<&FullyCompiledProgram>,
    prog: N::Program,
) -> T::Program {
    let mut context = Context::new(compilation_env, pre_compiled_lib, &prog);
    let N::Program {
        addresses,
        modules: nmodules,
        scripts: nscripts,
    } = prog;
    let modules = modules(&mut context, nmodules);
    let scripts = scripts(&mut context, nscripts);

    assert!(context.constraints.is_empty());
    recursive_structs::modules(context.env, &modules);
    infinite_instantiations::modules(context.env, &modules);
    T::Program {
        addresses,
        modules,
        scripts,
    }
}

fn modules(
    context: &mut Context,
    modules: UniqueMap<ModuleIdent, N::ModuleDefinition>,
) -> UniqueMap<ModuleIdent, T::ModuleDefinition> {
    modules.map(|ident, mdef| module(context, ident, mdef))
}

fn module(
    context: &mut Context,
    ident: ModuleIdent,
    mdef: N::ModuleDefinition,
) -> T::ModuleDefinition {
    assert!(context.current_script_constants.is_none());
    context.current_module = Some(ident);
    let N::ModuleDefinition {
        attributes,
        is_source_module,
        dependency_order,
        friends,
        mut structs,
        functions: nfunctions,
        constants: nconstants,
    } = mdef;
    structs
        .iter_mut()
        .for_each(|(_, _, s)| struct_def(context, s));
    let constants = nconstants.map(|name, c| constant(context, name, c));
    let functions = nfunctions.map(|name, f| function(context, name, f, false));
    assert!(context.constraints.is_empty());
    T::ModuleDefinition {
        attributes,
        is_source_module,
        dependency_order,
        friends,
        structs,
        constants,
        functions,
    }
}

fn scripts(
    context: &mut Context,
    nscripts: BTreeMap<String, N::Script>,
) -> BTreeMap<String, T::Script> {
    nscripts
        .into_iter()
        .map(|(n, s)| (n, script(context, s)))
        .collect()
}

fn script(context: &mut Context, nscript: N::Script) -> T::Script {
    assert!(context.current_script_constants.is_none());
    context.current_module = None;
    let N::Script {
        attributes,
        loc,
        constants: nconstants,
        function_name,
        function: nfunction,
    } = nscript;
    context.bind_script_constants(&nconstants);
    let constants = nconstants.map(|name, c| constant(context, name, c));
    let function = function(context, function_name.clone(), nfunction, true);
    context.current_script_constants = None;
    T::Script {
        attributes,
        loc,
        constants,
        function_name,
        function,
    }
}

fn check_primitive_script_arg(
    context: &mut Context,
    mloc: Loc,
    seen_non_signer: &mut bool,
    ty: &Type,
) {
    let current_function = context.current_function.clone().unwrap();
    let mk_msg = move || {
        format!(
            "Invalid parameter for script function '{}'",
            current_function
        )
    };

    let loc = ty.loc;
    let signer = Type_::signer(loc);
    let is_signer = {
        let old_subst = context.subst.clone();
        let result = subtype_no_report(context, ty.clone(), signer.clone());
        context.subst = old_subst;
        result.is_ok()
    };
    if is_signer {
        if !*seen_non_signer {
            return;
        } else {
            let msg = mk_msg();
            let tmsg = format!(
                "{}s must be a prefix of the arguments to a script--they must come before any \
                 non-signer types",
                core::error_format(&signer, &Subst::empty()),
            );
            context
                .env
                .add_diag(diag!(TypeSafety::ScriptSignature, (mloc, msg), (loc, tmsg)));
            return;
        }
    } else {
        *seen_non_signer = true;
    }

    check_valid_constant::signature(context, mloc, mk_msg, TypeSafety::ScriptSignature, ty);
}

//**************************************************************************************************
// Functions
//**************************************************************************************************

fn function(
    context: &mut Context,
    name: FunctionName,
    f: N::Function,
    is_script: bool,
) -> T::Function {
    let loc = name.loc();
    let N::Function {
        attributes,
        visibility,
        mut signature,
        body: n_body,
        acquires,
    } = f;
    assert!(context.constraints.is_empty());
    context.reset_for_module_item();
    context.current_function = Some(name);

    function_signature(context, &signature);
    if is_script {
        let mut seen_non_signer = false;
        for (_, param_ty) in signature.parameters.iter() {
            check_primitive_script_arg(context, loc, &mut seen_non_signer, param_ty);
        }
        subtype(
            context,
            loc,
            || {
                let tu = core::error_format_(&Type_::Unit, &Subst::empty());
                format!(
                    "Invalid 'script' function return type. The function entry point to a \
                     'script' must have the return type {}",
                    tu
                )
            },
            signature.return_type.clone(),
            sp(loc, Type_::Unit),
        );
    }
    expand::function_signature(context, &mut signature);

    let body = function_body(context, &acquires, n_body);
    context.current_function = None;
    T::Function {
        attributes,
        visibility,
        signature,
        acquires,
        body,
    }
}

fn function_signature(context: &mut Context, sig: &N::FunctionSignature) {
    assert!(context.constraints.is_empty());

    let mut declared = UniqueMap::new();
    for (param, param_ty) in &sig.parameters {
        let param_ty = core::instantiate(context, param_ty.clone());
        context.add_single_type_constraint(
            param_ty.loc,
            "Invalid parameter type",
            param_ty.clone(),
        );
        if let Err((param, prev_loc)) = declared.add(param.clone(), ()) {
            let msg = format!("Duplicate parameter with name '{}'", param);
            context.env.add_diag(diag!(
                Declarations::DuplicateItem,
                (param.loc(), msg),
                (prev_loc, "Previously declared here"),
            ))
        }
        context.declare_local(param.clone(), Some(param_ty));
    }
    context.return_type = Some(core::instantiate(context, sig.return_type.clone()));
    core::solve_constraints(context);
}

fn function_body(
    context: &mut Context,
    acquires: &BTreeMap<StructName, Loc>,
    sp!(loc, nb_): N::FunctionBody,
) -> T::FunctionBody {
    assert!(context.constraints.is_empty());
    let mut b_ = match nb_ {
        N::FunctionBody_::Native => T::FunctionBody_::Native,
        N::FunctionBody_::Defined(es) => {
            let seq = sequence(context, es);
            let ety = sequence_type(&seq);
            let ret_ty = context.return_type.clone().unwrap();
            let sloc = seq.back().unwrap().loc;
            subtype(
                context,
                sloc,
                || "Invalid return expression",
                ety.clone(),
                ret_ty,
            );
            T::FunctionBody_::Defined(seq)
        }
    };
    core::solve_constraints(context);
    expand::function_body_(context, &mut b_);
    globals::function_body_(context, &acquires, &b_);
    // freeze::function_body_(context, &mut b_);
    sp(loc, b_)
}

//**************************************************************************************************
// Constants
//**************************************************************************************************

fn constant(context: &mut Context, _name: ConstantName, nconstant: N::Constant) -> T::Constant {
    assert!(context.constraints.is_empty());
    context.reset_for_module_item();

    let N::Constant {
        attributes,
        loc,
        signature,
        value: nvalue,
    } = nconstant;

    // Don't need to add base type constraint, as it is checked in `check_valid_constant::signature`
    let mut signature = core::instantiate(context, signature);
    check_valid_constant::signature(
        context,
        signature.loc,
        || "Unpermitted constant type",
        TypeSafety::TypeForConstant,
        &signature,
    );
    context.return_type = Some(signature.clone());

    let mut value = exp_(context, nvalue);

    subtype(
        context,
        signature.loc,
        || "Invalid constant signature",
        value.ty.clone(),
        signature.clone(),
    );
    core::solve_constraints(context);

    expand::type_(context, &mut signature);
    expand::exp(context, &mut value);

    check_valid_constant::exp(context, &value);

    T::Constant {
        attributes,
        loc,
        signature,
        value,
    }
}

mod check_valid_constant {
    use super::subtype_no_report;
    use crate::{
        diag,
        errors::diagnostic_codes::DiagnosticCode,
        naming::ast::{Type, Type_},
        shared::*,
        typing::{
            ast as T,
            core::{self, Context, Subst},
        },
    };
    use move_ir_types::location::*;

    pub(crate) fn signature<T: ToString, F: FnOnce() -> T>(
        context: &mut Context,
        sloc: Loc,
        fmsg: F,
        code: impl DiagnosticCode,
        ty: &Type,
    ) {
        let loc = ty.loc;

        let mut acceptable_types = vec![
            Type_::u8(loc),
            Type_::u64(loc),
            Type_::u128(loc),
            Type_::bool(loc),
            Type_::address(loc),
        ];
        let ty_is_an_acceptable_type = acceptable_types.iter().any(|acceptable_type| {
            let old_subst = context.subst.clone();
            let result = subtype_no_report(context, ty.clone(), acceptable_type.clone());
            context.subst = old_subst;
            result.is_ok()
        });
        if ty_is_an_acceptable_type {
            return;
        }

        let inner_tvar = core::make_tvar(context, sloc);
        let vec_ty = Type_::vector(sloc, inner_tvar.clone());
        let old_subst = context.subst.clone();
        let is_vec = subtype_no_report(context, ty.clone(), vec_ty.clone()).is_ok();
        let inner = core::ready_tvars(&context.subst, inner_tvar);
        context.subst = old_subst;
        if is_vec {
            signature(context, sloc, fmsg, code, &inner);
            return;
        }

        acceptable_types.push(vec_ty);
        let tys = acceptable_types
            .iter()
            .map(|t| core::error_format(t, &Subst::empty()));
        let tmsg = format!(
            "Found: {}. But expected one of: {}",
            core::error_format(ty, &Subst::empty()),
            format_comma(tys),
        );
        context
            .env
            .add_diag(diag!(code, (sloc, fmsg()), (loc, tmsg)))
    }

    pub fn exp(context: &mut Context, e: &T::Exp) {
        exp_(context, &e.exp)
    }

    fn exp_(context: &mut Context, sp!(loc, e_): &T::UnannotatedExp) {
        use T::UnannotatedExp_ as E;
        const REFERENCE_CASE: &str = "References (and reference operations) are";
        let s;
        let error_case = match e_ {
            //*****************************************
            // Error cases handled elsewhere
            //*****************************************
            E::Use(_) | E::Continue | E::Break | E::UnresolvedError => return,

            //*****************************************
            // Valid cases
            //*****************************************
            E::Unit { .. } | E::Value(_) | E::Move { .. } | E::Copy { .. } => return,
            E::Block(seq) => {
                sequence(context, seq);
                return;
            }
            E::UnaryExp(_, er) => {
                exp(context, er);
                return;
            }
            E::BinopExp(el, _, _, er) => {
                exp(context, el);
                exp(context, er);
                return;
            }
            E::Cast(el, _) | E::Annotate(el, _) => {
                exp(context, el);
                return;
            }

            //*****************************************
            // Invalid cases
            //*****************************************
            E::Spec(_, _) => "Spec blocks are",
            E::BorrowLocal(_, _) => REFERENCE_CASE,
            E::ModuleCall(call) => {
                exp(context, &call.arguments);
                "Module calls are"
            }
            E::Builtin(b, args) => {
                exp(context, args);
                s = format!("'{}' is", b);
                &s
            }
            E::IfElse(eb, et, ef) => {
                exp(context, eb);
                exp(context, et);
                exp(context, ef);
                "'if' expressions are"
            }
            E::While(eb, eloop) => {
                exp(context, eb);
                exp(context, eloop);
                "'while' expressions are"
            }
            E::Loop { body: eloop, .. } => {
                exp(context, eloop);
                "'loop' expressions are"
            }
            E::Assign(_assigns, _tys, er) => {
                exp(context, er);
                "Assignments are"
            }
            E::Return(er) => {
                exp(context, er);
                "'return' expressions are"
            }
            E::Abort(er) => {
                exp(context, er);
                "'abort' expressions are"
            }
            E::Dereference(er) | E::Borrow(_, er, _) | E::TempBorrow(_, er) => {
                exp(context, er);
                REFERENCE_CASE
            }
            E::Mutate(el, er) => {
                exp(context, el);
                exp(context, er);
                REFERENCE_CASE
            }
            E::Pack(_, _, _, fields) => {
                for (_, _, (_, (_, fe))) in fields {
                    exp(context, fe)
                }
                "Structs are"
            }
            E::ExpList(el) => {
                exp_list(context, el);
                "Expression lists are"
            }
            E::Constant(_, _) => "Other constants are",
        };
        context.env.add_diag(diag!(
            TypeSafety::UnsupportedConstant,
            (*loc, format!("{} not supported in constants", error_case))
        ));
    }

    fn exp_list(context: &mut Context, items: &[T::ExpListItem]) {
        for item in items {
            exp_list_item(context, item)
        }
    }

    fn exp_list_item(context: &mut Context, item: &T::ExpListItem) {
        use T::ExpListItem as I;
        match item {
            I::Single(e, _st) => {
                exp(context, e);
            }
            I::Splat(_, e, _ss) => {
                exp(context, e);
            }
        }
    }

    fn sequence(context: &mut Context, seq: &T::Sequence) {
        for item in seq {
            sequence_item(context, item)
        }
    }

    fn sequence_item(context: &mut Context, sp!(loc, item_): &T::SequenceItem) {
        use T::SequenceItem_ as S;
        let error_case = match &item_ {
            S::Seq(te) => {
                exp(context, te);
                return;
            }

            S::Declare(_) => "'let' declarations",
            S::Bind(_, _, te) => {
                exp(context, te);
                "'let' declarations"
            }
        };
        let msg = format!("{} are not supported in constants", error_case);
        context
            .env
            .add_diag(diag!(TypeSafety::UnsupportedConstant, (*loc, msg),))
    }
}

//**************************************************************************************************
// Structs
//**************************************************************************************************

fn struct_def(context: &mut Context, s: &mut N::StructDefinition) {
    assert!(context.constraints.is_empty());
    context.reset_for_module_item();

    let field_map = match &mut s.fields {
        N::StructFields::Native(_) => return,
        N::StructFields::Defined(m) => m,
    };

    let declared_abilities = &s.abilities;
    let tparam_subst = &core::make_tparam_subst(
        s.type_parameters.iter().map(|tp| &tp.param),
        s.type_parameters
            .iter()
            .map(|tp| sp(tp.param.user_specified_name.loc, Type_::Anything)),
    );
    for (_field_loc, _field, idx_ty) in field_map.iter() {
        let loc = idx_ty.1.loc;
        let subst_ty = core::subst_tparams(tparam_subst, idx_ty.1.clone());
        let inst_ty = core::instantiate(context, subst_ty);
        context.add_base_type_constraint(loc, "Invalid field type", inst_ty.clone());
        for declared_ability in declared_abilities {
            let required = declared_ability.value.requires();
            let msg = format!(
                "Invalid field type. The struct was declared with the ability '{}' so all fields \
                 require the ability '{}'",
                declared_ability, required
            );
            context.add_ability_constraint(loc, Some(msg), inst_ty.clone(), required)
        }
    }
    core::solve_constraints(context);

    let type_params: BTreeMap<_, _> = s
        .type_parameters
        .iter()
        .map(|sp| {
            let loc = sp.param.user_specified_name.loc;
            (sp.param.id, (sp.is_phantom, loc))
        })
        .collect();

    for (_field_loc, _field_, idx_ty) in field_map.iter_mut() {
        expand::type_(context, &mut idx_ty.1);
        check_phantom_params(
            context,
            &type_params,
            &idx_ty.1,
            Some(NonPhantomPos::FieldType),
        );
    }
}

enum NonPhantomPos {
    FieldType,
    TypeArg,
}

fn check_phantom_params(
    context: &mut Context,
    type_parameters: &BTreeMap<TParamID, (bool, Loc)>,
    ty: &Type,
    non_phantom_pos: Option<NonPhantomPos>,
) {
    use NonPhantomPos::*;

    match &ty.value {
        Type_::Param(param) => {
            // Don't bother checking unbound type parameters as it should fail somewhere else
            match (type_parameters.get(&param.id), non_phantom_pos) {
                (Some(&(is_phantom, param_decl_loc)), Some(non_phantom_pos)) if is_phantom => {
                    invalid_phantom_use_error(
                        context,
                        non_phantom_pos,
                        param_decl_loc,
                        param,
                        ty.loc,
                    );
                }
                _ => {}
            }
        }
        Type_::Apply(_, n, ty_args) => match &n.value {
            // Tuples cannot appear in structs, but we still report them as a non-phantom position in
            // case they are ever allowed.
            TypeName_::Builtin(_) | TypeName_::Multiple(_) => {
                for ty_arg in ty_args {
                    check_phantom_params(context, type_parameters, ty_arg, Some(TypeArg));
                }
            }
            TypeName_::ModuleType(m, n) => {
                let param_is_phantom: Vec<_> = context
                    .struct_tparams(m, n)
                    .iter()
                    .map(|param| param.is_phantom)
                    .collect();
                // Length of params and args may be different but we can still report errors
                // for parameters with information
                for (is_phantom, ty_arg) in param_is_phantom.into_iter().zip(ty_args) {
                    check_phantom_params(
                        context,
                        type_parameters,
                        ty_arg,
                        (!is_phantom).then(|| TypeArg),
                    );
                }
            }
        },
        // References cannot appear in structs, but we still report them as a non-phantom position
        // in case they are ever allowed.
        Type_::Ref(_, inner) => {
            check_phantom_params(context, type_parameters, &inner, Some(TypeArg))
        }
        Type_::Var(_) | Type_::Anything | Type_::Unit | Type_::UnresolvedError => {}
    }
}

fn invalid_phantom_use_error(
    context: &mut Context,
    non_phantom_pos: NonPhantomPos,
    param_decl_loc: Loc,
    param: &TParam,
    ty_loc: Loc,
) {
    let msg = match non_phantom_pos {
        NonPhantomPos::FieldType => "Phantom type parameter cannot be used as a field type",
        NonPhantomPos::TypeArg => "Phantom type parameter cannot be used as an argument to a parameter not declared as phantom",
    };
    let decl_msg = format!("'{}' declared here as phantom", &param.user_specified_name);
    context.env.add_diag(diag!(
        Declarations::InvalidPhantomUse,
        (ty_loc, msg),
        (param_decl_loc, decl_msg),
    ));
}

//**************************************************************************************************
// Types
//**************************************************************************************************

fn typing_error<T: ToString, F: FnOnce() -> T>(
    context: &mut Context,
    from_subtype: bool,
    loc: Loc,
    mk_msg: F,
    e: core::TypingError,
) {
    use super::core::TypingError::*;
    let msg = mk_msg().to_string();
    let subst = &context.subst;
    let diag = match e {
        SubtypeError(t1, t2) => {
            let loc1 = core::best_loc(subst, &t1);
            let loc2 = core::best_loc(subst, &t2);
            let t1_str = core::error_format(&t1, subst);
            let t2_str = core::error_format(&t2, subst);
            let m1 = format!("Given: {}", t1_str);
            let m2 = format!("Expected: {}", t2_str);
            diag!(TypeSafety::SubtypeError, (loc, msg), (loc1, m1), (loc2, m2))
        }
        ArityMismatch(n1, t1, n2, t2) => {
            let loc1 = core::best_loc(subst, &t1);
            let loc2 = core::best_loc(subst, &t2);
            let t1_str = core::error_format(&t1, subst);
            let t2_str = core::error_format(&t2, subst);
            let msg1 = if from_subtype {
                format!("Given expression list of length {}: {}", n1, t1_str)
            } else {
                format!(
                    "Found expression list of length {}: {}. It is not compatible with the other \
                     type of length {}.",
                    n1, t1_str, n2
                )
            };
            let msg2 = if from_subtype {
                format!("Expected expression list of length {}: {}", n2, t2_str)
            } else {
                format!(
                    "Found expression list of length {}: {}. It is not compatible with the other \
                     type of length {}.",
                    n2, t2_str, n1
                )
            };

            diag!(
                TypeSafety::JoinError,
                (loc, msg),
                (loc1, msg1),
                (loc2, msg2)
            )
        }
        Incompatible(t1, t2) => {
            let loc1 = core::best_loc(subst, &t1);
            let loc2 = core::best_loc(subst, &t2);
            let t1_str = core::error_format(&t1, subst);
            let t2_str = core::error_format(&t2, subst);
            let m1 = if from_subtype {
                format!("Given: {}", t1_str)
            } else {
                format!(
                    "Found: {}. It is not compatible with the other type.",
                    t1_str
                )
            };
            let m2 = if from_subtype {
                format!("Expected: {}", t2_str)
            } else {
                format!(
                    "Found: {}. It is not compatible with the other type.",
                    t2_str
                )
            };
            diag!(TypeSafety::JoinError, (loc, msg), (loc1, m1), (loc2, m2))
        }
        RecursiveType(rloc) => diag!(
            TypeSafety::RecursiveType,
            (loc, msg),
            (rloc, "Unable to infer the type. Recursive type found."),
        ),
    };
    context.env.add_diag(diag)
}

fn subtype_no_report(
    context: &mut Context,
    pre_lhs: Type,
    pre_rhs: Type,
) -> Result<Type, core::TypingError> {
    let subst = std::mem::replace(&mut context.subst, Subst::empty());
    let lhs = core::ready_tvars(&subst, pre_lhs);
    let rhs = core::ready_tvars(&subst, pre_rhs);
    core::subtype(subst, &lhs, &rhs).map(|(next_subst, ty)| {
        context.subst = next_subst;
        ty
    })
}

fn subtype_impl<T: ToString, F: FnOnce() -> T>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    pre_lhs: Type,
    pre_rhs: Type,
) -> Result<Type, Type> {
    let subst = std::mem::replace(&mut context.subst, Subst::empty());
    let lhs = core::ready_tvars(&subst, pre_lhs);
    let rhs = core::ready_tvars(&subst, pre_rhs);
    match core::subtype(subst.clone(), &lhs, &rhs) {
        Err(e) => {
            context.subst = subst;
            typing_error(context, /* from_subtype */ true, loc, msg, e);
            Err(rhs)
        }
        Ok((next_subst, ty)) => {
            context.subst = next_subst;
            Ok(ty)
        }
    }
}

fn subtype_opt<T: ToString, F: FnOnce() -> T>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    pre_lhs: Type,
    pre_rhs: Type,
) -> Option<Type> {
    match subtype_impl(context, loc, msg, pre_lhs, pre_rhs) {
        Err(_rhs) => None,
        Ok(t) => Some(t),
    }
}

fn subtype<T: ToString, F: FnOnce() -> T>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    pre_lhs: Type,
    pre_rhs: Type,
) -> Type {
    match subtype_impl(context, loc, msg, pre_lhs, pre_rhs) {
        Err(rhs) => rhs,
        Ok(t) => t,
    }
}

fn join_opt<T: ToString, F: FnOnce() -> T>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    pre_t1: Type,
    pre_t2: Type,
) -> Option<Type> {
    let subst = std::mem::replace(&mut context.subst, Subst::empty());
    let t1 = core::ready_tvars(&subst, pre_t1);
    let t2 = core::ready_tvars(&subst, pre_t2);
    match core::join(subst.clone(), &t1, &t2) {
        Err(e) => {
            context.subst = subst;
            typing_error(context, /* from_subtype */ false, loc, msg, e);
            None
        }
        Ok((next_subst, ty)) => {
            context.subst = next_subst;
            Some(ty)
        }
    }
}

fn join<T: ToString, F: FnOnce() -> T>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    pre_t1: Type,
    pre_t2: Type,
) -> Type {
    match join_opt(context, loc, msg, pre_t1, pre_t2) {
        None => context.error_type(loc),
        Some(ty) => ty,
    }
}

//**************************************************************************************************
// Expressions
//**************************************************************************************************

enum SeqCase {
    Seq(Loc, Box<T::Exp>),
    Declare {
        old_locals: UniqueMap<Var, Type>,
        declared: UniqueMap<Var, ()>,
        loc: Loc,
        b: T::LValueList,
    },
    Bind {
        old_locals: UniqueMap<Var, Type>,
        declared: UniqueMap<Var, ()>,
        loc: Loc,
        b: T::LValueList,
        e: Box<T::Exp>,
    },
}

fn sequence(context: &mut Context, seq: N::Sequence) -> T::Sequence {
    use N::SequenceItem_ as NS;
    use T::SequenceItem_ as TS;

    let mut work_queue = VecDeque::new();
    let mut resulting_sequence = T::Sequence::new();

    let len = seq.len();
    for (idx, sp!(loc, ns_)) in seq.into_iter().enumerate() {
        match ns_ {
            NS::Seq(ne) => {
                let e = exp_(context, ne);
                // If it is not the last element
                if idx < len - 1 {
                    context.add_ability_constraint(
                        loc,
                        Some(format!(
                            "Cannot ignore values without the '{}' ability. The value must be used",
                            Ability_::Drop
                        )),
                        e.ty.clone(),
                        Ability_::Drop,
                    )
                }
                work_queue.push_front(SeqCase::Seq(loc, Box::new(e)));
            }
            NS::Declare(nbind, ty_opt) => {
                let old_locals = context.save_locals_scope();
                let instantiated_ty_op = ty_opt.map(|t| core::instantiate(context, t));
                let (declared, b) = bind_list(context, nbind, instantiated_ty_op);
                work_queue.push_front(SeqCase::Declare {
                    old_locals,
                    declared,
                    loc,
                    b,
                });
            }
            NS::Bind(nbind, nr) => {
                let e = exp_(context, nr);
                let old_locals = context.save_locals_scope();
                let (declared, b) = bind_list(context, nbind, Some(e.ty.clone()));
                work_queue.push_front(SeqCase::Bind {
                    old_locals,
                    declared,
                    loc,
                    b,
                    e: Box::new(e),
                });
            }
        }
    }

    for case in work_queue {
        match case {
            SeqCase::Seq(loc, e) => resulting_sequence.push_front(sp(loc, TS::Seq(e))),
            SeqCase::Declare {
                old_locals,
                declared,
                loc,
                b,
            } => {
                context.close_locals_scope(old_locals, declared);
                resulting_sequence.push_front(sp(loc, TS::Declare(b)))
            }
            SeqCase::Bind {
                old_locals,
                declared,
                loc,
                b,
                e,
            } => {
                context.close_locals_scope(old_locals, declared);
                let lvalue_ty = lvalues_expected_types(context, &b);
                resulting_sequence.push_front(sp(loc, TS::Bind(b, lvalue_ty, e)))
            }
        }
    }

    resulting_sequence
}

fn sequence_type(seq: &T::Sequence) -> &Type {
    use T::SequenceItem_ as TS;
    match seq.back().unwrap() {
        sp!(_, TS::Bind(_, _, _)) | sp!(_, TS::Declare(_)) => {
            panic!("ICE unit should have been inserted past bind/decl")
        }
        sp!(_, TS::Seq(last_e)) => &last_e.ty,
    }
}

fn exp_vec(context: &mut Context, es: Vec<N::Exp>) -> Vec<T::Exp> {
    es.into_iter().map(|e| exp_(context, e)).collect()
}

fn exp(context: &mut Context, ne: Box<N::Exp>) -> Box<T::Exp> {
    Box::new(exp_(context, *ne))
}

fn exp_(context: &mut Context, initial_ne: N::Exp) -> T::Exp {
    use N::Exp_ as NE;
    use T::UnannotatedExp_ as TE;
    struct Stack<'a, 'env> {
        frames: Vec<Box<dyn FnOnce(&mut Self)>>,
        operands: Vec<T::Exp>,
        context: &'a mut Context<'env>,
    }
    macro_rules! inner {
        ($e:expr) => {{
            move |s: &mut Stack| exp_loop(s, $e)
        }};
    }
    fn exp_loop(stack: &mut Stack, sp!(loc, cur_): N::Exp) {
        match cur_ {
            NE::BinopExp(nlhs, bop, nrhs) => {
                let f_lhs = inner!(*nlhs);
                let f_rhs = inner!(*nrhs);
                let f_binop = move |s: &mut Stack| {
                    let er = Box::new(s.operands.pop().unwrap());
                    let el = Box::new(s.operands.pop().unwrap());
                    use BinOp_::*;
                    let msg = || format!("Incompatible arguments to '{}'", &bop);
                    let context = &mut s.context;
                    let (ty, operand_ty) = match &bop.value {
                        Sub | Add | Mul | Mod | Div => {
                            context.add_numeric_constraint(
                                el.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            context.add_numeric_constraint(
                                er.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            let operand_ty =
                                join(context, bop.loc, msg, el.ty.clone(), er.ty.clone());
                            (operand_ty.clone(), operand_ty)
                        }

                        BitOr | BitAnd | Xor => {
                            context.add_bits_constraint(
                                el.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            context.add_bits_constraint(
                                er.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            let operand_ty =
                                join(context, bop.loc, msg, el.ty.clone(), er.ty.clone());
                            (operand_ty.clone(), operand_ty)
                        }

                        Shl | Shr => {
                            let msg = || format!("Invalid argument to '{}'", &bop);
                            let u8ty = Type_::u8(er.exp.loc);
                            context.add_bits_constraint(
                                el.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            subtype(context, er.exp.loc, msg, er.ty.clone(), u8ty);
                            (el.ty.clone(), el.ty.clone())
                        }

                        Lt | Gt | Le | Ge => {
                            context.add_ordered_constraint(
                                el.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            context.add_ordered_constraint(
                                er.exp.loc,
                                bop.value.symbol(),
                                el.ty.clone(),
                            );
                            let operand_ty =
                                join(context, bop.loc, msg, el.ty.clone(), er.ty.clone());
                            (Type_::bool(loc), operand_ty)
                        }

                        Eq | Neq => {
                            let ability_msg = Some(format!(
                                "'{}' requires the '{}' ability as the value is consumed. Try \
                                 borrowing the values with '&' first.'",
                                &bop,
                                Ability_::Drop,
                            ));
                            context.add_ability_constraint(
                                el.exp.loc,
                                ability_msg.clone(),
                                el.ty.clone(),
                                Ability_::Drop,
                            );
                            context.add_ability_constraint(
                                er.exp.loc,
                                ability_msg,
                                er.ty.clone(),
                                Ability_::Drop,
                            );
                            let ty = join(context, bop.loc, msg, el.ty.clone(), er.ty.clone());
                            context.add_single_type_constraint(loc, msg(), ty.clone());
                            (Type_::bool(loc), ty)
                        }

                        And | Or => {
                            let msg = || format!("Invalid argument to '{}'", &bop);
                            let lloc = el.exp.loc;
                            subtype(context, lloc, msg, el.ty.clone(), Type_::bool(bop.loc));
                            let rloc = er.exp.loc;
                            subtype(context, rloc, msg, er.ty.clone(), Type_::bool(bop.loc));
                            (Type_::bool(loc), Type_::bool(loc))
                        }

                        Range | Implies | Iff => panic!("specification operator unexpected"),
                    };
                    let binop =
                        T::exp(ty, sp(loc, TE::BinopExp(el, bop, Box::new(operand_ty), er)));
                    s.operands.push(binop)
                };

                stack.frames.push(Box::new(f_binop));
                stack.frames.push(Box::new(f_rhs));
                stack.frames.push(Box::new(f_lhs));
            }
            cur_ => stack.operands.push(exp_inner(stack.context, sp(loc, cur_))),
        }
    }

    let mut stack = Stack {
        frames: vec![],
        operands: vec![],
        context,
    };
    exp_loop(&mut stack, initial_ne);
    while let Some(f) = stack.frames.pop() {
        f(&mut stack)
    }
    let e_res = stack.operands.pop().unwrap();
    assert!(stack.frames.is_empty());
    assert!(stack.operands.is_empty());
    e_res
}

fn exp_inner(context: &mut Context, sp!(eloc, ne_): N::Exp) -> T::Exp {
    use N::Exp_ as NE;
    use T::UnannotatedExp_ as TE;
    let (ty, e_) = match ne_ {
        NE::Unit { trailing } => (sp(eloc, Type_::Unit), TE::Unit { trailing }),
        NE::Value(sp!(vloc, Value_::InferredNum(v))) => (
            core::make_num_tvar(context, eloc),
            TE::Value(sp(vloc, Value_::InferredNum(v))),
        ),
        NE::Value(sp!(vloc, v)) => (v.type_(vloc).unwrap(), TE::Value(sp(vloc, v))),

        NE::Constant(m, c) => {
            let ty = core::make_constant_type(context, eloc, &m, &c);
            (ty, TE::Constant(m, c))
        }

        NE::Move(var) => {
            let ty = context.get_local(eloc, "move", &var);
            let from_user = true;
            (ty, TE::Move { var, from_user })
        }
        NE::Copy(var) => {
            let ty = context.get_local(eloc, "copy", &var);
            context.add_ability_constraint(
                eloc,
                Some(format!(
                    "Invalid 'copy' of owned value without the '{}' ability",
                    Ability_::Copy
                )),
                ty.clone(),
                Ability_::Copy,
            );
            let from_user = true;
            (ty, TE::Copy { var, from_user })
        }
        NE::Use(var) => {
            let ty = context.get_local(eloc, "variable usage", &var);
            (ty, TE::Use(var))
        }

        NE::ModuleCall(m, f, ty_args_opt, sp!(argloc, nargs_)) => {
            let args = exp_vec(context, nargs_);
            module_call(context, eloc, m, f, ty_args_opt, argloc, args)
        }
        NE::Builtin(b, sp!(argloc, nargs_)) => {
            let args = exp_vec(context, nargs_);
            builtin_call(context, eloc, b, argloc, args)
        }

        NE::IfElse(nb, nt, nf) => {
            let eb = exp(context, nb);
            let bloc = eb.exp.loc;
            subtype(
                context,
                bloc,
                || "Invalid if condition",
                eb.ty.clone(),
                Type_::bool(bloc),
            );
            let et = exp(context, nt);
            let ef = exp(context, nf);
            let ty = join(
                context,
                eloc,
                || "Incompatible branches",
                et.ty.clone(),
                ef.ty.clone(),
            );
            (ty, TE::IfElse(eb, et, ef))
        }
        NE::While(nb, nloop) => {
            let eb = exp(context, nb);
            let bloc = eb.exp.loc;
            subtype(
                context,
                bloc,
                || "Invalid while condition",
                eb.ty.clone(),
                Type_::bool(bloc),
            );
            let (_has_break, ty, body) = loop_body(context, eloc, false, nloop);
            (sp(eloc, ty.value), TE::While(eb, body))
        }
        NE::Loop(nloop) => {
            let (has_break, ty, body) = loop_body(context, eloc, true, nloop);
            let eloop = TE::Loop { has_break, body };
            (sp(eloc, ty.value), eloop)
        }
        NE::Block(nseq) => {
            let seq = sequence(context, nseq);
            (sequence_type(&seq).clone(), TE::Block(seq))
        }

        NE::Assign(na, nr) => {
            let er = exp(context, nr);
            let a = assign_list(context, na, er.ty.clone());
            let lvalue_ty = lvalues_expected_types(context, &a);
            (sp(eloc, Type_::Unit), TE::Assign(a, lvalue_ty, er))
        }

        NE::Mutate(nl, nr) => {
            let el = exp(context, nl);
            let er = exp(context, nr);
            check_mutation(context, el.exp.loc, el.ty.clone(), &er.ty);
            (sp(eloc, Type_::Unit), TE::Mutate(el, er))
        }

        NE::FieldMutate(ndotted, nr) => {
            let lhsloc = ndotted.loc;
            let er = exp(context, nr);
            let (edotted, _) = exp_dotted(context, "mutation", ndotted);
            let eborrow = exp_dotted_to_borrow(context, lhsloc, true, edotted);
            check_mutation(context, eborrow.exp.loc, eborrow.ty.clone(), &er.ty);
            (sp(eloc, Type_::Unit), TE::Mutate(Box::new(eborrow), er))
        }

        NE::Return(nret) => {
            let eret = exp(context, nret);
            let ret_ty = context.return_type.clone().unwrap();
            subtype(context, eloc, || "Invalid return", eret.ty.clone(), ret_ty);
            (sp(eloc, Type_::Anything), TE::Return(eret))
        }
        NE::Abort(ncode) => {
            let ecode = exp(context, ncode);
            let code_ty = Type_::u64(eloc);
            subtype(context, eloc, || "Invalid abort", ecode.ty.clone(), code_ty);
            (sp(eloc, Type_::Anything), TE::Abort(ecode))
        }
        NE::Break => {
            if !context.in_loop() {
                let msg = "Invalid usage of 'break'. 'break' can only be used inside a loop body";
                context
                    .env
                    .add_diag(diag!(TypeSafety::InvalidLoopControl, (eloc, msg)))
            }
            let current_break_ty = sp(eloc, Type_::Unit);
            let break_ty = match context.get_break_type() {
                None => current_break_ty,
                Some(t) => {
                    let t = t.clone();
                    join(context, eloc, || "Invalid break.", t, current_break_ty)
                }
            };
            context.set_break_type(break_ty);
            (sp(eloc, Type_::Anything), TE::Break)
        }
        NE::Continue => {
            if !context.in_loop() {
                let msg =
                    "Invalid usage of 'continue'. 'continue' can only be used inside a loop body";
                context
                    .env
                    .add_diag(diag!(TypeSafety::InvalidLoopControl, (eloc, msg)))
            }
            (sp(eloc, Type_::Anything), TE::Continue)
        }

        NE::Dereference(nref) => {
            let eref = exp(context, nref);
            let inner = core::make_tvar(context, eloc);
            let ref_ty = sp(eloc, Type_::Ref(false, Box::new(inner.clone())));
            subtype(
                context,
                eloc,
                || "Invalid dereference.",
                eref.ty.clone(),
                ref_ty,
            );
            context.add_ability_constraint(
                eloc,
                Some(format!(
                    "Invalid dereference. Dereference requires the '{}' ability",
                    Ability_::Copy
                )),
                inner.clone(),
                Ability_::Copy,
            );
            (inner, TE::Dereference(eref))
        }
        NE::UnaryExp(uop, nr) => {
            use UnaryOp_::*;
            let msg = || format!("Invalid argument to '{}'", &uop);
            let er = exp(context, nr);
            let ty = match &uop.value {
                Not => {
                    let rloc = er.exp.loc;
                    subtype(context, rloc, msg, er.ty.clone(), Type_::bool(rloc));
                    Type_::bool(eloc)
                }
            };
            (ty, TE::UnaryExp(uop, er))
        }

        NE::ExpList(nes) => {
            assert!(!nes.is_empty());
            let es = exp_vec(context, nes);
            let locs = es.iter().map(|e| e.exp.loc).collect();
            let tvars = core::make_expr_list_tvars(
                context,
                eloc,
                "Invalid expression list type argument",
                locs,
            );
            for (e, tvar) in es.iter().zip(&tvars) {
                join(
                    context,
                    e.exp.loc,
                    || -> String { panic!("ICE failed tvar join") },
                    e.ty.clone(),
                    tvar.clone(),
                );
            }
            let ty = Type_::multiple(eloc, tvars);
            let items = es.into_iter().map(T::single_item).collect();
            (ty, TE::ExpList(items))
        }
        NE::Pack(m, n, ty_args_opt, nfields) => {
            let (bt, targs) = core::make_struct_type(context, eloc, &m, &n, ty_args_opt);
            let typed_nfields =
                add_field_types(context, eloc, "argument", &m, &n, targs.clone(), nfields);

            let tfields = typed_nfields.map(|f, (idx, (fty, narg))| {
                let arg = exp_(context, narg);
                subtype(
                    context,
                    arg.exp.loc,
                    || format!("Invalid argument for field '{}' for '{}::{}'", f, &m, &n),
                    arg.ty.clone(),
                    fty.clone(),
                );
                (idx, (fty, arg))
            });
            if !context.is_current_module(&m) {
                let msg = format!(
                    "Invalid instantiation of '{}::{}'.\nAll structs can only be constructed in \
                     the module in which they are declared",
                    &m, &n,
                );
                context
                    .env
                    .add_diag(diag!(TypeSafety::Visibility, (eloc, msg)));
            }
            (bt, TE::Pack(m, n, targs, tfields))
        }

        NE::Borrow(mut_, sp!(_, N::ExpDotted_::Exp(ner))) => {
            let er = exp_(context, *ner);
            context.add_base_type_constraint(eloc, "Invalid borrow", er.ty.clone());
            let ty = sp(eloc, Type_::Ref(mut_, Box::new(er.ty.clone())));
            let eborrow = match er.exp {
                sp!(_, TE::Use(v)) => TE::BorrowLocal(mut_, v),
                erexp => TE::TempBorrow(mut_, Box::new(T::exp(er.ty, erexp))),
            };
            (ty, eborrow)
        }

        NE::Borrow(mut_, ndotted) => {
            let (edotted, _) = exp_dotted(context, "borrow", ndotted);
            let eborrow = exp_dotted_to_borrow(context, eloc, mut_, edotted);
            (eborrow.ty, eborrow.exp.value)
        }

        NE::DerefBorrow(ndotted) => {
            assert!(!matches!(ndotted, sp!(_, N::ExpDotted_::Exp(_))));

            let (edotted, inner_ty) = exp_dotted(context, "dot access", ndotted);
            let ederefborrow = exp_dotted_to_owned_value(context, eloc, edotted, inner_ty);
            (ederefborrow.ty, ederefborrow.exp.value)
        }

        NE::Cast(nl, ty) => {
            let el = exp(context, nl);
            let tyloc = ty.loc;
            let rhs = core::instantiate(context, ty);
            context.add_numeric_constraint(el.exp.loc, "as", el.ty.clone());
            context.add_numeric_constraint(tyloc, "as", rhs.clone());
            (rhs.clone(), TE::Cast(el, Box::new(rhs)))
        }

        NE::Annotate(nl, ty_annot) => {
            let el = exp(context, nl);
            let annot_loc = ty_annot.loc;
            let rhs = core::instantiate(context, ty_annot);
            subtype(
                context,
                annot_loc,
                || "Invalid type annotation",
                el.ty.clone(),
                rhs.clone(),
            );
            (rhs.clone(), TE::Annotate(el, Box::new(rhs)))
        }
        NE::Spec(u, used_locals) => {
            let used_local_types = used_locals
                .into_iter()
                .filter_map(|v| {
                    let ty = context.get_local_(&v)?;
                    Some((v, ty))
                })
                .collect();
            (sp(eloc, Type_::Unit), TE::Spec(u, used_local_types))
        }
        NE::UnresolvedError => {
            assert!(context.env.has_errors());
            (context.error_type(eloc), TE::UnresolvedError)
        }

        NE::BinopExp(..) => unreachable!(),
    };
    T::exp(ty, sp(eloc, e_))
}

fn loop_body(
    context: &mut Context,
    eloc: Loc,
    is_loop: bool,
    nloop: Box<N::Exp>,
) -> (bool, Type, Box<T::Exp>) {
    let old_loop_info = context.enter_loop();
    let eloop = exp(context, nloop);
    let break_type_opt = context.exit_loop(old_loop_info);

    let lloc = eloop.exp.loc;
    subtype(
        context,
        lloc,
        || "Invalid loop body",
        eloop.ty.clone(),
        sp(lloc, Type_::Unit),
    );
    let has_break = break_type_opt.is_some();
    let ty = if is_loop && !has_break {
        core::make_tvar(context, lloc)
    } else {
        break_type_opt.unwrap_or_else(|| sp(eloc, Type_::Unit))
    };
    (has_break, ty, eloop)
}

//**************************************************************************************************
// Locals and LValues
//**************************************************************************************************

fn lvalues_expected_types(
    context: &mut Context,
    sp!(_loc, bs_): &T::LValueList,
) -> Vec<Option<N::Type>> {
    bs_.iter()
        .map(|b| lvalue_expected_types(context, b))
        .collect()
}

fn lvalue_expected_types(_context: &mut Context, sp!(loc, b_): &T::LValue) -> Option<N::Type> {
    use N::Type_::*;
    use T::LValue_ as L;
    let loc = *loc;
    match b_ {
        L::Ignore => None,
        L::Var(_, ty) => Some(*ty.clone()),
        L::BorrowUnpack(mut_, m, s, tys, _) => {
            let tn = sp(loc, N::TypeName_::ModuleType(m.clone(), s.clone()));
            Some(sp(
                loc,
                Ref(*mut_, Box::new(sp(loc, Apply(None, tn, tys.clone())))),
            ))
        }
        L::Unpack(m, s, tys, _) => {
            let tn = sp(loc, N::TypeName_::ModuleType(m.clone(), s.clone()));
            Some(sp(loc, Apply(None, tn, tys.clone())))
        }
    }
}

#[derive(Clone, Copy)]
enum LValueCase {
    Bind,
    Assign,
}

fn bind_list(
    context: &mut Context,
    ls: N::LValueList,
    ty_opt: Option<Type>,
) -> (UniqueMap<Var, ()>, T::LValueList) {
    lvalue_list(context, LValueCase::Bind, ls, ty_opt)
}

fn assign_list(context: &mut Context, ls: N::LValueList, rvalue_ty: Type) -> T::LValueList {
    lvalue_list(context, LValueCase::Assign, ls, Some(rvalue_ty)).1
}

fn lvalue_list(
    context: &mut Context,
    case: LValueCase,
    sp!(loc, nlvalues): N::LValueList,
    ty_opt: Option<Type>,
) -> (UniqueMap<Var, ()>, T::LValueList) {
    use LValueCase as C;
    let arity = nlvalues.len();
    let locs = nlvalues.iter().map(|sp!(loc, _)| *loc).collect();
    let msg = "Invalid type for local";
    let ty_vars = core::make_expr_list_tvars(context, loc, msg, locs);
    let var_ty = match arity {
        0 => sp(loc, Type_::Unit),
        1 => sp(loc, ty_vars[0].value.clone()),
        _ => Type_::multiple(loc, ty_vars.clone()),
    };
    if let Some(ty) = ty_opt {
        let result = subtype_opt(
            context,
            loc,
            || {
                format!(
                    "Invalid value for {}",
                    match case {
                        C::Bind => "binding",
                        C::Assign => "assignment",
                    }
                )
            },
            ty,
            var_ty,
        );
        if result.is_none() {
            for ty_var in ty_vars.clone() {
                let ety = context.error_type(ty_var.loc);
                join(
                    context,
                    loc,
                    || -> String { panic!("ICE unresolved error join, failed") },
                    ty_var,
                    ety,
                );
            }
        }
    }
    let mut seen_locals: UniqueMap<Var, ()> = UniqueMap::new();
    assert!(ty_vars.len() == nlvalues.len(), "ICE invalid lvalue tvars");
    let tbinds = nlvalues
        .into_iter()
        .zip(ty_vars)
        .map(|(l, t)| lvalue(context, case, &mut seen_locals, l, t))
        .collect();
    (seen_locals, sp(loc, tbinds))
}

fn lvalue(
    context: &mut Context,
    case: LValueCase,
    seen_locals: &mut UniqueMap<Var, ()>,
    sp!(loc, nl_): N::LValue,
    ty: Type,
) -> T::LValue {
    use LValueCase as C;

    use N::LValue_ as NL;
    use T::LValue_ as TL;
    let tl_ = match nl_ {
        NL::Ignore => {
            context.add_ability_constraint(
                loc,
                Some(format!(
                    "Cannot ignore values without the '{}' ability. The value must be used",
                    Ability_::Drop
                )),
                ty,
                Ability_::Drop,
            );
            TL::Ignore
        }
        NL::Var(var) => {
            let var_ty = match case {
                C::Bind => {
                    context.declare_local(var.clone(), Some(ty.clone()));
                    ty
                }
                C::Assign => {
                    let var_ty = context.get_local(loc, "assignment", &var);
                    subtype(
                        context,
                        loc,
                        || format!("Invalid assignment to local '{}'", &var),
                        ty,
                        var_ty.clone(),
                    );
                    var_ty
                }
            };
            if let Err((var, prev_loc)) = seen_locals.add(var.clone(), ()) {
                let (primary, secondary) = match case {
                    C::Bind => {
                        let msg = format!(
                            "Duplicate declaration for local '{}' in a given 'let'",
                            &var
                        );
                        ((var.loc(), msg), (prev_loc, "Previously declared here"))
                    }
                    C::Assign => {
                        let msg =
                            format!("Duplicate usage of local '{}' in a given assignment", &var);
                        ((var.loc(), msg), (prev_loc, "Previously assigned here"))
                    }
                };
                context
                    .env
                    .add_diag(diag!(Declarations::DuplicateItem, primary, secondary));
            }
            TL::Var(var, Box::new(var_ty))
        }
        NL::Unpack(m, n, ty_args_opt, fields) => {
            let (bt, targs) = core::make_struct_type(context, loc, &m, &n, ty_args_opt);
            let (ref_mut, ty_inner) = match core::unfold_type(&context.subst, ty.clone()).value {
                Type_::Ref(mut_, inner) => (Some(mut_), *inner),
                _ => {
                    // Do not need base constraint because of the join below
                    (None, ty)
                }
            };
            match case {
                C::Bind => subtype(
                    context,
                    loc,
                    || "Invalid deconstruction binding",
                    bt,
                    ty_inner,
                ),
                C::Assign => subtype(
                    context,
                    loc,
                    || "Invalid deconstruction assignment",
                    bt,
                    ty_inner,
                ),
            };
            let verb = match case {
                C::Bind => "binding",
                C::Assign => "assignment",
            };
            let typed_fields = add_field_types(context, loc, verb, &m, &n, targs.clone(), fields);
            let tfields = typed_fields.map(|f, (idx, (fty, nl))| {
                let nl_ty = match ref_mut {
                    None => fty.clone(),
                    Some(mut_) => sp(f.loc(), Type_::Ref(mut_, Box::new(fty.clone()))),
                };
                let tl = lvalue(context, case, seen_locals, nl, nl_ty);
                (idx, (fty, tl))
            });
            if !context.is_current_module(&m) {
                let msg = format!(
                    "Invalid deconstruction {} of '{}::{}'.\n All structs can only be \
                     deconstructed in the module in which they are declared",
                    verb, &m, &n,
                );
                context
                    .env
                    .add_diag(diag!(TypeSafety::Visibility, (loc, msg)));
            }
            match ref_mut {
                None => TL::Unpack(m, n, targs, tfields),
                Some(mut_) => TL::BorrowUnpack(mut_, m, n, targs, tfields),
            }
        }
    };
    sp(loc, tl_)
}

fn check_mutation(context: &mut Context, loc: Loc, given_ref: Type, rvalue_ty: &Type) -> Type {
    let inner = core::make_tvar(context, loc);
    let ref_ty = sp(loc, Type_::Ref(true, Box::new(inner.clone())));
    let res_ty = subtype(
        context,
        loc,
        || "Invalid mutation. Expected a mutable reference",
        given_ref,
        ref_ty,
    );
    subtype(
        context,
        loc,
        || "Invalid mutation. New value is not valid for the reference",
        rvalue_ty.clone(),
        inner.clone(),
    );
    context.add_ability_constraint(
        loc,
        Some(format!(
            "Invalid mutation. Mutation requires the '{}' ability as the old value is destroyed",
            Ability_::Drop
        )),
        inner,
        Ability_::Drop,
    );
    res_ty
}

//**************************************************************************************************
// Fields
//**************************************************************************************************

fn resolve_field(context: &mut Context, loc: Loc, ty: Type, field: &Field) -> Type {
    use TypeName_::*;
    use Type_::*;
    const UNINFERRED_MSG: &str =
        "Could not infer the type before field access. Try annotating here";
    let msg = || format!("Unbound field '{}'", field);
    match core::ready_tvars(&context.subst, ty) {
        sp!(_, UnresolvedError) => context.error_type(loc),
        sp!(tloc, Anything) => {
            context.env.add_diag(diag!(
                TypeSafety::UninferredType,
                (loc, msg()),
                (tloc, UNINFERRED_MSG),
            ));
            context.error_type(loc)
        }
        sp!(tloc, Var(i)) if !context.subst.is_num_var(i) => {
            context.env.add_diag(diag!(
                TypeSafety::UninferredType,
                (loc, msg()),
                (tloc, UNINFERRED_MSG),
            ));
            context.error_type(loc)
        }
        sp!(_, Apply(_, sp!(_, ModuleType(m, n)), targs)) => {
            if !context.is_current_module(&m) {
                let msg = format!(
                    "Invalid access of field '{}' on '{}::{}'. Fields can only be accessed inside \
                     the struct's module",
                    field, &m, &n
                );
                context
                    .env
                    .add_diag(diag!(TypeSafety::Visibility, (loc, msg)));
            }
            core::make_field_type(context, loc, &m, &n, targs, field)
        }
        t => {
            let smsg = format!(
                "Expected a struct type in the current module but got: {}",
                core::error_format(&t, &context.subst)
            );
            context.env.add_diag(diag!(
                TypeSafety::ExpectedSpecificType,
                (loc, msg()),
                (t.loc, smsg),
            ));
            context.error_type(loc)
        }
    }
}

fn add_field_types<T>(
    context: &mut Context,
    loc: Loc,
    verb: &str,
    m: &ModuleIdent,
    n: &StructName,
    targs: Vec<Type>,
    fields: Fields<T>,
) -> Fields<(Type, T)> {
    let maybe_fields_ty = core::make_field_types(context, loc, m, n, targs);
    let mut fields_ty = match maybe_fields_ty {
        N::StructFields::Defined(m) => m,
        N::StructFields::Native(nloc) => {
            let msg = format!(
                "Invalid {} usage for native struct '{}::{}'. Native structs cannot be directly \
                 constructed/deconstructed, and their fields cannot be dirctly accessed",
                verb, m, n
            );
            context.env.add_diag(diag!(
                TypeSafety::InvalidNativeUsage,
                (loc, msg),
                (nloc, "Struct declared 'native' here")
            ));
            return fields.map(|f, (idx, x)| (idx, (context.error_type(f.loc()), x)));
        }
    };
    for (_, f_, _) in &fields_ty {
        if fields.get_(&f_).is_none() {
            let msg = format!("Missing {} for field '{}' in '{}::{}'", verb, f_, m, n);
            context
                .env
                .add_diag(diag!(TypeSafety::TooFewArguments, (loc, msg)))
        }
    }
    fields.map(|f, (idx, x)| {
        let fty = match fields_ty.remove(&f) {
            None => {
                context.env.add_diag(diag!(
                    NameResolution::UnboundField,
                    (loc, format!("Unbound field '{}' in '{}::{}'", &f, m, n))
                ));
                context.error_type(f.loc())
            }
            Some((_, fty)) => fty,
        };
        (idx, (fty, x))
    })
}

enum ExpDotted_ {
    Exp(Box<T::Exp>),
    TmpBorrow(Box<T::Exp>, Box<Type>),
    Dot(Box<ExpDotted>, Field, Box<Type>),
}
type ExpDotted = Spanned<ExpDotted_>;

fn exp_dotted(
    context: &mut Context,
    verb: &str,
    sp!(dloc, ndot_): N::ExpDotted,
) -> (ExpDotted, Type) {
    use N::ExpDotted_ as NE;
    let (edot_, ty) = match ndot_ {
        NE::Exp(ne) => {
            use Type_::*;
            let e = exp(context, ne);
            let ety = &e.ty;
            let unfolded = core::unfold_type(&context.subst, ety.clone());
            let (borrow_needed, ty) = match unfolded.value {
                Ref(_, inner) => (false, *inner),
                _ => (true, ety.clone()),
            };
            let edot_ = if borrow_needed {
                context.add_single_type_constraint(dloc, format!("Invalid {}", verb), ty.clone());
                ExpDotted_::TmpBorrow(e, Box::new(ty.clone()))
            } else {
                ExpDotted_::Exp(e)
            };
            (edot_, ty)
        }
        NE::Dot(nlhs, field) => {
            let (lhs, inner) = exp_dotted(context, "dot access", *nlhs);
            let field_ty = resolve_field(context, dloc, inner, &field);
            (
                ExpDotted_::Dot(Box::new(lhs), field, Box::new(field_ty.clone())),
                field_ty,
            )
        }
    };
    (sp(dloc, edot_), ty)
}

fn exp_dotted_to_borrow(
    context: &mut Context,
    loc: Loc,
    mut_: bool,
    sp!(dloc, dot_): ExpDotted,
) -> T::Exp {
    use Type_::*;
    use T::UnannotatedExp_ as TE;
    match dot_ {
        ExpDotted_::Exp(e) => *e,
        ExpDotted_::TmpBorrow(eb, desired_inner_ty) => {
            let eb_ty = eb.ty;
            let sp!(ebloc, eb_) = eb.exp;
            let e_ = match eb_ {
                TE::Use(v) => TE::BorrowLocal(mut_, v),
                eb_ => {
                    match &eb_ {
                        TE::Move { from_user, .. } | TE::Copy { from_user, .. } => {
                            assert!(*from_user)
                        }
                        _ => (),
                    }
                    TE::TempBorrow(mut_, Box::new(T::exp(eb_ty, sp(ebloc, eb_))))
                }
            };
            let ty = sp(loc, Ref(mut_, desired_inner_ty));
            T::exp(ty, sp(dloc, e_))
        }
        ExpDotted_::Dot(lhs, field, field_ty) => {
            let lhs_borrow = exp_dotted_to_borrow(context, dloc, mut_, *lhs);
            let sp!(tyloc, unfolded_) = core::unfold_type(&context.subst, lhs_borrow.ty.clone());
            let lhs_mut = match unfolded_ {
                Ref(lhs_mut, _) => lhs_mut,
                _ => panic!(
                    "ICE expected a ref from exp_dotted borrow, otherwise should have gotten a \
                     TmpBorrow"
                ),
            };
            // lhs is immutable and current borrow is mutable
            if !lhs_mut && mut_ {
                context.env.add_diag(diag!(
                    ReferenceSafety::RefTrans,
                    (loc, "Invalid mutable borrow from an immutable reference"),
                    (tyloc, "Immutable because of this position"),
                ))
            }
            let e_ = TE::Borrow(mut_, Box::new(lhs_borrow), field);
            let ty = sp(loc, Ref(mut_, field_ty));
            T::exp(ty, sp(dloc, e_))
        }
    }
}

fn exp_dotted_to_owned_value(
    context: &mut Context,
    eloc: Loc,
    edot: ExpDotted,
    inner_ty: Type,
) -> T::Exp {
    use T::UnannotatedExp_ as TE;
    match edot {
        // TODO investigate this nonsense
        sp!(_, ExpDotted_::Exp(lhs)) => *lhs,
        edot => {
            let name = match &edot {
                sp!(_, ExpDotted_::Exp(_)) => panic!("ICE covered above"),
                sp!(_, ExpDotted_::TmpBorrow(_, _)) => panic!("ICE why is this here?"),
                sp!(_, ExpDotted_::Dot(_, name, _)) => name.clone(),
            };
            let eborrow = exp_dotted_to_borrow(context, eloc, false, edot);
            context.add_implicit_copyable_constraint(
                eloc,
                format!("Invalid implicit copy of field '{}'.", name),
                inner_ty.clone(),
                "Try adding '*&' to the front of the field access",
            );
            T::exp(inner_ty, sp(eloc, TE::Dereference(Box::new(eborrow))))
        }
    }
}

impl crate::shared::ast_debug::AstDebug for ExpDotted_ {
    fn ast_debug(&self, w: &mut crate::shared::ast_debug::AstWriter) {
        use ExpDotted_ as D;
        match self {
            D::Exp(e) => e.ast_debug(w),
            D::TmpBorrow(e, ty) => {
                w.write("&tmp ");
                w.annotate(|w| e.ast_debug(w), ty)
            }
            D::Dot(e, n, ty) => {
                e.ast_debug(w);
                w.write(".");
                w.annotate(|w| w.write(&format!("{}", n)), ty)
            }
        }
    }
}

//**************************************************************************************************
// Calls
//**************************************************************************************************

fn module_call(
    context: &mut Context,
    loc: Loc,
    m: ModuleIdent,
    f: FunctionName,
    ty_args_opt: Option<Vec<Type>>,
    argloc: Loc,
    args: Vec<T::Exp>,
) -> (Type, T::UnannotatedExp_) {
    let (_, ty_args, parameters, acquires, ret_ty) =
        core::make_function_type(context, loc, &m, &f, ty_args_opt);
    let (arguments, arg_tys) = call_args(
        context,
        loc,
        || format!("Invalid call of '{}::{}'", &m, &f),
        parameters.len(),
        argloc,
        args,
    );
    assert!(arg_tys.len() == parameters.len());
    for (arg_ty, (param, param_ty)) in arg_tys.into_iter().zip(parameters.clone()) {
        let msg = || {
            format!(
                "Invalid call of '{}::{}'. Invalid argument for parameter '{}'",
                &m, &f, param
            )
        };
        subtype(context, loc, msg, arg_ty, param_ty);
    }
    let params_ty_list = parameters.into_iter().map(|(_, ty)| ty).collect();
    let call = T::ModuleCall {
        module: m,
        name: f,
        type_arguments: ty_args,
        arguments,
        parameter_types: params_ty_list,
        acquires,
    };
    (ret_ty, T::UnannotatedExp_::ModuleCall(Box::new(call)))
}

fn builtin_call(
    context: &mut Context,
    loc: Loc,
    sp!(bloc, nb_): N::BuiltinFunction,
    argloc: Loc,
    args: Vec<T::Exp>,
) -> (Type, T::UnannotatedExp_) {
    use N::BuiltinFunction_ as NB;
    use T::BuiltinFunction_ as TB;
    let mut mk_ty_arg = |ty_arg_opt| match ty_arg_opt {
        None => core::make_tvar(context, loc),
        Some(ty_arg) => core::instantiate(context, ty_arg),
    };
    let (b_, params_ty, ret_ty);
    match nb_ {
        NB::MoveTo(ty_arg_opt) => {
            let ty_arg = mk_ty_arg(ty_arg_opt);
            b_ = TB::MoveTo(ty_arg.clone());
            context.add_ability_constraint(
                loc,
                Some(format!("Invalid call of '{}'", &b_)),
                ty_arg.clone(),
                Ability_::Key,
            );
            let signer_ = Box::new(Type_::signer(bloc));
            params_ty = vec![sp(bloc, Type_::Ref(false, signer_)), ty_arg];
            ret_ty = sp(loc, Type_::Unit);
        }
        NB::MoveFrom(ty_arg_opt) => {
            let ty_arg = mk_ty_arg(ty_arg_opt);
            b_ = TB::MoveFrom(ty_arg.clone());
            context.add_ability_constraint(
                loc,
                Some(format!("Invalid call of '{}'", &b_)),
                ty_arg.clone(),
                Ability_::Key,
            );
            params_ty = vec![Type_::address(bloc)];
            ret_ty = ty_arg;
        }
        NB::BorrowGlobal(mut_, ty_arg_opt) => {
            let ty_arg = mk_ty_arg(ty_arg_opt);
            b_ = TB::BorrowGlobal(mut_, ty_arg.clone());
            context.add_ability_constraint(
                loc,
                Some(format!("Invalid call of '{}'", &b_)),
                ty_arg.clone(),
                Ability_::Key,
            );
            params_ty = vec![Type_::address(bloc)];
            ret_ty = sp(loc, Type_::Ref(mut_, Box::new(ty_arg)));
        }
        NB::Exists(ty_arg_opt) => {
            let ty_arg = mk_ty_arg(ty_arg_opt);
            b_ = TB::Exists(ty_arg.clone());
            context.add_ability_constraint(
                loc,
                Some(format!("Invalid call of '{}'", &b_)),
                ty_arg,
                Ability_::Key,
            );
            params_ty = vec![Type_::address(bloc)];
            ret_ty = Type_::bool(loc);
        }
        NB::Freeze(ty_arg_opt) => {
            let ty_arg = mk_ty_arg(ty_arg_opt);
            b_ = TB::Freeze(ty_arg.clone());
            params_ty = vec![sp(bloc, Type_::Ref(true, Box::new(ty_arg.clone())))];
            ret_ty = sp(loc, Type_::Ref(false, Box::new(ty_arg)));
        }
        NB::Assert => {
            b_ = TB::Assert;
            params_ty = vec![Type_::bool(bloc), Type_::u64(bloc)];
            ret_ty = sp(loc, Type_::Unit);
        }
    };
    let (arguments, arg_tys) = call_args(
        context,
        loc,
        || format!("Invalid call of '{}'", &b_),
        params_ty.len(),
        argloc,
        args,
    );
    assert!(arg_tys.len() == params_ty.len());
    for ((idx, arg_ty), param_ty) in arg_tys.into_iter().enumerate().zip(params_ty) {
        let msg = || {
            format!(
                "Invalid call of '{}'. Invalid argument for parameter '{}'",
                &b_, idx
            )
        };
        subtype(context, loc, msg, arg_ty, param_ty);
    }
    let call = T::UnannotatedExp_::Builtin(Box::new(sp(bloc, b_)), arguments);
    (ret_ty, call)
}

fn call_args<S: std::fmt::Display, F: Fn() -> S>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    arity: usize,
    argloc: Loc,
    mut args: Vec<T::Exp>,
) -> (Box<T::Exp>, Vec<Type>) {
    use T::UnannotatedExp_ as TE;
    let tys = args.iter().map(|e| e.ty.clone()).collect();
    let tys = make_arg_types(context, loc, msg, arity, argloc, tys);
    let arg = match args.len() {
        0 => T::exp(
            sp(argloc, Type_::Unit),
            sp(argloc, TE::Unit { trailing: false }),
        ),
        1 => args.pop().unwrap(),
        _ => {
            let ty = Type_::multiple(argloc, tys.clone());
            let items = args.into_iter().map(T::single_item).collect();
            T::exp(ty, sp(argloc, TE::ExpList(items)))
        }
    };
    (Box::new(arg), tys)
}

fn make_arg_types<S: std::fmt::Display, F: Fn() -> S>(
    context: &mut Context,
    loc: Loc,
    msg: F,
    arity: usize,
    argloc: Loc,
    mut given: Vec<Type>,
) -> Vec<Type> {
    let given_len = given.len();
    if given_len != arity {
        let code = if given_len < arity {
            TypeSafety::TooFewArguments
        } else {
            TypeSafety::TooManyArguments
        };
        let cmsg = format!(
            "{}. The call expected {} argument(s) but got {}",
            msg(),
            arity,
            given_len
        );
        context.env.add_diag(diag!(
            code,
            (loc, cmsg),
            (argloc, format!("Found {} argument(s) here", given_len)),
        ));
    }
    while given.len() < arity {
        given.push(context.error_type(argloc))
    }
    while given.len() > arity {
        given.pop();
    }
    given
}
