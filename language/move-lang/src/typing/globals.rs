// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::core::{self, Context, Subst};
use crate::{
    diag,
    naming::ast::{self as N, Type, TypeName_, Type_},
    parser::ast::{Ability_, StructName},
    typing::ast as T,
};
use move_ir_types::location::*;
use std::collections::BTreeMap;

pub type Seen = BTreeMap<StructName, Loc>;

//**************************************************************************************************
// Functions
//**************************************************************************************************

pub fn function_body_(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    b_: &T::FunctionBody_,
) {
    let mut seen = Seen::new();
    match b_ {
        T::FunctionBody_::Native => return,
        T::FunctionBody_::Defined(es) => sequence(context, annotated_acquires, &mut seen, es),
    }

    for (annotated_acquire, annotated_loc) in annotated_acquires {
        if !seen.contains_key(&annotated_acquire) {
            let msg = format!(
                "Invalid 'acquires' list. The struct '{}::{}' was never acquired by '{}', '{}', \
                 '{}', or a transitive call",
                context.current_module.as_ref().unwrap(),
                annotated_acquire,
                N::BuiltinFunction_::MOVE_FROM,
                N::BuiltinFunction_::BORROW_GLOBAL,
                N::BuiltinFunction_::BORROW_GLOBAL_MUT
            );
            context
                .env
                .add_diag(diag!(Declarations::UnnecessaryItem, (*annotated_loc, msg)))
        }
    }
}

//**************************************************************************************************
// Expressions
//**************************************************************************************************

fn sequence(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    seen: &mut Seen,
    seq: &T::Sequence,
) {
    for item in seq {
        sequence_item(context, annotated_acquires, seen, item)
    }
}

fn sequence_item(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    seen: &mut Seen,
    item: &T::SequenceItem,
) {
    use T::SequenceItem_ as S;
    match &item.value {
        S::Bind(_, _, te) | S::Seq(te) => exp(context, annotated_acquires, seen, te),

        S::Declare(_) => (),
    }
}

fn exp(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    seen: &mut Seen,
    e: &T::Exp,
) {
    use T::UnannotatedExp_ as E;
    match &e.exp.value {
        E::Use(_) => panic!("ICE should have been expanded"),

        E::Unit { .. }
        | E::Value(_)
        | E::Constant(_, _)
        | E::Move { .. }
        | E::Copy { .. }
        | E::BorrowLocal(_, _)
        | E::Break
        | E::Continue
        | E::Spec(_, _)
        | E::UnresolvedError => (),

        E::ModuleCall(call) if is_current_function(context, call) => {
            exp(context, annotated_acquires, seen, &call.arguments);
        }

        E::ModuleCall(call) => {
            let loc = e.exp.loc;
            let msg = || format!("Invalid call to '{}::{}'", &call.module, &call.name);
            for (sn, sloc) in &call.acquires {
                check_acquire_listed(context, annotated_acquires, loc, msg, sn, *sloc);
                seen.insert(sn.clone(), *sloc);
            }

            exp(context, annotated_acquires, seen, &call.arguments);
        }
        E::Builtin(b, args) => {
            builtin_function(context, annotated_acquires, seen, &e.exp.loc, b);
            exp(context, annotated_acquires, seen, args);
        }

        E::IfElse(eb, et, ef) => {
            exp(context, annotated_acquires, seen, eb);
            exp(context, annotated_acquires, seen, et);
            exp(context, annotated_acquires, seen, ef);
        }
        E::While(eb, eloop) => {
            exp(context, annotated_acquires, seen, eb);
            exp(context, annotated_acquires, seen, eloop);
        }
        E::Loop { body: eloop, .. } => exp(context, annotated_acquires, seen, eloop),
        E::Block(seq) => sequence(context, annotated_acquires, seen, seq),
        E::Assign(_, _, er) => {
            exp(context, annotated_acquires, seen, er);
        }

        E::Return(er)
        | E::Abort(er)
        | E::Dereference(er)
        | E::UnaryExp(_, er)
        | E::Borrow(_, er, _)
        | E::TempBorrow(_, er) => exp(context, annotated_acquires, seen, er),
        E::Mutate(el, er) | E::BinopExp(el, _, _, er) => {
            exp(context, annotated_acquires, seen, el);
            exp(context, annotated_acquires, seen, er)
        }

        E::Pack(_, _, _, fields) => {
            for (_, _, (_, (_, fe))) in fields {
                exp(context, annotated_acquires, seen, fe)
            }
        }
        E::ExpList(el) => exp_list(context, annotated_acquires, seen, el),

        E::Cast(e, _) | E::Annotate(e, _) => exp(context, annotated_acquires, seen, e),
    }
}

fn exp_list(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    seen: &mut Seen,
    items: &[T::ExpListItem],
) {
    for item in items {
        exp_list_item(context, annotated_acquires, seen, item)
    }
}

fn exp_list_item(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    seen: &mut Seen,
    item: &T::ExpListItem,
) {
    use T::ExpListItem as I;
    match item {
        I::Single(e, _) | I::Splat(_, e, _) => {
            exp(context, annotated_acquires, seen, e);
        }
    }
}

fn is_current_function(context: &Context, call: &T::ModuleCall) -> bool {
    context.is_current_function(&call.module, &call.name)
}

fn builtin_function(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    seen: &mut Seen,
    loc: &Loc,
    sp!(_, b_): &T::BuiltinFunction,
) {
    use T::BuiltinFunction_ as B;
    let mk_msg = |s| move || format!("Invalid call to {}.", s);
    match b_ {
        B::MoveFrom(bt) | B::BorrowGlobal(_, bt) => {
            let msg = mk_msg(b_.display_name());
            if let Some(sn) = check_global_access(context, loc, msg, bt) {
                check_acquire_listed(context, annotated_acquires, *loc, msg, sn, bt.loc);
                seen.insert(sn.clone(), bt.loc);
            }
        }

        B::MoveTo(bt) | B::Exists(bt) => {
            let msg = mk_msg(b_.display_name());
            check_global_access(context, loc, msg, bt);
        }

        B::Freeze(_) | B::Assert => (),
    }
}

//**************************************************************************************************
// Checks
//**************************************************************************************************

fn check_acquire_listed<F>(
    context: &mut Context,
    annotated_acquires: &BTreeMap<StructName, Loc>,
    loc: Loc,
    msg: F,
    global_type_name: &StructName,
    global_type_loc: Loc,
) where
    F: Fn() -> String,
{
    if !annotated_acquires.contains_key(global_type_name) {
        let tmsg = format!(
            "The call acquires '{}::{}', but the 'acquires' list for the current function does \
             not contain this type. It must be present in the calling context's acquires list",
            context.current_module.as_ref().unwrap(),
            global_type_name
        );
        context.env.add_diag(diag!(
            TypeSafety::MissingAcquires,
            (loc, msg()),
            (global_type_loc, tmsg)
        ));
    }
}

fn check_global_access<'a, F>(
    context: &mut Context,
    loc: &Loc,
    msg: F,
    global_type: &'a Type,
) -> Option<&'a StructName>
where
    F: Fn() -> String,
{
    check_global_access_(context, loc, msg, global_type)
}

fn check_global_access_<'a, F>(
    context: &mut Context,
    loc: &Loc,
    msg: F,
    global_type: &'a Type,
) -> Option<&'a StructName>
where
    F: Fn() -> String,
{
    use TypeName_ as TN;
    use Type_ as T;
    let tloc = &global_type.loc;
    let (declared_module, sn) = match &global_type.value {
        T::Var(_) | T::Apply(None, _, _) => panic!("ICE type expansion failed"),
        T::Anything | T::UnresolvedError => {
            return None;
        }
        T::Ref(_, _) | T::Unit => {
            // Key ability is checked by constraints, and these types do not have Key
            assert!(context.env.has_errors());
            return None;
        }
        T::Apply(Some(abilities), sp!(_, TN::Multiple(_)), _)
        | T::Apply(Some(abilities), sp!(_, TN::Builtin(_)), _) => {
            // Key ability is checked by constraints
            assert!(!abilities.has_ability_(Ability_::Key));
            assert!(context.env.has_errors());
            return None;
        }
        T::Param(_) => {
            let ty_debug = core::error_format(global_type, &Subst::empty());
            let tmsg = format!(
                "Expected a struct type. Global storage operations are restricted to struct types \
                 declared in the current module. Found the type parameter: {}",
                ty_debug
            );

            context.env.add_diag(diag!(
                TypeSafety::ExpectedSpecificType,
                (*loc, msg()),
                (*tloc, tmsg)
            ));
            return None;
        }

        T::Apply(Some(_), sp!(_, TN::ModuleType(m, s)), _args) => (m.clone(), s),
    };

    match &context.current_module {
        Some(current_module) if current_module != &declared_module => {
            let ty_debug = core::error_format(global_type, &Subst::empty());
            let tmsg = format!(
                "The type {} was not declared in the current module. Global storage access is \
                 internal to the module'",
                ty_debug
            );
            context
                .env
                .add_diag(diag!(TypeSafety::Visibility, (*loc, msg()), (*tloc, tmsg)));
            return None;
        }
        None => {
            let msg = "Global storage operator cannot be used from a 'script' function";
            context
                .env
                .add_diag(diag!(TypeSafety::Visibility, (*loc, msg)));
            return None;
        }
        _ => (),
    }

    Some(sn)
}
