// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::core::{self, Context};
use crate::{
    diag,
    expansion::ast::Value_,
    naming::ast::{BuiltinTypeName_, FunctionSignature, Type, TypeName_, Type_},
    typing::ast as T,
};
use move_ir_types::location::*;
use std::convert::TryInto;

//**************************************************************************************************
// Functions
//**************************************************************************************************

pub fn function_body_(context: &mut Context, b_: &mut T::FunctionBody_) {
    match b_ {
        T::FunctionBody_::Native => (),
        T::FunctionBody_::Defined(es) => sequence(context, es),
    }
}

pub fn function_signature(context: &mut Context, sig: &mut FunctionSignature) {
    for (_, st) in &mut sig.parameters {
        type_(context, st);
    }
    type_(context, &mut sig.return_type);
}

//**************************************************************************************************
// Types
//**************************************************************************************************

fn expected_types(context: &mut Context, ss: &mut Vec<Option<Type>>) {
    for st_opt in ss.iter_mut().flatten() {
        type_(context, st_opt);
    }
}

fn types(context: &mut Context, ss: &mut Vec<Type>) {
    for st in ss {
        type_(context, st);
    }
}

pub fn type_(context: &mut Context, ty: &mut Type) {
    use Type_::*;
    match &mut ty.value {
        Anything | UnresolvedError | Param(_) | Unit => (),
        Ref(_, b) => type_(context, b),
        Var(tvar) => {
            let ty_tvar = sp(ty.loc, Var(*tvar));
            let replacement = core::unfold_type(&context.subst, ty_tvar);
            let replacement = match replacement {
                sp!(_, Var(_)) => panic!("ICE unfold_type_base failed to expand"),
                sp!(loc, Anything) => {
                    let msg = "Could not infer this type. Try adding an annotation";
                    context
                        .env
                        .add_diag(diag!(TypeSafety::UninferredType, (ty.loc, msg)));
                    sp(loc, UnresolvedError)
                }
                t => t,
            };
            *ty = replacement;
            type_(context, ty);
        }
        Apply(Some(_), sp!(_, TypeName_::Builtin(_)), tys) => types(context, tys),
        Apply(Some(_), _, _) => panic!("ICE expanding pre expanded type"),
        Apply(None, _, _) => {
            let abilities = core::infer_abilities(&context, &context.subst, ty.clone());
            match &mut ty.value {
                Apply(abilities_opt, _, tys) => {
                    *abilities_opt = Some(abilities);
                    types(context, tys);
                }
                _ => panic!("ICE impossible. tapply switched to nontapply"),
            }
        }
    }
}

//**************************************************************************************************
// Expressions
//**************************************************************************************************

fn sequence(context: &mut Context, seq: &mut T::Sequence) {
    for item in seq {
        sequence_item(context, item)
    }
}

fn sequence_item(context: &mut Context, item: &mut T::SequenceItem) {
    use T::SequenceItem_ as S;
    match &mut item.value {
        S::Seq(te) => exp(context, te),

        S::Declare(tbind) => lvalues(context, tbind),
        S::Bind(tbind, tys, te) => {
            lvalues(context, tbind);
            expected_types(context, tys);
            exp(context, te)
        }
    }
}

pub fn exp(context: &mut Context, e: &mut T::Exp) {
    use T::UnannotatedExp_ as E;
    match &e.exp.value {
        // dont expand the type for return, abort, break, or continue
        E::Break | E::Continue | E::Return(_) | E::Abort(_) => {
            let t = e.ty.clone();
            match core::unfold_type(&context.subst, t) {
                sp!(_, Type_::Anything) => (),
                mut t => {
                    // report errors if there is an uninferred type argument somewhere
                    type_(context, &mut t);
                }
            }
            e.ty = sp(e.ty.loc, Type_::Anything)
        }
        // Loop's default type is ()
        E::Loop {
            has_break: false, ..
        } => {
            let t = e.ty.clone();
            match core::unfold_type(&context.subst, t) {
                sp!(_, Type_::Anything) => (),
                mut t => {
                    // report errors if there is an uninferred type argument somewhere
                    type_(context, &mut t);
                }
            }
            e.ty = sp(e.ty.loc, Type_::Anything)
        }
        _ => type_(context, &mut e.ty),
    }
    match &mut e.exp.value {
        E::Use(v) => {
            let from_user = false;
            let var = v.clone();
            e.exp.value = if core::is_implicitly_copyable(&context.subst, &e.ty) {
                E::Copy { from_user, var }
            } else {
                E::Move { from_user, var }
            }
        }
        E::Value(sp!(vloc, Value_::InferredNum(v))) => {
            use BuiltinTypeName_ as BT;
            let bt = match e.ty.value.builtin_name() {
                Some(sp!(_, bt)) if bt.is_numeric() => bt,
                _ => panic!("ICE inferred num failed {:?}", &e.ty.value),
            };
            let v = *v;
            let u8_max = std::u8::MAX as u128;
            let u64_max = std::u64::MAX as u128;
            let u128_max = std::u128::MAX;
            let max = match bt {
                BT::U8 => u8_max,
                BT::U64 => u64_max,
                BT::U128 => u128_max,
                _ => unreachable!(),
            };
            let new_exp = if v > max {
                let msg = format!(
                    "Expected a literal of type '{}', but the value is too large.",
                    bt
                );
                let fix_bt = if v > u64_max {
                    BT::U128
                } else {
                    assert!(v > u8_max);
                    BT::U64
                };
                let fix = format!(
                    "Annotating the literal might help inference: '{value}{type}'",
                    value=v,
                    type=fix_bt,
                );
                context.env.add_diag(diag!(
                    TypeSafety::InvalidNum,
                    (e.exp.loc, "Invalid numerical literal"),
                    (e.ty.loc, msg),
                    (e.exp.loc, fix),
                ));
                E::UnresolvedError
            } else {
                let value_ = match bt {
                    BT::U8 => Value_::U8(v.try_into().unwrap()),
                    BT::U64 => Value_::U64(v.try_into().unwrap()),
                    BT::U128 => Value_::U128(v),
                    _ => unreachable!(),
                };
                E::Value(sp(*vloc, value_))
            };
            e.exp.value = new_exp;
        }

        E::Spec(_, used_locals) => used_locals.values_mut().for_each(|ty| type_(context, ty)),

        E::Unit { .. }
        | E::Value(_)
        | E::Constant(_, _)
        | E::Move { .. }
        | E::Copy { .. }
        | E::BorrowLocal(_, _)
        | E::Break
        | E::Continue
        | E::UnresolvedError => (),

        E::ModuleCall(call) => module_call(context, call),
        E::Builtin(b, args) => {
            builtin_function(context, b);
            exp(context, args);
        }

        E::IfElse(eb, et, ef) => {
            exp(context, eb);
            exp(context, et);
            exp(context, ef);
        }
        E::While(eb, eloop) => {
            exp(context, eb);
            exp(context, eloop);
        }
        E::Loop { body: eloop, .. } => exp(context, eloop),
        E::Block(seq) => sequence(context, seq),
        E::Assign(assigns, tys, er) => {
            lvalues(context, assigns);
            expected_types(context, tys);
            exp(context, er);
        }

        E::Return(er)
        | E::Abort(er)
        | E::Dereference(er)
        | E::UnaryExp(_, er)
        | E::Borrow(_, er, _)
        | E::TempBorrow(_, er) => exp(context, er),
        E::Mutate(el, er) => {
            exp(context, el);
            exp(context, er)
        }
        E::BinopExp(el, _, operand_ty, er) => {
            exp(context, el);
            exp(context, er);
            type_(context, operand_ty);
        }

        E::Pack(_, _, bs, fields) => {
            types(context, bs);
            for (_, _, (_, (bt, fe))) in fields.iter_mut() {
                type_(context, bt);
                exp(context, fe)
            }
        }
        E::ExpList(el) => exp_list(context, el),
        E::Cast(el, rhs_ty) | E::Annotate(el, rhs_ty) => {
            exp(context, el);
            type_(context, rhs_ty);
        }
    }
}

fn lvalues(context: &mut Context, binds: &mut T::LValueList) {
    for b in &mut binds.value {
        lvalue(context, b)
    }
}

fn lvalue(context: &mut Context, b: &mut T::LValue) {
    use T::LValue_ as L;
    match &mut b.value {
        L::Ignore => (),
        L::Var(_, ty) => {
            type_(context, ty);
        }
        L::BorrowUnpack(_, _, _, bts, fields) | L::Unpack(_, _, bts, fields) => {
            types(context, bts);
            for (_, _, (_, (bt, innerb))) in fields.iter_mut() {
                type_(context, bt);
                lvalue(context, innerb)
            }
        }
    }
}

fn module_call(context: &mut Context, call: &mut T::ModuleCall) {
    types(context, &mut call.type_arguments);
    exp(context, &mut call.arguments);
    types(context, &mut call.parameter_types)
}

fn builtin_function(context: &mut Context, b: &mut T::BuiltinFunction) {
    use T::BuiltinFunction_ as B;
    match &mut b.value {
        B::MoveTo(bt)
        | B::MoveFrom(bt)
        | B::BorrowGlobal(_, bt)
        | B::Exists(bt)
        | B::Freeze(bt) => {
            type_(context, bt);
        }
        B::Assert => (),
    }
}

fn exp_list(context: &mut Context, items: &mut Vec<T::ExpListItem>) {
    for item in items {
        exp_list_item(context, item)
    }
}

fn exp_list_item(context: &mut Context, item: &mut T::ExpListItem) {
    use T::ExpListItem as I;
    match item {
        I::Single(e, st) => {
            exp(context, e);
            type_(context, st);
        }
        I::Splat(_, e, ss) => {
            exp(context, e);
            types(context, ss);
        }
    }
}
