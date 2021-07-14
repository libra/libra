// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    diag,
    errors::{
        diagnostic_codes::{AbilitySafety, NameResolution},
        new::Diagnostic,
        *,
    },
    expansion::ast::{AbilitySet, ModuleIdent},
    naming::ast::{
        self as N, BuiltinTypeName_, FunctionSignature, StructDefinition, StructTypeParameter,
        TParam, TParamID, TVar, Type, TypeName, TypeName_, Type_,
    },
    parser::ast::{Ability_, ConstantName, Field, FunctionName, StructName, Var, Visibility},
    shared::{unique_map::UniqueMap, *},
    FullyCompiledProgram,
};
use move_ir_types::location::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

//**************************************************************************************************
// Context
//**************************************************************************************************

pub enum Constraint {
    IsImplicitlyCopyable {
        loc: Loc,
        msg: String,
        ty: Type,
        fix: String,
    },
    AbilityConstraint {
        loc: Loc,
        msg: Option<String>,
        ty: Type,
        constraints: AbilitySet,
    },
    NumericConstraint(Loc, &'static str, Type),
    BitsConstraint(Loc, &'static str, Type),
    OrderedConstraint(Loc, &'static str, Type),
    BaseTypeConstraint(Loc, String, Type),
    SingleTypeConstraint(Loc, String, Type),
}
pub type Constraints = Vec<Constraint>;
pub type TParamSubst = HashMap<TParamID, Type>;

pub struct FunctionInfo {
    pub defined_loc: Loc,
    pub visibility: Visibility,
    pub signature: FunctionSignature,
    pub acquires: BTreeMap<StructName, Loc>,
}

pub struct ConstantInfo {
    pub defined_loc: Loc,
    pub signature: Type,
}

pub struct ModuleInfo {
    pub friends: UniqueMap<ModuleIdent, Loc>,
    pub structs: UniqueMap<StructName, StructDefinition>,
    pub functions: UniqueMap<FunctionName, FunctionInfo>,
    pub constants: UniqueMap<ConstantName, ConstantInfo>,
}

pub struct LoopInfo(LoopInfo_);

enum LoopInfo_ {
    NotInLoop,
    BreakTypeUnknown,
    BreakType(Box<Type>),
}

pub struct Context<'env> {
    pub modules: UniqueMap<ModuleIdent, ModuleInfo>,
    pub env: &'env mut CompilationEnv,

    pub current_module: Option<ModuleIdent>,
    pub current_function: Option<FunctionName>,
    pub current_script_constants: Option<UniqueMap<ConstantName, ConstantInfo>>,
    pub return_type: Option<Type>,
    locals: UniqueMap<Var, Type>,

    pub subst: Subst,
    pub constraints: Constraints,

    loop_info: LoopInfo,
}

impl<'env> Context<'env> {
    pub fn new(
        env: &'env mut CompilationEnv,
        pre_compiled_lib: Option<&FullyCompiledProgram>,
        prog: &N::Program,
    ) -> Self {
        let all_modules = prog.modules.key_cloned_iter().chain(
            pre_compiled_lib
                .iter()
                .map(|pre_compiled| {
                    pre_compiled
                        .naming
                        .modules
                        .key_cloned_iter()
                        .filter(|(mident, _m)| !prog.modules.contains_key(mident))
                })
                .flatten(),
        );
        let modules = UniqueMap::maybe_from_iter(all_modules.map(|(mident, mdef)| {
            let structs = mdef.structs.clone();
            let functions = mdef.functions.ref_map(|fname, fdef| FunctionInfo {
                defined_loc: fname.loc(),
                visibility: fdef.visibility.clone(),
                signature: fdef.signature.clone(),
                acquires: fdef.acquires.clone(),
            });
            let constants = mdef.constants.ref_map(|cname, cdef| ConstantInfo {
                defined_loc: cname.loc(),
                signature: cdef.signature.clone(),
            });
            let minfo = ModuleInfo {
                friends: mdef.friends.ref_map(|_, friend| friend.loc),
                structs,
                functions,
                constants,
            };
            (mident, minfo)
        }))
        .unwrap();
        Context {
            subst: Subst::empty(),
            current_module: None,
            current_function: None,
            current_script_constants: None,
            return_type: None,
            constraints: vec![],
            locals: UniqueMap::new(),
            loop_info: LoopInfo(LoopInfo_::NotInLoop),
            modules,
            env,
        }
    }

    pub fn reset_for_module_item(&mut self) {
        assert!(
            matches!(&self.loop_info, LoopInfo(LoopInfo_::NotInLoop)),
            "ICE loop_info should be reset after the loop"
        );
        self.return_type = None;
        self.locals = UniqueMap::new();
        self.subst = Subst::empty();
        self.constraints = Constraints::new();
        self.current_function = None;
    }

    pub fn bind_script_constants(&mut self, constants: &UniqueMap<ConstantName, N::Constant>) {
        assert!(self.current_script_constants.is_none());
        self.current_script_constants = Some(constants.ref_map(|cname, cdef| ConstantInfo {
            defined_loc: cname.loc(),
            signature: cdef.signature.clone(),
        }));
    }

    pub fn error_type(&mut self, loc: Loc) -> Type {
        sp(loc, Type_::UnresolvedError)
    }

    pub fn add_implicit_copyable_constraint(
        &mut self,
        loc: Loc,
        msg: impl Into<String>,
        ty: Type,
        fix: impl Into<String>,
    ) {
        let msg = msg.into();
        let fix = fix.into();
        self.constraints
            .push(Constraint::IsImplicitlyCopyable { loc, msg, ty, fix })
    }
    pub fn add_ability_constraint(
        &mut self,
        loc: Loc,
        msg_opt: Option<impl Into<String>>,
        ty: Type,
        ability_: Ability_,
    ) {
        self.add_ability_set_constraint(
            loc,
            msg_opt,
            ty,
            AbilitySet::from_abilities(vec![sp(loc, ability_)]).unwrap(),
        )
    }

    pub fn add_ability_set_constraint(
        &mut self,
        loc: Loc,
        msg_opt: Option<impl Into<String>>,
        ty: Type,
        constraints: AbilitySet,
    ) {
        self.constraints.push(Constraint::AbilityConstraint {
            loc,
            msg: msg_opt.map(|s| s.into()),
            ty,
            constraints,
        })
    }

    pub fn add_base_type_constraint(&mut self, loc: Loc, msg: impl Into<String>, t: Type) {
        self.constraints
            .push(Constraint::BaseTypeConstraint(loc, msg.into(), t))
    }

    pub fn add_single_type_constraint(&mut self, loc: Loc, msg: impl Into<String>, t: Type) {
        self.constraints
            .push(Constraint::SingleTypeConstraint(loc, msg.into(), t))
    }

    pub fn add_numeric_constraint(&mut self, loc: Loc, op: &'static str, t: Type) {
        self.constraints
            .push(Constraint::NumericConstraint(loc, op, t))
    }

    pub fn add_bits_constraint(&mut self, loc: Loc, op: &'static str, t: Type) {
        self.constraints
            .push(Constraint::BitsConstraint(loc, op, t))
    }

    pub fn add_ordered_constraint(&mut self, loc: Loc, op: &'static str, t: Type) {
        self.constraints
            .push(Constraint::OrderedConstraint(loc, op, t))
    }

    pub fn declare_local(&mut self, var: Var, ty_opt: Option<Type>) {
        let status = match ty_opt {
            None => make_tvar(self, var.loc()),
            Some(t) => t,
        };
        // Might overwrite (i.e. shadow) the current local's type
        self.locals.remove(&var);
        self.locals.add(var, status).unwrap();
    }

    pub fn get_local_(&mut self, var: &Var) -> Option<Type> {
        self.locals.get(var).cloned()
    }

    pub fn get_local(&mut self, loc: Loc, verb: &str, var: &Var) -> Type {
        match self.get_local_(var) {
            None => {
                self.env.add_diag(diag!(
                    NameResolution::UnboundVariable,
                    (loc, format!("Invalid {}. Unbound variable '{}'", verb, var)),
                ));
                self.error_type(loc)
            }
            Some(t) => t,
        }
    }

    pub fn save_locals_scope(&self) -> UniqueMap<Var, Type> {
        self.locals.clone()
    }

    pub fn close_locals_scope(
        &mut self,
        old_locals: UniqueMap<Var, Type>,
        declared: UniqueMap<Var, ()>,
    ) {
        // remove new locals from inner scope
        for (_, new_local, _) in declared
            .iter()
            .filter(|(_, v, _)| !old_locals.contains_key_(v))
        {
            self.locals.remove_(&new_local);
        }

        // return old type
        let shadowed = old_locals
            .into_iter()
            .filter(|(k, _)| declared.contains_key(k));
        for (var, shadowed_type) in shadowed {
            self.locals.remove(&var);
            self.locals.add(var, shadowed_type).unwrap();
        }
    }

    pub fn is_current_module(&self, m: &ModuleIdent) -> bool {
        match &self.current_module {
            Some(curm) => curm == m,
            None => false,
        }
    }

    pub fn is_current_function(&self, m: &ModuleIdent, f: &FunctionName) -> bool {
        self.is_current_module(m) && matches!(&self.current_function, Some(curf) if curf == f)
    }

    fn is_in_script_context(&self) -> bool {
        match (&self.current_module, &self.current_function) {
            // in a constant
            (_, None) => false,
            // in a script function
            (None, Some(_)) => true,
            // in a module function
            (Some(current_m), Some(current_f)) => {
                let current_finfo = self.function_info(current_m, current_f);
                match &current_finfo.visibility {
                    Visibility::Public(_) | Visibility::Friend(_) | Visibility::Internal => false,
                    Visibility::Script(_) => true,
                }
            }
        }
    }

    fn current_module_is_a_friend_of(&self, m: &ModuleIdent) -> bool {
        match &self.current_module {
            None => false,
            Some(current_mident) => {
                let minfo = self.module_info(m);
                minfo.friends.contains_key(current_mident)
            }
        }
    }

    fn module_info(&self, m: &ModuleIdent) -> &ModuleInfo {
        self.modules
            .get(m)
            .expect("ICE should have failed in naming")
    }

    fn struct_definition(&self, m: &ModuleIdent, n: &StructName) -> &StructDefinition {
        let minfo = self.module_info(m);
        minfo
            .structs
            .get(n)
            .expect("ICE should have failed in naming")
    }

    pub fn struct_declared_abilities(&self, m: &ModuleIdent, n: &StructName) -> &AbilitySet {
        &self.struct_definition(m, n).abilities
    }

    pub fn struct_declared_loc(&self, m: &ModuleIdent, n: &StructName) -> Loc {
        let minfo = self.module_info(m);
        *minfo
            .structs
            .get_loc(n)
            .expect("ICE should have failed in naming")
    }

    pub fn struct_tparams(&self, m: &ModuleIdent, n: &StructName) -> &Vec<StructTypeParameter> {
        &self.struct_definition(m, n).type_parameters
    }

    fn function_info(&self, m: &ModuleIdent, n: &FunctionName) -> &FunctionInfo {
        self.module_info(m)
            .functions
            .get(n)
            .expect("ICE should have failed in naming")
    }

    fn constant_info(&mut self, m_opt: &Option<ModuleIdent>, n: &ConstantName) -> &ConstantInfo {
        let constants = match m_opt {
            None => self.current_script_constants.as_ref().unwrap(),
            Some(m) => &self.module_info(m).constants,
        };
        constants.get(n).expect("ICE should have failed in naming")
    }

    pub fn in_loop(&self) -> bool {
        match &self.loop_info.0 {
            LoopInfo_::NotInLoop => false,
            LoopInfo_::BreakTypeUnknown | LoopInfo_::BreakType(_) => true,
        }
    }

    pub fn get_break_type(&self) -> Option<&Type> {
        match &self.loop_info.0 {
            LoopInfo_::NotInLoop | LoopInfo_::BreakTypeUnknown => None,
            LoopInfo_::BreakType(t) => Some(&*t),
        }
    }

    pub fn set_break_type(&mut self, t: Type) {
        match &self.loop_info.0 {
            LoopInfo_::NotInLoop => (),
            LoopInfo_::BreakTypeUnknown | LoopInfo_::BreakType(_) => {
                self.loop_info.0 = LoopInfo_::BreakType(Box::new(t))
            }
        }
    }

    pub fn enter_loop(&mut self) -> LoopInfo {
        std::mem::replace(&mut self.loop_info, LoopInfo(LoopInfo_::BreakTypeUnknown))
    }

    // Reset loop info and return the loop's break type, if it has one
    pub fn exit_loop(&mut self, old_info: LoopInfo) -> Option<Type> {
        match std::mem::replace(&mut self.loop_info, old_info).0 {
            LoopInfo_::NotInLoop => panic!("ICE exit_loop called while not in a loop"),
            LoopInfo_::BreakTypeUnknown => None,
            LoopInfo_::BreakType(t) => Some(*t),
        }
    }
}

//**************************************************************************************************
// Subst
//**************************************************************************************************

#[derive(Clone, Debug)]
pub struct Subst {
    tvars: HashMap<TVar, Type>,
    num_vars: HashMap<TVar, Loc>,
}

impl Subst {
    pub fn empty() -> Self {
        Self {
            tvars: HashMap::new(),
            num_vars: HashMap::new(),
        }
    }

    pub fn insert(&mut self, tvar: TVar, bt: Type) {
        self.tvars.insert(tvar, bt);
    }

    pub fn get(&self, tvar: TVar) -> Option<&Type> {
        self.tvars.get(&tvar)
    }

    pub fn new_num_var(&mut self, loc: Loc) -> TVar {
        let tvar = TVar::next();
        assert!(self.num_vars.insert(tvar, loc).is_none());
        tvar
    }

    pub fn set_num_var(&mut self, tvar: TVar, loc: Loc) {
        self.num_vars.entry(tvar).or_insert(loc);
        if let Some(sp!(_, Type_::Var(next))) = self.get(tvar) {
            let next = *next;
            self.set_num_var(next, loc)
        }
    }

    pub fn is_num_var(&self, tvar: TVar) -> bool {
        self.num_vars.contains_key(&tvar)
    }
}

impl ast_debug::AstDebug for Subst {
    fn ast_debug(&self, w: &mut ast_debug::AstWriter) {
        let Subst { tvars, num_vars } = self;

        w.write("tvars:");
        w.indent(4, |w| {
            let mut tvars = tvars.iter().collect::<Vec<_>>();
            tvars.sort_by_key(|(v, _)| *v);
            for (tvar, bt) in tvars {
                w.write(&format!("{:?} => ", tvar));
                bt.ast_debug(w);
                w.new_line();
            }
        });
        w.write("num_vars:");
        w.indent(4, |w| {
            let mut num_vars = num_vars.keys().collect::<Vec<_>>();
            num_vars.sort();
            for tvar in num_vars {
                w.writeln(&format!("{:?}", tvar))
            }
        })
    }
}

//**************************************************************************************************
// Type error display
//**************************************************************************************************

pub fn error_format(b: &Type, subst: &Subst) -> String {
    error_format_impl(b, subst, false)
}

pub fn error_format_(b_: &Type_, subst: &Subst) -> String {
    error_format_impl_(b_, subst, false)
}

pub fn error_format_nested(b: &Type, subst: &Subst) -> String {
    error_format_impl(b, subst, true)
}

fn error_format_impl(sp!(_, b_): &Type, subst: &Subst, nested: bool) -> String {
    error_format_impl_(b_, subst, nested)
}

fn error_format_impl_(b_: &Type_, subst: &Subst, nested: bool) -> String {
    use Type_::*;
    let res = match b_ {
        UnresolvedError | Anything => "_".to_string(),
        Unit => "()".to_string(),
        Var(id) => match subst.get(*id) {
            Some(t) => error_format_nested(t, subst),
            None if nested && subst.is_num_var(*id) => "{integer}".to_string(),
            None if subst.is_num_var(*id) => return "integer".to_string(),
            None => "_".to_string(),
        },
        Apply(_, sp!(_, TypeName_::Multiple(_)), tys) => {
            let inner = format_comma(tys.iter().map(|s| error_format_nested(s, subst)));
            format!("({})", inner)
        }
        Apply(_, n, tys) => {
            let tys_str = if !tys.is_empty() {
                format!(
                    "<{}>",
                    format_comma(tys.iter().map(|t| error_format_nested(t, subst)))
                )
            } else {
                "".to_string()
            };
            format!("{}{}", n, tys_str)
        }
        Param(tp) => tp.user_specified_name.value.to_string(),
        Ref(mut_, ty) => format!(
            "&{}{}",
            if *mut_ { "mut " } else { "" },
            error_format_nested(ty, subst)
        ),
    };
    if nested {
        res
    } else {
        format!("'{}'", res)
    }
}

//**************************************************************************************************
// Type utils
//**************************************************************************************************

pub fn infer_abilities(context: &Context, subst: &Subst, ty: Type) -> AbilitySet {
    use Type_ as T;
    let loc = ty.loc;
    match unfold_type(subst, ty).value {
        T::Unit => AbilitySet::collection(loc),
        T::Ref(_, _) => AbilitySet::references(loc),
        T::Var(_) => unreachable!("ICE unfold_type failed, which is impossible"),
        T::UnresolvedError | T::Anything => AbilitySet::all(loc),
        T::Param(TParam { abilities, .. }) | T::Apply(Some(abilities), _, _) => abilities,
        T::Apply(None, n, ty_args) => {
            let (declared_abilities, ty_args) = match &n.value {
                TypeName_::Multiple(_) => (AbilitySet::collection(loc), ty_args),
                TypeName_::Builtin(b) => (b.value.declared_abilities(b.loc), ty_args),
                TypeName_::ModuleType(m, n) => {
                    let declared_abilities = context.struct_declared_abilities(&m, &n).clone();
                    let non_phantom_ty_args = ty_args
                        .into_iter()
                        .zip(context.struct_tparams(&m, &n))
                        .filter(|(_, param)| !param.is_phantom)
                        .map(|(arg, _)| arg)
                        .collect::<Vec<_>>();
                    (declared_abilities, non_phantom_ty_args)
                }
            };
            let ty_args_abilities = ty_args
                .into_iter()
                .map(|ty| infer_abilities(context, subst, ty))
                .collect::<Vec<_>>();
            AbilitySet::from_abilities(declared_abilities.into_iter().filter(|ab| {
                let requirement = ab.value.requires();
                ty_args_abilities
                    .iter()
                    .all(|ty_arg_abilities| ty_arg_abilities.has_ability_(requirement))
            }))
            .unwrap()
        }
    }
}

// Returns
// - the declared location where abilities are added (if applicable)
// - the set of declared abilities
// - its type arguments
fn debug_abilities_info(context: &Context, ty: &Type) -> (Option<Loc>, AbilitySet, Vec<Type>) {
    use Type_ as T;
    let loc = ty.loc;
    match &ty.value {
        T::Unit | T::Ref(_, _) => (None, AbilitySet::references(loc), vec![]),
        T::Var(_) => panic!("ICE call unfold_type before debug_abilities_info"),
        T::UnresolvedError | T::Anything => (None, AbilitySet::all(loc), vec![]),
        T::Param(TParam {
            abilities,
            user_specified_name,
            ..
        }) => (Some(user_specified_name.loc), abilities.clone(), vec![]),
        T::Apply(_, sp!(_, TypeName_::Multiple(_)), ty_args) => {
            (None, AbilitySet::collection(loc), ty_args.clone())
        }
        T::Apply(_, sp!(_, TypeName_::Builtin(b)), ty_args) => {
            (None, b.value.declared_abilities(b.loc), ty_args.clone())
        }
        T::Apply(_, sp!(_, TypeName_::ModuleType(m, n)), ty_args) => (
            Some(context.struct_declared_loc(&m, &n)),
            context.struct_declared_abilities(&m, &n).clone(),
            ty_args.clone(),
        ),
    }
}

pub fn make_num_tvar(context: &mut Context, loc: Loc) -> Type {
    let tvar = context.subst.new_num_var(loc);
    sp(loc, Type_::Var(tvar))
}

pub fn make_tvar(_context: &mut Context, loc: Loc) -> Type {
    sp(loc, Type_::Var(TVar::next()))
}

//**************************************************************************************************
// Structs
//**************************************************************************************************

pub fn make_struct_type(
    context: &mut Context,
    loc: Loc,
    m: &ModuleIdent,
    n: &StructName,
    ty_args_opt: Option<Vec<Type>>,
) -> (Type, Vec<Type>) {
    let tn = sp(loc, TypeName_::ModuleType(m.clone(), n.clone()));
    let sdef = context.struct_definition(m, n);
    match ty_args_opt {
        None => {
            let constraints = sdef
                .type_parameters
                .iter()
                .map(|tp| (loc, tp.param.abilities.clone()))
                .collect();
            let ty_args = make_tparams(context, loc, TVarCase::Base, constraints);
            (sp(loc, Type_::Apply(None, tn, ty_args.clone())), ty_args)
        }
        Some(ty_args) => {
            let tapply_ = instantiate_apply(context, loc, None, tn, ty_args);
            let targs = match &tapply_ {
                Type_::Apply(_, _, targs) => targs.clone(),
                _ => panic!("ICE instantiate_apply returned non Apply"),
            };
            (sp(loc, tapply_), targs)
        }
    }
}

pub fn make_expr_list_tvars(
    context: &mut Context,
    loc: Loc,
    constraint_msg: impl Into<String>,
    locs: Vec<Loc>,
) -> Vec<Type> {
    let constraints = locs.iter().map(|l| (*l, AbilitySet::empty())).collect();
    let tys = make_tparams(
        context,
        loc,
        TVarCase::Single(constraint_msg.into()),
        constraints,
    );
    tys.into_iter()
        .zip(locs)
        .map(|(tvar, l)| sp(l, tvar.value))
        .collect()
}

// ty_args should come from make_struct_type
pub fn make_field_types(
    context: &mut Context,
    _loc: Loc,
    m: &ModuleIdent,
    n: &StructName,
    ty_args: Vec<Type>,
) -> N::StructFields {
    let sdef = context.struct_definition(m, n);
    let tparam_subst = &make_tparam_subst(
        context
            .struct_definition(m, n)
            .type_parameters
            .iter()
            .map(|tp| &tp.param),
        ty_args,
    );
    match &sdef.fields {
        N::StructFields::Native(loc) => N::StructFields::Native(*loc),
        N::StructFields::Defined(m) => {
            N::StructFields::Defined(m.ref_map(|_, (idx, field_ty)| {
                (*idx, subst_tparams(tparam_subst, field_ty.clone()))
            }))
        }
    }
}

// ty_args should come from make_struct_type
pub fn make_field_type(
    context: &mut Context,
    loc: Loc,
    m: &ModuleIdent,
    n: &StructName,
    ty_args: Vec<Type>,
    field: &Field,
) -> Type {
    let sdef = context.struct_definition(m, n);
    let fields_map = match &sdef.fields {
        N::StructFields::Native(nloc) => {
            let nloc = *nloc;
            let msg = format!("Unbound field '{}' for native struct '{}::{}'", field, m, n);
            context.env.add_diag(diag!(
                NameResolution::UnboundField,
                (loc, msg),
                (nloc, "Struct declared 'native' here")
            ));
            return context.error_type(loc);
        }
        N::StructFields::Defined(m) => m,
    };
    match fields_map.get(field).cloned() {
        None => {
            context.env.add_diag(diag!(
                NameResolution::UnboundField,
                (loc, format!("Unbound field '{}' in '{}::{}'", field, m, n)),
            ));
            context.error_type(loc)
        }
        Some((_, field_ty)) => {
            let tparam_subst = &make_tparam_subst(
                context
                    .struct_definition(m, n)
                    .type_parameters
                    .iter()
                    .map(|tp| &tp.param),
                ty_args,
            );
            subst_tparams(tparam_subst, field_ty)
        }
    }
}

//**************************************************************************************************
// Constants
//**************************************************************************************************

pub fn make_constant_type(
    context: &mut Context,
    loc: Loc,
    m: &Option<ModuleIdent>,
    c: &ConstantName,
) -> Type {
    let in_current_module = m == &context.current_module;
    let (defined_loc, signature) = {
        let ConstantInfo {
            defined_loc,
            signature,
        } = context.constant_info(m, c);
        (*defined_loc, signature.clone())
    };
    if !in_current_module {
        let msg = match m {
            None => format!("Invalid access of '{}'", c),
            Some(mident) => format!("Invalid access of '{}::{}'", mident, c),
        };
        let internal_msg = "Constants are internal to their module, and cannot can be accessed \
                            outside of their module";
        context.env.add_diag(diag!(
            TypeSafety::Visibility,
            (loc, msg),
            (defined_loc, internal_msg)
        ));
    }

    signature
}

//**************************************************************************************************
// Functions
//**************************************************************************************************

pub fn make_function_type(
    context: &mut Context,
    loc: Loc,
    m: &ModuleIdent,
    f: &FunctionName,
    ty_args_opt: Option<Vec<Type>>,
) -> (
    Loc,
    Vec<Type>,
    Vec<(Var, Type)>,
    BTreeMap<StructName, Loc>,
    Type,
) {
    let in_current_module = match &context.current_module {
        Some(current) => m == current,
        None => false,
    };
    let constraints: Vec<_> = context
        .function_info(m, f)
        .signature
        .type_parameters
        .iter()
        .map(|tp| tp.abilities.clone())
        .collect();

    let ty_args = match ty_args_opt {
        None => {
            let locs_constraints = constraints.into_iter().map(|k| (loc, k)).collect();
            make_tparams(context, loc, TVarCase::Base, locs_constraints)
        }
        Some(ty_args) => {
            let ty_args = check_type_argument_arity(
                context,
                loc,
                || format!("{}::{}", m, f),
                ty_args,
                &constraints,
            );
            instantiate_type_args(context, loc, None, ty_args, constraints)
        }
    };

    let finfo = context.function_info(m, f);
    let tparam_subst = &make_tparam_subst(&finfo.signature.type_parameters, ty_args.clone());
    let params = finfo
        .signature
        .parameters
        .iter()
        .map(|(n, t)| (n.clone(), subst_tparams(tparam_subst, t.clone())))
        .collect();
    let return_ty = subst_tparams(tparam_subst, finfo.signature.return_type.clone());
    let acquires = if in_current_module {
        finfo.acquires.clone()
    } else {
        BTreeMap::new()
    };
    let defined_loc = finfo.defined_loc;
    match finfo.visibility {
        Visibility::Internal if in_current_module => (),
        Visibility::Internal => {
            let internal_msg = format!(
                "This function is internal to its module. Only '{}', '{}', and '{}' functions can \
                 be called outside of their module",
                Visibility::PUBLIC,
                Visibility::SCRIPT,
                Visibility::FRIEND
            );
            context.env.add_diag(diag!(
                TypeSafety::Visibility,
                (loc, format!("Invalid call to '{}::{}'", m, f)),
                (defined_loc, internal_msg),
            ));
        }
        Visibility::Script(_) if context.is_in_script_context() => (),
        Visibility::Script(vis_loc) => {
            let internal_msg = format!(
                "This function can only be called from a script context, i.e. a 'script' function \
                 or a '{}' function",
                Visibility::SCRIPT
            );
            context.env.add_diag(diag!(
                TypeSafety::ScriptContext,
                (loc, format!("Invalid call to '{}::{}'", m, f)),
                (vis_loc, internal_msg),
            ));
        }
        Visibility::Friend(_) if in_current_module || context.current_module_is_a_friend_of(m) => {}
        Visibility::Friend(vis_loc) => {
            let internal_msg = format!(
                "This function can only be called from a 'friend' of module '{}'",
                m
            );
            context.env.add_diag(diag!(
                TypeSafety::Visibility,
                (loc, format!("Invalid call to '{}::{}'", m, f)),
                (vis_loc, internal_msg),
            ));
        }
        Visibility::Public(_) => (),
    };
    (defined_loc, ty_args, params, acquires, return_ty)
}

//**************************************************************************************************
// Constraints
//**************************************************************************************************

pub fn solve_constraints(context: &mut Context) {
    use BuiltinTypeName_ as BT;
    let num_vars = context.subst.num_vars.clone();
    let mut subst = std::mem::replace(&mut context.subst, Subst::empty());
    for (num_var, loc) in num_vars {
        let tvar = sp(loc, Type_::Var(num_var));
        match unfold_type(&subst, tvar.clone()).value {
            Type_::UnresolvedError | Type_::Anything => {
                let next_subst = join(subst, &Type_::u64(loc), &tvar).unwrap().0;
                subst = next_subst;
            }
            _ => (),
        }
    }
    context.subst = subst;

    let constraints = std::mem::replace(&mut context.constraints, vec![]);
    for constraint in constraints {
        match constraint {
            Constraint::IsImplicitlyCopyable { loc, msg, ty, fix } => {
                solve_implicitly_copyable_constraint(context, loc, msg, ty, fix)
            }
            Constraint::AbilityConstraint {
                loc,
                msg,
                ty,
                constraints,
            } => solve_ability_constraint(context, loc, msg, ty, constraints),
            Constraint::NumericConstraint(loc, op, t) => {
                solve_builtin_type_constraint(context, BT::numeric(), loc, op, t)
            }
            Constraint::BitsConstraint(loc, op, t) => {
                solve_builtin_type_constraint(context, BT::bits(), loc, op, t)
            }
            Constraint::OrderedConstraint(loc, op, t) => {
                solve_builtin_type_constraint(context, BT::ordered(), loc, op, t)
            }
            Constraint::BaseTypeConstraint(loc, msg, t) => {
                solve_base_type_constraint(context, loc, msg, &t)
            }
            Constraint::SingleTypeConstraint(loc, msg, t) => {
                solve_single_type_constraint(context, loc, msg, &t)
            }
        }
    }
}

fn solve_ability_constraint(
    context: &mut Context,
    loc: Loc,
    given_msg_opt: Option<String>,
    ty: Type,
    constraints: AbilitySet,
) {
    let ty = unfold_type(&context.subst, ty);
    let ty_abilities = infer_abilities(context, &context.subst, ty.clone());

    let (declared_loc_opt, declared_abilities, ty_args) = debug_abilities_info(context, &ty);
    for constraint in constraints {
        if ty_abilities.has_ability(&constraint) {
            continue;
        }

        let constraint_msg = match &given_msg_opt {
            Some(s) => s.clone(),
            None => format!("'{}' constraint not satisifed", constraint),
        };
        let mut secondary_labels = vec![];
        ability_not_satisified_tips(
            &context.subst,
            &mut secondary_labels,
            constraint.value,
            &ty,
            declared_loc_opt,
            &declared_abilities,
            ty_args.iter().map(|ty_arg| {
                let abilities = infer_abilities(context, &context.subst, ty_arg.clone());
                (ty_arg, abilities)
            }),
        );

        // is none if it is from a user constraint and not a part of the type system
        if given_msg_opt.is_none() {
            secondary_labels.push((
                constraint.loc,
                format!("'{}' constraint declared here", constraint),
            ));
        }
        context.env.add_diag(Diagnostic::new(
            AbilitySafety::Constraint,
            (loc, constraint_msg),
            secondary_labels,
        ))
    }
}

pub fn ability_not_satisified_tips<'a>(
    subst: &Subst,
    error: &mut Error,
    constraint: Ability_,
    ty: &Type,
    declared_loc_opt: Option<Loc>,
    declared_abilities: &AbilitySet,
    ty_args: impl IntoIterator<Item = (&'a Type, AbilitySet)>,
) {
    let ty_str = error_format(ty, subst);
    let ty_msg = format!(
        "The type {} does not have the ability '{}'",
        ty_str, constraint
    );
    error.push((ty.loc, ty_msg));
    match (
        declared_loc_opt,
        declared_abilities.has_ability_(constraint),
    ) {
        // Type was not given the ability
        (Some(dloc), false) => error.push((
            dloc,
            format!(
                "To satisfy the constraint, the '{}' ability would need to be added here",
                constraint
            ),
        )),
        // Type does not have the ability
        (_, false) => (),
        // Type has the ability but a type argument causes it to fail
        (_, true) => {
            let requirement = constraint.requires();
            let mut error_added = false;
            for (ty_arg, ty_arg_abilities) in ty_args {
                if !ty_arg_abilities.has_ability_(requirement) {
                    let ty_arg_str = error_format(ty_arg, &subst);
                    let msg = format!(
                        "The type {ty} can have the ability '{constraint}' but the type argument \
                         {ty_arg} does not have the required ability '{requirement}'",
                        ty = ty_str,
                        ty_arg = ty_arg_str,
                        constraint = constraint,
                        requirement = requirement,
                    );
                    error.push((ty_arg.loc, msg));
                    error_added = true;
                    break;
                }
            }
            assert!(error_added)
        }
    }
}

// This could be done with abilities, but currently all abilities are user accessable. So it seems
// reasonable to keep this separate for now
pub fn is_implicitly_copyable(subst: &Subst, ty: &Type) -> bool {
    use BuiltinTypeName_ as B;
    use Type_ as T;
    match &ty.value {
        T::Var(_) => panic!("ICE call unfold_type before is_implicitly_copyable"),

        T::Unit
        | T::Ref(_, _)
        | T::UnresolvedError
        | T::Anything
        | T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::Address))), _)
        | T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::U8))), _)
        | T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::U64))), _)
        | T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::U128))), _)
        | T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::Bool))), _) => true,

        T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::Signer))), _)
        | T::Apply(_, sp!(_, TypeName_::Builtin(sp!(_, B::Vector))), _)
        | T::Param(TParam { .. })
        | T::Apply(_, sp!(_, TypeName_::ModuleType(_, _)), _) => false,

        T::Apply(_, sp!(_, TypeName_::Multiple(_)), ty_args) => ty_args
            .iter()
            .all(|ty_arg| is_implicitly_copyable(subst, &unfold_type(subst, ty_arg.clone()))),
    }
}

fn solve_implicitly_copyable_constraint(
    context: &mut Context,
    loc: Loc,
    msg: String,
    ty: Type,
    fix: String,
) {
    let ty = unfold_type(&context.subst, ty);
    let tloc = ty.loc;
    if !is_implicitly_copyable(&context.subst, &ty) {
        let ty_msg = format!(
            "The type {} is not implicitly copyable. Implicit copies are limited to simple \
             primitive values",
            error_format(&ty, &context.subst),
        );
        context.env.add_diag(diag!(
            AbilitySafety::ImplicitlyCopyable,
            (loc, format!("{} {}", msg, fix)),
            (tloc, ty_msg),
        ))
    }
}

fn solve_builtin_type_constraint(
    context: &mut Context,
    builtin_set: &BTreeSet<BuiltinTypeName_>,
    loc: Loc,
    op: &'static str,
    ty: Type,
) {
    use TypeName_::*;
    use Type_::*;
    let t = unfold_type(&context.subst, ty);
    let tloc = t.loc;
    let mk_tmsg = || {
        let set_msg = if builtin_set.is_empty() {
            "the operation is not yet supported on any type".to_string()
        } else {
            format!(
                "expected: {}",
                format_comma(builtin_set.iter().map(|b| format!("'{}'", b)))
            )
        };
        format!(
            "Found: {}. But {}",
            error_format(&t, &context.subst),
            set_msg
        )
    };
    match &t.value {
        Apply(abilities_opt, sp!(_, Builtin(sp!(_, b))), args) if builtin_set.contains(b) => {
            if let Some(abilities) = abilities_opt {
                assert!(
                    abilities.has_ability_(Ability_::Drop),
                    "ICE assumes this type is being consumed so should have drop"
                );
            }
            assert!(args.is_empty());
        }
        _ => {
            let tmsg = mk_tmsg();
            context.env.add_diag(diag!(
                TypeSafety::BuiltinOperation,
                (loc, format!("Invalid argument to '{}'", op)),
                (tloc, tmsg)
            ))
        }
    }
}

fn solve_base_type_constraint(context: &mut Context, loc: Loc, msg: String, ty: &Type) {
    use TypeName_::*;
    use Type_::*;
    let sp!(tyloc, unfolded_) = unfold_type(&context.subst, ty.clone());
    match unfolded_ {
        Var(_) => unreachable!(),
        Unit | Ref(_, _) | Apply(_, sp!(_, Multiple(_)), _) => {
            let tystr = error_format(ty, &context.subst);
            let tmsg = format!("Expected a single non-reference type, but found: {}", tystr);
            context.env.add_diag(diag!(
                TypeSafety::ExpectedBaseType,
                (loc, msg),
                (tyloc, tmsg)
            ))
        }
        UnresolvedError | Anything | Param(_) | Apply(_, _, _) => (),
    }
}

fn solve_single_type_constraint(context: &mut Context, loc: Loc, msg: String, ty: &Type) {
    use TypeName_::*;
    use Type_::*;
    let sp!(tyloc, unfolded_) = unfold_type(&context.subst, ty.clone());
    match unfolded_ {
        Var(_) => unreachable!(),
        Unit | Apply(_, sp!(_, Multiple(_)), _) => {
            let tmsg = format!(
                "Expected a single type, but found expression list type: {}",
                error_format(ty, &context.subst)
            );
            context.env.add_diag(diag!(
                TypeSafety::ExpectedSingleType,
                (loc, msg),
                (tyloc, tmsg)
            ))
        }
        UnresolvedError | Anything | Ref(_, _) | Param(_) | Apply(_, _, _) => (),
    }
}

//**************************************************************************************************
// Subst
//**************************************************************************************************

pub fn unfold_type(subst: &Subst, sp!(loc, t_): Type) -> Type {
    match t_ {
        Type_::Var(i) => match subst.get(i) {
            None => sp(loc, Type_::Anything),
            Some(inner) => unfold_type(subst, inner.clone()),
        },
        x => sp(loc, x),
    }
}

// Equivelent to unfold_type, but only returns the loc.
// The hope is to point to the last loc in a chain of type var's, giving the loc closest to the
// actual type in the source code
pub fn best_loc(subst: &Subst, sp!(loc, t_): &Type) -> Loc {
    match t_ {
        Type_::Var(i) => match subst.get(*i) {
            None => *loc,
            Some(inner) => best_loc(subst, inner),
        },
        _ => *loc,
    }
}

pub fn make_tparam_subst<'a, I1, I2>(tps: I1, args: I2) -> TParamSubst
where
    I1: IntoIterator<Item = &'a TParam>,
    I1::IntoIter: ExactSizeIterator,
    I2: IntoIterator<Item = Type>,
    I2::IntoIter: ExactSizeIterator,
{
    let tps = tps.into_iter();
    let args = args.into_iter();
    assert!(tps.len() == args.len());
    let mut subst = TParamSubst::new();
    for (tp, arg) in tps.zip(args) {
        let old_val = subst.insert(tp.id, arg);
        assert!(old_val.is_none())
    }
    subst
}

pub fn subst_tparams(subst: &TParamSubst, sp!(loc, t_): Type) -> Type {
    use Type_::*;
    match t_ {
        x @ Unit | x @ UnresolvedError | x @ Anything => sp(loc, x),
        Var(_) => panic!("ICE tvar in subst_tparams"),
        Ref(mut_, t) => sp(loc, Ref(mut_, Box::new(subst_tparams(subst, *t)))),
        Param(tp) => subst
            .get(&tp.id)
            .expect("ICE unmapped tparam in subst_tparams_base")
            .clone(),
        Apply(k, n, ty_args) => {
            let ftys = ty_args
                .into_iter()
                .map(|t| subst_tparams(subst, t))
                .collect();
            sp(loc, Apply(k, n, ftys))
        }
    }
}

pub fn ready_tvars(subst: &Subst, sp!(loc, t_): Type) -> Type {
    use Type_::*;
    match t_ {
        x @ UnresolvedError | x @ Unit | x @ Anything | x @ Param(_) => sp(loc, x),
        Ref(mut_, t) => sp(loc, Ref(mut_, Box::new(ready_tvars(subst, *t)))),
        Apply(k, n, tys) => {
            let tys = tys.into_iter().map(|t| ready_tvars(subst, t)).collect();
            sp(loc, Apply(k, n, tys))
        }
        Var(i) => match subst.get(i) {
            None => sp(loc, Var(i)),
            Some(t) => ready_tvars(subst, t.clone()),
        },
    }
}

//**************************************************************************************************
// Instantiate
//**************************************************************************************************

pub fn instantiate(context: &mut Context, sp!(loc, t_): Type) -> Type {
    use Type_::*;
    let it_ = match t_ {
        Unit => Unit,
        UnresolvedError => UnresolvedError,
        Anything => make_tvar(context, loc).value,
        Ref(mut_, b) => {
            let inner = *b;
            context.add_base_type_constraint(loc, "Invalid reference type", inner.clone());
            Ref(mut_, Box::new(instantiate(context, inner)))
        }
        Apply(abilities_opt, n, ty_args) => {
            instantiate_apply(context, loc, abilities_opt, n, ty_args)
        }
        x @ Param(_) => x,
        Var(_) => panic!("ICE instantiate type variable"),
    };
    sp(loc, it_)
}

// abilities_opt is expected to be None for non primitive types
fn instantiate_apply(
    context: &mut Context,
    loc: Loc,
    abilities_opt: Option<AbilitySet>,
    n: TypeName,
    ty_args: Vec<Type>,
) -> Type_ {
    let tparam_constraints: Vec<AbilitySet> = match &n {
        sp!(nloc, N::TypeName_::Builtin(b)) => b.value.tparam_constraints(*nloc),
        sp!(_, N::TypeName_::Multiple(len)) => {
            debug_assert!(abilities_opt.is_none(), "ICE instantiated expanded type");
            (0..*len).map(|_| AbilitySet::empty()).collect()
        }
        sp!(_, N::TypeName_::ModuleType(m, s)) => {
            debug_assert!(abilities_opt.is_none(), "ICE instantiated expanded type");
            let tps = context.struct_tparams(m, s);
            tps.iter().map(|tp| tp.param.abilities.clone()).collect()
        }
    };

    let tys = instantiate_type_args(context, loc, Some(&n.value), ty_args, tparam_constraints);
    Type_::Apply(abilities_opt, n, tys)
}

// The type arguments are bound to type variables after intantiation
// i.e. vec<t1, ..., tn> ~> vec<a1, ..., an> s.t a1 => t1, ... , an => tn
// This might be needed for any variance case, and I THINK that it should be fine without it
// BUT I'm adding it as a safeguard against instantiating twice. Can always remove once this
// stabilizes
fn instantiate_type_args(
    context: &mut Context,
    loc: Loc,
    n: Option<&TypeName_>,
    mut ty_args: Vec<Type>,
    constraints: Vec<AbilitySet>,
) -> Vec<Type> {
    assert!(ty_args.len() == constraints.len());
    let locs_constraints = constraints
        .into_iter()
        .zip(&ty_args)
        .map(|(abilities, t)| (t.loc, abilities))
        .collect();
    let tvar_case = match n {
        Some(TypeName_::Multiple(_)) => {
            TVarCase::Single("Invalid expression list type argument".to_owned())
        }
        None | Some(TypeName_::Builtin(_)) | Some(TypeName_::ModuleType(_, _)) => TVarCase::Base,
    };
    let tvars = make_tparams(context, loc, tvar_case, locs_constraints);
    ty_args = ty_args
        .into_iter()
        .map(|t| instantiate(context, t))
        .collect();

    assert!(ty_args.len() == tvars.len());
    let mut res = vec![];
    let subst = std::mem::replace(&mut context.subst, /* dummy value */ Subst::empty());
    context.subst = tvars
        .into_iter()
        .zip(ty_args)
        .fold(subst, |subst, (tvar, ty_arg)| {
            // tvar is just a type variable, so shouldn't throw ever...
            let (subst, t) = join(subst, &tvar, &ty_arg).ok().unwrap();
            res.push(t);
            subst
        });
    res
}

fn check_type_argument_arity<F: FnOnce() -> String>(
    context: &mut Context,
    loc: Loc,
    name_f: F,
    mut ty_args: Vec<Type>,
    tparam_constraints: &[AbilitySet],
) -> Vec<Type> {
    let args_len = ty_args.len();
    let arity = tparam_constraints.len();
    if args_len != arity {
        let code = if args_len < arity {
            NameResolution::TooFewTypeArguments
        } else {
            NameResolution::TooManyTypeArguments
        };
        let msg = format!(
            "Invalid instantiation of '{}'. Expected {} type argument(s) but got {}",
            name_f(),
            arity,
            args_len
        );
        context.env.add_diag(diag!(code, (loc, msg)));
    }

    while ty_args.len() > arity {
        ty_args.pop();
    }

    while ty_args.len() < arity {
        ty_args.push(context.error_type(loc));
    }

    ty_args
}

enum TVarCase {
    Single(String),
    Base,
}

fn make_tparams(
    context: &mut Context,
    loc: Loc,
    case: TVarCase,
    tparam_constraints: Vec<(Loc, AbilitySet)>,
) -> Vec<Type> {
    tparam_constraints
        .into_iter()
        .map(|(vloc, constraint)| {
            let tvar = make_tvar(context, vloc);
            context.add_ability_set_constraint(loc, None::<String>, tvar.clone(), constraint);
            match &case {
                TVarCase::Single(msg) => context.add_single_type_constraint(loc, msg, tvar.clone()),
                TVarCase::Base => {
                    context.add_base_type_constraint(loc, "Invalid type argument", tvar.clone())
                }
            };
            tvar
        })
        .collect()
}

//**************************************************************************************************
// Subtype and joining
//**************************************************************************************************

#[derive(Debug)]
pub enum TypingError {
    SubtypeError(Box<Type>, Box<Type>),
    Incompatible(Box<Type>, Box<Type>),
    ArityMismatch(usize, Box<Type>, usize, Box<Type>),
    RecursiveType(Loc),
}

#[derive(Clone, Copy, Debug)]
enum TypingCase {
    Join,
    Subtype,
}

pub fn subtype(subst: Subst, lhs: &Type, rhs: &Type) -> Result<(Subst, Type), TypingError> {
    join_impl(subst, TypingCase::Subtype, lhs, rhs)
}

pub fn join(subst: Subst, lhs: &Type, rhs: &Type) -> Result<(Subst, Type), TypingError> {
    join_impl(subst, TypingCase::Join, lhs, rhs)
}

fn join_impl(
    mut subst: Subst,
    case: TypingCase,
    lhs: &Type,
    rhs: &Type,
) -> Result<(Subst, Type), TypingError> {
    use TypeName_::*;
    use Type_::*;
    use TypingCase::*;
    match (lhs, rhs) {
        (sp!(_, Anything), other) | (other, sp!(_, Anything)) => Ok((subst, other.clone())),

        (sp!(_, Unit), sp!(loc, Unit)) => Ok((subst, sp(*loc, Unit))),

        (sp!(loc1, Ref(mut1, t1)), sp!(loc2, Ref(mut2, t2))) => {
            let (loc, mut_) = match (case, mut1, mut2) {
                (Join, _, _) => {
                    // if 1 is imm and 2 is mut, use loc1. Else, loc2
                    let loc = if !*mut1 && *mut2 { *loc1 } else { *loc2 };
                    (loc, *mut1 && *mut2)
                }
                // imm <: imm
                // mut <: imm
                (Subtype, false, false) | (Subtype, true, false) => (*loc2, false),
                // mut <: mut
                (Subtype, true, true) => (*loc2, true),
                // imm <\: mut
                (Subtype, false, true) => {
                    return Err(TypingError::SubtypeError(
                        Box::new(lhs.clone()),
                        Box::new(rhs.clone()),
                    ))
                }
            };
            let (subst, t) = join_impl(subst, case, t1, t2)?;
            Ok((subst, sp(loc, Ref(mut_, Box::new(t)))))
        }
        (sp!(_, Param(TParam { id: id1, .. })), sp!(_, Param(TParam { id: id2, .. })))
            if id1 == id2 =>
        {
            Ok((subst, rhs.clone()))
        }
        (sp!(_, Apply(_, sp!(_, Multiple(n1)), _)), sp!(_, Apply(_, sp!(_, Multiple(n2)), _)))
            if n1 != n2 =>
        {
            Err(TypingError::ArityMismatch(
                *n1,
                Box::new(lhs.clone()),
                *n2,
                Box::new(rhs.clone()),
            ))
        }
        (sp!(_, Apply(k1, n1, tys1)), sp!(loc, Apply(k2, n2, tys2))) if n1 == n2 => {
            assert!(
                k1 == k2,
                "ICE failed naming: {:#?}kind != {:#?}kind. {:#?} !=  {:#?}",
                n1,
                n2,
                k1,
                k2
            );
            let (subst, tys) = join_impl_types(subst, case, tys1, tys2)?;
            Ok((subst, sp(*loc, Apply(k2.clone(), n2.clone(), tys))))
        }
        (sp!(loc1, Var(id1)), sp!(loc2, Var(id2))) => {
            if *id1 == *id2 {
                Ok((subst, sp(*loc2, Var(*id2))))
            } else {
                join_tvar(subst, case, *loc1, *id1, *loc2, *id2)
            }
        }
        (sp!(loc, Var(id)), other) if subst.get(*id).is_none() => {
            if join_bind_tvar(&mut subst, *loc, *id, other.clone())? {
                Ok((subst, sp(*loc, Var(*id))))
            } else {
                Err(TypingError::Incompatible(
                    Box::new(sp(*loc, Var(*id))),
                    Box::new(other.clone()),
                ))
            }
        }
        (other, sp!(loc, Var(id))) if subst.get(*id).is_none() => {
            if join_bind_tvar(&mut subst, *loc, *id, other.clone())? {
                Ok((subst, sp(*loc, Var(*id))))
            } else {
                Err(TypingError::Incompatible(
                    Box::new(other.clone()),
                    Box::new(sp(*loc, Var(*id))),
                ))
            }
        }
        (sp!(loc, Var(id)), other) => {
            let new_tvar = TVar::next();
            subst.insert(new_tvar, other.clone());
            join_tvar(subst, case, *loc, *id, other.loc, new_tvar)
        }
        (other, sp!(loc, Var(id))) => {
            let new_tvar = TVar::next();
            subst.insert(new_tvar, other.clone());
            join_tvar(subst, case, other.loc, new_tvar, *loc, *id)
        }

        (sp!(_, UnresolvedError), other) | (other, sp!(_, UnresolvedError)) => {
            Ok((subst, other.clone()))
        }
        _ => Err(TypingError::Incompatible(
            Box::new(lhs.clone()),
            Box::new(rhs.clone()),
        )),
    }
}

fn join_impl_types(
    mut subst: Subst,
    case: TypingCase,
    tys1: &[Type],
    tys2: &[Type],
) -> Result<(Subst, Vec<Type>), TypingError> {
    // if tys1.len() != tys2.len(), we will get an error when instantiating the type elsewhere
    // as all types are instantiated as a sanity check
    let mut tys = vec![];
    for (ty1, ty2) in tys1.iter().zip(tys2) {
        let (nsubst, t) = join_impl(subst, case, ty1, ty2)?;
        subst = nsubst;
        tys.push(t)
    }
    Ok((subst, tys))
}

fn join_tvar(
    mut subst: Subst,
    case: TypingCase,
    loc1: Loc,
    id1: TVar,
    loc2: Loc,
    id2: TVar,
) -> Result<(Subst, Type), TypingError> {
    use Type_::*;
    let last_id1 = forward_tvar(&subst, id1);
    let last_id2 = forward_tvar(&subst, id2);
    let ty1 = match subst.get(last_id1) {
        None => sp(loc1, Anything),
        Some(t) => t.clone(),
    };
    let ty2 = match subst.get(last_id2) {
        None => sp(loc2, Anything),
        Some(t) => t.clone(),
    };

    let new_tvar = TVar::next();
    let num_loc_1 = subst.num_vars.get(&last_id1);
    let num_loc_2 = subst.num_vars.get(&last_id2);
    match (num_loc_1, num_loc_2) {
        (_, Some(nloc)) | (Some(nloc), _) => {
            let nloc = *nloc;
            subst.set_num_var(new_tvar, nloc);
        }
        _ => (),
    }
    subst.insert(last_id1, sp(loc1, Var(new_tvar)));
    subst.insert(last_id2, sp(loc2, Var(new_tvar)));

    let (mut subst, new_ty) = join_impl(subst, case, &ty1, &ty2)?;
    match subst.get(new_tvar) {
        Some(sp!(tloc, _)) => Err(TypingError::RecursiveType(*tloc)),
        None => {
            if join_bind_tvar(&mut subst, loc2, new_tvar, new_ty)? {
                Ok((subst, sp(loc2, Var(new_tvar))))
            } else {
                let ty1 = match ty1 {
                    sp!(loc, Anything) => sp(loc, Var(id1)),
                    t => t,
                };
                let ty2 = match ty2 {
                    sp!(loc, Anything) => sp(loc, Var(id2)),
                    t => t,
                };
                Err(TypingError::Incompatible(Box::new(ty1), Box::new(ty2)))
            }
        }
    }
}

fn forward_tvar(subst: &Subst, id: TVar) -> TVar {
    match subst.get(id) {
        Some(sp!(_, Type_::Var(next))) => forward_tvar(subst, *next),
        Some(_) | None => id,
    }
}

fn join_bind_tvar(subst: &mut Subst, loc: Loc, tvar: TVar, ty: Type) -> Result<bool, TypingError> {
    assert!(
        subst.get(tvar).is_none(),
        "ICE join_bind_tvar called on bound tvar"
    );

    fn used_tvars(used: &mut BTreeMap<TVar, Loc>, sp!(loc, t_): &Type) {
        use Type_ as T;
        match t_ {
            T::Var(v) => {
                used.insert(*v, *loc);
            }
            T::Ref(_, inner) => used_tvars(used, inner),
            T::Apply(_, _, inners) => inners
                .iter()
                .rev()
                .for_each(|inner| used_tvars(used, inner)),
            T::Unit | T::Param(_) | T::Anything | T::UnresolvedError => (),
        }
    }

    // check not necessary for soundness but improves error message structure
    if !check_num_tvar(&subst, loc, tvar, &ty) {
        return Ok(false);
    }

    let used = &mut BTreeMap::new();
    used_tvars(used, &ty);
    if let Some(_rec_loc) = used.get(&tvar) {
        return Err(TypingError::RecursiveType(loc));
    }

    match &ty.value {
        Type_::Anything => (),
        _ => subst.insert(tvar, ty),
    }
    Ok(true)
}

fn check_num_tvar(subst: &Subst, loc: Loc, tvar: TVar, ty: &Type) -> bool {
    !subst.is_num_var(tvar) || check_num_tvar_(subst, loc, tvar, ty)
}

fn check_num_tvar_(subst: &Subst, loc: Loc, tvar: TVar, ty: &Type) -> bool {
    use Type_::*;
    match &ty.value {
        UnresolvedError | Anything => true,
        Apply(_, sp!(_, TypeName_::Builtin(sp!(_, bt))), _) => bt.is_numeric(),

        Var(v) if subst.tvars.contains_key(v) => {
            check_num_tvar_(subst, loc, tvar, subst.get(*v).unwrap())
        }
        Var(v) => subst.is_num_var(*v),
        _ => false,
    }
}
