// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    diag,
    errors::new::Diagnostic,
    expansion::{
        address_map::build_address_map,
        aliases::{AliasMap, AliasSet},
        ast::{self as E, Address, Fields, ModuleIdent, ModuleIdent_, SpecId},
        byte_string, hex_string,
    },
    parser::ast::{
        self as P, Ability, ConstantName, Field, FunctionName, ModuleName, StructName, Var,
        Visibility,
    },
    shared::{unique_map::UniqueMap, *},
    FullyCompiledProgram,
};
use move_ir_types::location::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    iter::IntoIterator,
};

//**************************************************************************************************
// Context
//**************************************************************************************************

type ModuleMembers = BTreeMap<Name, ModuleMemberKind>;
struct Context<'env> {
    address_mapping: UniqueMap<Name, Option<Spanned<AddressBytes>>>,
    module_members: UniqueMap<ModuleIdent, ModuleMembers>,
    address: Option<Address>,
    aliases: AliasMap,
    is_source_definition: bool,
    in_spec_context: bool,
    exp_specs: BTreeMap<SpecId, E::SpecBlock>,
    env: &'env mut CompilationEnv,
}
impl<'env> Context<'env> {
    fn new(
        compilation_env: &'env mut CompilationEnv,
        address_mapping: UniqueMap<Name, Option<Spanned<AddressBytes>>>,
        module_members: UniqueMap<ModuleIdent, ModuleMembers>,
    ) -> Self {
        Self {
            address_mapping,
            module_members,
            env: compilation_env,
            address: None,
            aliases: AliasMap::new(),
            is_source_definition: false,
            in_spec_context: false,
            exp_specs: BTreeMap::new(),
        }
    }

    fn cur_address(&self) -> &Address {
        self.address.as_ref().unwrap()
    }

    /// Adds all of the new items in the new inner scope as shadowing the outer one.
    /// Gives back the outer scope
    pub fn new_alias_scope(&mut self, inner_scope: AliasMap) -> AliasMap {
        let outer_scope = self.aliases.clone();
        self.aliases.add_and_shadow_all(inner_scope);
        outer_scope
    }

    /// Resets the alias map and gives the set of aliases that were used
    pub fn set_to_outer_scope(&mut self, outer_scope: AliasMap) {
        let inner_scope = std::mem::replace(&mut self.aliases, outer_scope);
        let AliasSet { modules, members } = self.aliases.close_scope_and_report_unused(inner_scope);
        for alias in modules {
            unused_alias(self, alias)
        }
        for alias in members {
            unused_alias(self, alias)
        }
    }

    pub fn bind_exp_spec(&mut self, spec_block: P::SpecBlock) -> (SpecId, BTreeSet<Name>) {
        let len = self.exp_specs.len();
        let id = SpecId::new(len);
        let espec_block = spec(self, spec_block);
        let mut unbound_names = BTreeSet::new();
        unbound_names_spec_block(&mut unbound_names, &espec_block);
        self.exp_specs.insert(id, espec_block);

        (id, unbound_names)
    }

    pub fn extract_exp_specs(&mut self) -> BTreeMap<SpecId, E::SpecBlock> {
        std::mem::replace(&mut self.exp_specs, BTreeMap::new())
    }
}

//**************************************************************************************************
// Entry
//**************************************************************************************************

pub fn program(
    compilation_env: &mut CompilationEnv,
    pre_compiled_lib: Option<&FullyCompiledProgram>,
    prog: P::Program,
) -> E::Program {
    let address_mapping = build_address_map(compilation_env, pre_compiled_lib, &prog);
    let module_members = {
        let mut members = UniqueMap::new();
        all_module_members(
            compilation_env,
            &address_mapping,
            &mut members,
            true,
            &prog.source_definitions,
        );
        all_module_members(
            compilation_env,
            &address_mapping,
            &mut members,
            true,
            &prog.lib_definitions,
        );
        if let Some(pre_compiled) = pre_compiled_lib {
            assert!(pre_compiled.parser.source_definitions.is_empty());
            all_module_members(
                compilation_env,
                &address_mapping,
                &mut members,
                false,
                &pre_compiled.parser.lib_definitions,
            );
        }
        members
    };

    let mut context = Context::new(compilation_env, address_mapping, module_members);

    let mut module_map = UniqueMap::new();
    let mut scripts = vec![];
    let P::Program {
        source_definitions,
        lib_definitions,
    } = prog;

    context.is_source_definition = true;
    for def in source_definitions {
        definition(&mut context, &mut module_map, &mut scripts, def)
    }

    context.is_source_definition = false;
    for def in lib_definitions {
        definition(&mut context, &mut module_map, &mut scripts, def)
    }

    let mut scripts = {
        let mut collected: BTreeMap<String, Vec<E::Script>> = BTreeMap::new();
        for s in scripts {
            collected
                .entry(s.function_name.value().to_owned())
                .or_insert_with(Vec::new)
                .push(s)
        }
        let mut keyed: BTreeMap<String, E::Script> = BTreeMap::new();
        for (n, mut ss) in collected {
            match ss.len() {
                0 => unreachable!(),
                1 => assert!(
                    keyed.insert(n, ss.pop().unwrap()).is_none(),
                    "ICE duplicate script key"
                ),
                _ => {
                    for (i, s) in ss.into_iter().enumerate() {
                        let k = format!("{}_{}", n, i);
                        assert!(keyed.insert(k, s).is_none(), "ICE duplicate script key")
                    }
                }
            }
        }
        keyed
    };

    super::unique_modules_after_mapping::verify(context.env, &context.address_mapping, &module_map);
    super::dependency_ordering::verify(context.env, &mut module_map, &mut scripts);
    E::Program {
        addresses: context.address_mapping,
        modules: module_map,
        scripts,
    }
}

fn definition(
    context: &mut Context,
    module_map: &mut UniqueMap<ModuleIdent, E::ModuleDefinition>,
    scripts: &mut Vec<E::Script>,
    def: P::Definition,
) {
    match def {
        P::Definition::Module(mut m) => {
            let module_paddr = std::mem::take(&mut m.address);
            let module_addr = module_paddr
                .map(|a| sp(a.loc, address(context, /* suggest_declaration */ true, a)));
            module(context, module_map, module_addr, m)
        }
        P::Definition::Address(a) => {
            check_valid_address_name(context, &a.addr);
            let addr = address(context, /* suggest_declaration */ false, a.addr);
            for mut m in a.modules {
                let module_addr = check_module_address(context, a.loc, addr.clone(), &mut m);
                module(context, module_map, Some(module_addr), m)
            }
        }

        P::Definition::Script(_) if !context.is_source_definition => (),
        P::Definition::Script(s) => script(context, scripts, s),
    }
}

fn unbound_address_error(suggest_declaration: bool, loc: Loc, n: &Name) -> Diagnostic {
    let mut msg = format!("Unbound address '{}'", n);
    if suggest_declaration {
        msg = format!("{}. Try declaring it with 'address {};'", msg, n)
    }
    diag!(NameResolution::UnboundAddress, (loc, msg))
}

// Access a top level address as declared, not affected by any aliasing/shadowing
fn address(context: &mut Context, suggest_declaration: bool, ln: P::LeadingNameAccess) -> Address {
    address_impl(
        context.env,
        &context.address_mapping,
        suggest_declaration,
        ln,
    )
}

fn address_impl(
    compilation_env: &mut CompilationEnv,
    address_mapping: &UniqueMap<Name, Option<Spanned<AddressBytes>>>,
    suggest_declaration: bool,
    sp!(loc, ln_): P::LeadingNameAccess,
) -> Address {
    match ln_ {
        P::LeadingNameAccess_::AnonymousAddress(bytes) => Address::Anonymous(sp(loc, bytes)),
        P::LeadingNameAccess_::Name(n) => {
            if address_mapping.get(&n).is_none() {
                compilation_env.add_diag(unbound_address_error(suggest_declaration, loc, &n));
            }
            Address::Named(n)
        }
    }
}

fn module_ident(context: &mut Context, sp!(loc, mident_): P::ModuleIdent) -> ModuleIdent {
    let P::ModuleIdent_ {
        address: ln,
        module,
    } = mident_;
    let addr = address(context, /* suggest_declaration */ false, ln);
    sp(loc, ModuleIdent_::new(addr, module))
}

fn check_module_address(
    context: &mut Context,
    loc: Loc,
    addr: Address,
    m: &mut P::ModuleDefinition,
) -> Spanned<Address> {
    let module_address = std::mem::take(&mut m.address);
    match module_address {
        Some(other_paddr) => {
            let other_loc = other_paddr.loc;
            let other_addr = address(context, /* suggest_declaration */ true, other_paddr);
            let msg = if addr == other_addr {
                "Redundant address specification"
            } else {
                "Multiple addresses specified for module"
            };
            context.env.add_diag(diag!(
                Declarations::DuplicateItem,
                (other_loc, msg),
                (loc, "Address previously specified here")
            ));
            sp(other_loc, other_addr)
        }
        None => sp(loc, addr),
    }
}

fn module(
    context: &mut Context,
    module_map: &mut UniqueMap<ModuleIdent, E::ModuleDefinition>,
    module_address: Option<Spanned<Address>>,
    module_def: P::ModuleDefinition,
) {
    assert!(context.address == None);
    let (mident, mod_) = module_(context, module_address, module_def);
    if let Err((mident, old_loc)) = module_map.add(mident, mod_) {
        let mmsg = format!("Duplicate definition for module '{}'", mident);
        context.env.add_diag(diag!(
            Declarations::DuplicateItem,
            (mident.loc, mmsg),
            (old_loc, "Module previously defined here"),
        ));
    }
    context.address = None
}

fn set_sender_address(
    context: &mut Context,
    module_name: &ModuleName,
    sender: Option<Spanned<Address>>,
) {
    context.address = Some(match sender {
        Some(sp!(_, addr)) => addr,
        None => {
            let loc = module_name.loc();
            let msg = format!(
                "Invalid module declaration. The module does not have a specified address. Either \
                 declare it inside of an 'address <address> {{' block or declare it with an \
                 address 'module <address>::{}''",
                module_name
            );
            context
                .env
                .add_diag(diag!(Declarations::InvalidModule, (loc, msg)));
            Address::Anonymous(sp(loc, AddressBytes::DEFAULT_ERROR_BYTES))
        }
    })
}

fn module_(
    context: &mut Context,
    module_address: Option<Spanned<Address>>,
    mdef: P::ModuleDefinition,
) -> (ModuleIdent, E::ModuleDefinition) {
    let P::ModuleDefinition {
        attributes,
        loc,
        address,
        is_spec_module: _,
        name,
        members,
    } = mdef;
    let attributes = flatten_attributes(context, attributes);
    assert!(context.address == None);
    assert!(address == None);
    set_sender_address(context, &name, module_address);
    let _ = check_restricted_self_name(context, "module", &name.0);
    if name.value().starts_with(|c| c == '_') {
        let msg = format!(
            "Invalid module name '{}'. Module names cannot start with '_'",
            name,
        );
        context
            .env
            .add_diag(diag!(Declarations::InvalidName, (name.loc(), msg)));
    }

    let name = name;
    let name_loc = name.0.loc;
    let current_module = sp(
        name_loc,
        ModuleIdent_::new(context.cur_address().clone(), name),
    );

    let mut new_scope = AliasMap::new();
    module_self_aliases(&mut new_scope, &current_module);
    let members = members
        .into_iter()
        .filter_map(|member| aliases_from_member(context, &mut new_scope, &current_module, member))
        .collect::<Vec<_>>();
    let old_aliases = context.new_alias_scope(new_scope);
    assert!(
        old_aliases.is_empty(),
        "ICE there should be no aliases entering a module"
    );

    let mut friends = UniqueMap::new();
    let mut functions = UniqueMap::new();
    let mut constants = UniqueMap::new();
    let mut structs = UniqueMap::new();
    let mut specs = vec![];
    for member in members {
        match member {
            P::ModuleMember::Use(_) => unreachable!(),
            P::ModuleMember::Friend(f) => friend(context, &mut friends, f),
            P::ModuleMember::Function(mut f) => {
                if !context.is_source_definition {
                    f.body.value = P::FunctionBody_::Native
                }
                function(context, &mut functions, f)
            }
            P::ModuleMember::Constant(c) => constant(context, &mut constants, c),
            P::ModuleMember::Struct(s) => struct_def(context, &mut structs, s),
            P::ModuleMember::Spec(s) => specs.push(spec(context, s)),
        }
    }
    context.set_to_outer_scope(old_aliases);

    let def = E::ModuleDefinition {
        attributes,
        loc,
        is_source_module: context.is_source_definition,
        dependency_order: 0,
        immediate_neighbors: UniqueMap::new(),
        used_addresses: BTreeSet::new(),
        friends,
        structs,
        constants,
        functions,
        specs,
    };
    (current_module, def)
}

fn script(context: &mut Context, scripts: &mut Vec<E::Script>, pscript: P::Script) {
    scripts.push(script_(context, pscript))
}

fn script_(context: &mut Context, pscript: P::Script) -> E::Script {
    assert!(context.address == None);
    assert!(context.is_source_definition);
    let P::Script {
        attributes,
        loc,
        uses,
        constants: pconstants,
        function: pfunction,
        specs: pspecs,
    } = pscript;

    let attributes = flatten_attributes(context, attributes);
    let mut new_scope = AliasMap::new();
    for u in uses {
        use_(context, &mut new_scope, u.use_);
    }
    let old_aliases = context.new_alias_scope(new_scope);
    assert!(
        old_aliases.is_empty(),
        "ICE there should be no aliases entering a script"
    );

    let mut constants = UniqueMap::new();
    for c in pconstants {
        // TODO remove after Self rework
        check_valid_module_member_name(context, ModuleMemberKind::Constant, c.name.0.clone());
        constant(context, &mut constants, c);
    }

    // TODO remove after Self rework
    check_valid_module_member_name(
        context,
        ModuleMemberKind::Function,
        pfunction.name.0.clone(),
    );
    let (function_name, function) = function_(context, pfunction);
    match &function.visibility {
        Visibility::Public(loc) | Visibility::Script(loc) | Visibility::Friend(loc) => {
            let msg = format!(
                "Extraneous '{}' modifier. Script functions are always '{}'",
                function.visibility,
                Visibility::SCRIPT,
            );
            context
                .env
                .add_diag(diag!(Declarations::UnnecessaryItem, (*loc, msg)));
        }
        Visibility::Internal => (),
    }
    match &function.body {
        sp!(_, E::FunctionBody_::Defined(_)) => (),
        sp!(loc, E::FunctionBody_::Native) => {
            context.env.add_diag(diag!(
                Declarations::InvalidScript,
                (
                    *loc,
                    "Invalid 'native' function. 'script' functions must have a defined body"
                )
            ));
        }
    }
    let specs = specs(context, pspecs);
    context.set_to_outer_scope(old_aliases);

    E::Script {
        attributes,
        loc,
        immediate_neighbors: UniqueMap::new(),
        used_addresses: BTreeSet::new(),
        constants,
        function_name,
        function,
        specs,
    }
}

fn flatten_attributes(context: &mut Context, attributes: Vec<P::Attributes>) -> Vec<E::Attribute> {
    attributes
        .into_iter()
        .map(|attrs| attrs.value)
        .flatten()
        .flat_map(|attr| attribute(context, attr))
        .collect()
}

fn attribute(context: &mut Context, sp!(loc, attribute_): P::Attribute) -> Option<E::Attribute> {
    use E::Attribute_ as EA;
    use P::Attribute_ as PA;
    Some(sp(
        loc,
        match attribute_ {
            PA::Name(n) => EA::Name(n),
            PA::Assigned(n, v) => EA::Assigned(n, Box::new(attribute_value(context, *v)?)),
            PA::Parameterized(n, sp!(_, attrs_)) => EA::Parameterized(
                n,
                attrs_
                    .into_iter()
                    .map(|a| attribute(context, a))
                    .collect::<Option<Vec<_>>>()?,
            ),
        },
    ))
}

fn attribute_value(
    context: &mut Context,
    sp!(loc, avalue_): P::AttributeValue,
) -> Option<E::AttributeValue> {
    use E::AttributeValue_ as EV;
    use P::AttributeValue_ as PV;
    Some(sp(
        loc,
        match avalue_ {
            PV::Value(v) => EV::Value(value(context, v)?),
            PV::ModuleAccess(ma) => EV::ModuleAccess(name_access_chain(context, Access::Type, ma)?),
        },
    ))
}

//**************************************************************************************************
// Aliases
//**************************************************************************************************

fn all_module_members<'a>(
    compilation_env: &mut CompilationEnv,
    address_mapping: &UniqueMap<Name, Option<Spanned<AddressBytes>>>,
    members: &mut UniqueMap<ModuleIdent, ModuleMembers>,
    always_add: bool,
    defs: impl IntoIterator<Item = &'a P::Definition>,
) {
    for def in defs {
        match def {
            P::Definition::Module(m) => {
                let addr = match &m.address {
                    Some(a) => address_impl(
                        compilation_env,
                        &address_mapping,
                        /* suggest_declaration */ true,
                        a.clone(),
                    ),
                    // Error will be handled when the module is compiled
                    None => Address::Anonymous(sp(m.loc, AddressBytes::DEFAULT_ERROR_BYTES)),
                };
                module_members(members, always_add, addr, m)
            }
            P::Definition::Address(addr_def) => {
                let addr = address_impl(
                    compilation_env,
                    &address_mapping,
                    /* suggest_declaration */ false,
                    addr_def.addr.clone(),
                );
                for m in &addr_def.modules {
                    module_members(members, always_add, addr.clone(), m)
                }
            }
            P::Definition::Script(_) => (),
        }
    }
}

fn module_members(
    members: &mut UniqueMap<ModuleIdent, ModuleMembers>,
    always_add: bool,
    address: Address,
    m: &P::ModuleDefinition,
) {
    let mident = sp(m.name.loc(), ModuleIdent_::new(address, m.name.clone()));
    if !always_add && members.contains_key(&mident) {
        return;
    }
    let mut cur_members = members.remove(&mident).unwrap_or_else(ModuleMembers::new);
    for mem in &m.members {
        use P::{SpecBlockMember_ as SBM, SpecBlockTarget_ as SBT, SpecBlock_ as SB};
        match mem {
            P::ModuleMember::Function(f) => {
                cur_members.insert(f.name.0.clone(), ModuleMemberKind::Function);
            }
            P::ModuleMember::Constant(c) => {
                cur_members.insert(c.name.0.clone(), ModuleMemberKind::Constant);
            }
            P::ModuleMember::Struct(s) => {
                cur_members.insert(s.name.0.clone(), ModuleMemberKind::Struct);
            }
            P::ModuleMember::Spec(
                sp!(
                    _,
                    SB {
                        target,
                        members,
                        ..
                    }
                ),
            ) => match &target.value {
                SBT::Schema(n, _) => {
                    cur_members.insert(n.clone(), ModuleMemberKind::Schema);
                }
                SBT::Module => {
                    for sp!(_, smember_) in members {
                        if let SBM::Function { name, .. } = smember_ {
                            cur_members.insert(name.0.clone(), ModuleMemberKind::Function);
                        }
                    }
                }
                _ => (),
            },
            P::ModuleMember::Use(_) | P::ModuleMember::Friend(_) => (),
        };
    }
    members.add(mident, cur_members).unwrap();
}

fn module_self_aliases(acc: &mut AliasMap, current_module: &ModuleIdent) {
    let self_name = sp(current_module.loc, ModuleName::SELF_NAME.into());
    acc.add_implicit_module_alias(self_name, current_module.clone())
        .unwrap()
}

fn aliases_from_member(
    context: &mut Context,
    acc: &mut AliasMap,
    current_module: &ModuleIdent,
    member: P::ModuleMember,
) -> Option<P::ModuleMember> {
    use P::{SpecBlockMember_ as SBM, SpecBlockTarget_ as SBT, SpecBlock_ as SB};
    macro_rules! check_name_and_add_implicit_alias {
        ($kind:expr, $name:expr) => {{
            if let Some(n) = check_valid_module_member_name(context, $kind, $name) {
                if let Err(loc) =
                    acc.add_implicit_member_alias(n.clone(), current_module.clone(), n.clone())
                {
                    duplicate_module_member(context, loc, n)
                }
            }
        }};
    }

    match member {
        P::ModuleMember::Use(u) => {
            use_(context, acc, u.use_);
            None
        }
        f @ P::ModuleMember::Friend(_) => {
            // friend declarations do not produce implicit aliases
            Some(f)
        }
        P::ModuleMember::Function(f) => {
            let n = f.name.0.clone();
            check_name_and_add_implicit_alias!(ModuleMemberKind::Function, n);
            Some(P::ModuleMember::Function(f))
        }
        P::ModuleMember::Constant(c) => {
            let n = c.name.0.clone();
            check_name_and_add_implicit_alias!(ModuleMemberKind::Constant, n);
            Some(P::ModuleMember::Constant(c))
        }
        P::ModuleMember::Struct(s) => {
            let n = s.name.0.clone();
            check_name_and_add_implicit_alias!(ModuleMemberKind::Struct, n);
            Some(P::ModuleMember::Struct(s))
        }
        P::ModuleMember::Spec(s) => {
            let sp!(
                _,
                SB {
                    target,
                    members,
                    ..
                }
            ) = &s;
            match &target.value {
                SBT::Schema(n, _) => {
                    check_name_and_add_implicit_alias!(ModuleMemberKind::Schema, n.clone());
                }
                SBT::Module => {
                    for sp!(_, smember_) in members {
                        if let SBM::Function { name, .. } = smember_ {
                            let n = name.0.clone();
                            check_name_and_add_implicit_alias!(ModuleMemberKind::Function, n);
                        }
                    }
                }
                _ => (),
            };
            Some(P::ModuleMember::Spec(s))
        }
    }
}

fn use_(context: &mut Context, acc: &mut AliasMap, u: P::Use) {
    let unbound_module = |mident: &ModuleIdent| -> Diagnostic {
        diag!(
            NameResolution::UnboundModule,
            (
                mident.loc,
                format!("Invalid 'use'. Unbound module: '{}'", mident),
            )
        )
    };
    macro_rules! add_module_alias {
        ($ident:expr, $alias_opt:expr) => {{
            let alias: Name = $alias_opt.unwrap_or_else(|| $ident.value.module.0.clone());
            if let Err(()) = check_restricted_self_name(context, "module alias", &alias) {
                return;
            }

            if let Err(old_loc) = acc.add_module_alias(alias.clone(), $ident) {
                duplicate_module_alias(context, old_loc, alias)
            }
        }};
    }
    match u {
        P::Use::Module(pmident, alias_opt) => {
            let mident = module_ident(context, pmident);
            if !context.module_members.contains_key(&mident) {
                context.env.add_diag(unbound_module(&mident));
                return;
            };
            add_module_alias!(mident, alias_opt.map(|m| m.0))
        }
        P::Use::Members(pmident, sub_uses) => {
            let mident = module_ident(context, pmident);
            let members = match context.module_members.get(&mident) {
                Some(members) => members,
                None => {
                    context.env.add_diag(unbound_module(&mident));
                    return;
                }
            };
            let mloc = *context.module_members.get_loc(&mident).unwrap();
            let sub_uses_kinds = sub_uses
                .into_iter()
                .map(|(member, alia_opt)| {
                    let kind = members.get(&member).cloned();
                    (member, alia_opt, kind)
                })
                .collect::<Vec<_>>();

            for (member, alias_opt, member_kind_opt) in sub_uses_kinds {
                if member.value == ModuleName::SELF_NAME {
                    add_module_alias!(mident.clone(), alias_opt);
                    continue;
                }

                // check is member

                let member_kind = match member_kind_opt {
                    None => {
                        let msg = format!(
                            "Invalid 'use'. Unbound member '{}' in module '{}'",
                            member, mident
                        );
                        context.env.add_diag(diag!(
                            NameResolution::UnboundModuleMember,
                            (member.loc, msg),
                            (mloc, format!("Module '{}' declared here", mident)),
                        ));
                        continue;
                    }
                    Some(m) => m,
                };

                let alias = alias_opt.unwrap_or_else(|| member.clone());

                let alias = match check_valid_module_member_alias(context, member_kind, alias) {
                    None => continue,
                    Some(alias) => alias,
                };
                if let Err(old_loc) = acc.add_member_alias(alias.clone(), mident.clone(), member) {
                    duplicate_module_member(context, old_loc, alias)
                }
            }
        }
    }
}

fn duplicate_module_alias(context: &mut Context, old_loc: Loc, alias: Name) {
    let msg = format!(
        "Duplicate module alias '{}'. Module aliases must be unique within a given namespace",
        alias
    );
    context.env.add_diag(diag!(
        Declarations::DuplicateItem,
        (alias.loc, msg),
        (old_loc, "Alias previously defined here"),
    ));
}

fn duplicate_module_member(context: &mut Context, old_loc: Loc, alias: Name) {
    let msg = format!(
        "Duplicate module member or alias '{}'. Top level names in a namespace must be unique",
        alias
    );
    context.env.add_diag(diag!(
        Declarations::DuplicateItem,
        (alias.loc, msg),
        (old_loc, "Alias previously defined here"),
    ));
}

fn unused_alias(context: &mut Context, alias: Name) {
    if !context.is_source_definition {
        return;
    }

    context.env.add_diag(diag!(
        UnusedItem::Alias,
        (
            alias.loc,
            format!("Unused 'use' of alias '{}'. Consider removing it", alias)
        ),
    ))
}

//**************************************************************************************************
// Structs
//**************************************************************************************************

fn struct_def(
    context: &mut Context,
    structs: &mut UniqueMap<StructName, E::StructDefinition>,
    pstruct: P::StructDefinition,
) {
    let (sname, sdef) = struct_def_(context, pstruct);
    if let Err(_old_loc) = structs.add(sname, sdef) {
        assert!(context.env.has_errors())
    }
}

fn struct_def_(
    context: &mut Context,
    pstruct: P::StructDefinition,
) -> (StructName, E::StructDefinition) {
    let P::StructDefinition {
        attributes,
        loc,
        name,
        abilities: abilities_vec,
        type_parameters: pty_params,
        fields: pfields,
    } = pstruct;
    let attributes = flatten_attributes(context, attributes);
    let old_aliases = context.new_alias_scope(AliasMap::new());
    let type_parameters = struct_type_parameters(context, pty_params);
    let abilities = ability_set(context, "modifier", abilities_vec);
    let fields = struct_fields(context, &name, pfields);
    let sdef = E::StructDefinition {
        attributes,
        loc,
        abilities,
        type_parameters,
        fields,
    };
    context.set_to_outer_scope(old_aliases);
    (name, sdef)
}

fn struct_fields(
    context: &mut Context,
    sname: &StructName,
    pfields: P::StructFields,
) -> E::StructFields {
    let pfields_vec = match pfields {
        P::StructFields::Native(loc) => return E::StructFields::Native(loc),
        P::StructFields::Defined(v) => v,
    };
    let mut field_map = UniqueMap::new();
    for (idx, (field, pt)) in pfields_vec.into_iter().enumerate() {
        let t = type_(context, pt);
        if let Err((field, old_loc)) = field_map.add(field, (idx, t)) {
            context.env.add_diag(diag!(
                Declarations::DuplicateItem,
                (
                    field.loc(),
                    format!(
                        "Duplicate definition for field '{}' in struct '{}'",
                        field, sname
                    ),
                ),
                (old_loc, "Field previously defined here"),
            ));
        }
    }
    E::StructFields::Defined(field_map)
}

//**************************************************************************************************
// Friends
//**************************************************************************************************

fn friend(
    context: &mut Context,
    friends: &mut UniqueMap<ModuleIdent, E::Friend>,
    pfriend: P::FriendDecl,
) {
    match friend_(context, pfriend) {
        Some((mident, friend)) => match friends.get(&mident) {
            None => friends.add(mident, friend).unwrap(),
            Some(old_friend) => {
                let msg = format!(
                    "Duplicate friend declaration '{}'. Friend declarations in a module must be \
                     unique",
                    mident
                );
                context.env.add_diag(diag!(
                    Declarations::DuplicateItem,
                    (friend.loc, msg),
                    (old_friend.loc, "Friend previously declared here"),
                ));
            }
        },
        None => assert!(context.env.has_errors()),
    };
}

fn friend_(context: &mut Context, pfriend_decl: P::FriendDecl) -> Option<(ModuleIdent, E::Friend)> {
    assert!(context.exp_specs.is_empty());
    let P::FriendDecl {
        attributes: pattributes,
        loc,
        friend: pfriend,
    } = pfriend_decl;
    let mident = name_access_chain_to_module_ident(context, pfriend)?;
    let attributes = flatten_attributes(context, pattributes);
    Some((mident, E::Friend { attributes, loc }))
}

//**************************************************************************************************
// Constants
//**************************************************************************************************

fn constant(
    context: &mut Context,
    constants: &mut UniqueMap<ConstantName, E::Constant>,
    pconstant: P::Constant,
) {
    let (name, constant) = constant_(context, pconstant);
    if let Err(_old_loc) = constants.add(name, constant) {
        assert!(context.env.has_errors())
    }
}

fn constant_(context: &mut Context, pconstant: P::Constant) -> (ConstantName, E::Constant) {
    assert!(context.exp_specs.is_empty());
    let P::Constant {
        attributes: pattributes,
        loc,
        name,
        signature: psignature,
        value: pvalue,
    } = pconstant;
    let attributes = flatten_attributes(context, pattributes);
    let signature = type_(context, psignature);
    let value = exp_(context, pvalue);
    let _specs = context.extract_exp_specs();
    let constant = E::Constant {
        attributes,
        loc,
        signature,
        value,
    };
    (name, constant)
}

//**************************************************************************************************
// Functions
//**************************************************************************************************

fn function(
    context: &mut Context,
    functions: &mut UniqueMap<FunctionName, E::Function>,
    pfunction: P::Function,
) {
    let (fname, fdef) = function_(context, pfunction);
    if let Err(_old_loc) = functions.add(fname, fdef) {
        assert!(context.env.has_errors())
    }
}

fn function_(context: &mut Context, pfunction: P::Function) -> (FunctionName, E::Function) {
    let P::Function {
        attributes: pattributes,
        loc,
        name,
        visibility,
        signature: psignature,
        body: pbody,
        acquires,
    } = pfunction;
    assert!(context.exp_specs.is_empty());
    let attributes = flatten_attributes(context, pattributes);
    let old_aliases = context.new_alias_scope(AliasMap::new());
    let signature = function_signature(context, psignature);
    let acquires = acquires
        .into_iter()
        .flat_map(|a| name_access_chain(context, Access::Type, a))
        .collect();
    let body = function_body(context, pbody);
    let specs = context.extract_exp_specs();
    let fdef = E::Function {
        attributes,
        loc,
        visibility,
        signature,
        acquires,
        body,
        specs,
    };
    context.set_to_outer_scope(old_aliases);

    (name, fdef)
}

fn function_signature(
    context: &mut Context,
    psignature: P::FunctionSignature,
) -> E::FunctionSignature {
    let P::FunctionSignature {
        type_parameters: pty_params,
        parameters: pparams,
        return_type: pret_ty,
    } = psignature;
    let type_parameters = fun_type_parameters(context, pty_params);
    let parameters = pparams
        .into_iter()
        .map(|(v, t)| (v, type_(context, t)))
        .collect::<Vec<_>>();
    for (v, _) in &parameters {
        check_valid_local_name(context, v)
    }
    let return_type = type_(context, pret_ty);
    E::FunctionSignature {
        type_parameters,
        parameters,
        return_type,
    }
}

fn function_body(context: &mut Context, sp!(loc, pbody_): P::FunctionBody) -> E::FunctionBody {
    use E::FunctionBody_ as EF;
    use P::FunctionBody_ as PF;
    let body_ = match pbody_ {
        PF::Native => EF::Native,
        PF::Defined(seq) => EF::Defined(sequence(context, loc, seq)),
    };
    sp(loc, body_)
}

//**************************************************************************************************
// Specification Blocks
//**************************************************************************************************

fn specs(context: &mut Context, pspecs: Vec<P::SpecBlock>) -> Vec<E::SpecBlock> {
    pspecs.into_iter().map(|s| spec(context, s)).collect()
}

fn spec(context: &mut Context, sp!(loc, pspec): P::SpecBlock) -> E::SpecBlock {
    let P::SpecBlock_ {
        attributes: pattributes,
        target,
        uses,
        members: pmembers,
    } = pspec;

    let attributes = flatten_attributes(context, pattributes);
    context.in_spec_context = true;
    let mut new_scope = AliasMap::new();
    for u in uses {
        use_(context, &mut new_scope, u.use_);
    }
    let old_aliases = context.new_alias_scope(new_scope);

    let members = pmembers
        .into_iter()
        .map(|m| spec_member(context, m))
        .collect();

    context.set_to_outer_scope(old_aliases);
    context.in_spec_context = false;

    sp(
        loc,
        E::SpecBlock_ {
            attributes,
            target: spec_target(context, target),
            members,
        },
    )
}

fn spec_target(context: &mut Context, sp!(loc, pt): P::SpecBlockTarget) -> E::SpecBlockTarget {
    use E::SpecBlockTarget_ as ET;
    use P::SpecBlockTarget_ as PT;
    let et = match pt {
        PT::Code => ET::Code,
        PT::Module => ET::Module,
        PT::Schema(name, type_params) => {
            let old_aliases = context.new_alias_scope(AliasMap::new());
            let target = ET::Schema(name, fun_type_parameters(context, type_params));
            context.set_to_outer_scope(old_aliases);
            target
        }
        PT::Member(name, signature_opt) => {
            let old_aliases = context.new_alias_scope(AliasMap::new());
            let target = ET::Member(
                name,
                signature_opt.map(|s| Box::new(function_signature(context, *s))),
            );
            context.set_to_outer_scope(old_aliases);
            target
        }
    };
    sp(loc, et)
}

fn spec_member(context: &mut Context, sp!(loc, pm): P::SpecBlockMember) -> E::SpecBlockMember {
    use E::SpecBlockMember_ as EM;
    use P::SpecBlockMember_ as PM;
    let em = match pm {
        PM::Condition {
            kind,
            properties: pproperties,
            exp,
            additional_exps,
        } => {
            let properties = pproperties
                .into_iter()
                .map(|p| pragma_property(context, p))
                .collect();
            let exp = exp_(context, exp);
            let additional_exps = additional_exps
                .into_iter()
                .map(|e| exp_(context, e))
                .collect();
            EM::Condition {
                kind,
                properties,
                exp,
                additional_exps,
            }
        }
        PM::Function {
            name,
            uninterpreted,
            signature,
            body,
        } => {
            let old_aliases = context.new_alias_scope(AliasMap::new());
            let body = function_body(context, body);
            let signature = function_signature(context, signature);
            context.set_to_outer_scope(old_aliases);
            EM::Function {
                uninterpreted,
                name,
                signature,
                body,
            }
        }
        PM::Variable {
            is_global,
            name,
            type_parameters: pty_params,
            type_: t,
        } => {
            let old_aliases = context.new_alias_scope(AliasMap::new());
            let type_parameters = fun_type_parameters(context, pty_params);
            let t = type_(context, t);
            context.set_to_outer_scope(old_aliases);
            EM::Variable {
                is_global,
                name,
                type_parameters,
                type_: t,
            }
        }
        PM::Let {
            name,
            post_state: old,
            def: pdef,
        } => {
            let def = exp_(context, pdef);
            EM::Let {
                name,
                post_state: old,
                def,
            }
        }
        PM::Include {
            properties: pproperties,
            exp: pexp,
        } => {
            let properties = pproperties
                .into_iter()
                .map(|p| pragma_property(context, p))
                .collect();
            EM::Include {
                properties,
                exp: exp_(context, pexp),
            }
        }
        PM::Apply {
            exp: pexp,
            patterns,
            exclusion_patterns,
        } => EM::Apply {
            exp: exp_(context, pexp),
            patterns,
            exclusion_patterns,
        },
        PM::Pragma {
            properties: pproperties,
        } => {
            let properties = pproperties
                .into_iter()
                .map(|p| pragma_property(context, p))
                .collect();
            EM::Pragma { properties }
        }
    };
    sp(loc, em)
}

fn pragma_property(context: &mut Context, sp!(loc, pp_): P::PragmaProperty) -> E::PragmaProperty {
    let P::PragmaProperty_ {
        name,
        value: pv_opt,
    } = pp_;
    let value = pv_opt.and_then(|pv| pragma_value(context, pv));
    sp(loc, E::PragmaProperty_ { name, value })
}

fn pragma_value(context: &mut Context, pv: P::PragmaValue) -> Option<E::PragmaValue> {
    match pv {
        P::PragmaValue::Literal(v) => value(context, v).map(E::PragmaValue::Literal),
        P::PragmaValue::Ident(ma) => {
            name_access_chain(context, Access::Term, ma).map(E::PragmaValue::Ident)
        }
    }
}

//**************************************************************************************************
// Types
//**************************************************************************************************

fn ability_set(context: &mut Context, case: &str, abilities_vec: Vec<Ability>) -> E::AbilitySet {
    let mut set = E::AbilitySet::empty();
    for ability in abilities_vec {
        let loc = ability.loc;
        if let Err(prev_loc) = set.add(ability) {
            context.env.add_diag(diag!(
                Declarations::DuplicateItem,
                (loc, format!("Duplicate '{}' ability {}", ability, case)),
                (prev_loc, "Ability previously given here")
            ));
        }
    }
    set
}

fn fun_type_parameters(
    context: &mut Context,
    pty_params: Vec<(Name, Vec<Ability>)>,
) -> Vec<(Name, E::AbilitySet)> {
    assert!(
        context.aliases.current_scope_is_empty(),
        "ICE alias scope should be cleared before handling type parameters"
    );
    pty_params
        .into_iter()
        .map(|(name, constraints_vec)| {
            context.aliases.remove_member_alias(&name);
            let constraints = ability_set(context, "constraint", constraints_vec);
            (name, constraints)
        })
        .collect()
}

fn struct_type_parameters(
    context: &mut Context,
    pty_params: Vec<P::StructTypeParameter>,
) -> Vec<E::StructTypeParameter> {
    assert!(
        context.aliases.current_scope_is_empty(),
        "ICE alias scope should be cleared before handling type parameters"
    );
    pty_params
        .into_iter()
        .map(|param| {
            context.aliases.remove_member_alias(&param.name);
            E::StructTypeParameter {
                is_phantom: param.is_phantom,
                name: param.name,
                constraints: ability_set(context, "constraint", param.constraints),
            }
        })
        .collect()
}

fn type_(context: &mut Context, sp!(loc, pt_): P::Type) -> E::Type {
    use E::Type_ as ET;
    use P::Type_ as PT;
    let t_ = match pt_ {
        PT::Unit => ET::Unit,
        PT::Multiple(ts) => ET::Multiple(types(context, ts)),
        PT::Apply(pn, ptyargs) => {
            let tyargs = types(context, ptyargs);
            match name_access_chain(context, Access::Type, *pn) {
                None => {
                    assert!(context.env.has_errors());
                    ET::UnresolvedError
                }
                Some(n) => ET::Apply(n, tyargs),
            }
        }
        PT::Ref(mut_, inner) => ET::Ref(mut_, Box::new(type_(context, *inner))),
        PT::Fun(args, result) => {
            if context.in_spec_context {
                let args = types(context, args);
                let result = type_(context, *result);
                ET::Fun(args, Box::new(result))
            } else {
                context.env.add_diag(diag!(
                    Syntax::SpecContextRestricted,
                    (loc, "`|_|_` function type only allowed in specifications")
                ));
                ET::UnresolvedError
            }
        }
    };
    sp(loc, t_)
}

fn types(context: &mut Context, pts: Vec<P::Type>) -> Vec<E::Type> {
    pts.into_iter().map(|pt| type_(context, pt)).collect()
}

fn optional_types(context: &mut Context, pts_opt: Option<Vec<P::Type>>) -> Option<Vec<E::Type>> {
    pts_opt.map(|pts| pts.into_iter().map(|pt| type_(context, pt)).collect())
}

#[derive(Clone, Copy)]
enum Access {
    Type,
    ApplyNamed,
    ApplyPositional,
    Term,
}

fn name_access_chain(
    context: &mut Context,
    access: Access,
    sp!(loc, ptn_): P::NameAccessChain,
) -> Option<E::ModuleAccess> {
    use E::ModuleAccess_ as EN;
    use P::{LeadingNameAccess_ as LN, NameAccessChain_ as PN};

    let tn_ = match (access, ptn_) {
        (Access::ApplyPositional, PN::One(n))
        | (Access::ApplyNamed, PN::One(n))
        | (Access::Type, PN::One(n)) => match context.aliases.member_alias_get(&n) {
            Some((mident, mem)) => EN::ModuleAccess(mident.clone(), mem.clone()),
            None => EN::Name(n),
        },
        (Access::Term, PN::One(n)) if is_valid_struct_constant_or_schema_name(&n.value) => {
            match context.aliases.member_alias_get(&n) {
                Some((mident, mem)) => EN::ModuleAccess(mident.clone(), mem.clone()),
                None => EN::Name(n),
            }
        }
        (Access::Term, PN::One(n)) => EN::Name(n),
        (_, PN::Two(sp!(nloc, LN::AnonymousAddress(_)), _)) => {
            context
                .env
                .add_diag(unexpected_address_module_error(loc, nloc, access));
            return None;
        }

        (_, PN::Two(sp!(_, LN::Name(n1)), n2)) => match context.aliases.module_alias_get(&n1) {
            None => {
                context.env.add_diag(diag!(
                    NameResolution::UnboundModule,
                    (n1.loc, format!("Unbound module alias '{}'", n1))
                ));
                return None;
            }
            Some(mident) => EN::ModuleAccess(mident.clone(), n2),
        },
        (_, PN::Three(sp!(ident_loc, (ln, n2)), n3)) => {
            let addr = address(context, /* suggest_declaration */ false, ln);
            let mident = sp(ident_loc, ModuleIdent_::new(addr, ModuleName(n2)));
            EN::ModuleAccess(mident, n3)
        }
    };
    Some(sp(loc, tn_))
}

fn name_access_chain_to_module_ident(
    context: &mut Context,
    sp!(loc, pn_): P::NameAccessChain,
) -> Option<E::ModuleIdent> {
    use P::NameAccessChain_ as PN;
    match pn_ {
        PN::One(name) => match context.aliases.module_alias_get(&name) {
            None => {
                context.env.add_diag(diag!(
                    NameResolution::UnboundModule,
                    (name.loc, format!("Unbound module alias '{}'", name)),
                ));
                None
            }
            Some(mident) => Some(mident.clone()),
        },
        PN::Two(ln, n) => {
            let pmident_ = P::ModuleIdent_ {
                address: ln,
                module: ModuleName(n),
            };
            Some(module_ident(context, sp(loc, pmident_)))
        }
        PN::Three(sp!(ident_loc, (ln, n)), mem) => {
            // Process the module ident just for errors
            let pmident_ = P::ModuleIdent_ {
                address: ln,
                module: ModuleName(n),
            };
            let _ = module_ident(context, sp(ident_loc, pmident_));
            context.env.add_diag(diag!(
                NameResolution::NamePositionMismatch,
                (
                    mem.loc,
                    "Unexpected module member access. Expected a module identifier only",
                )
            ));
            None
        }
    }
}

fn unexpected_address_module_error(loc: Loc, nloc: Loc, access: Access) -> Diagnostic {
    let case = match access {
        Access::Type | Access::ApplyNamed | Access::ApplyPositional => "type",
        Access::Term => "expression",
    };
    let unexpected_msg = format!(
        "Unexpected module identifier. A module identifier is not a valid {}",
        case
    );
    diag!(
        NameResolution::NamePositionMismatch,
        (loc, unexpected_msg),
        (nloc, "Expected a module name".to_owned()),
    )
}

//**************************************************************************************************
// Expressions
//**************************************************************************************************

// TODO Support uses inside functions. AliasMap will become an accumulator

fn sequence(context: &mut Context, loc: Loc, seq: P::Sequence) -> E::Sequence {
    let (uses, pitems, maybe_last_semicolon_loc, pfinal_item) = seq;

    let mut new_scope = AliasMap::new();
    for u in uses {
        use_(context, &mut new_scope, u.use_);
    }
    let old_aliases = context.new_alias_scope(new_scope);
    let mut items: VecDeque<E::SequenceItem> = pitems
        .into_iter()
        .map(|item| sequence_item(context, item))
        .collect();
    let final_e_opt = pfinal_item.map(|item| exp_(context, item));
    let final_e = match final_e_opt {
        None => {
            let last_semicolon_loc = match maybe_last_semicolon_loc {
                Some(l) => l,
                None => loc,
            };
            sp(last_semicolon_loc, E::Exp_::Unit { trailing: true })
        }
        Some(e) => e,
    };
    let final_item = sp(final_e.loc, E::SequenceItem_::Seq(final_e));
    items.push_back(final_item);
    context.set_to_outer_scope(old_aliases);
    items
}

fn sequence_item(context: &mut Context, sp!(loc, pitem_): P::SequenceItem) -> E::SequenceItem {
    use E::SequenceItem_ as ES;
    use P::SequenceItem_ as PS;
    let item_ = match pitem_ {
        PS::Seq(e) => ES::Seq(exp_(context, *e)),
        PS::Declare(pb, pty_opt) => {
            let b_opt = bind_list(context, pb);
            let ty_opt = pty_opt.map(|t| type_(context, t));
            match b_opt {
                None => {
                    assert!(context.env.has_errors());
                    ES::Seq(sp(loc, E::Exp_::UnresolvedError))
                }
                Some(b) => ES::Declare(b, ty_opt),
            }
        }
        PS::Bind(pb, pty_opt, pe) => {
            let b_opt = bind_list(context, pb);
            let ty_opt = pty_opt.map(|t| type_(context, t));
            let e_ = exp_(context, *pe);
            let e = match ty_opt {
                None => e_,
                Some(ty) => sp(e_.loc, E::Exp_::Annotate(Box::new(e_), ty)),
            };
            match b_opt {
                None => {
                    assert!(context.env.has_errors());
                    ES::Seq(sp(loc, E::Exp_::UnresolvedError))
                }
                Some(b) => ES::Bind(b, e),
            }
        }
    };
    sp(loc, item_)
}

fn exps(context: &mut Context, pes: Vec<P::Exp>) -> Vec<E::Exp> {
    pes.into_iter().map(|pe| exp_(context, pe)).collect()
}

fn exp(context: &mut Context, pe: P::Exp) -> Box<E::Exp> {
    Box::new(exp_(context, pe))
}

fn exp_(context: &mut Context, sp!(loc, pe_): P::Exp) -> E::Exp {
    use E::Exp_ as EE;
    use P::Exp_ as PE;
    let e_ = match pe_ {
        PE::Unit => EE::Unit { trailing: false },
        PE::Value(pv) => match value(context, pv) {
            Some(v) => EE::Value(v),
            None => {
                assert!(context.env.has_errors());
                EE::UnresolvedError
            }
        },
        PE::Move(v) => EE::Move(v),
        PE::Copy(v) => EE::Copy(v),
        PE::Name(_, Some(_)) if !context.in_spec_context => {
            context.env.add_diag(diag!(
                Syntax::SpecContextRestricted,
                (
                    loc,
                    "Expected name to be followed by a brace-enclosed list of field expressions \
                     or a parenthesized list of arguments for a function call",
                )
            ));
            EE::UnresolvedError
        }
        PE::Name(pn, ptys_opt) => {
            let en_opt = name_access_chain(context, Access::Term, pn);
            let tys_opt = optional_types(context, ptys_opt);
            match en_opt {
                Some(en) => EE::Name(en, tys_opt),
                None => {
                    assert!(context.env.has_errors());
                    EE::UnresolvedError
                }
            }
        }
        PE::Call(pn, ptys_opt, sp!(rloc, prs)) => {
            let tys_opt = optional_types(context, ptys_opt);
            let ers = sp(rloc, exps(context, prs));
            let en_opt = name_access_chain(context, Access::ApplyPositional, pn);
            match en_opt {
                Some(en) => EE::Call(en, tys_opt, ers),
                None => {
                    assert!(context.env.has_errors());
                    EE::UnresolvedError
                }
            }
        }
        PE::Pack(pn, ptys_opt, pfields) => {
            let en_opt = name_access_chain(context, Access::ApplyNamed, pn);
            let tys_opt = optional_types(context, ptys_opt);
            let efields_vec = pfields
                .into_iter()
                .map(|(f, pe)| (f, exp_(context, pe)))
                .collect();
            let efields = fields(context, loc, "construction", "argument", efields_vec);
            match en_opt {
                Some(en) => EE::Pack(en, tys_opt, efields),
                None => {
                    assert!(context.env.has_errors());
                    EE::UnresolvedError
                }
            }
        }
        PE::IfElse(pb, pt, pf_opt) => {
            let eb = exp(context, *pb);
            let et = exp(context, *pt);
            let ef = match pf_opt {
                None => Box::new(sp(loc, EE::Unit { trailing: false })),
                Some(pf) => exp(context, *pf),
            };
            EE::IfElse(eb, et, ef)
        }
        PE::While(pb, ploop) => EE::While(exp(context, *pb), exp(context, *ploop)),
        PE::Loop(ploop) => EE::Loop(exp(context, *ploop)),
        PE::Block(seq) => EE::Block(sequence(context, loc, seq)),
        PE::Lambda(pbs, pe) => {
            if !context.in_spec_context {
                context.env.add_diag(diag!(
                    Syntax::SpecContextRestricted,
                    (loc, "lambda expression only allowed in specifications"),
                ));
                EE::UnresolvedError
            } else {
                let bs_opt = bind_list(context, pbs);
                let e = exp_(context, *pe);
                match bs_opt {
                    Some(bs) => EE::Lambda(bs, Box::new(e)),
                    None => {
                        assert!(context.env.has_errors());
                        EE::UnresolvedError
                    }
                }
            }
        }
        PE::Quant(k, prs, ptrs, pc, pe) => {
            if !context.in_spec_context {
                context.env.add_diag(diag!(
                    Syntax::SpecContextRestricted,
                    (loc, "quantifer expression only allowed in specifications")
                ));
                EE::UnresolvedError
            } else {
                let rs_opt = bind_with_range_list(context, prs);
                let rtrs = ptrs
                    .into_iter()
                    .map(|trs| trs.into_iter().map(|tr| exp_(context, tr)).collect())
                    .collect();
                let rc = pc.map(|c| Box::new(exp_(context, *c)));
                let re = exp_(context, *pe);
                match rs_opt {
                    Some(rs) => EE::Quant(k, rs, rtrs, rc, Box::new(re)),
                    None => {
                        assert!(context.env.has_errors());
                        EE::UnresolvedError
                    }
                }
            }
        }
        PE::ExpList(pes) => {
            assert!(pes.len() > 1);
            EE::ExpList(exps(context, pes))
        }

        PE::Assign(lvalue, rhs) => {
            let l_opt = lvalues(context, *lvalue);
            let er = exp(context, *rhs);
            match l_opt {
                None => {
                    assert!(context.env.has_errors());
                    EE::UnresolvedError
                }
                Some(LValue::Assigns(al)) => EE::Assign(al, er),
                Some(LValue::Mutate(el)) => EE::Mutate(el, er),
                Some(LValue::FieldMutate(edotted)) => EE::FieldMutate(edotted, er),
            }
        }
        PE::Return(pe_opt) => {
            let ev = match pe_opt {
                None => Box::new(sp(loc, EE::Unit { trailing: false })),
                Some(pe) => exp(context, *pe),
            };
            EE::Return(ev)
        }
        PE::Abort(pe) => EE::Abort(exp(context, *pe)),
        PE::Break => EE::Break,
        PE::Continue => EE::Continue,
        PE::Dereference(pe) => EE::Dereference(exp(context, *pe)),
        PE::UnaryExp(op, pe) => EE::UnaryExp(op, exp(context, *pe)),
        PE::BinopExp(pl, op, pr) => {
            if op.value.is_spec_only() && !context.in_spec_context {
                let msg = format!(
                    "`{}` operator only allowed in specifications",
                    op.value.symbol()
                );
                context
                    .env
                    .add_diag(diag!(Syntax::SpecContextRestricted, (loc, msg)));
                EE::UnresolvedError
            } else {
                EE::BinopExp(exp(context, *pl), op, exp(context, *pr))
            }
        }
        PE::Borrow(mut_, pr) => EE::Borrow(mut_, exp(context, *pr)),
        pdotted_ @ PE::Dot(_, _) => match exp_dotted(context, sp(loc, pdotted_)) {
            Some(edotted) => EE::ExpDotted(Box::new(edotted)),
            None => {
                assert!(context.env.has_errors());
                EE::UnresolvedError
            }
        },
        PE::Cast(e, ty) => EE::Cast(exp(context, *e), type_(context, ty)),
        PE::Index(e, i) => {
            if context.in_spec_context {
                EE::Index(exp(context, *e), exp(context, *i))
            } else {
                let msg = "`_[_]` index operator only allowed in specifications";
                context
                    .env
                    .add_diag(diag!(Syntax::SpecContextRestricted, (loc, msg)));
                EE::UnresolvedError
            }
        }
        PE::Annotate(e, ty) => EE::Annotate(exp(context, *e), type_(context, ty)),
        PE::Spec(_) if context.in_spec_context => {
            context.env.add_diag(diag!(
                Syntax::SpecContextRestricted,
                (loc, "'spec' blocks cannot be used inside of a spec context",)
            ));
            EE::UnresolvedError
        }
        PE::Spec(spec_block) => {
            let (spec_id, unbound_names) = context.bind_exp_spec(spec_block);
            EE::Spec(spec_id, unbound_names)
        }
        PE::UnresolvedError => panic!("ICE error should have been thrown"),
    };
    sp(loc, e_)
}

fn exp_dotted(context: &mut Context, sp!(loc, pdotted_): P::Exp) -> Option<E::ExpDotted> {
    use E::ExpDotted_ as EE;
    use P::Exp_ as PE;
    let edotted_ = match pdotted_ {
        PE::Dot(plhs, field) => {
            let lhs = exp_dotted(context, *plhs)?;
            EE::Dot(Box::new(lhs), field)
        }
        pe_ => EE::Exp(exp_(context, sp(loc, pe_))),
    };
    Some(sp(loc, edotted_))
}

fn value(context: &mut Context, sp!(loc, pvalue_): P::Value) -> Option<E::Value> {
    use E::Value_ as EV;
    use P::Value_ as PV;
    let value_ = match pvalue_ {
        PV::Address(addr) => {
            EV::Address(address(context, /* suggest_declaration */ true, addr))
        }
        PV::Num(s) if s.ends_with("u8") => match parse_u8(&s[..s.len() - 2]) {
            Ok(u) => EV::U8(u),
            Err(_) => {
                context.env.add_diag(num_too_big_error(loc, "'u8'"));
                return None;
            }
        },
        PV::Num(s) if s.ends_with("u64") => match parse_u64(&s[..s.len() - 3]) {
            Ok(u) => EV::U64(u),
            Err(_) => {
                context.env.add_diag(num_too_big_error(loc, "'u64'"));
                return None;
            }
        },
        PV::Num(s) if s.ends_with("u128") => match parse_u128(&s[..s.len() - 4]) {
            Ok(u) => EV::U128(u),
            Err(_) => {
                context.env.add_diag(num_too_big_error(loc, "'u128'"));
                return None;
            }
        },
        PV::Num(s) => match parse_u128(&s) {
            Ok(u) => EV::InferredNum(u),
            Err(_) => {
                context.env.add_diag(num_too_big_error(
                    loc,
                    "the largest possible integer type, 'u128'",
                ));
                return None;
            }
        },
        PV::Bool(b) => EV::Bool(b),
        PV::HexString(s) => match hex_string::decode(loc, &s) {
            Ok(v) => EV::Bytearray(v),
            Err(e) => {
                context.env.add_diag(e);
                return None;
            }
        },
        PV::ByteString(s) => match byte_string::decode(loc, &s) {
            Ok(v) => EV::Bytearray(v),
            Err(e) => {
                context.env.add_diags(e);
                return None;
            }
        },
    };
    Some(sp(loc, value_))
}

// Create an error for an integer literal that is too big to fit in its type.
// This assumes that the literal is the current token.
fn num_too_big_error(loc: Loc, type_description: &'static str) -> Diagnostic {
    diag!(
        Syntax::InvalidNumber,
        (
            loc,
            format!(
                "Invalid number literal. The given literal is too large to fit into {}",
                type_description
            )
        ),
    )
}

//**************************************************************************************************
// Fields
//**************************************************************************************************

fn fields<T>(
    context: &mut Context,
    loc: Loc,
    case: &str,
    verb: &str,
    xs: Vec<(Field, T)>,
) -> Fields<T> {
    let mut fmap = UniqueMap::new();
    for (idx, (field, x)) in xs.into_iter().enumerate() {
        if let Err((field, old_loc)) = fmap.add(field, (idx, x)) {
            context.env.add_diag(diag!(
                Declarations::DuplicateItem,
                (loc, format!("Invalid {}", case)),
                (
                    field.loc(),
                    format!("Duplicate {} given for field '{}'", verb, field),
                ),
                (old_loc, "Field previously defined here".into()),
            ))
        }
    }
    fmap
}

//**************************************************************************************************
// LValues
//**************************************************************************************************

fn bind_list(context: &mut Context, sp!(loc, pbs_): P::BindList) -> Option<E::LValueList> {
    let bs_: Option<Vec<E::LValue>> = pbs_.into_iter().map(|pb| bind(context, pb)).collect();
    Some(sp(loc, bs_?))
}

fn bind_with_range_list(
    context: &mut Context,
    sp!(loc, prs_): P::BindWithRangeList,
) -> Option<E::LValueWithRangeList> {
    let rs_: Option<Vec<E::LValueWithRange>> = prs_
        .into_iter()
        .map(|sp!(loc, (pb, pr))| -> Option<E::LValueWithRange> {
            let r = exp_(context, pr);
            let b = bind(context, pb)?;
            Some(sp(loc, (b, r)))
        })
        .collect();
    Some(sp(loc, rs_?))
}

fn bind(context: &mut Context, sp!(loc, pb_): P::Bind) -> Option<E::LValue> {
    use E::LValue_ as EL;
    use P::Bind_ as PB;
    let b_ = match pb_ {
        PB::Var(v) => {
            check_valid_local_name(context, &v);
            EL::Var(sp(loc, E::ModuleAccess_::Name(v.0)), None)
        }
        PB::Unpack(ptn, ptys_opt, pfields) => {
            let tn = name_access_chain(context, Access::ApplyNamed, *ptn)?;
            let tys_opt = optional_types(context, ptys_opt);
            let vfields: Option<Vec<(Field, E::LValue)>> = pfields
                .into_iter()
                .map(|(f, pb)| Some((f, bind(context, pb)?)))
                .collect();
            let fields = fields(context, loc, "deconstruction binding", "binding", vfields?);
            EL::Unpack(tn, tys_opt, fields)
        }
    };
    Some(sp(loc, b_))
}

enum LValue {
    Assigns(E::LValueList),
    FieldMutate(Box<E::ExpDotted>),
    Mutate(Box<E::Exp>),
}

fn lvalues(context: &mut Context, sp!(loc, e_): P::Exp) -> Option<LValue> {
    use LValue as L;
    use P::Exp_ as PE;
    let al: LValue = match e_ {
        PE::Unit => L::Assigns(sp(loc, vec![])),
        PE::ExpList(pes) => {
            let al_opt: Option<E::LValueList_> =
                pes.into_iter().map(|pe| assign(context, pe)).collect();
            L::Assigns(sp(loc, al_opt?))
        }
        PE::Dereference(pr) => {
            let er = exp(context, *pr);
            L::Mutate(er)
        }
        pdotted_ @ PE::Dot(_, _) => {
            let dotted = exp_dotted(context, sp(loc, pdotted_))?;
            L::FieldMutate(Box::new(dotted))
        }
        _ => L::Assigns(sp(loc, vec![assign(context, sp(loc, e_))?])),
    };
    Some(al)
}

fn assign(context: &mut Context, sp!(loc, e_): P::Exp) -> Option<E::LValue> {
    use E::LValue_ as EL;
    use P::Exp_ as PE;
    let a_ = match e_ {
        PE::Name(n @ sp!(_, P::NameAccessChain_::Two(_, _)), _)
        | PE::Name(n @ sp!(_, P::NameAccessChain_::Three(_, _)), _)
            if !context.in_spec_context =>
        {
            let msg = format!(
                "Unexpected assignment of module access without fields outside of a spec \
                 context.\nIf you are trying to unpack a struct, try adding fields, e.g. '{} {{}}'",
                n
            );
            context
                .env
                .add_diag(diag!(Syntax::SpecContextRestricted, (loc, msg)));

            // For unused alias warnings and unbound modules
            name_access_chain(context, Access::Term, n);

            return None;
        }
        PE::Name(n, Some(_)) if !context.in_spec_context => {
            let msg = format!(
                "Unexpected assignment of instantiated type without fields outside of a spec \
                 context.\nIf you are trying to unpack a struct, try adding fields, e.g. '{} {{}}'",
                n
            );
            context
                .env
                .add_diag(diag!(Syntax::SpecContextRestricted, (loc, msg)));

            // For unused alias warnings and unbound modules
            name_access_chain(context, Access::Term, n);

            return None;
        }
        PE::Name(pn, ptys_opt) => {
            let en = name_access_chain(context, Access::Term, pn)?;
            match &en.value {
                E::ModuleAccess_::ModuleAccess(m, n) if !context.in_spec_context => {
                    let msg = format!(
                        "Unexpected assignment of module access without fields outside of a spec \
                         context.\nIf you are trying to unpack a struct, try adding fields, e.g. \
                         '{}::{} {{}}'",
                        m, n,
                    );
                    context
                        .env
                        .add_diag(diag!(Syntax::SpecContextRestricted, (loc, msg)));
                    return None;
                }
                _ => {
                    let tys_opt = optional_types(context, ptys_opt);
                    EL::Var(en, tys_opt)
                }
            }
        }
        PE::Pack(pn, ptys_opt, pfields) => {
            let en = name_access_chain(context, Access::ApplyNamed, pn)?;
            let tys_opt = optional_types(context, ptys_opt);
            let efields = assign_unpack_fields(context, loc, pfields)?;
            EL::Unpack(en, tys_opt, efields)
        }
        _ => {
            context.env.add_diag(diag!(
                Syntax::InvalidLValue,
                (
                    loc,
                    "Invalid assignment syntax. Expected: a local, a field write, or a \
                     deconstructing assignment"
                )
            ));
            return None;
        }
    };
    Some(sp(loc, a_))
}

fn assign_unpack_fields(
    context: &mut Context,
    loc: Loc,
    pfields: Vec<(Field, P::Exp)>,
) -> Option<Fields<E::LValue>> {
    let afields = pfields
        .into_iter()
        .map(|(f, e)| Some((f, assign(context, e)?)))
        .collect::<Option<_>>()?;
    Some(fields(
        context,
        loc,
        "deconstructing assignment",
        "assignment binding",
        afields,
    ))
}

//**************************************************************************************************
// Unbound names
//**************************************************************************************************

fn unbound_names_spec_block(unbound: &mut BTreeSet<Name>, sp!(_, sb_): &E::SpecBlock) {
    sb_.members
        .iter()
        .for_each(|member| unbound_names_spec_block_member(unbound, member))
}

fn unbound_names_spec_block_member(unbound: &mut BTreeSet<Name>, sp!(_, m_): &E::SpecBlockMember) {
    use E::SpecBlockMember_ as M;
    match &m_ {
        M::Condition {
            exp,
            additional_exps,
            ..
        } => {
            unbound_names_exp(unbound, exp);
            additional_exps
                .iter()
                .for_each(|e| unbound_names_exp(unbound, e));
        }
        // No unbound names
        // And will error in the Move prover
        M::Function { .. }
        | M::Variable { .. }
        | M::Let { .. }
        | M::Include { .. }
        | M::Apply { .. }
        | M::Pragma { .. } => (),
    }
}

fn unbound_names_exp(unbound: &mut BTreeSet<Name>, sp!(_, e_): &E::Exp) {
    use E::Exp_ as EE;
    match e_ {
        EE::Value(_)
        | EE::Break
        | EE::Continue
        | EE::UnresolvedError
        | EE::Name(sp!(_, E::ModuleAccess_::ModuleAccess(..)), _)
        | EE::Unit { .. } => (),
        EE::Copy(v) | EE::Move(v) => {
            unbound.insert(v.0.clone());
        }
        EE::Name(sp!(_, E::ModuleAccess_::Name(n)), _) => {
            unbound.insert(n.clone());
        }
        EE::Call(_, _, sp!(_, es_)) => unbound_names_exps(unbound, es_),
        EE::Pack(_, _, es) => unbound_names_exps(unbound, es.iter().map(|(_, _, (_, e))| e)),
        EE::IfElse(econd, et, ef) => {
            unbound_names_exp(unbound, ef);
            unbound_names_exp(unbound, et);
            unbound_names_exp(unbound, econd)
        }
        EE::While(econd, eloop) => {
            unbound_names_exp(unbound, eloop);
            unbound_names_exp(unbound, econd)
        }
        EE::Loop(eloop) => unbound_names_exp(unbound, eloop),

        EE::Block(seq) => unbound_names_sequence(unbound, seq),
        EE::Lambda(ls, er) => {
            unbound_names_exp(unbound, er);
            // remove anything in `ls`
            unbound_names_binds(unbound, ls);
        }
        EE::Quant(_, rs, trs, cr_opt, er) => {
            unbound_names_exp(unbound, er);
            if let Some(cr) = cr_opt {
                unbound_names_exp(unbound, cr);
            }
            for tr in trs {
                unbound_names_exps(unbound, tr);
            }
            // remove anything in `rs`
            unbound_names_binds_with_range(unbound, rs);
        }
        EE::Assign(ls, er) => {
            unbound_names_exp(unbound, er);
            // remove anything in `ls`
            unbound_names_assigns(unbound, ls);
        }
        EE::Return(e)
        | EE::Abort(e)
        | EE::Dereference(e)
        | EE::UnaryExp(_, e)
        | EE::Borrow(_, e)
        | EE::Cast(e, _)
        | EE::Annotate(e, _) => unbound_names_exp(unbound, e),
        EE::FieldMutate(ed, er) => {
            unbound_names_exp(unbound, er);
            unbound_names_dotted(unbound, ed)
        }
        EE::Mutate(el, er) | EE::BinopExp(el, _, er) => {
            unbound_names_exp(unbound, er);
            unbound_names_exp(unbound, el)
        }
        EE::ExpList(es) => unbound_names_exps(unbound, es),
        EE::ExpDotted(ed) => unbound_names_dotted(unbound, ed),
        EE::Index(el, ei) => {
            unbound_names_exp(unbound, ei);
            unbound_names_exp(unbound, el)
        }

        EE::Spec(_, unbound_names) => unbound.extend(unbound_names.iter().cloned()),
    }
}

fn unbound_names_exps<'a>(unbound: &mut BTreeSet<Name>, es: impl IntoIterator<Item = &'a E::Exp>) {
    es.into_iter().for_each(|e| unbound_names_exp(unbound, e))
}

fn unbound_names_sequence(unbound: &mut BTreeSet<Name>, seq: &E::Sequence) {
    seq.iter()
        .rev()
        .for_each(|s| unbound_names_sequence_item(unbound, s))
}

fn unbound_names_sequence_item(unbound: &mut BTreeSet<Name>, sp!(_, es_): &E::SequenceItem) {
    use E::SequenceItem_ as ES;
    match es_ {
        ES::Seq(e) => unbound_names_exp(unbound, e),
        ES::Declare(ls, _) => unbound_names_binds(unbound, ls),
        ES::Bind(ls, er) => {
            unbound_names_exp(unbound, er);
            // remove anything in `ls`
            unbound_names_binds(unbound, ls);
        }
    }
}

fn unbound_names_binds(unbound: &mut BTreeSet<Name>, sp!(_, ls_): &E::LValueList) {
    ls_.iter()
        .rev()
        .for_each(|l| unbound_names_bind(unbound, l))
}

fn unbound_names_binds_with_range(
    unbound: &mut BTreeSet<Name>,
    sp!(_, rs_): &E::LValueWithRangeList,
) {
    rs_.iter().rev().for_each(|sp!(_, (b, r))| {
        unbound_names_bind(unbound, b);
        unbound_names_exp(unbound, r)
    })
}

fn unbound_names_bind(unbound: &mut BTreeSet<Name>, sp!(_, l_): &E::LValue) {
    use E::LValue_ as EL;
    match l_ {
        EL::Var(sp!(_, E::ModuleAccess_::Name(n)), _) => {
            unbound.remove(&n);
        }
        EL::Var(sp!(_, E::ModuleAccess_::ModuleAccess(..)), _) => {
            // Qualified vars are not considered in unbound set.
        }
        EL::Unpack(_, _, efields) => efields
            .iter()
            .for_each(|(_, _, (_, l))| unbound_names_bind(unbound, l)),
    }
}

fn unbound_names_assigns(unbound: &mut BTreeSet<Name>, sp!(_, ls_): &E::LValueList) {
    ls_.iter()
        .rev()
        .for_each(|l| unbound_names_assign(unbound, l))
}

fn unbound_names_assign(unbound: &mut BTreeSet<Name>, sp!(_, l_): &E::LValue) {
    use E::LValue_ as EL;
    match l_ {
        EL::Var(sp!(_, E::ModuleAccess_::Name(n)), _) => {
            unbound.insert(n.clone());
        }
        EL::Var(sp!(_, E::ModuleAccess_::ModuleAccess(..)), _) => {
            // Qualified vars are not considered in unbound set.
        }
        EL::Unpack(_, _, efields) => efields
            .iter()
            .for_each(|(_, _, (_, l))| unbound_names_assign(unbound, l)),
    }
}

fn unbound_names_dotted(unbound: &mut BTreeSet<Name>, sp!(_, edot_): &E::ExpDotted) {
    use E::ExpDotted_ as ED;
    match edot_ {
        ED::Exp(e) => unbound_names_exp(unbound, e),
        ED::Dot(d, _) => unbound_names_dotted(unbound, d),
    }
}

//**************************************************************************************************
// Valid names
//**************************************************************************************************

fn check_valid_address_name(context: &mut Context, sp!(_, ln_): &P::LeadingNameAccess) {
    use P::LeadingNameAccess_ as LN;
    match ln_ {
        LN::AnonymousAddress(_) => (),
        LN::Name(n) => {
            let _ = check_restricted_self_name(context, "address", n);
        }
    }
}

fn check_valid_local_name(context: &mut Context, v: &Var) {
    fn is_valid(s: &str) -> bool {
        s.starts_with('_') || s.starts_with(|c| matches!(c, 'a'..='z'))
    }
    if !is_valid(v.value()) {
        let msg = format!(
            "Invalid local variable name '{}'. Local variable names must start with 'a'..'z' (or \
             '_')",
            v,
        );
        context
            .env
            .add_diag(diag!(Declarations::InvalidName, (v.loc(), msg)));
    }
}

#[derive(Copy, Clone, Debug)]
enum ModuleMemberKind {
    Constant,
    Function,
    Struct,
    Schema,
}

impl ModuleMemberKind {
    pub fn case(&self) -> &'static str {
        match self {
            ModuleMemberKind::Function => "function",
            ModuleMemberKind::Constant => "constant",
            ModuleMemberKind::Struct => "struct",
            ModuleMemberKind::Schema => "schema",
        }
    }
}

fn check_valid_module_member_name(
    context: &mut Context,
    member: ModuleMemberKind,
    name: Name,
) -> Option<Name> {
    match check_valid_module_member_name_impl(context, member, &name, member.case()) {
        Err(()) => None,
        Ok(()) => Some(name),
    }
}

fn check_valid_module_member_alias(
    context: &mut Context,
    member: ModuleMemberKind,
    alias: Name,
) -> Option<Name> {
    match check_valid_module_member_name_impl(
        context,
        member,
        &alias,
        &format!("{} alias", member.case()),
    ) {
        Err(()) => None,
        Ok(()) => Some(alias),
    }
}

fn check_valid_module_member_name_impl(
    context: &mut Context,
    member: ModuleMemberKind,
    n: &Name,
    case: &str,
) -> Result<(), ()> {
    use ModuleMemberKind as M;
    fn upper_first_letter(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }
    let lcase = case;
    match member {
        M::Function => {
            if n.value.starts_with(|c| c == '_') {
                let msg = format!(
                    "Invalid {} name '{}'. {} names cannot start with '_'",
                    lcase,
                    n,
                    upper_first_letter(case),
                );
                context
                    .env
                    .add_diag(diag!(Declarations::InvalidName, (n.loc, msg)));
                return Err(());
            }
        }
        M::Constant | M::Struct | M::Schema => {
            if !is_valid_struct_constant_or_schema_name(&n.value) {
                let msg = format!(
                    "Invalid {} name '{}'. {} names must start with 'A'..'Z'",
                    lcase,
                    n,
                    upper_first_letter(case),
                );
                context
                    .env
                    .add_diag(diag!(Declarations::InvalidName, (n.loc, msg)));
                return Err(());
            }
        }
    }

    // TODO move these names to a more central place?
    check_restricted_names(
        context,
        lcase,
        n,
        crate::naming::ast::BuiltinFunction_::all_names(),
    )?;
    check_restricted_names(
        context,
        lcase,
        n,
        crate::naming::ast::BuiltinTypeName_::all_names(),
    )?;

    // Restricting Self for now in the case where we ever have impls
    // Otherwise, we could allow it
    check_restricted_self_name(context, lcase, n)?;

    Ok(())
}

pub fn is_valid_struct_constant_or_schema_name(s: &str) -> bool {
    s.starts_with(|c| matches!(c, 'A'..='Z'))
}

fn check_restricted_self_name(context: &mut Context, case: &str, n: &Name) -> Result<(), ()> {
    if n.value == ModuleName::SELF_NAME {
        context
            .env
            .add_diag(restricted_name_error(case, n.loc, ModuleName::SELF_NAME));
        Err(())
    } else {
        Ok(())
    }
}

fn check_restricted_names(
    context: &mut Context,
    case: &str,
    sp!(loc, n_): &Name,
    all_names: &BTreeSet<&str>,
) -> Result<(), ()> {
    if all_names.contains(n_.as_str()) {
        context.env.add_diag(restricted_name_error(case, *loc, n_));
        Err(())
    } else {
        Ok(())
    }
}

fn restricted_name_error(case: &str, loc: Loc, restricted: &str) -> Diagnostic {
    let msg = format!(
        "Invalid {case} name '{restricted}'. '{restricted}' is restricted and cannot be used to \
         name a {case}",
        case = case,
        restricted = restricted,
    );
    diag!(Declarations::InvalidName, (loc, msg))
}
