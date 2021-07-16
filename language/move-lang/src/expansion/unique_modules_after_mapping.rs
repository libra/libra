// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    compiled_unit::CompiledModuleIdent,
    diag,
    expansion::ast::{self as E, Address, ModuleIdent, ModuleIdent_},
    parser::ast::ModuleName,
    shared::{unique_map::UniqueMap, *},
};
use move_ir_types::location::*;
use std::collections::BTreeMap;

//**************************************************************************************************
// Entry
//**************************************************************************************************

/// Verifies that modules remain unique, even after substituting named addresses for their values
pub fn verify(
    compilation_env: &mut CompilationEnv,
    addresses: &UniqueMap<Name, Option<Spanned<AddressBytes>>>,
    modules: &UniqueMap<ModuleIdent, E::ModuleDefinition>,
) {
    let mut decl_locs: BTreeMap<(AddressBytes, String), CompiledModuleIdent> = BTreeMap::new();
    for (sp!(loc, ModuleIdent_ { address, module }), _mdef) in modules.key_cloned_iter() {
        let sp!(nloc, n_) = module.0;
        let addr_name = match &address {
            Address::Anonymous(_) => None,
            Address::Named(n) => Some(n.clone()),
        };
        let addr_bytes = match &address {
            Address::Anonymous(sp!(_, addr_bytes)) => *addr_bytes,
            Address::Named(n) => match addresses.get(n) {
                // undeclared or no value bound, so can skip
                None | Some(None) => continue,
                // copy the assigned value
                Some(Some(sp!(_, addr_bytes))) => *addr_bytes,
            },
        };
        let mident_ = (addr_bytes, n_.clone());
        let compiled_mident =
            CompiledModuleIdent::new(loc, addr_name, addr_bytes, ModuleName(sp(nloc, n_)));
        if let Some(prev) = decl_locs.insert(mident_.clone(), compiled_mident) {
            let prev = &prev;
            let cur = &decl_locs[&mident_];
            let (orig, duplicate) = if cur.loc.file() == prev.loc.file()
                && cur.loc.span().start() > prev.loc.span().start()
            {
                (prev, cur)
            } else {
                (cur, prev)
            };

            // Formatting here is a bit weird, but it is guaranteed that at least one of the
            // declarations (prev or cur) will have an address_name of Some(_)
            let format_name = |m: &CompiledModuleIdent| match &m.address_name {
                None => format!("'{}::{}'", &m.address_bytes, &m.module_name),
                Some(aname) => format!(
                    "'{aname}::{mname}', with '{aname}' = {abytes}",
                    aname = aname,
                    abytes = &m.address_bytes,
                    mname = &m.module_name
                ),
            };
            let msg = format!("Duplicate definition of {}", format_name(duplicate));
            let prev_msg = format!("Module previously defined here as {}", format_name(orig));
            compilation_env.add_diag(diag!(
                Declarations::DuplicateItem,
                (duplicate.loc, msg),
                (orig.loc, prev_msg)
            ))
        }
    }
}
