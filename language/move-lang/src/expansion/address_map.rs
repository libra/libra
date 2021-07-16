// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    diag,
    parser::ast::{self as P},
    shared::{unique_map::UniqueMap, *},
    FullyCompiledProgram,
};
use move_ir_types::location::*;

struct Context<'a> {
    env: &'a mut CompilationEnv,
    map: &'a mut UniqueMap<Name, Option<Spanned<AddressBytes>>>,
}

impl<'a> Context<'a> {
    fn new(
        env: &'a mut CompilationEnv,
        map: &'a mut UniqueMap<Name, Option<Spanned<AddressBytes>>>,
    ) -> Self {
        Self { env, map }
    }
}

pub(crate) fn build_address_map(
    env: &mut CompilationEnv,
    pre_compiled_lib: Option<&FullyCompiledProgram>,
    prog: &P::Program,
) -> UniqueMap<Name, Option<Spanned<AddressBytes>>> {
    let mut map = UniqueMap::new();
    let context = &mut Context::new(env, &mut map);
    for def in &prog.source_definitions {
        definition(context, def)
    }
    for def in &prog.lib_definitions {
        definition(context, def)
    }
    if let Some(pre_compiled) = pre_compiled_lib {
        for def in &pre_compiled.parser.source_definitions {
            definition(context, def)
        }
        for def in &pre_compiled.parser.lib_definitions {
            definition(context, def)
        }
    }
    map
}

fn definition(context: &mut Context, def: &P::Definition) {
    let addr_def = match def {
        P::Definition::Address(addr_def) => addr_def,
        P::Definition::Script(_) | P::Definition::Module(_) => return,
    };

    let name = match &addr_def.addr.value {
        P::LeadingNameAccess_::Name(n) => n,
        P::LeadingNameAccess_::AnonymousAddress(_) => return,
    };

    let addr_value_opt = &addr_def.addr_value;
    match (context.map.get(&name), addr_value_opt) {
        // If address name is not bound, add it to the map
        (None, _) => context.map.add(name.clone(), *addr_value_opt).unwrap(),

        // If the address was previously just a name, bind the declaration, whatever it is
        (Some(None), addr_value_opt) => {
            context.map.remove(name);
            context.map.add(name.clone(), *addr_value_opt).unwrap()
        }

        // If the address was assigned a value, and now there is just a name, keep the value
        (Some(Some(_)), None) => (),

        // No error on previous value if equal
        (Some(Some(prev_value)), Some(addr_value)) if prev_value.value == addr_value.value => (),

        // Otherwise, error on previous value
        (Some(Some(prev_value)), Some(addr_value)) => {
            let loc = addr_value.loc;
            let msg = format!(
                "Invalid address assignment. Multiple values were given for address '{}'",
                name
            );
            let prev_loc = prev_value.loc;
            let prev_msg = "Address previously assigned here";

            context.env.add_diag(diag!(
                Declarations::InvalidAddress,
                (loc, msg),
                (prev_loc, prev_msg)
            ));
        }
    }
}
