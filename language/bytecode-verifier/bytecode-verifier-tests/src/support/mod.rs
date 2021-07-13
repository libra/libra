// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use move_binary_format::{
    file_format::{
        empty_module, Bytecode, CodeUnit, FunctionDefinition, FunctionHandle, IdentifierIndex,
        ModuleHandleIndex, SignatureIndex,
    },
    CompiledModule,
};

/// Create a dummy module to wrap the bytecode program in local@code
pub fn dummy_procedure_module(code: Vec<Bytecode>) -> CompiledModule {
    let mut module = empty_module();
    let code_unit = CodeUnit {
        code,
        ..Default::default()
    };
    let fun_def = FunctionDefinition {
        code: Some(code_unit),
        ..Default::default()
    };

    let fun_handle = FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(0),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
    };

    module.function_handles.push(fun_handle);
    module.function_defs.push(fun_def);
    module.freeze().unwrap()
}
