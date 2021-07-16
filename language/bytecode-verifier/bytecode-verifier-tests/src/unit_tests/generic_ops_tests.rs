// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use bytecode_verifier::InstructionConsistency;
use move_binary_format::file_format::*;
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, vm_status::StatusCode,
};

// Make a Module with 2 structs and 2 resources with one field each, and 2 functions.
// One of the struct/resource and one of the function is generic, the other "normal".
// Also make a test function whose body will be filled by given test cases.
fn make_module() -> CompiledModule {
    CompiledModule {
        version: move_binary_format::file_format_common::VERSION_MAX,
        module_handles: vec![
            // only self module
            ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            },
        ],
        self_module_handle_idx: ModuleHandleIndex(0),
        identifiers: vec![
            Identifier::new("M").unwrap(),       // Module name
            Identifier::new("S").unwrap(),       // Struct name
            Identifier::new("GS").unwrap(),      // Generic struct name
            Identifier::new("R").unwrap(),       // Resource name
            Identifier::new("GR").unwrap(),      // Generic resource name
            Identifier::new("f").unwrap(),       // Field name
            Identifier::new("fn").unwrap(),      // Function name
            Identifier::new("g_fn").unwrap(),    // Generic function name
            Identifier::new("test_fn").unwrap(), // Test function name
        ],
        address_identifiers: vec![
            AccountAddress::ZERO, // Module address
        ],
        struct_handles: vec![
            StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(1),
                abilities: AbilitySet::PRIMITIVES,
                type_parameters: vec![],
            },
            StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(2),
                abilities: AbilitySet::PRIMITIVES,
                type_parameters: vec![StructTypeParameter {
                    constraints: AbilitySet::PRIMITIVES,
                    is_phantom: false,
                }],
            },
            StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(3),
                abilities: AbilitySet::EMPTY | Ability::Key,
                type_parameters: vec![],
            },
            StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(4),
                abilities: AbilitySet::EMPTY | Ability::Key,
                type_parameters: vec![StructTypeParameter {
                    constraints: AbilitySet::PRIMITIVES,
                    is_phantom: false,
                }],
            },
        ],
        struct_defs: vec![
            // struct S { f: u64 }
            StructDefinition {
                struct_handle: StructHandleIndex(0),
                field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                    name: IdentifierIndex(5),
                    signature: TypeSignature(SignatureToken::U64),
                }]),
            },
            // struct GS<T> { f: T }
            StructDefinition {
                struct_handle: StructHandleIndex(1),
                field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                    name: IdentifierIndex(5),
                    signature: TypeSignature(SignatureToken::TypeParameter(0)),
                }]),
            },
            // struct R has key { f: u64 }
            StructDefinition {
                struct_handle: StructHandleIndex(2),
                field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                    name: IdentifierIndex(5),
                    signature: TypeSignature(SignatureToken::U64),
                }]),
            },
            // struct GR<T> has key { f: T }
            StructDefinition {
                struct_handle: StructHandleIndex(3),
                field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                    name: IdentifierIndex(5),
                    signature: TypeSignature(SignatureToken::TypeParameter(0)),
                }]),
            },
        ],
        function_handles: vec![
            // fun fn()
            FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(6),
                parameters: SignatureIndex(0),
                return_: SignatureIndex(0),
                type_parameters: vec![],
            },
            // fun g_fn<T: key>()
            FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(7),
                parameters: SignatureIndex(0),
                return_: SignatureIndex(0),
                type_parameters: vec![AbilitySet::EMPTY | Ability::Key],
            },
            // fun test_fn(Sender)
            FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(8),
                parameters: SignatureIndex(1),
                return_: SignatureIndex(0),
                type_parameters: vec![],
            },
        ],
        function_defs: vec![
            // public fun fn() { return; }
            FunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Public,
                acquires_global_resources: vec![],
                code: Some(CodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![Bytecode::Ret],
                }),
            },
            // fun g_fn<T>() { return; }
            FunctionDefinition {
                function: FunctionHandleIndex(1),
                visibility: Visibility::Private,
                acquires_global_resources: vec![],
                code: Some(CodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![Bytecode::Ret],
                }),
            },
            // fun test_fn() { ... } - tests will fill up the code
            FunctionDefinition {
                function: FunctionHandleIndex(2),
                visibility: Visibility::Private,
                acquires_global_resources: vec![],
                code: Some(CodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![],
                }),
            },
        ],
        signatures: vec![
            Signature(vec![]),                       // void
            Signature(vec![SignatureToken::Signer]), // Signer
        ],
        constant_pool: vec![
            // an address
            Constant {
                type_: SignatureToken::Address,
                data: AccountAddress::random().to_vec(),
            },
        ],
        field_handles: vec![],
        friend_decls: vec![],
        struct_def_instantiations: vec![],
        function_instantiations: vec![],
        field_instantiations: vec![],
    }
}

#[test]
fn generic_call_to_non_generic_func() {
    let mut module = make_module();
    // bogus `CallGeneric fn()`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::CallGeneric(FunctionInstantiationIndex(0)),
            Bytecode::Ret,
        ],
    });
    module.function_instantiations.push(FunctionInstantiation {
        handle: FunctionHandleIndex(0),
        type_parameters: SignatureIndex(2),
    });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("CallGeneric to non generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_call_to_generic_func() {
    let mut module = make_module();
    // bogus `Call g_fn<T>()`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![Bytecode::Call(FunctionHandleIndex(1)), Bytecode::Ret],
    });
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("Call to generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_pack_on_non_generic_struct() {
    let mut module = make_module();
    // bogus `PackGeneric S`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::PackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(0),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("PackGeneric to non generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_pack_on_generic_struct() {
    let mut module = make_module();
    // bogus `Pack GS<T>`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::Pack(StructDefinitionIndex(1)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("Pack to generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_unpack_on_non_generic_struct() {
    let mut module = make_module();
    // bogus `UnpackGeneric S`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::Pack(StructDefinitionIndex(0)),
            Bytecode::UnpackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(0),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("UnpackGeneric to non generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_unpack_on_generic_struct() {
    let mut module = make_module();
    // bogus `Unpack GS<T>`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::PackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Unpack(StructDefinitionIndex(1)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(1),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("Unpack to generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_mut_borrow_field_on_non_generic_struct() {
    let mut module = make_module();
    // bogus `MutBorrowFieldGeneric S.t`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::Pack(StructDefinitionIndex(0)),
            Bytecode::MutBorrowFieldGeneric(FieldInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module.field_instantiations.push(FieldInstantiation {
        handle: FieldHandleIndex(0),
        type_parameters: SignatureIndex(2),
    });
    module.field_handles.push(FieldHandle {
        owner: StructDefinitionIndex(0),
        field: 0,
    });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MutBorrowFieldGeneric to non generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_mut_borrow_field_on_generic_struct() {
    let mut module = make_module();
    // bogus `MutBorrowField GS<T>.f`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::PackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::MutBorrowField(FieldHandleIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(1),
            type_parameters: SignatureIndex(2),
        });
    module.field_handles.push(FieldHandle {
        owner: StructDefinitionIndex(1),
        field: 0,
    });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MutBorrowField to generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_borrow_field_on_non_generic_struct() {
    let mut module = make_module();
    // bogus `ImmBorrowFieldGeneric S.f`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::Pack(StructDefinitionIndex(0)),
            Bytecode::ImmBorrowFieldGeneric(FieldInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module.field_instantiations.push(FieldInstantiation {
        handle: FieldHandleIndex(0),
        type_parameters: SignatureIndex(2),
    });
    module.field_handles.push(FieldHandle {
        owner: StructDefinitionIndex(0),
        field: 0,
    });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("ImmBorrowFieldGeneric to non generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_borrow_field_on_generic_struct() {
    let mut module = make_module();
    // bogus `ImmBorrowField GS<T>.f`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdU64(10),
            Bytecode::PackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::ImmBorrowField(FieldHandleIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(1),
            type_parameters: SignatureIndex(2),
        });
    module.field_handles.push(FieldHandle {
        owner: StructDefinitionIndex(1),
        field: 0,
    });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("ImmBorrowField to generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_mut_borrow_global_to_non_generic_struct() {
    let mut module = make_module();
    // bogus `MutBorrowGlobalGeneric R`
    module.function_defs[2]
        .acquires_global_resources
        .push(StructDefinitionIndex(2));
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::MutBorrowGlobalGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(2),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MutBorrowGlobalGeneric to non generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_mut_borrow_global_to_generic_struct() {
    let mut module = make_module();
    // bogus `MutBorrowGlobal GR<T>`
    module.function_defs[2]
        .acquires_global_resources
        .push(StructDefinitionIndex(3));
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::MutBorrowGlobal(StructDefinitionIndex(3)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MutBorrowGlobal to generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_immut_borrow_global_to_non_generic_struct() {
    let mut module = make_module();
    // bogus `ImmBorrowGlobalGeneric R`
    module.function_defs[2]
        .acquires_global_resources
        .push(StructDefinitionIndex(2));
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::ImmBorrowGlobalGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(2),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("ImmBorrowGlobalGeneric to non generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_immut_borrow_global_to_generic_struct() {
    let mut module = make_module();
    // bogus `ImmBorrowGlobal GR<T>`
    module.function_defs[2]
        .acquires_global_resources
        .push(StructDefinitionIndex(3));
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::ImmBorrowGlobal(StructDefinitionIndex(3)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("ImmBorrowGlobal to generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_exists_to_non_generic_struct() {
    let mut module = make_module();
    // bogus `ExistsGeneric R`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::ExistsGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(2),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("ExistsGeneric to non generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_exists_to_generic_struct() {
    let mut module = make_module();
    // bogus `Exists GR<T>`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::Exists(StructDefinitionIndex(3)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("Exists to generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_move_from_to_non_generic_struct() {
    let mut module = make_module();
    // bogus `MoveFromGeneric R`
    module.function_defs[2]
        .acquires_global_resources
        .push(StructDefinitionIndex(2));
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::MoveFromGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Unpack(StructDefinitionIndex(2)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(2),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MoveFromGeneric to non generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_move_from_to_generic_struct() {
    let mut module = make_module();
    // bogus `MoveFrom GR<T>`
    module.function_defs[2]
        .acquires_global_resources
        .push(StructDefinitionIndex(3));
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::LdConst(ConstantPoolIndex(0)),
            Bytecode::MoveFrom(StructDefinitionIndex(3)),
            Bytecode::UnpackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Pop,
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(3),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MoveFrom to generic function must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn generic_move_to_on_non_generic_struct() {
    let mut module = make_module();
    // bogus `MoveToGeneric R`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::MoveLoc(0),
            Bytecode::LdU64(10),
            Bytecode::Pack(StructDefinitionIndex(2)),
            Bytecode::MoveToGeneric(StructDefInstantiationIndex(0)),
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(2),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MoveToGeneric to non generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}

#[test]
fn non_generic_move_to_on_generic_struct() {
    let mut module = make_module();
    // bogus `MoveTo GR<T>`
    module.function_defs[2].code = Some(CodeUnit {
        locals: SignatureIndex(0),
        code: vec![
            Bytecode::MoveLoc(0),
            Bytecode::LdU64(10),
            Bytecode::PackGeneric(StructDefInstantiationIndex(0)),
            Bytecode::MoveTo(StructDefinitionIndex(3)),
            Bytecode::Ret,
        ],
    });
    module
        .struct_def_instantiations
        .push(StructDefInstantiation {
            def: StructDefinitionIndex(3),
            type_parameters: SignatureIndex(2),
        });
    module.signatures.push(Signature(vec![SignatureToken::U64]));
    let err = InstructionConsistency::verify_module(&module)
        .expect_err("MoveTo to generic struct must fail");
    assert_eq!(
        err.major_status(),
        StatusCode::GENERIC_MEMBER_OPCODE_MISMATCH
    );
}
