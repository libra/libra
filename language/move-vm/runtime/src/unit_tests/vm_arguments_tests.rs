// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{data_cache::MoveStorage, move_vm::MoveVM};
use move_binary_format::{
    errors::{PartialVMResult, VMResult},
    file_format::{
        empty_module, AbilitySet, AddressIdentifierIndex, Bytecode, CodeUnit, CompiledModule,
        CompiledScript, FieldDefinition, FunctionDefinition, FunctionHandle, FunctionHandleIndex,
        IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        SignatureToken, StructDefinition, StructFieldInformation, StructHandle, StructHandleIndex,
        TableIndex, TypeSignature, Visibility,
    },
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, StructTag, TypeTag},
    value::{serialize_values, MoveValue},
    vm_status::{StatusCode, StatusType},
};
use move_vm_types::gas_schedule::GasStatus;

// make a script with a given signature for main.
fn make_script(parameters: Signature) -> Vec<u8> {
    let mut blob = vec![];
    let mut signatures = vec![Signature(vec![])];
    let parameters_idx = match signatures
        .iter()
        .enumerate()
        .find(|(_, s)| *s == &parameters)
    {
        Some((idx, _)) => SignatureIndex(idx as TableIndex),
        None => {
            signatures.push(parameters);
            SignatureIndex((signatures.len() - 1) as TableIndex)
        }
    };
    CompiledScript {
        version: move_binary_format::file_format_common::VERSION_MAX,
        module_handles: vec![],
        struct_handles: vec![],
        function_handles: vec![],

        function_instantiations: vec![],

        signatures,

        identifiers: vec![],
        address_identifiers: vec![],
        constant_pool: vec![],

        type_parameters: vec![],
        parameters: parameters_idx,
        code: CodeUnit {
            locals: SignatureIndex(0),
            code: vec![Bytecode::LdU64(0), Bytecode::Abort],
        },
    }
    .serialize(&mut blob)
    .expect("script must serialize");
    blob
}

// make a script with an external function that has the same signature as
// the main. That allows us to pass resources and make the verifier happy that
// they are consumed.
// Dependencies check happens after main signature check, so we should expect
// a signature check error.
fn make_script_with_non_linking_structs(parameters: Signature) -> Vec<u8> {
    let mut blob = vec![];
    let mut signatures = vec![Signature(vec![])];
    let parameters_idx = match signatures
        .iter()
        .enumerate()
        .find(|(_, s)| *s == &parameters)
    {
        Some((idx, _)) => SignatureIndex(idx as TableIndex),
        None => {
            signatures.push(parameters);
            SignatureIndex((signatures.len() - 1) as TableIndex)
        }
    };
    CompiledScript {
        version: move_binary_format::file_format_common::VERSION_MAX,
        module_handles: vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }],
        struct_handles: vec![StructHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        }],
        function_handles: vec![FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            parameters: SignatureIndex(1),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        }],

        function_instantiations: vec![],

        signatures,

        identifiers: vec![
            Identifier::new("one").unwrap(),
            Identifier::new("two").unwrap(),
            Identifier::new("three").unwrap(),
        ],
        address_identifiers: vec![AccountAddress::random()],
        constant_pool: vec![],

        type_parameters: vec![],
        parameters: parameters_idx,
        code: CodeUnit {
            locals: SignatureIndex(0),
            code: vec![Bytecode::LdU64(0), Bytecode::Abort],
        },
    }
    .serialize(&mut blob)
    .expect("script must serialize");
    blob
}

fn make_module_with_function(
    visibility: Visibility,
    parameters: Signature,
    return_: Signature,
    type_parameters: Vec<AbilitySet>,
) -> (CompiledModule, Identifier) {
    let function_name = Identifier::new("foo").unwrap();
    let mut signatures = vec![Signature(vec![])];
    let parameters_idx = match signatures
        .iter()
        .enumerate()
        .find(|(_, s)| *s == &parameters)
    {
        Some((idx, _)) => SignatureIndex(idx as TableIndex),
        None => {
            signatures.push(parameters);
            SignatureIndex((signatures.len() - 1) as TableIndex)
        }
    };
    let return_idx = match signatures.iter().enumerate().find(|(_, s)| *s == &return_) {
        Some((idx, _)) => SignatureIndex(idx as TableIndex),
        None => {
            signatures.push(return_);
            SignatureIndex((signatures.len() - 1) as TableIndex)
        }
    };
    let module = CompiledModule {
        version: move_binary_format::file_format_common::VERSION_MAX,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles: vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }],
        struct_handles: vec![StructHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        }],
        function_handles: vec![FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            parameters: parameters_idx,
            return_: return_idx,
            type_parameters,
        }],
        field_handles: vec![],
        friend_decls: vec![],

        struct_def_instantiations: vec![],
        function_instantiations: vec![],
        field_instantiations: vec![],

        signatures,

        identifiers: vec![
            Identifier::new("M").unwrap(),
            Identifier::new("X").unwrap(),
            function_name.clone(),
        ],
        address_identifiers: vec![AccountAddress::random()],
        constant_pool: vec![],

        struct_defs: vec![StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(1),
                signature: TypeSignature(SignatureToken::Bool),
            }]),
        }],
        function_defs: vec![FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::LdU64(0), Bytecode::Abort],
            }),
        }],
    };
    (module, function_name)
}

// make a script function with a given signature for main.
fn make_script_function(signature: Signature) -> (CompiledModule, Identifier) {
    make_module_with_function(Visibility::Script, signature, Signature(vec![]), vec![])
}

struct RemoteStore {
    modules: HashMap<ModuleId, Vec<u8>>,
}

impl RemoteStore {
    fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    fn add_module(&mut self, compiled_module: CompiledModule) {
        let id = compiled_module.self_id();
        let mut bytes = vec![];
        compiled_module.serialize(&mut bytes).unwrap();
        self.modules.insert(id, bytes);
    }
}

impl MoveStorage for RemoteStore {
    fn get_module(&self, module_id: &ModuleId) -> VMResult<Option<Vec<u8>>> {
        Ok(self.modules.get(module_id).cloned())
    }

    fn get_resource(
        &self,
        _address: &AccountAddress,
        _tag: &StructTag,
    ) -> PartialVMResult<Option<Vec<u8>>> {
        Ok(None)
    }
}

fn call_script_with_args_ty_args_signers(
    script: Vec<u8>,
    args: Vec<Vec<u8>>,
    ty_args: Vec<TypeTag>,
    signers: Vec<AccountAddress>,
) -> VMResult<()> {
    let move_vm = MoveVM::new(vec![]).unwrap();
    let remote_view = RemoteStore::new();
    let mut session = move_vm.new_session(&remote_view);
    let mut gas_status = GasStatus::new_unmetered();
    session.execute_script(script, ty_args, args, signers, &mut gas_status)
}

fn call_script(script: Vec<u8>, args: Vec<Vec<u8>>) -> VMResult<()> {
    call_script_with_args_ty_args_signers(script, args, vec![], vec![])
}

fn call_script_function_with_args_ty_args_signers(
    module: CompiledModule,
    function_name: Identifier,
    args: Vec<Vec<u8>>,
    ty_args: Vec<TypeTag>,
    signers: Vec<AccountAddress>,
) -> VMResult<()> {
    let move_vm = MoveVM::new(vec![]).unwrap();
    let mut remote_view = RemoteStore::new();
    let id = module.self_id();
    remote_view.add_module(module);
    let mut session = move_vm.new_session(&remote_view);
    let mut gas_status = GasStatus::new_unmetered();
    session.execute_script_function(
        &id,
        function_name.as_ident_str(),
        ty_args,
        args,
        signers,
        &mut gas_status,
    )?;
    Ok(())
}

fn call_script_function(
    module: CompiledModule,
    function_name: Identifier,
    args: Vec<Vec<u8>>,
) -> VMResult<()> {
    call_script_function_with_args_ty_args_signers(module, function_name, args, vec![], vec![])
}

fn bad_signatures() -> Vec<Signature> {
    vec![
        // struct in signature
        Signature(vec![SignatureToken::Struct(StructHandleIndex(0))]),
        // struct in signature
        Signature(vec![
            SignatureToken::Bool,
            SignatureToken::Struct(StructHandleIndex(0)),
            SignatureToken::U64,
        ]),
        // reference to struct in signature
        Signature(vec![
            SignatureToken::Address,
            SignatureToken::MutableReference(Box::new(SignatureToken::Struct(StructHandleIndex(
                0,
            )))),
        ]),
        // vector of struct in signature
        Signature(vec![
            SignatureToken::Bool,
            SignatureToken::Vector(Box::new(SignatureToken::Struct(StructHandleIndex(0)))),
            SignatureToken::U64,
        ]),
        // vector of vector of struct in signature
        Signature(vec![
            SignatureToken::Bool,
            SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
                SignatureToken::Struct(StructHandleIndex(0)),
            )))),
            SignatureToken::U64,
        ]),
        // reference to vector in signature
        Signature(vec![SignatureToken::Reference(Box::new(
            SignatureToken::Vector(Box::new(SignatureToken::Struct(StructHandleIndex(0)))),
        ))]),
        // reference to vector in signature
        Signature(vec![SignatureToken::Reference(Box::new(
            SignatureToken::U64,
        ))]),
        // `&Signer` in signature (not `Signer`)
        Signature(vec![SignatureToken::Reference(Box::new(
            SignatureToken::Signer,
        ))]),
        // vector of `Signer` in signature
        Signature(vec![SignatureToken::Vector(Box::new(
            SignatureToken::Signer,
        ))]),
        // `Signer` ref not first arg
        Signature(vec![SignatureToken::Bool, SignatureToken::Signer]),
    ]
}

fn good_signatures_and_arguments() -> Vec<(Signature, Vec<MoveValue>)> {
    vec![
        // U128 arg
        (
            Signature(vec![SignatureToken::U128]),
            vec![MoveValue::U128(0)],
        ),
        // All constants
        (
            Signature(vec![SignatureToken::Vector(Box::new(SignatureToken::Bool))]),
            vec![MoveValue::Vector(vec![
                MoveValue::Bool(false),
                MoveValue::Bool(true),
            ])],
        ),
        // All constants
        (
            Signature(vec![
                SignatureToken::Bool,
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
                SignatureToken::Address,
            ]),
            vec![
                MoveValue::Bool(true),
                MoveValue::vector_u8(vec![0, 1]),
                MoveValue::Address(AccountAddress::random()),
            ],
        ),
        // vector<vector<address>>
        (
            Signature(vec![
                SignatureToken::Bool,
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
                SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
                    SignatureToken::Address,
                )))),
            ]),
            vec![
                MoveValue::Bool(true),
                MoveValue::vector_u8(vec![0, 1]),
                MoveValue::Vector(vec![
                    MoveValue::Vector(vec![
                        MoveValue::Address(AccountAddress::random()),
                        MoveValue::Address(AccountAddress::random()),
                    ]),
                    MoveValue::Vector(vec![
                        MoveValue::Address(AccountAddress::random()),
                        MoveValue::Address(AccountAddress::random()),
                    ]),
                    MoveValue::Vector(vec![
                        MoveValue::Address(AccountAddress::random()),
                        MoveValue::Address(AccountAddress::random()),
                    ]),
                ]),
            ],
        ),
        //
        // Vector arguments
        //
        // empty vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![])],
        ),
        // one elem vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![MoveValue::Address(
                AccountAddress::random(),
            )])],
        ),
        // multiple elems vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
            ])],
        ),
        // empty vector of vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
            ))]),
            vec![MoveValue::Vector(vec![])],
        ),
        // multiple element vector of vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
            ))]),
            vec![MoveValue::Vector(vec![
                MoveValue::vector_u8(vec![0, 1]),
                MoveValue::vector_u8(vec![2, 3]),
                MoveValue::vector_u8(vec![4, 5]),
            ])],
        ),
    ]
}

fn mismatched_cases() -> Vec<(Signature, Vec<MoveValue>, StatusCode)> {
    vec![
        // Too few args
        (
            Signature(vec![SignatureToken::U64]),
            vec![],
            StatusCode::NUMBER_OF_ARGUMENTS_MISMATCH,
        ),
        // Too many args
        (
            Signature(vec![SignatureToken::Bool]),
            vec![
                MoveValue::Bool(false),
                MoveValue::Bool(false),
                MoveValue::Bool(false),
            ],
            StatusCode::NUMBER_OF_ARGUMENTS_MISMATCH,
        ),
        // Vec<bool> passed for vec<address>
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![MoveValue::Bool(true)])],
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
        ),
        // u128 passed for vec<address>
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::U128(12)],
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
        ),
        // u8 passed for vector<vector<u8>>
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
            ))]),
            vec![MoveValue::U8(12)],
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
        ),
    ]
}

fn general_cases() -> Vec<(
    Signature,
    Vec<MoveValue>,
    Vec<AccountAddress>,
    Option<StatusCode>,
)> {
    vec![
        // too few signers (0)
        (
            Signature(vec![SignatureToken::Signer, SignatureToken::Signer]),
            vec![],
            vec![],
            Some(StatusCode::NUMBER_OF_SIGNER_ARGUMENTS_MISMATCH),
        ),
        // too few signers (1)
        (
            Signature(vec![SignatureToken::Signer, SignatureToken::Signer]),
            vec![],
            vec![AccountAddress::random()],
            Some(StatusCode::NUMBER_OF_SIGNER_ARGUMENTS_MISMATCH),
        ),
        // too few signers (3)
        (
            Signature(vec![SignatureToken::Signer, SignatureToken::Signer]),
            vec![],
            vec![
                AccountAddress::random(),
                AccountAddress::random(),
                AccountAddress::random(),
            ],
            Some(StatusCode::NUMBER_OF_SIGNER_ARGUMENTS_MISMATCH),
        ),
        // correct number of signers (2)
        (
            Signature(vec![SignatureToken::Signer, SignatureToken::Signer]),
            vec![],
            vec![AccountAddress::random(), AccountAddress::random()],
            None,
        ),
        // too many signers (1) in a script that expects 0 is ok
        (
            Signature(vec![SignatureToken::U8]),
            vec![MoveValue::U8(0)],
            vec![AccountAddress::random()],
            None,
        ),
        // signer
        (
            Signature(vec![
                SignatureToken::Signer,
                SignatureToken::Bool,
                SignatureToken::Address,
            ]),
            vec![
                MoveValue::Bool(false),
                MoveValue::Address(AccountAddress::random()),
            ],
            vec![AccountAddress::random()],
            None,
        ),
    ]
}

#[test]
fn check_script() {
    //
    // Bad signatures
    //
    for signature in bad_signatures() {
        let script = make_script_with_non_linking_structs(signature);
        assert_eq!(
            call_script(script, serialize_values(&vec![MoveValue::U128(0)]))
                .err()
                .unwrap()
                .major_status(),
            StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE,
        );
    }

    //
    // Good signatures
    //
    for (signature, args) in good_signatures_and_arguments() {
        // Body of the script is just an abort, so `ABORTED` means the script was accepted and ran
        let expected_status = StatusCode::ABORTED;
        let script = make_script(signature);
        assert_eq!(
            call_script(script, serialize_values(&args))
                .err()
                .unwrap()
                .major_status(),
            expected_status
        )
    }

    //
    // Mismatched Cases
    //
    for (signature, args, error) in mismatched_cases() {
        let script = make_script(signature);
        assert_eq!(
            call_script(script, serialize_values(&args))
                .err()
                .unwrap()
                .major_status(),
            error
        );
    }

    for (signature, args, signers, expected_status_opt) in general_cases() {
        // Body of the script is just an abort, so `ABORTED` means the script was accepted and ran
        let expected_status = expected_status_opt.unwrap_or(StatusCode::ABORTED);
        let script = make_script(signature);
        assert_eq!(
            call_script_with_args_ty_args_signers(script, serialize_values(&args), vec![], signers)
                .err()
                .unwrap()
                .major_status(),
            expected_status
        );
    }
}

#[test]
fn check_script_function() {
    //
    // Bad signatures
    //
    for signature in bad_signatures() {
        let (module, function_name) = make_script_function(signature);
        let res = call_script_function(
            module,
            function_name,
            serialize_values(&vec![MoveValue::U128(0)]),
        )
        .err()
        .unwrap();
        assert_eq!(
            res.major_status(),
            StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE,
        );
    }

    //
    // Good signatures
    //
    for (signature, args) in good_signatures_and_arguments() {
        // Body of the script is just an abort, so `ABORTED` means the script was accepted and ran
        let expected_status = StatusCode::ABORTED;
        let (module, function_name) = make_script_function(signature);
        assert_eq!(
            call_script_function(module, function_name, serialize_values(&args))
                .err()
                .unwrap()
                .major_status(),
            expected_status
        )
    }

    //
    // Mismatched Cases
    //
    for (signature, args, error) in mismatched_cases() {
        let (module, function_name) = make_script_function(signature);
        assert_eq!(
            call_script_function(module, function_name, serialize_values(&args))
                .err()
                .unwrap()
                .major_status(),
            error
        );
    }

    for (signature, args, signers, expected_status_opt) in general_cases() {
        // Body of the script is just an abort, so `ABORTED` means the script was accepted and ran
        let expected_status = expected_status_opt.unwrap_or(StatusCode::ABORTED);
        let (module, function_name) = make_script_function(signature);
        assert_eq!(
            call_script_function_with_args_ty_args_signers(
                module,
                function_name,
                serialize_values(&args),
                vec![],
                signers
            )
            .err()
            .unwrap()
            .major_status(),
            expected_status
        );
    }

    //
    // Non script visible
    //
    // public
    let (module, function_name) = make_module_with_function(
        Visibility::Public,
        Signature(vec![]),
        Signature(vec![]),
        vec![],
    );
    assert_eq!(
        call_script_function_with_args_ty_args_signers(
            module,
            function_name,
            vec![],
            vec![],
            vec![],
        )
        .err()
        .unwrap()
        .major_status(),
        StatusCode::EXECUTE_SCRIPT_FUNCTION_CALLED_ON_NON_SCRIPT_VISIBLE,
    );
    // private
    let (module, function_name) = make_module_with_function(
        Visibility::Private,
        Signature(vec![]),
        Signature(vec![]),
        vec![],
    );
    assert_eq!(
        call_script_function_with_args_ty_args_signers(
            module,
            function_name,
            vec![],
            vec![],
            vec![],
        )
        .err()
        .unwrap()
        .major_status(),
        StatusCode::EXECUTE_SCRIPT_FUNCTION_CALLED_ON_NON_SCRIPT_VISIBLE,
    );
}

#[test]
fn call_missing_item() {
    let module = empty_module();
    let id = &module.self_id();
    let function_name = IdentStr::new("foo").unwrap();
    // mising module
    let move_vm = MoveVM::new(vec![]).unwrap();
    let mut remote_view = RemoteStore::new();
    let mut session = move_vm.new_session(&remote_view);
    let mut gas_status = GasStatus::new_unmetered();
    let error = session
        .execute_script_function(id, function_name, vec![], vec![], vec![], &mut gas_status)
        .err()
        .unwrap();
    assert_eq!(error.major_status(), StatusCode::LINKER_ERROR);
    assert_eq!(error.status_type(), StatusType::Verification);

    // missing function
    remote_view.add_module(module);
    let mut session = move_vm.new_session(&remote_view);
    let error = session
        .execute_script_function(id, function_name, vec![], vec![], vec![], &mut gas_status)
        .err()
        .unwrap();
    assert_eq!(
        error.major_status(),
        StatusCode::FUNCTION_RESOLUTION_FAILURE
    );
    assert_eq!(error.status_type(), StatusType::Verification);
}
