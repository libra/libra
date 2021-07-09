// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::compiler::{as_module, as_script, compile_units};
use move_binary_format::errors::{Location, PartialVMError, PartialVMResult, VMResult};
use move_core_types::{
    account_address::AccountAddress,
    effects::ChangeSet,
    identifier::Identifier,
    language_storage::{ModuleId, StructTag},
    value::{serialize_values, MoveValue},
    vm_status::{StatusCode, StatusType},
};
use move_vm_runtime::{data_cache::MoveStorage, move_vm::MoveVM};
use move_vm_test_utils::{DeltaStorage, InMemoryStorage};
use move_vm_types::gas_schedule::GasStatus;

const TEST_ADDR: AccountAddress = AccountAddress::new([42; AccountAddress::LENGTH]);

#[test]
fn test_malformed_resource() {
    // Compile the modules and scripts.
    // TODO: find a better way to include the Signer module.
    let code = r#"
        address Std = 0x1 {
            module Signer {
                native public fun borrow_address(s: &signer): &address;

                public fun address_of(s: &signer): address {
                    *borrow_address(s)
                }
            }
        }

        module {{ADDR}}::M {
            use Std::Signer;

            struct Foo has key { x: u64, y: bool }

            public fun publish(s: &signer) {
                move_to(s, Foo { x: 123, y : false });
            }

            public fun check(s: &signer) acquires Foo {
                let foo = borrow_global<Foo>(Signer::address_of(s));
                assert(foo.x == 123 && foo.y == false, 42);
            }
        }

        script {
            use {{ADDR}}::M;

            fun main(s: signer) {
                M::publish(&s);
            }
        }

        script {
            use {{ADDR}}::M;

            fun main(s: signer) {
                M::check(&s);
            }
        }
    "#;
    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));
    let mut units = compile_units(&code).unwrap();

    let s2 = as_script(units.pop().unwrap());
    let s1 = as_script(units.pop().unwrap());
    let m = as_module(units.pop().unwrap());
    let ms = as_module(units.pop().unwrap());

    let mut storage = InMemoryStorage::new();

    // Publish module Signer and module M.
    let mut blob = vec![];
    ms.serialize(&mut blob).unwrap();
    storage.publish_or_overwrite_module(ms.self_id(), blob);

    let mut blob = vec![];
    m.serialize(&mut blob).unwrap();
    storage.publish_or_overwrite_module(m.self_id(), blob);

    let vm = MoveVM::new(move_stdlib::natives::all_natives(
        AccountAddress::from_hex_literal("0x1").unwrap(),
    ))
    .unwrap();

    let mut gas_status = GasStatus::new_unmetered();

    // Execute the first script to publish a resource Foo.
    let mut script_blob = vec![];
    s1.serialize(&mut script_blob).unwrap();
    let mut sess = vm.new_session(&storage);
    sess.execute_script(
        script_blob,
        vec![],
        vec![],
        vec![TEST_ADDR],
        &mut gas_status,
    )
    .unwrap();
    let (changeset, _) = sess.finish().unwrap();
    storage.apply(changeset).unwrap();

    // Execut the second script and make sure it succeeds. This script simply checks
    // that the published resource is what we expect it to be. This inital run is to ensure
    // the testing environment is indeed free of errors without external interference.
    let mut script_blob = vec![];
    s2.serialize(&mut script_blob).unwrap();
    {
        let mut sess = vm.new_session(&storage);
        sess.execute_script(
            script_blob.clone(),
            vec![],
            vec![],
            vec![TEST_ADDR],
            &mut gas_status,
        )
        .unwrap();
    }

    // Corrupt the resource in the storage.
    storage.publish_or_overwrite_resource(
        TEST_ADDR,
        StructTag {
            address: TEST_ADDR,
            module: Identifier::new("M").unwrap(),
            name: Identifier::new("Foo").unwrap(),
            type_params: vec![],
        },
        vec![0x3, 0x4, 0x5],
    );

    // Run the second script again.
    // The test will be successful if it fails with an invariant violation.
    {
        let mut sess = vm.new_session(&storage);
        let err = sess
            .execute_script(
                script_blob,
                vec![],
                vec![],
                vec![TEST_ADDR],
                &mut gas_status,
            )
            .unwrap_err();
        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

#[test]
fn test_malformed_module() {
    // Compile module M.
    let code = r#"
        module {{ADDR}}::M {
            public fun foo() {}
        }
    "#;

    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));
    let mut units = compile_units(&code).unwrap();

    let m = as_module(units.pop().unwrap());

    let mut blob = vec![];
    m.serialize(&mut blob).unwrap();

    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("M").unwrap());
    let fun_name = Identifier::new("foo").unwrap();

    let mut gas_status = GasStatus::new_unmetered();

    // Publish M and call M::foo. No errors should be thrown.
    {
        let mut storage = InMemoryStorage::new();
        storage.publish_or_overwrite_module(m.self_id(), blob.clone());
        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);
        sess.execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap();
    }

    // Start over with a fresh storage and publish a corrupted version of M.
    // A fresh VM needs to be used whenever the storage has been modified or otherwise the
    // loader cache gets out of sync.
    //
    // Try to call M::foo again and the module should fail to load, causing an
    // invariant violation error.
    {
        blob[0] = 0xde;
        blob[1] = 0xad;
        blob[2] = 0xbe;
        blob[3] = 0xef;
        let mut storage = InMemoryStorage::new();
        storage.publish_or_overwrite_module(m.self_id(), blob);
        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);
        let err = sess
            .execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap_err();
        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

#[test]
fn test_unverifiable_module() {
    // Compile module M.
    let code = r#"
        module {{ADDR}}::M {
            public fun foo() {}
        }
    "#;

    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));
    let mut units = compile_units(&code).unwrap();
    let m = as_module(units.pop().unwrap());

    let mut gas_status = GasStatus::new_unmetered();
    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("M").unwrap());
    let fun_name = Identifier::new("foo").unwrap();

    // Publish M and call M::foo to make sure it works.
    {
        let mut storage = InMemoryStorage::new();

        let mut blob = vec![];
        m.serialize(&mut blob).unwrap();
        storage.publish_or_overwrite_module(m.self_id(), blob);

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        sess.execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap();
    }

    // Erase the body of M::foo to make it fail verification.
    // Publish this modified version of M and the VM should fail to load it.
    {
        let mut storage = InMemoryStorage::new();

        let mut m = m;
        m.function_defs[0].code.as_mut().unwrap().code = vec![];
        let mut blob = vec![];
        m.serialize(&mut blob).unwrap();
        storage.publish_or_overwrite_module(m.self_id(), blob);

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        let err = sess
            .execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap_err();

        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

#[test]
fn test_missing_module_dependency() {
    // Compile two modules M, N where N depends on M.
    let code = r#"
        module {{ADDR}}::M {
            public fun foo() {}
        }

        module {{ADDR}}::N {
            use {{ADDR}}::M;

            public fun bar() { M::foo(); }
        }
    "#;
    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));
    let mut units = compile_units(&code).unwrap();
    let n = as_module(units.pop().unwrap());
    let m = as_module(units.pop().unwrap());

    let mut blob_m = vec![];
    m.serialize(&mut blob_m).unwrap();
    let mut blob_n = vec![];
    n.serialize(&mut blob_n).unwrap();

    let mut gas_status = GasStatus::new_unmetered();

    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("N").unwrap());
    let fun_name = Identifier::new("bar").unwrap();

    // Publish M and N and call N::bar. Everything should work.
    {
        let mut storage = InMemoryStorage::new();

        storage.publish_or_overwrite_module(m.self_id(), blob_m);
        storage.publish_or_overwrite_module(n.self_id(), blob_n.clone());

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        sess.execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap();
    }

    // Publish only N and try to call N::bar. The VM should fail to find M and raise
    // an invariant violation.
    {
        let mut storage = InMemoryStorage::new();
        storage.publish_or_overwrite_module(n.self_id(), blob_n);

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        let err = sess
            .execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap_err();

        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

#[test]
fn test_malformed_module_denpency() {
    // Compile two modules M, N where N depends on M.
    let code = r#"
        module {{ADDR}}::M {
            public fun foo() {}
        }

        module {{ADDR}}::N {
            use {{ADDR}}::M;

            public fun bar() { M::foo(); }
        }
    "#;
    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));
    let mut units = compile_units(&code).unwrap();
    let n = as_module(units.pop().unwrap());
    let m = as_module(units.pop().unwrap());

    let mut blob_m = vec![];
    m.serialize(&mut blob_m).unwrap();
    let mut blob_n = vec![];
    n.serialize(&mut blob_n).unwrap();

    let mut gas_status = GasStatus::new_unmetered();

    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("N").unwrap());
    let fun_name = Identifier::new("bar").unwrap();

    // Publish M and N and call N::bar. Everything should work.
    {
        let mut storage = InMemoryStorage::new();

        storage.publish_or_overwrite_module(m.self_id(), blob_m.clone());
        storage.publish_or_overwrite_module(n.self_id(), blob_n.clone());

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        sess.execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap();
    }

    // Publish N and a corrupted version of M and try to call N::bar, the VM should fail to load M.
    {
        blob_m[0] = 0xde;
        blob_m[1] = 0xad;
        blob_m[2] = 0xbe;
        blob_m[3] = 0xef;

        let mut storage = InMemoryStorage::new();

        storage.publish_or_overwrite_module(m.self_id(), blob_m);
        storage.publish_or_overwrite_module(n.self_id(), blob_n);

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        let err = sess
            .execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap_err();

        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

#[test]
fn test_unverifiable_module_dependency() {
    // Compile two modules M, N where N depends on M.
    let code = r#"
        module {{ADDR}}::M {
            public fun foo() {}
        }

        module {{ADDR}}::N {
            use {{ADDR}}::M;

            public fun bar() { M::foo(); }
        }
    "#;
    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));
    let mut units = compile_units(&code).unwrap();
    let n = as_module(units.pop().unwrap());
    let m = as_module(units.pop().unwrap());

    let mut blob_n = vec![];
    n.serialize(&mut blob_n).unwrap();

    let mut gas_status = GasStatus::new_unmetered();

    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("N").unwrap());
    let fun_name = Identifier::new("bar").unwrap();

    // Publish M and N and call N::bar. Everything should work.
    {
        let mut blob_m = vec![];
        m.serialize(&mut blob_m).unwrap();

        let mut storage = InMemoryStorage::new();

        storage.publish_or_overwrite_module(m.self_id(), blob_m);
        storage.publish_or_overwrite_module(n.self_id(), blob_n.clone());

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        sess.execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap();
    }

    // Publish N and an unverifiable version of M and try to call N::bar, the VM should fail to load M.
    {
        let mut m = m;
        m.function_defs[0].code.as_mut().unwrap().code = vec![];
        let mut blob_m = vec![];
        m.serialize(&mut blob_m).unwrap();

        let mut storage = InMemoryStorage::new();

        storage.publish_or_overwrite_module(m.self_id(), blob_m);
        storage.publish_or_overwrite_module(n.self_id(), blob_n);

        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        let err = sess
            .execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap_err();

        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

struct BogusStorage {
    bad_status_code: StatusCode,
}

impl MoveStorage for BogusStorage {
    fn get_module(&self, _module_id: &ModuleId) -> VMResult<Option<Vec<u8>>> {
        Err(PartialVMError::new(self.bad_status_code).finish(Location::Undefined))
    }

    fn get_resource(
        &self,
        _address: &AccountAddress,
        _tag: &StructTag,
    ) -> PartialVMResult<Option<Vec<u8>>> {
        Err(PartialVMError::new(self.bad_status_code))
    }
}

const LIST_OF_ERROR_CODES: &[StatusCode] = &[
    StatusCode::UNKNOWN_VALIDATION_STATUS,
    StatusCode::INVALID_SIGNATURE,
    StatusCode::UNKNOWN_VERIFICATION_ERROR,
    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
    StatusCode::UNKNOWN_BINARY_ERROR,
    StatusCode::UNKNOWN_RUNTIME_STATUS,
    StatusCode::UNKNOWN_STATUS,
];

#[test]
fn test_storage_returns_bogus_error_when_loading_module() {
    let mut gas_status = GasStatus::new_unmetered();
    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("N").unwrap());
    let fun_name = Identifier::new("bar").unwrap();

    for error_code in LIST_OF_ERROR_CODES {
        let storage = BogusStorage {
            bad_status_code: *error_code,
        };
        let vm = MoveVM::new(vec![]).unwrap();
        let mut sess = vm.new_session(&storage);

        let err = sess
            .execute_function(&module_id, &fun_name, vec![], vec![], &mut gas_status)
            .unwrap_err();

        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}

#[test]
fn test_storage_returns_bogus_error_when_loading_resource() {
    let mut gas_status = GasStatus::new_unmetered();

    let code = r#"
        address Std = 0x1 {
            module Signer {
                native public fun borrow_address(s: &signer): &address;

                public fun address_of(s: &signer): address {
                    *borrow_address(s)
                }
            }
        }

        module {{ADDR}}::M {
            use Std::Signer;

            struct R has key {}

            public fun foo() {}

            public fun bar(sender: &signer) acquires R {
                _ = borrow_global<R>(Signer::address_of(sender));
            }
        }
    "#;
    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_string()));

    let mut units = compile_units(&code).unwrap();
    let m = as_module(units.pop().unwrap());
    let s = as_module(units.pop().unwrap());
    let mut m_blob = vec![];
    let mut s_blob = vec![];
    m.serialize(&mut m_blob).unwrap();
    s.serialize(&mut s_blob).unwrap();
    let mut delta = ChangeSet::new();
    delta.publish_module(m.self_id(), m_blob).unwrap();
    delta.publish_module(s.self_id(), s_blob).unwrap();

    let m_id = m.self_id();
    let foo_name = Identifier::new("foo").unwrap();
    let bar_name = Identifier::new("bar").unwrap();

    for error_code in LIST_OF_ERROR_CODES {
        let storage = BogusStorage {
            bad_status_code: *error_code,
        };
        let storage = DeltaStorage::new(&storage, &delta);

        let vm = MoveVM::new(move_stdlib::natives::all_natives(
            AccountAddress::from_hex_literal("0x1").unwrap(),
        ))
        .unwrap();
        let mut sess = vm.new_session(&storage);

        sess.execute_function(&m_id, &foo_name, vec![], vec![], &mut gas_status)
            .unwrap();

        let err = sess
            .execute_function(
                &m_id,
                &bar_name,
                vec![],
                serialize_values(&vec![MoveValue::Signer(TEST_ADDR)]),
                &mut gas_status,
            )
            .unwrap_err();

        assert_eq!(err.status_type(), StatusType::InvariantViolation);
    }
}
