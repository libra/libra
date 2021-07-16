// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::release_flow::create::create_release_writeset;
use bytecode_verifier::verify_module;
use diem_types::{
    access_path::AccessPath,
    transaction::{ChangeSet, WriteSetPayload},
    write_set::{WriteOp, WriteSet, WriteSetMut},
};
use move_binary_format::file_format::{basic_test_module, empty_module};
use move_core_types::identifier::Identifier;

#[test]
fn release_test() {
    let result = create_release_writeset(&[], &[]).unwrap();

    assert_eq!(
        result,
        WriteSetPayload::Direct(ChangeSet::new(WriteSet::default(), vec![]))
    );

    // Create 10 distinct modules.
    let mut modules = vec![];
    let mut modules_and_bytes = vec![];
    let mut modules_bytes = vec![];
    for i in 0..10 {
        let mut module = empty_module();
        module.identifiers[0] = Identifier::new(format!("test_{:?}", i)).unwrap();
        verify_module(&module).expect("invalid module");

        let mut bytes = vec![];
        module.serialize(&mut bytes).unwrap();
        modules_and_bytes.push((bytes.clone(), module.clone()));
        modules.push(module);
        modules_bytes.push(bytes);
    }

    // With one module replacing the test_9 module.
    let replace_module = {
        let mut module = basic_test_module();
        module.identifiers[0] = Identifier::new(format!("test_{:?}", 9)).unwrap();
        verify_module(&module).expect("invalid module");
        module
    };
    let mut replace_module_bytes = vec![];
    replace_module.serialize(&mut replace_module_bytes).unwrap();

    // 1. Old and new framework are exactly the same.
    let result = create_release_writeset(&modules, &modules_and_bytes).unwrap();

    assert_eq!(
        result,
        WriteSetPayload::Direct(ChangeSet::new(WriteSet::default(), vec![]))
    );

    // 2. Remove one existing module
    {
        let result =
            create_release_writeset(&modules, &modules_and_bytes.clone().split_off(1)).unwrap();
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![(
                    AccessPath::code_access_path(modules[0].self_id()),
                    WriteOp::Deletion
                )])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 3. Add one module
    {
        let result =
            create_release_writeset(&modules.clone().split_off(1), &modules_and_bytes).unwrap();
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![(
                    AccessPath::code_access_path(modules[0].self_id()),
                    WriteOp::Value(modules_bytes[0].clone())
                )])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 4. Modify one module
    {
        let mut replace_modules = modules_and_bytes.clone();
        replace_modules.pop();
        replace_modules.push((replace_module_bytes.clone(), replace_module.clone()));

        let result = create_release_writeset(&modules, &replace_modules).unwrap();
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![(
                    AccessPath::code_access_path(replace_module.self_id()),
                    WriteOp::Value(replace_module_bytes.clone())
                )])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 5. Add and remove modules
    {
        // New modules has test_0 .. test_8
        let mut new_modules = modules_and_bytes.clone();
        new_modules.pop();
        // Old modules has test_1 .. test_9
        let mut old_modules = modules.clone();
        old_modules.swap_remove(0);

        let result = create_release_writeset(&old_modules, &new_modules).unwrap();
        // Result should be in sorted order
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![
                    (
                        AccessPath::code_access_path(modules[0].self_id()),
                        WriteOp::Value(modules_bytes[0].clone())
                    ),
                    (
                        AccessPath::code_access_path(modules[9].self_id()),
                        WriteOp::Deletion
                    )
                ])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 6. Remove and replace modules
    {
        // New modules has test_1 .. test_8, test_9'
        let mut new_modules = modules_and_bytes.clone();
        new_modules.pop();
        new_modules.push((replace_module_bytes.clone(), replace_module.clone()));
        new_modules.swap_remove(0);

        let result = create_release_writeset(&modules, &new_modules).unwrap();
        // Result should be in sorted order
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![
                    (
                        AccessPath::code_access_path(modules[0].self_id()),
                        WriteOp::Deletion
                    ),
                    (
                        AccessPath::code_access_path(modules[9].self_id()),
                        WriteOp::Value(replace_module_bytes.clone())
                    )
                ])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 7. Add and replace modules
    {
        // New modules has test_0 .. test_8, test_9'
        let mut new_modules = modules_and_bytes.clone();
        new_modules.pop();
        new_modules.push((replace_module_bytes.clone(), replace_module.clone()));

        // Old modules has test_1 .. test_9
        let mut old_modules = modules.clone();
        old_modules.swap_remove(0);

        let result = create_release_writeset(&old_modules, &new_modules).unwrap();
        // Result should be in sorted order
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![
                    (
                        AccessPath::code_access_path(modules[0].self_id()),
                        WriteOp::Value(modules_bytes[0].clone())
                    ),
                    (
                        AccessPath::code_access_path(modules[9].self_id()),
                        WriteOp::Value(replace_module_bytes.clone())
                    )
                ])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 8. Add, replace and remove modules
    {
        // New modules has test_0 .. test_7, test_9'
        let mut new_modules = modules_and_bytes.clone();
        new_modules.pop();
        new_modules.pop();
        new_modules.push((replace_module_bytes.clone(), replace_module.clone()));

        // Old modules has test_1 .. test_9
        let mut old_modules = modules.clone();
        old_modules.swap_remove(0);

        let result = create_release_writeset(&old_modules, &new_modules).unwrap();
        // Result should be in sorted order
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![
                    (
                        AccessPath::code_access_path(modules[0].self_id()),
                        WriteOp::Value(modules_bytes[0].clone())
                    ),
                    (
                        AccessPath::code_access_path(modules[8].self_id()),
                        WriteOp::Deletion
                    ),
                    (
                        AccessPath::code_access_path(modules[9].self_id()),
                        WriteOp::Value(replace_module_bytes.clone())
                    )
                ])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }

    // 8. Swapping input order will not change result.
    {
        // New modules has test_0 .. test_7, test_9'
        let mut new_modules = modules_and_bytes;
        new_modules.pop();
        new_modules.pop();
        new_modules.push((replace_module_bytes.clone(), replace_module));
        new_modules.swap(0, 2);

        // Old modules has test_1 .. test_9
        let mut old_modules = modules.clone();
        old_modules.swap_remove(0);
        new_modules.swap(4, 5);

        let result = create_release_writeset(&old_modules, &new_modules).unwrap();
        // Result should be in sorted order
        assert_eq!(
            result,
            WriteSetPayload::Direct(ChangeSet::new(
                WriteSetMut::new(vec![
                    (
                        AccessPath::code_access_path(modules[0].self_id()),
                        WriteOp::Value(modules_bytes[0].clone())
                    ),
                    (
                        AccessPath::code_access_path(modules[8].self_id()),
                        WriteOp::Deletion
                    ),
                    (
                        AccessPath::code_access_path(modules[9].self_id()),
                        WriteOp::Value(replace_module_bytes)
                    )
                ])
                .freeze()
                .unwrap(),
                vec![]
            ))
        );
    }
}
