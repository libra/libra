// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use bytecode_verifier::verify_module;
use move_binary_format::CompiledModule;
use proptest::prelude::*;

proptest! {
    #[test]
    fn check_verifier_passes(module in CompiledModule::valid_strategy(20)) {
        verify_module(&module).expect("module verification failure");
    }
}
