// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use bytecode::{
    function_target::FunctionTarget,
    function_target_pipeline::{FunctionTargetsHolder, FunctionVariant, VerificationFlavor},
};
use move_model::model::FunctionEnv;

// TODO (mengxu): find a better way to determine which variant to call
pub fn choose_variant<'env>(
    holder: &'env FunctionTargetsHolder,
    func_env: &'env FunctionEnv<'env>,
) -> FunctionTarget<'env> {
    let mut target_variant = None;
    for (variant, target) in holder.get_targets(func_env) {
        // regular verification variant is preferred, baseline version is the second choice
        match variant {
            FunctionVariant::Baseline => {
                if target_variant.is_none() {
                    target_variant = Some(target);
                }
            }
            FunctionVariant::Verification(VerificationFlavor::Regular) => {
                target_variant = Some(target);
            }
            _ => (),
        }
    }
    target_variant.unwrap()
}
