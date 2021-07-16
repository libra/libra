// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod unit_tests;

pub mod artifacts;
mod create;
mod verify;

pub use artifacts::{
    get_commit_hash, hash_for_modules, load_latest_artifact, save_release_artifact, ReleaseArtifact,
};
pub use create::create_release;
pub use verify::verify_release;

pub mod test_utils {
    use diem_types::account_config::CORE_CODE_ADDRESS;
    use move_binary_format::{file_format::empty_module, CompiledModule};

    pub fn release_modules() -> Vec<(Vec<u8>, CompiledModule)> {
        let mut modules: Vec<_> = diem_framework_releases::current_modules_with_blobs()
            .into_iter()
            .map(|(bytes, modules)| (bytes.clone(), modules.clone()))
            .collect();
        // Publish a new dummy module
        let mut module = empty_module();
        module.address_identifiers[0] = CORE_CODE_ADDRESS;
        let bytes = {
            let mut buf = vec![];
            module.serialize(&mut buf).unwrap();
            buf
        };
        modules.push((bytes, module));
        // TODO: See if there's a module that we can remove and if we can modify an existing module
        modules
    }
}
