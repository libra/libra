// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// FIXME: (gnazario) storage helper doesn't belong in the genesis tool, but it's attached to it right now

use crate::command::Command;
use consensus_types::safety_data::SafetyData;
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    Uniform,
};
use diem_global_constants::{
    CONSENSUS_KEY, DIEM_ROOT_KEY, EXECUTION_KEY, FULLNODE_NETWORK_KEY, OPERATOR_KEY, OWNER_KEY,
    SAFETY_DATA, TREASURY_COMPLIANCE_KEY, VALIDATOR_NETWORK_KEY, WAYPOINT,
};
use diem_management::{error::Error, secure_backend::DISK};
use diem_secure_storage::{CryptoStorage, KVStorage, Namespaced, OnDiskStorage, Storage};
use diem_types::{
    chain_id::ChainId,
    network_address::{self, NetworkAddress},
    transaction::Transaction,
    waypoint::Waypoint,
};
use std::{fs::File, path::Path};
use structopt::StructOpt;

pub struct StorageHelper {
    temppath: diem_temppath::TempPath,
}

impl StorageHelper {
    pub fn new() -> Self {
        let temppath = diem_temppath::TempPath::new();
        temppath.create_as_file().unwrap();
        File::create(temppath.path()).unwrap();
        Self { temppath }
    }

    pub fn storage(&self, namespace: String) -> Storage {
        let storage = OnDiskStorage::new(self.temppath.path().to_path_buf());
        Storage::from(Namespaced::new(namespace, Box::new(Storage::from(storage))))
    }

    pub fn path_string(&self) -> &str {
        self.temppath.path().to_str().unwrap()
    }

    pub fn initialize_by_idx(&self, namespace: String, idx: usize) {
        let partial_seed = bcs::to_bytes(&idx).unwrap();
        let mut seed = [0u8; 32];
        let data_to_copy = 32 - std::cmp::min(32, partial_seed.len());
        seed[data_to_copy..].copy_from_slice(partial_seed.as_slice());
        self.initialize(namespace, seed);
    }

    pub fn initialize(&self, namespace: String, seed: [u8; 32]) {
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
        let mut storage = self.storage(namespace);

        // Initialize all keys in storage
        storage
            .import_private_key(DIEM_ROOT_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();
        // TODO(davidiw) use distinct keys in tests for treasury and diem root keys
        let diem_root_key = storage.export_private_key(DIEM_ROOT_KEY).unwrap();
        storage
            .import_private_key(TREASURY_COMPLIANCE_KEY, diem_root_key)
            .unwrap();
        storage
            .import_private_key(CONSENSUS_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();
        storage
            .import_private_key(EXECUTION_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();
        storage
            .import_private_key(FULLNODE_NETWORK_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();
        storage
            .import_private_key(OWNER_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();
        storage
            .import_private_key(OPERATOR_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();
        storage
            .import_private_key(VALIDATOR_NETWORK_KEY, Ed25519PrivateKey::generate(&mut rng))
            .unwrap();

        // Initialize all other data in storage
        storage
            .set(SAFETY_DATA, SafetyData::new(0, 0, 0, 0, None))
            .unwrap();
        storage.set(WAYPOINT, Waypoint::default()).unwrap();
        let mut encryptor = diem_network_address_encryption::Encryptor::new(storage);
        encryptor.initialize().unwrap();
        encryptor
            .add_key(
                network_address::encrypted::TEST_SHARED_VAL_NETADDR_KEY_VERSION,
                network_address::encrypted::TEST_SHARED_VAL_NETADDR_KEY,
            )
            .unwrap();
    }

    pub fn create_waypoint(&self, chain_id: ChainId) -> Result<Waypoint, Error> {
        let args = format!(
            "
                diem-genesis-tool
                create-waypoint
                --chain-id {chain_id}
                --shared-backend backend={backend};\
                    path={path}
            ",
            chain_id = chain_id,
            backend = DISK,
            path = self.path_string(),
        );

        let command = Command::from_iter(args.split_whitespace());
        command.create_waypoint()
    }

    pub fn insert_waypoint(&self, validator_ns: &str, waypoint: Waypoint) -> Result<(), Error> {
        let args = format!(
            "
                diem-genesis-tool
                insert-waypoint
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={validator_ns}
                --waypoint {waypoint}
                --set-genesis
            ",
            backend = DISK,
            path = self.path_string(),
            validator_ns = validator_ns,
            waypoint = waypoint,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.insert_waypoint()
    }

    pub fn genesis(&self, chain_id: ChainId, genesis_path: &Path) -> Result<Transaction, Error> {
        let args = format!(
            "
                diem-genesis-tool
                genesis
                --chain-id {chain_id}
                --shared-backend backend={backend};\
                    path={path}
                --path {genesis_path}
            ",
            chain_id = chain_id,
            backend = DISK,
            path = self.path_string(),
            genesis_path = genesis_path.to_str().expect("Unable to parse genesis_path"),
        );

        let command = Command::from_iter(args.split_whitespace());
        command.genesis()
    }

    pub fn diem_root_key(
        &self,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                diem-root-key
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            path = self.path_string(),
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.diem_root_key()
    }

    pub fn operator_key(
        &self,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                operator-key
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            path = self.path_string(),
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.operator_key()
    }

    pub fn owner_key(
        &self,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                owner-key
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            path = self.path_string(),
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.owner_key()
    }

    #[cfg(test)]
    pub fn set_layout(&self, path: &str) -> Result<crate::layout::Layout, Error> {
        let args = format!(
            "
                diem-genesis-tool
                set-layout
                --path {path}
                --shared-backend backend={backend};\
                    path={storage_path}
            ",
            path = path,
            backend = DISK,
            storage_path = self.path_string(),
        );

        let command = Command::from_iter(args.split_whitespace());
        command.set_layout()
    }

    #[cfg(test)]
    pub fn set_move_modules(&self, dir: &str) -> Result<Vec<Vec<u8>>, Error> {
        println!("setting move modules with dir {}", dir);
        let args = format!(
            "
                diem-genesis-tool
                set-move-modules
                --dir {dir}
                --shared-backend backend={backend};\
                    path={storage_path}
            ",
            dir = dir,
            backend = DISK,
            storage_path = self.path_string(),
        );

        let command = Command::from_iter(args.split_whitespace());
        command.set_move_modules()
    }

    pub fn set_operator(&self, operator_name: &str, shared_ns: &str) -> Result<String, Error> {
        let args = format!(
            "
                diem-genesis-tool
                set-operator
                --operator-name {operator_name}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            operator_name = operator_name,
            backend = DISK,
            path = self.path_string(),
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.set_operator()
    }

    pub fn treasury_compliance_key(
        &self,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                treasury-compliance-key
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            path = self.path_string(),
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.treasury_compliance_key()
    }

    pub fn validator_config(
        &self,
        owner_name: &str,
        validator_address: NetworkAddress,
        fullnode_address: NetworkAddress,
        chain_id: ChainId,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Transaction, Error> {
        let args = format!(
            "
                diem-genesis-tool
                validator-config
                --owner-name {owner_name}
                --validator-address {validator_address}
                --fullnode-address {fullnode_address}
                --chain-id {chain_id}
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            owner_name = owner_name,
            validator_address = validator_address,
            fullnode_address = fullnode_address,
            chain_id = chain_id.id(),
            backend = DISK,
            path = self.path_string(),
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.validator_config()
    }

    #[cfg(test)]
    pub fn verify(&self, namespace: &str) -> Result<String, Error> {
        let args = format!(
            "
                diem-genesis-tool
                verify
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={ns}
            ",
            backend = DISK,
            path = self.path_string(),
            ns = namespace,
        );

        let command = Command::from_iter(args.split_whitespace());
        command.verify()
    }

    pub fn verify_genesis(&self, namespace: &str, genesis_path: &Path) -> Result<String, Error> {
        let args = format!(
            "
                diem-genesis-tool
                verify
                --validator-backend backend={backend};\
                    path={path};\
                    namespace={ns}
                --genesis-path {genesis_path}
            ",
            backend = DISK,
            path = self.path_string(),
            ns = namespace,
            genesis_path = genesis_path.to_str().expect("Unable to parse genesis_path"),
        );

        let command = Command::from_iter(args.split_whitespace());
        command.verify()
    }
}
