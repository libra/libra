// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use diem_crypto::ed25519::Ed25519PublicKey;
use diem_genesis_tool::{command::Command, layout::Layout};
use diem_management::{error::Error, secure_backend::DISK};
use diem_operational_tool::command::Command as OperationalCommand;
use diem_types::{
    chain_id::ChainId, network_address::NetworkAddress, transaction::Transaction,
    waypoint::Waypoint,
};
use std::path::Path;
use structopt::StructOpt;
use tokio::task::spawn_blocking;

pub struct GenesisHelper {
    path: &'static str,
}

impl GenesisHelper {
    pub fn new(path: &'static str) -> Self {
        GenesisHelper { path }
    }

    pub async fn set_layout(&self, path: &str, namespace: &str) -> Result<Layout, Error> {
        let args = format!(
            "
                diem-genesis-tool
                set-layout
                --path {path}
                --shared-backend backend={backend};\
                    path={storage_path};\
                    namespace={ns}
            ",
            path = path,
            backend = DISK,
            storage_path = self.path,
            ns = namespace,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.set_layout())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn set_move_modules(
        &self,
        dir: &str,
        namespace: &str,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let args = format!(
            "
                diem-genesis-tool
                set-move-modules
                --dir {dir}
                --shared-backend backend={backend};\
                    path={storage_path};\
                    namespace={ns}
            ",
            dir = dir,
            backend = DISK,
            storage_path = self.path,
            ns = namespace,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.set_move_modules())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn diem_root_key(
        &self,
        validator_backend: &str,
        server: &str,
        token_path: &str,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                diem-root-key
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
            path = self.path,
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.diem_root_key())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn owner_key(
        &self,
        validator_backend: &str,
        server: &str,
        token_path: &str,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                owner-key
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
            path = self.path,
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.owner_key())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn operator_key(
        &self,
        validator_backend: &str,
        server: &str,
        token_path: &str,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                operator-key
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
            path = self.path,
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.operator_key())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn treasury_compliance_key(
        &self,
        validator_backend: &str,
        server: &str,
        token_path: &str,
        validator_ns: &str,
        shared_ns: &str,
    ) -> Result<Ed25519PublicKey, Error> {
        let args = format!(
            "
                diem-genesis-tool
                treasury-compliance-key
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            backend = DISK,
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
            path = self.path,
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.treasury_compliance_key())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn validator_config(
        &self,
        owner_name: &str,
        validator_address: NetworkAddress,
        fullnode_address: NetworkAddress,
        chain_id: ChainId,
        validator_backend: &str,
        server: &str,
        token_path: &str,
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
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path};\
                    namespace={validator_ns}
                --shared-backend backend={backend};\
                    path={path};\
                    namespace={shared_ns}
            ",
            owner_name = owner_name,
            validator_address = validator_address,
            fullnode_address = fullnode_address,
            chain_id = chain_id.id(),
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
            backend = DISK,
            path = self.path,
            validator_ns = validator_ns,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.validator_config())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn set_operator(
        &self,
        operator_name: &str,
        shared_ns: &str,
    ) -> Result<String, Error> {
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
            path = self.path,
            shared_ns = shared_ns,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.set_operator())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn genesis(
        &self,
        chain_id: ChainId,
        genesis_path: &Path,
    ) -> Result<Transaction, Error> {
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
            path = self.path,
            genesis_path = genesis_path.to_str().expect("Unable to parse genesis_path"),
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.genesis())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn create_and_insert_waypoint(
        &self,
        chain_id: ChainId,
        validator_backend: &str,
        server: &str,
        token_path: &str,
        validator_ns: &str,
    ) -> Result<Waypoint, Error> {
        let waypoint = self.create_waypoint(chain_id).await?;

        let args = format!(
            "
                diem-genesis-tool
                insert-waypoint
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path};\
                    namespace={validator_ns}
                --waypoint {waypoint}
                --set-genesis
            ",
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
            validator_ns = validator_ns,
            waypoint = waypoint,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.insert_waypoint())
            .await
            .expect("tokio spawn_blocking runtime error")
            .map(|_| waypoint)
    }

    pub async fn create_waypoint(&self, chain_id: ChainId) -> Result<Waypoint, Error> {
        let args = format!(
            "
                diem-genesis-tool
                create-waypoint
                --chain-id {chain_id}
                --shared-backend backend={backend};\
                    path={path}\
            ",
            chain_id = chain_id,
            backend = DISK,
            path = self.path,
        );

        let command = Command::from_iter(args.split_whitespace());
        spawn_blocking(|| command.create_waypoint())
            .await
            .expect("tokio spawn_blocking runtime error")
    }

    pub async fn extract_private_key(
        &self,
        key_name: &str,
        key_file: &str,
        validator_backend: &str,
        server: &str,
        token_path: &str,
    ) -> Result<(), Error> {
        let args = format!(
            "
                diem-operational-tool
                extract-private-key
                --key-name {key_name}
                --key-file {key_file}
                --validator-backend backend={validator_backend};\
                    server={server};\
                    token={token_path}\
            ",
            key_name = key_name,
            key_file = key_file,
            validator_backend = validator_backend,
            server = server,
            token_path = token_path,
        );

        let command = OperationalCommand::from_iter(args.split_whitespace());
        spawn_blocking(|| command.extract_private_key())
            .await
            .expect("tokio spawn_blocking runtime error")
    }
}
