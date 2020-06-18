// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants, error::Error, layout::Layout, secure_backend::StorageLocation::RemoteStorage,
    SingleBackend,
};
use libra_crypto::ed25519::Ed25519PublicKey;
use libra_global_constants::{ASSOCIATION_KEY, OPERATOR_KEY};
use libra_secure_storage::KVStorage;
use libra_types::transaction::{Transaction, TransactionPayload};
use std::{fs::File, io::Write, path::PathBuf};
use structopt::StructOpt;
use vm_genesis::ValidatorRegistration;

// TODO(davidiw) add operator_address, since that will eventually be the identity producing this.
/// Note, it is implicitly expected that the storage supports
/// a namespace but one has not been set.
#[derive(Debug, StructOpt)]
pub struct Genesis {
    #[structopt(flatten)]
    pub backend: SingleBackend,
    #[structopt(long)]
    pub path: Option<PathBuf>,
}

impl Genesis {
    pub fn execute(self) -> Result<Transaction, Error> {
        let layout = self.layout()?;
        let association_key = self.association(&layout)?;
        let validators = self.validators(&layout)?;

        let genesis = vm_genesis::encode_genesis_transaction_with_validator(
            association_key,
            &validators,
            None,
        );

        if let Some(path) = self.path {
            let mut file = File::create(path).map_err(|e| {
                Error::UnexpectedError(format!("Unable to create genesis file: {}", e.to_string()))
            })?;
            let bytes = lcs::to_bytes(&genesis).map_err(|e| {
                Error::UnexpectedError(format!("Unable to serialize genesis: {}", e.to_string()))
            })?;
            file.write_all(&bytes).map_err(|e| {
                Error::UnexpectedError(format!("Unable to write genesis file: {}", e.to_string()))
            })?;
        }

        Ok(genesis)
    }

    /// Retrieves association key from the remote storage. Note, at this point in time, genesis
    /// only supports a single association key.
    pub fn association(&self, layout: &Layout) -> Result<Ed25519PublicKey, Error> {
        let association_config = self.backend.backend.clone();
        let association_storage = association_config.new_available_storage_with_namespace(
            RemoteStorage,
            Some(layout.association[0].clone()),
        )?;

        let association_key = association_storage
            .get(ASSOCIATION_KEY)
            .map_err(|e| Error::RemoteStorageReadError(ASSOCIATION_KEY, e.to_string()))?;
        association_key
            .value
            .ed25519_public_key()
            .map_err(|e| Error::RemoteStorageReadError(ASSOCIATION_KEY, e.to_string()))
    }

    /// Retrieves a layout from the remote storage.
    pub fn layout(&self) -> Result<Layout, Error> {
        let common_config = self.backend.backend.clone();
        let common_storage = common_config.new_available_storage_with_namespace(
            RemoteStorage,
            Some(constants::COMMON_NS.into()),
        )?;

        let layout = common_storage
            .get(constants::LAYOUT)
            .and_then(|v| v.value.string())
            .map_err(|e| Error::RemoteStorageReadError(constants::LAYOUT, e.to_string()))?;
        Layout::parse(&layout)
            .map_err(|e| Error::RemoteStorageReadError(constants::LAYOUT, e.to_string()))
    }

    /// Produces a set of ValidatorRegistration from the remote storage.
    /// TODO(joshlind): verify that owner account address specified by the validator config matches
    /// the owner account address that was uploaded to the remote storage. Also verify that the
    /// operator selection has been signed by the owner (somehow...)
    pub fn validators(&self, layout: &Layout) -> Result<Vec<ValidatorRegistration>, Error> {
        let mut validators = Vec::new();

        for owner in layout.owners.iter() {
            let owner_config = self.backend.backend.clone();
            let owner_storage = owner_config
                .new_available_storage_with_namespace(RemoteStorage, Some(owner.into()))?;

            let operator_key = owner_storage
                .get(constants::VALIDATOR_OPERATOR)
                .map_err(|e| Error::RemoteStorageReadError(OPERATOR_KEY, e.to_string()))?
                .value
                .ed25519_public_key()
                .map_err(|e| Error::RemoteStorageReadError(OPERATOR_KEY, e.to_string()))?;

            let validator_config_txn = owner_storage
                .get(constants::VALIDATOR_CONFIG)
                .and_then(|v| v.value.transaction())
                .map_err(|e| {
                    Error::RemoteStorageReadError(constants::VALIDATOR_CONFIG, e.to_string())
                })?;
            let validator_config_txn = validator_config_txn.as_signed_user_txn().unwrap().payload();

            if let TransactionPayload::Script(txn_script) = validator_config_txn {
                validators.push((operator_key, txn_script.clone()));
            } else {
                return Err(Error::UnexpectedError("Found invalid registration".into()));
            }
        }

        Ok(validators)
    }
}
