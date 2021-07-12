// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    builder::GenesisBuilder, layout::Layout, verify::verify_genesis,
    waypoint::create_genesis_waypoint,
};
use anyhow::Result;
use consensus_types::safety_data::SafetyData;
use diem_config::config::{
    Identity, NodeConfig, OnDiskStorageConfig, SafetyRulesService, SecureBackend, WaypointConfig,
};
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    Uniform,
};
use diem_global_constants::{
    CONSENSUS_KEY, EXECUTION_KEY, FULLNODE_NETWORK_KEY, GENESIS_WAYPOINT, OPERATOR_ACCOUNT,
    OPERATOR_KEY, OWNER_ACCOUNT, OWNER_KEY, SAFETY_DATA, VALIDATOR_NETWORK_KEY, WAYPOINT,
};
use diem_management::{
    storage::StorageWrapper, validator_config::build_validator_config_transaction,
};
use diem_secure_storage::{CryptoStorage, KVStorage, OnDiskStorage, Storage};
use diem_types::{
    chain_id::ChainId,
    network_address::encrypted::{
        Key as NetworkAddressEncryptionKey, KeyVersion as NetworkAddressEncryptionKeyVersion,
    },
    transaction::{authenticator::AuthenticationKey, Transaction},
    waypoint::Waypoint,
};
use std::{
    convert::TryFrom,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

const DIEM_ROOT_NS: &str = "diem_root";
const OPERATOR_NS: &str = "_operator";
const OWNER_NS: &str = "_owner";

pub struct ValidatorConfig {
    pub name: String,
    pub storage_config: OnDiskStorageConfig,
    pub config: NodeConfig,
    pub directory: PathBuf,
}

impl ValidatorConfig {
    fn new(
        name: String,
        storage_config: OnDiskStorageConfig,
        directory: PathBuf,
        config: NodeConfig,
    ) -> Self {
        Self {
            name,
            storage_config,
            config,
            directory,
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.directory.join("node.yaml")
    }

    fn save_config(&mut self) -> Result<()> {
        self.config.save(self.config_path()).map_err(Into::into)
    }

    fn owner(&self) -> String {
        format!("{}{}", self.name, OWNER_NS)
    }

    fn operator(&self) -> String {
        format!("{}{}", self.name, OPERATOR_NS)
    }

    fn storage(&self) -> OnDiskStorage {
        OnDiskStorage::new(self.storage_config.path())
    }

    fn owner_key(&self) -> Result<Ed25519PublicKey> {
        self.storage()
            .get_public_key(OWNER_KEY)
            .map(|r| r.public_key)
            .map_err(Into::into)
    }

    fn operator_key(&self) -> Result<Ed25519PublicKey> {
        self.storage()
            .get_public_key(OPERATOR_KEY)
            .map(|r| r.public_key)
            .map_err(Into::into)
    }

    fn insert_waypoint(&mut self, waypoint: &Waypoint) -> Result<()> {
        // set waypoint in storage
        let mut storage = self.storage();
        storage.set(WAYPOINT, waypoint)?;
        storage.set(GENESIS_WAYPOINT, waypoint)?;

        self.config.base.waypoint =
            WaypointConfig::FromStorage(SecureBackend::OnDiskStorage(self.storage_config.clone()));

        Ok(())
    }

    fn insert_genesis(&mut self, genesis: &Transaction) -> Result<()> {
        // Save genesis file in this validator's config directory
        let genesis_file_location = self.directory.join("genesis.blob");
        File::create(&genesis_file_location)?.write_all(&bcs::to_bytes(&genesis)?)?;

        self.config.execution.genesis = Some(genesis.clone());
        self.config.execution.genesis_file_location = genesis_file_location;

        Ok(())
    }
}

pub struct RootKeys {
    pub root_key: Ed25519PrivateKey,
    pub treasury_compliance_key: Ed25519PrivateKey,
    pub validator_network_address_encryption_key: NetworkAddressEncryptionKey,
    pub validator_network_address_encryption_key_version: NetworkAddressEncryptionKeyVersion,
}

impl RootKeys {
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        // TODO use distinct keys for diem root and treasury
        // let root_key = Ed25519PrivateKey::generate(rng);
        // let treasury_compliance_key = Ed25519PrivateKey::generate(rng);
        let key = Ed25519PrivateKey::generate(rng).to_bytes();
        let root_key = Ed25519PrivateKey::try_from(key.as_ref()).unwrap();
        let treasury_compliance_key = Ed25519PrivateKey::try_from(key.as_ref()).unwrap();

        let mut validator_network_address_encryption_key = NetworkAddressEncryptionKey::default();
        rng.fill_bytes(&mut validator_network_address_encryption_key);

        Self {
            root_key,
            treasury_compliance_key,
            validator_network_address_encryption_key,
            validator_network_address_encryption_key_version: 0,
        }
    }
}

#[derive(Clone)]
pub struct ValidatorBuilder {
    config_directory: PathBuf,
    /// Bytecodes of Move genesis modules
    move_modules: Vec<Vec<u8>>,
    num_validators: usize,
    randomize_first_validator_ports: bool,
    template: NodeConfig,
}

impl ValidatorBuilder {
    pub fn new<T: AsRef<Path>>(config_directory: T, move_modules: Vec<Vec<u8>>) -> Self {
        Self {
            config_directory: config_directory.as_ref().into(),
            move_modules,
            num_validators: 1,
            randomize_first_validator_ports: true,
            template: NodeConfig::default_for_validator(),
        }
    }

    pub fn randomize_first_validator_ports(mut self, value: bool) -> Self {
        self.randomize_first_validator_ports = value;
        self
    }

    pub fn num_validators(mut self, num_validators: usize) -> Self {
        self.num_validators = num_validators;
        self
    }

    pub fn template(mut self, template: NodeConfig) -> Self {
        self.template = template;
        self
    }

    pub fn build(mut self) -> Result<(RootKeys, Vec<ValidatorConfig>)> {
        // TODO Pass this in
        let mut rng = rand::rngs::OsRng;

        // Canonicalize the config directory path
        self.config_directory = self.config_directory.canonicalize()?;

        // Generate chain root keys
        let root_keys = RootKeys::generate(&mut rng);

        // Generate and initialize Validator configs
        let mut validators = (0..self.num_validators)
            .map(|i| {
                self.initialize_validator_config(
                    i,
                    &mut rng,
                    root_keys.validator_network_address_encryption_key,
                    root_keys.validator_network_address_encryption_key_version,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        // Build genesis
        let mut genesis_storage =
            OnDiskStorage::new(self.config_directory.join("genesis-storage.json"));
        let (genesis, waypoint) = Self::genesis_ceremony(
            &mut genesis_storage,
            &root_keys,
            &validators,
            self.move_modules,
        )?;

        // Insert Genesis and Waypoint into each validator
        for validator in &mut validators {
            validator.insert_genesis(&genesis)?;
            validator.insert_waypoint(&waypoint)?;

            // verify genesis
            let validator_storage = Storage::from(validator.storage());
            let output = verify_genesis(
                StorageWrapper::new("validator", validator_storage),
                Some(validator.config.execution.genesis_file_location.as_path()),
            )?;

            anyhow::ensure!(
                output.split("match").count() == 5,
                "Failed to verify genesis"
            );
        }

        // Save the configs for each validator
        for validator in &mut validators {
            validator.save_config()?;
        }

        Ok((root_keys, validators))
    }

    //
    // Build helpers
    //

    fn initialize_validator_config<R>(
        &self,
        index: usize,
        rng: &mut R,
        validator_network_address_encryption_key: NetworkAddressEncryptionKey,
        validator_network_address_encryption_key_version: NetworkAddressEncryptionKeyVersion,
    ) -> Result<ValidatorConfig>
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        let name = index.to_string();
        let directory = self.config_directory.join(&name);
        std::fs::create_dir_all(&directory)?;

        let storage_config = Self::storage_config(&directory);

        let mut validator =
            ValidatorConfig::new(name, storage_config, directory, self.template.clone());
        Self::initialize_validator_storage(
            &validator,
            rng,
            validator_network_address_encryption_key,
            validator_network_address_encryption_key_version,
        )?;

        validator.config.set_data_dir(validator.directory.clone());
        let mut config = &mut validator.config;
        if index > 0 || self.randomize_first_validator_ports {
            config.randomize_ports();
        }

        // Setup the network configs
        let validator_network = config.validator_network.as_mut().unwrap();
        let fullnode_network = &mut config.full_node_networks[0];

        let validator_identity = validator_network.identity_from_storage();
        validator_network.identity = Identity::from_storage(
            validator_identity.key_name,
            validator_identity.peer_id_name,
            SecureBackend::OnDiskStorage(validator.storage_config.clone()),
        );
        validator_network.network_address_key_backend = Some(SecureBackend::OnDiskStorage(
            validator.storage_config.clone(),
        ));

        let fullnode_identity = fullnode_network.identity_from_storage();
        fullnode_network.identity = Identity::from_storage(
            fullnode_identity.key_name,
            fullnode_identity.peer_id_name,
            SecureBackend::OnDiskStorage(validator.storage_config.clone()),
        );

        // Setup consensus and execution configs
        config.consensus.safety_rules.service = SafetyRulesService::Thread;
        config.consensus.safety_rules.backend =
            SecureBackend::OnDiskStorage(validator.storage_config.clone());
        config.execution.backend = SecureBackend::OnDiskStorage(validator.storage_config.clone());

        Ok(validator)
    }

    fn storage_config(directory: &Path) -> OnDiskStorageConfig {
        let mut storage_config = OnDiskStorageConfig::default();
        storage_config.path = directory.join("secure-storage.json");
        storage_config.set_data_dir(directory.into());
        storage_config
    }

    fn initialize_validator_storage<R>(
        validator: &ValidatorConfig,
        rng: &mut R,
        validator_network_address_encryption_key: NetworkAddressEncryptionKey,
        validator_network_address_encryption_key_version: NetworkAddressEncryptionKeyVersion,
    ) -> Result<()>
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        let mut storage = validator.storage();

        // Set owner key and account address
        storage.import_private_key(OWNER_KEY, Ed25519PrivateKey::generate(rng))?;
        let owner_address =
            diem_config::utils::validator_owner_account_from_name(validator.owner().as_bytes());
        storage.set(OWNER_ACCOUNT, owner_address)?;

        // Set operator key and account address
        let operator_key = Ed25519PrivateKey::generate(rng);
        let operator_address =
            AuthenticationKey::ed25519(&Ed25519PublicKey::from(&operator_key)).derived_address();
        storage.set(OPERATOR_ACCOUNT, operator_address)?;
        storage.import_private_key(OPERATOR_KEY, operator_key)?;

        storage.import_private_key(CONSENSUS_KEY, Ed25519PrivateKey::generate(rng))?;
        storage.import_private_key(EXECUTION_KEY, Ed25519PrivateKey::generate(rng))?;
        storage.import_private_key(FULLNODE_NETWORK_KEY, Ed25519PrivateKey::generate(rng))?;
        storage.import_private_key(VALIDATOR_NETWORK_KEY, Ed25519PrivateKey::generate(rng))?;

        // Initialize all other data in storage
        storage.set(SAFETY_DATA, SafetyData::new(0, 0, 0, 0, None))?;
        storage.set(WAYPOINT, Waypoint::default())?;

        let mut encryptor = diem_network_address_encryption::Encryptor::new(storage);
        encryptor.initialize()?;
        encryptor.add_key(
            validator_network_address_encryption_key_version,
            validator_network_address_encryption_key,
        )?;

        Ok(())
    }

    fn genesis_ceremony(
        genesis_storage: &mut OnDiskStorage,
        root_keys: &RootKeys,
        validators: &[ValidatorConfig],
        move_modules: Vec<Vec<u8>>,
    ) -> Result<(Transaction, Waypoint)> {
        let mut genesis_builder = GenesisBuilder::new(genesis_storage);

        // Set the Layout and Move modules
        let layout = Layout {
            owners: validators.iter().map(|v| v.owner()).collect(),
            operators: validators.iter().map(|v| v.operator()).collect(),
            diem_root: DIEM_ROOT_NS.into(),
            treasury_compliance: DIEM_ROOT_NS.into(),
        };
        genesis_builder.set_layout(&layout)?;
        genesis_builder.set_move_modules(move_modules)?;

        // Set Root and Treasury public keys
        genesis_builder.set_root_key(Ed25519PublicKey::from(&root_keys.root_key))?;
        genesis_builder.set_treasury_compliance_key(Ed25519PublicKey::from(
            &root_keys.treasury_compliance_key,
        ))?;

        // Set Validator specific information
        for validator in validators {
            // Upload validator owner info
            genesis_builder.set_owner_key(&validator.owner(), validator.owner_key()?)?;

            // Upload validator operator info
            genesis_builder.set_operator(&validator.owner(), &validator.operator())?;
            genesis_builder.set_operator_key(&validator.operator(), validator.operator_key()?)?;

            // Create and upload the onchain validator config
            let validator_config = build_validator_config_transaction(
                validator.storage(),
                ChainId::test(),
                0, // sequence_number
                validator.config.full_node_networks[0]
                    .listen_address
                    .clone(),
                validator
                    .config
                    .validator_network
                    .as_ref()
                    .map(|a| a.listen_address.clone())
                    .unwrap(),
                false, // This isn't a reconfiguration
                false, // Don't disable address validation
            )?;
            genesis_builder.set_validator_config(&validator.operator(), &validator_config)?;
        }

        // Create Genesis and Genesis Waypoint
        let genesis = genesis_builder.build(ChainId::test())?;
        let waypoint = create_genesis_waypoint(&genesis)?;

        Ok((genesis, waypoint))
    }
}
