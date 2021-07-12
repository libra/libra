// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use diem_crypto::ed25519::Ed25519PublicKey;
use diem_management::{error::Error, execute_command};
use diem_types::{transaction::Transaction, waypoint::Waypoint};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "Tool used for genesis")]
pub enum Command {
    #[structopt(about = "Create a waypoint")]
    CreateWaypoint(crate::waypoint::CreateWaypoint),
    #[structopt(about = "Retrieves data from a store to produce genesis")]
    Genesis(crate::genesis::Genesis),
    #[structopt(about = "Set the waypoint in the validator storage")]
    InsertWaypoint(diem_management::waypoint::InsertWaypoint),
    #[structopt(about = "Submits an Ed25519PublicKey for the diem root")]
    DiemRootKey(crate::key::DiemRootKey),
    #[structopt(about = "Submits an Ed25519PublicKey for the operator")]
    OperatorKey(crate::key::OperatorKey),
    #[structopt(about = "Submits an Ed25519PublicKey for the owner")]
    OwnerKey(crate::key::OwnerKey),
    #[structopt(about = "Submits a Layout doc to a shared storage")]
    SetLayout(crate::layout::SetLayout),
    #[structopt(about = "Submits Move module bytecodes to a shared storage")]
    SetMoveModules(crate::move_modules::SetMoveModules),
    #[structopt(about = "Sets the validator operator chosen by the owner")]
    SetOperator(crate::validator_operator::ValidatorOperator),
    #[structopt(about = "Submits an Ed25519PublicKey for the treasury root")]
    TreasuryComplianceKey(crate::key::TreasuryComplianceKey),
    #[structopt(about = "Constructs and signs a ValidatorConfig")]
    ValidatorConfig(crate::validator_config::ValidatorConfig),
    #[structopt(about = "Verifies and prints the current configuration state")]
    Verify(crate::verify::Verify),
}

#[derive(Debug, PartialEq)]
pub enum CommandName {
    CreateWaypoint,
    Genesis,
    InsertWaypoint,
    DiemRootKey,
    OperatorKey,
    OwnerKey,
    SetLayout,
    SetMoveModules,
    SetOperator,
    TreasuryComplianceKey,
    ValidatorConfig,
    Verify,
}

impl From<&Command> for CommandName {
    fn from(command: &Command) -> Self {
        match command {
            Command::CreateWaypoint(_) => CommandName::CreateWaypoint,
            Command::Genesis(_) => CommandName::Genesis,
            Command::InsertWaypoint(_) => CommandName::InsertWaypoint,
            Command::DiemRootKey(_) => CommandName::DiemRootKey,
            Command::OperatorKey(_) => CommandName::OperatorKey,
            Command::OwnerKey(_) => CommandName::OwnerKey,
            Command::SetLayout(_) => CommandName::SetLayout,
            Command::SetMoveModules(_) => CommandName::SetMoveModules,
            Command::SetOperator(_) => CommandName::SetOperator,
            Command::TreasuryComplianceKey(_) => CommandName::TreasuryComplianceKey,
            Command::ValidatorConfig(_) => CommandName::ValidatorConfig,
            Command::Verify(_) => CommandName::Verify,
        }
    }
}

impl std::fmt::Display for CommandName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match self {
            CommandName::CreateWaypoint => "create-waypoint",
            CommandName::Genesis => "genesis",
            CommandName::InsertWaypoint => "insert-waypoint",
            CommandName::DiemRootKey => "diem-root-key",
            CommandName::OperatorKey => "operator-key",
            CommandName::OwnerKey => "owner-key",
            CommandName::SetLayout => "set-layout",
            CommandName::SetMoveModules => "set-move-modules",
            CommandName::SetOperator => "set-operator",
            CommandName::TreasuryComplianceKey => "treasury-compliance-key",
            CommandName::ValidatorConfig => "validator-config",
            CommandName::Verify => "verify",
        };
        write!(f, "{}", name)
    }
}

impl Command {
    pub fn execute(self) -> Result<String, Error> {
        match &self {
            Command::CreateWaypoint(_) => {
                self.create_waypoint().map(|w| format!("Waypoint: {}", w))
            }
            Command::Genesis(_) => self.genesis().map(|_| "Success!".to_string()),
            Command::InsertWaypoint(_) => self.insert_waypoint().map(|_| "Success!".to_string()),
            Command::DiemRootKey(_) => self.diem_root_key().map(|_| "Success!".to_string()),
            Command::OperatorKey(_) => self.operator_key().map(|_| "Success!".to_string()),
            Command::OwnerKey(_) => self.owner_key().map(|_| "Success!".to_string()),
            Command::SetLayout(_) => self.set_layout().map(|_| "Success!".to_string()),
            Command::SetMoveModules(_) => self.set_move_modules().map(|_| "Success!".to_string()),
            Command::SetOperator(_) => self.set_operator().map(|_| "Success!".to_string()),
            Command::TreasuryComplianceKey(_) => self
                .treasury_compliance_key()
                .map(|_| "Success!".to_string()),
            Command::ValidatorConfig(_) => self.validator_config().map(|_| "Success!".to_string()),
            Command::Verify(_) => self.verify(),
        }
    }

    pub fn create_waypoint(self) -> Result<Waypoint, Error> {
        execute_command!(self, Command::CreateWaypoint, CommandName::CreateWaypoint)
    }

    pub fn genesis(self) -> Result<Transaction, Error> {
        execute_command!(self, Command::Genesis, CommandName::Genesis)
    }

    pub fn insert_waypoint(self) -> Result<(), Error> {
        execute_command!(self, Command::InsertWaypoint, CommandName::InsertWaypoint)
    }

    pub fn diem_root_key(self) -> Result<Ed25519PublicKey, Error> {
        execute_command!(self, Command::DiemRootKey, CommandName::DiemRootKey)
    }

    pub fn operator_key(self) -> Result<Ed25519PublicKey, Error> {
        execute_command!(self, Command::OperatorKey, CommandName::OperatorKey)
    }

    pub fn owner_key(self) -> Result<Ed25519PublicKey, Error> {
        execute_command!(self, Command::OwnerKey, CommandName::OwnerKey)
    }

    pub fn set_layout(self) -> Result<crate::layout::Layout, Error> {
        execute_command!(self, Command::SetLayout, CommandName::SetLayout)
    }

    pub fn set_move_modules(self) -> Result<Vec<Vec<u8>>, Error> {
        execute_command!(self, Command::SetMoveModules, CommandName::SetMoveModules)
    }

    pub fn set_operator(self) -> Result<String, Error> {
        execute_command!(self, Command::SetOperator, CommandName::SetOperator)
    }

    pub fn treasury_compliance_key(self) -> Result<Ed25519PublicKey, Error> {
        execute_command!(
            self,
            Command::TreasuryComplianceKey,
            CommandName::TreasuryComplianceKey
        )
    }

    pub fn validator_config(self) -> Result<Transaction, Error> {
        execute_command!(self, Command::ValidatorConfig, CommandName::ValidatorConfig)
    }

    pub fn verify(self) -> Result<String, Error> {
        execute_command!(self, Command::Verify, CommandName::Verify)
    }
}

/// These tests depends on running Vault, which can be done by using the provided docker run script
/// in `docker/vault/run.sh`.
/// Note: Some of these tests may fail if you run them too quickly one after another due to data
/// sychronization issues within Vault. It would seem the only way to fix it would be to restart
/// the Vault service between runs.
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage_helper::StorageHelper;
    use diem_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    use diem_global_constants::{OPERATOR_KEY, OWNER_KEY};
    use diem_management::constants;
    use diem_secure_storage::KVStorage;
    use diem_types::{account_address, chain_id::ChainId, transaction::TransactionPayload};
    use std::{
        fs::File,
        io::{Read, Write},
    };

    #[test]
    fn test_end_to_end() {
        let helper = StorageHelper::new();

        // Each identity works in their own namespace
        // Alice, Bob, and Carol are owners.
        // Operator_Alice, Operator_Bob and Operator_Carol are operators.
        // Dave is the diem root.
        // Each user will upload their contents to *_ns + "shared"
        // Common is used by the technical staff for coordination.
        let alice_ns = "alice";
        let bob_ns = "bob";
        let carol_ns = "carol";
        let operator_alice_ns = "operator_alice";
        let operator_bob_ns = "operator_bob";
        let operator_carol_ns = "operator_carol";
        let dave_ns = "dave";
        let shared = "_shared";
        let mut storage_idx = 0;

        // Step 1) Define and upload the layout specifying which identities have which roles. This
        // is uploaded to the common namespace:
        let layout_text = "\
            operators = [\"operator_alice_shared\", \"operator_bob_shared\", \"operator_carol_shared\"]\n\
            owners = [\"alice_shared\", \"bob_shared\", \"carol_shared\"]\n\
            diem_root = \"dave_shared\"\n\
            treasury_compliance = \"dave_shared\"\n\
        ";

        let temppath = diem_temppath::TempPath::new();
        temppath.create_as_file().unwrap();
        let mut file = File::create(temppath.path()).unwrap();
        file.write_all(&layout_text.to_string().into_bytes())
            .unwrap();
        file.sync_all().unwrap();

        helper
            .set_layout(temppath.path().to_str().unwrap())
            .unwrap();

        // Step 2) Upload the Move modules
        let tempdir = diem_temppath::TempPath::new();
        tempdir.create_as_dir().unwrap();
        for b in diem_framework_releases::current_module_blobs() {
            let mut temppath =
                diem_temppath::TempPath::new_with_temp_dir(tempdir.path().to_path_buf());
            temppath.create_as_file().unwrap();
            temppath.persist(); // otherwise, file will disappear before we call set_move_modules
            let mut file = File::create(temppath.path()).unwrap();
            file.write_all(b).unwrap();
            file.sync_all().unwrap();
        }
        helper
            .set_move_modules(tempdir.path().to_str().unwrap())
            .unwrap();

        // Step 3) Upload the root keys:
        helper.initialize_by_idx(dave_ns.into(), storage_idx);
        helper
            .diem_root_key(dave_ns, &(dave_ns.to_string() + shared))
            .unwrap();
        helper
            .treasury_compliance_key(dave_ns, &(dave_ns.to_string() + shared))
            .unwrap();

        // Step 4) Upload each owner key (except carol, she'll have auth_key [0; 32]):
        for ns in [alice_ns, bob_ns, carol_ns].iter() {
            let ns = (*ns).to_string();
            let ns_shared = (*ns).to_string() + shared;

            storage_idx += 1;
            helper.initialize_by_idx(ns.clone(), storage_idx);
            if ns != carol_ns {
                helper.owner_key(&ns, &ns_shared).unwrap();
            }
        }

        // Step 5) Upload each operator key:
        for ns in [operator_alice_ns, operator_bob_ns, operator_carol_ns].iter() {
            let ns = (*ns).to_string();
            let ns_shared = (*ns).to_string() + shared;

            storage_idx += 1;
            helper.initialize_by_idx(ns.clone(), storage_idx);
            helper.operator_key(&ns, &ns_shared).unwrap();
        }

        // Step 6) Set the operator for each owner:
        for ns in [alice_ns, bob_ns, carol_ns].iter() {
            let ns_shared = (*ns).to_string() + shared;

            let operator_name = format!("operator_{}", ns_shared);
            helper.set_operator(&operator_name, &ns_shared).unwrap();
        }

        // Step 7) Upload a signed validator config transaction for each operator:
        for ns in [operator_alice_ns, operator_bob_ns, operator_carol_ns].iter() {
            let ns = (*ns).to_string();
            let ns_shared = (*ns).to_string() + shared;

            let owner_name: String = (*ns).chars().skip(9).collect(); // Remove "operator_" prefix
            let owner_name = owner_name + shared;
            helper
                .validator_config(
                    &owner_name,
                    "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
                    "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
                    ChainId::test(),
                    &ns,
                    &ns_shared,
                )
                .unwrap();
        }

        // Step 8) Produce genesis
        let genesis_path = diem_temppath::TempPath::new();
        genesis_path.create_as_file().unwrap();
        helper
            .genesis(ChainId::test(), genesis_path.path())
            .unwrap();
        let mut file = File::open(genesis_path.path()).unwrap();
        let mut contents = Vec::new();
        assert!(contents.is_empty());
        file.read_to_end(&mut contents).unwrap();
        assert!(!contents.is_empty());

        // Step 9) Verify
        for ns in [operator_alice_ns, operator_bob_ns, operator_carol_ns].iter() {
            let waypoint = helper.create_waypoint(ChainId::test()).unwrap();
            helper.insert_waypoint(ns, waypoint).unwrap();
            helper.verify_genesis(ns, genesis_path.path()).unwrap();
        }
    }

    #[test]
    fn test_set_layout() {
        let helper = StorageHelper::new();

        let temppath = diem_temppath::TempPath::new();
        helper
            .set_layout(temppath.path().to_str().unwrap())
            .unwrap_err();

        temppath.create_as_file().unwrap();
        let mut file = File::create(temppath.path()).unwrap();
        let layout_text = "\
            operators = [\"alice\", \"bob\"]\n\
            owners = [\"carol\"]\n\
            diem_root = \"dave\"\n\
            treasury_compliance = \"other_dave\"\n\
        ";
        file.write_all(&layout_text.to_string().into_bytes())
            .unwrap();
        file.sync_all().unwrap();

        helper
            .set_layout(temppath.path().to_str().unwrap())
            .unwrap();
        let storage = helper.storage(constants::COMMON_NS.into());
        let stored_layout = storage.get::<String>(constants::LAYOUT).unwrap().value;
        assert_eq!(layout_text, stored_layout);
    }

    #[test]
    fn test_validator_config() {
        use diem_types::account_address::AccountAddress;

        let storage_helper = StorageHelper::new();
        let local_operator_ns = "local";
        let remote_operator_ns = "operator";
        storage_helper.initialize_by_idx(local_operator_ns.into(), 0);

        // Operator uploads key to shared storage and initializes address in local storage
        let operator_key = storage_helper
            .operator_key(local_operator_ns, remote_operator_ns)
            .unwrap();

        // Upload an owner key to the remote storage
        let owner_name = "owner";
        let owner_key = Ed25519PrivateKey::generate_for_testing().public_key();
        let owner_account =
            diem_config::utils::validator_owner_account_from_name(owner_name.as_bytes());
        let mut shared_storage = storage_helper.storage(owner_name.into());
        shared_storage
            .set(OWNER_KEY, owner_key)
            .map_err(|e| Error::StorageWriteError("shared", OWNER_KEY, e.to_string()))
            .unwrap();

        // Operator calls the validator-config command
        let local_config_tx = storage_helper
            .validator_config(
                owner_name,
                "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
                "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
                ChainId::test(),
                local_operator_ns,
                remote_operator_ns,
            )
            .unwrap();

        // Verify that a validator config transaction was uploaded to the remote storage
        let shared_storage = storage_helper.storage(remote_operator_ns.into());
        let uploaded_config_tx = shared_storage
            .get::<Transaction>(constants::VALIDATOR_CONFIG)
            .unwrap()
            .value;
        assert_eq!(local_config_tx, uploaded_config_tx);

        // Verify the transaction sender is the operator account address
        let operator_account = account_address::from_public_key(&operator_key);
        let uploaded_user_transaction = uploaded_config_tx.as_signed_user_txn().unwrap();
        assert_eq!(operator_account, uploaded_user_transaction.sender());

        // Verify the validator config in the transaction has the correct account address
        match uploaded_user_transaction.payload() {
            TransactionPayload::ScriptFunction(script_function) => {
                assert_eq!(4, script_function.args().len());

                match bcs::from_bytes::<AccountAddress>(script_function.args().get(0).unwrap()) {
                    Ok(account_address) => {
                        assert_eq!(owner_account, account_address);
                    }
                    _ => panic!(
                        "Found an invalid argument type for the validator-config transaction script function!"
                    ),
                };
            }
            _ => panic!("Invalid validator-config transaction payload found!"),
        };
    }

    #[test]
    fn test_set_operator() {
        let storage_helper = StorageHelper::new();
        let local_owner_ns = "local";
        let remote_owner_ns = "owner";
        storage_helper.initialize_by_idx(local_owner_ns.into(), 0);

        // Upload an operator key to the remote storage
        let operator_name = "operator";
        let operator_key = Ed25519PrivateKey::generate_for_testing().public_key();
        let mut shared_storage = storage_helper.storage(operator_name.into());
        shared_storage
            .set(OPERATOR_KEY, operator_key)
            .map_err(|e| Error::StorageWriteError("shared", OPERATOR_KEY, e.to_string()))
            .unwrap();

        // Owner calls the set-operator command
        let local_operator_name = storage_helper
            .set_operator(operator_name, remote_owner_ns)
            .unwrap();

        // Verify that a file setting the operator was uploaded to the remote storage
        let shared_storage = storage_helper.storage(remote_owner_ns.into());
        let uploaded_operator_name = shared_storage
            .get::<String>(constants::VALIDATOR_OPERATOR)
            .unwrap()
            .value;
        assert_eq!(local_operator_name, uploaded_operator_name);
    }

    #[test]
    fn test_verify() {
        let helper = StorageHelper::new();
        let namespace = "verify";

        let output = helper
            .verify(namespace)
            .unwrap()
            .split("Key not set")
            .count();
        // 9 KeyNotSet results in 10 splits
        assert_eq!(output, 10);

        helper.initialize_by_idx(namespace.into(), 0);

        let output = helper
            .verify(namespace)
            .unwrap()
            .split("Key not set")
            .count();
        // 2 KeyNotSet results in 3 split (the accounts aren't initialized via initialize)
        assert_eq!(output, 3);
    }
}
