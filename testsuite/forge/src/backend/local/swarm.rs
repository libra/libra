// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{ChainInfo, FullNode, HealthCheckError, LocalNode, Node, NodeExt, Swarm, Validator};
use anyhow::{anyhow, Result};
use diem_config::config::NodeConfig;
use diem_genesis_tool::validator_builder::ValidatorBuilder;
use diem_sdk::{
    crypto::ed25519::Ed25519PrivateKey,
    types::{chain_id::ChainId, AccountKey, LocalAccount, PeerId},
};
use itertools::Itertools;
use std::{
    collections::HashMap,
    convert::TryFrom,
    fs, mem, ops,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

#[derive(Debug)]
pub enum SwarmDirectory {
    Persistent(PathBuf),
    Temporary(TempDir),
}

impl SwarmDirectory {
    #[allow(dead_code)]
    pub fn persist(&mut self) {
        match self {
            SwarmDirectory::Persistent(_) => {}
            SwarmDirectory::Temporary(_) => {
                let mut temp = SwarmDirectory::Persistent(PathBuf::new());
                mem::swap(self, &mut temp);
                let _ = mem::replace(self, temp.into_persistent());
            }
        }
    }

    #[allow(dead_code)]
    pub fn into_persistent(self) -> Self {
        match self {
            SwarmDirectory::Temporary(tempdir) => SwarmDirectory::Persistent(tempdir.into_path()),
            SwarmDirectory::Persistent(dir) => SwarmDirectory::Persistent(dir),
        }
    }
}

impl ops::Deref for SwarmDirectory {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        match self {
            SwarmDirectory::Persistent(dir) => dir.deref(),
            SwarmDirectory::Temporary(dir) => dir.path(),
        }
    }
}

impl AsRef<Path> for SwarmDirectory {
    fn as_ref(&self) -> &Path {
        match self {
            SwarmDirectory::Persistent(dir) => dir.as_ref(),
            SwarmDirectory::Temporary(dir) => dir.as_ref(),
        }
    }
}

#[derive(Debug)]
struct ValidatorNetworkAddressEncryptionKey {
    key: diem_sdk::types::network_address::encrypted::Key,
    version: diem_sdk::types::network_address::encrypted::KeyVersion,
}

pub struct LocalSwarmBuilder {
    diem_node_bin_path: PathBuf,
    template: NodeConfig,
    number_of_validators: usize,
    dir: Option<PathBuf>,
}

impl LocalSwarmBuilder {
    pub fn new<T: AsRef<Path>>(diem_node_bin_path: T) -> Self {
        Self {
            diem_node_bin_path: diem_node_bin_path.as_ref().into(),
            template: NodeConfig::default_for_validator(),
            number_of_validators: 1,
            dir: None,
        }
    }

    pub fn template(mut self, template: NodeConfig) -> Self {
        self.template = template;
        self
    }

    pub fn number_of_validators(mut self, number_of_validators: usize) -> Self {
        self.number_of_validators = number_of_validators;
        self
    }

    pub fn dir<T: AsRef<Path>>(mut self, dir: T) -> Self {
        self.dir = Some(dir.as_ref().into());
        self
    }

    pub fn build(self) -> Result<LocalSwarm> {
        let dir = if let Some(dir) = self.dir {
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
            fs::create_dir_all(&dir)?;
            SwarmDirectory::Persistent(dir)
        } else {
            SwarmDirectory::Temporary(TempDir::new()?)
        };

        let (root_keys, validators) = ValidatorBuilder::new(
            &dir,
            diem_framework_releases::current_module_blobs().to_vec(),
        )
        .num_validators(self.number_of_validators)
        .template(self.template)
        .build()?;
        let diem_node_bin_path = self.diem_node_bin_path;

        let validators = validators
            .into_iter()
            .map(|v| {
                let node = LocalNode::new(&diem_node_bin_path, v.name, v.directory)?;
                Ok((node.peer_id(), node))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let validator_network_address_encryption_key = ValidatorNetworkAddressEncryptionKey {
            key: root_keys.validator_network_address_encryption_key,
            version: root_keys.validator_network_address_encryption_key_version,
        };

        let root_account = LocalAccount::new(
            diem_sdk::types::account_config::diem_root_address(),
            AccountKey::from_private_key(root_keys.root_key),
            1,
        );

        // Designated dealer account is built to have the same private key as the TC account
        let designated_dealer_account = LocalAccount::new(
            diem_sdk::types::account_config::testnet_dd_account_address(),
            AccountKey::from_private_key(
                Ed25519PrivateKey::try_from(root_keys.treasury_compliance_key.to_bytes().as_ref())
                    .unwrap(),
            ),
            0,
        );

        let treasury_compliance_account = LocalAccount::new(
            diem_sdk::types::account_config::treasury_compliance_account_address(),
            AccountKey::from_private_key(root_keys.treasury_compliance_key),
            0,
        );

        Ok(LocalSwarm {
            validators,
            dir,
            validator_network_address_encryption_key,
            root_account,
            treasury_compliance_account,
            designated_dealer_account,
            chain_id: ChainId::test(),
        })
    }
}

#[derive(Debug)]
pub struct LocalSwarm {
    validators: HashMap<PeerId, LocalNode>,
    dir: SwarmDirectory,
    validator_network_address_encryption_key: ValidatorNetworkAddressEncryptionKey,
    root_account: LocalAccount,
    treasury_compliance_account: LocalAccount,
    designated_dealer_account: LocalAccount,
    chain_id: ChainId,
}

impl LocalSwarm {
    pub fn builder<T: AsRef<Path>>(diem_node_bin_path: T) -> LocalSwarmBuilder {
        LocalSwarmBuilder::new(diem_node_bin_path)
    }

    pub fn launch(&mut self) -> Result<()> {
        // Start all the validators
        for validator in self.validators.values_mut() {
            validator.start()?;
        }

        // Wait for all of them to startup
        self.wait_for_startup()?;
        self.wait_for_connectivity()?;
        self.liveness_check()?;

        Ok(())
    }

    fn wait_for_startup(&mut self) -> Result<()> {
        let num_attempts = 10;
        let mut done = vec![false; self.validators.len()];
        for i in 0..num_attempts {
            println!("Wait for startup attempt: {} of {}", i, num_attempts);
            for (node, done) in self.validators.values_mut().zip(done.iter_mut()) {
                if *done {
                    continue;
                }
                match node.health_check() {
                    Ok(()) => *done = true,

                    Err(HealthCheckError::Unknown(e)) => {
                        return Err(anyhow!("Diem node '{}' is not running: {}", node.name(), e));
                    }
                    Err(HealthCheckError::NotRunning) => {
                        return Err(anyhow!("Diem node '{}' is not running", node.name()));
                    }
                    Err(HealthCheckError::RpcFailure(e)) => {
                        println!("rpc error: {}", e);
                        continue;
                    }
                }
            }

            // Check if all the nodes have been successfully launched
            if done.iter().all(|status| *status) {
                return Ok(());
            }

            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }

        Err(anyhow!("Launching Swarm timed out"))
    }

    fn wait_for_connectivity(&self) -> Result<()> {
        let expected_peers = self.validators.len().saturating_sub(1);

        let num_attempts = 60;
        for i in 0..num_attempts {
            println!("Wait for connectivity attempt: {}", i);

            if self
                .validators
                .values()
                .map(|node| Validator::check_connectivity(node, expected_peers))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .all(|b| b)
            {
                return Ok(());
            }

            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }

        Err(anyhow!("Waiting for connectivity timed out"))
    }

    fn liveness_check(&self) -> Result<()> {
        let num_attempts = 60;
        for i in 0..num_attempts {
            println!("Wait for liveness check attempt: {}", i);

            if self
                .validators
                .values()
                .map(|node| node.liveness_check(10))
                .collect_vec()
                .into_iter()
                .all(|b| matches!(b, Ok(..)))
            {
                return Ok(());
            }

            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }

        Err(anyhow!("Liveness check timed out"))
    }
}

impl Swarm for LocalSwarm {
    fn health_check(&mut self) -> Result<()> {
        todo!()
    }

    fn validators<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a dyn Validator> + 'a> {
        Box::new(self.validators.values().map(|v| v as &'a dyn Validator))
    }

    fn validators_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut dyn Validator> + 'a> {
        Box::new(
            self.validators
                .values_mut()
                .map(|v| v as &'a mut dyn Validator),
        )
    }

    fn validator(&self, id: PeerId) -> Option<&dyn Validator> {
        self.validators.get(&id).map(|v| v as &dyn Validator)
    }

    fn validator_mut(&mut self, id: PeerId) -> Option<&mut dyn Validator> {
        self.validators
            .get_mut(&id)
            .map(|v| v as &mut dyn Validator)
    }

    fn full_nodes<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a dyn FullNode> + 'a> {
        todo!()
    }

    fn full_nodes_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut dyn FullNode> + 'a> {
        todo!()
    }

    fn full_node(&self, _id: PeerId) -> Option<&dyn FullNode> {
        todo!()
    }

    fn full_node_mut(&mut self, _id: PeerId) -> Option<&mut dyn FullNode> {
        todo!()
    }

    fn add_validator(&mut self, _id: PeerId) -> Result<PeerId> {
        todo!()
    }

    fn remove_validator(&mut self, _id: PeerId) -> Result<()> {
        todo!()
    }

    fn add_full_node(&mut self, _id: PeerId) -> Result<()> {
        todo!()
    }

    fn remove_full_node(&mut self, _id: PeerId) -> Result<()> {
        todo!()
    }

    fn chain_info(&mut self) -> ChainInfo<'_> {
        ChainInfo::new(
            &mut self.root_account,
            &mut self.treasury_compliance_account,
            &mut self.designated_dealer_account,
            self.validators
                .values()
                .map(|v| v.json_rpc_endpoint().to_string())
                .next()
                .unwrap(),
            self.chain_id,
        )
    }
}
