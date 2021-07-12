// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{swarm_config::BuildSwarm, validator_builder::ValidatorBuilder};
use diem_config::{
    config::{NodeConfig, PeerRole},
    generator::build_seed_for_network,
    network_id::NetworkId,
};
use diem_crypto::ed25519::Ed25519PrivateKey;
use diem_secure_storage::{CryptoStorage, KVStorage, Storage};
use diem_temppath::TempPath;
use std::path::PathBuf;

#[derive(Debug, Copy, Clone)]
pub enum FullnodeType {
    ValidatorFullnode,
    PublicFullnode(usize),
}

pub struct FullnodeBuilder {
    validator_config_path: Vec<PathBuf>,
    diem_root_key_path: PathBuf,
    template: NodeConfig,
    build_type: FullnodeType,
}

impl FullnodeBuilder {
    pub fn new(
        validator_config_path: Vec<PathBuf>,
        diem_root_key_path: PathBuf,
        template: NodeConfig,
        build_type: FullnodeType,
    ) -> Self {
        Self {
            validator_config_path,
            diem_root_key_path,
            template,
            build_type,
        }
    }

    fn attach_validator_full_node(&self, validator_config: &mut NodeConfig) -> NodeConfig {
        // Create two vfns, we'll pass one to the validator later
        let mut full_node_config = self.template.clone();
        full_node_config.randomize_ports();

        // The FN's external, public network needs to swap listen addresses
        // with the validator's VFN and to copy it's key access:
        let pfn = &mut full_node_config
            .full_node_networks
            .iter_mut()
            .find(|n| n.network_id == NetworkId::Public)
            .expect("vfn missing external public network in config");
        let v_vfn = &mut validator_config.full_node_networks[0];
        pfn.identity = v_vfn.identity.clone();
        let temp_listen = v_vfn.listen_address.clone();
        v_vfn.listen_address = pfn.listen_address.clone();
        pfn.listen_address = temp_listen;

        // Now let's prepare the full nodes internal network to communicate with the validators
        // internal network
        let seeds = build_seed_for_network(v_vfn, PeerRole::Validator);

        let fn_vfn = &mut full_node_config
            .full_node_networks
            .iter_mut()
            .find(|n| n.network_id.is_vfn_network())
            .expect("vfn missing vfn full node network in config");
        fn_vfn.seeds = seeds;

        Self::insert_waypoint_and_genesis(&mut full_node_config, &validator_config);
        full_node_config
    }

    fn insert_waypoint_and_genesis(config: &mut NodeConfig, upstream: &NodeConfig) {
        config.base.waypoint = upstream.base.waypoint.clone();
        config.execution.genesis = upstream.execution.genesis.clone();
        config.execution.genesis_file_location = PathBuf::from("");
    }

    fn build_vfn(&self) -> anyhow::Result<Vec<NodeConfig>> {
        let mut configs = vec![];
        for path in &self.validator_config_path {
            let mut validator_config = NodeConfig::load(path)?;
            let fullnode_config = self.attach_validator_full_node(&mut validator_config);
            validator_config.save(path)?;
            configs.push(fullnode_config);
        }
        Ok(configs)
    }

    fn build_public_fn(&self, num_nodes: usize) -> anyhow::Result<Vec<NodeConfig>> {
        let mut configs = vec![];
        let validator_config = NodeConfig::load(
            self.validator_config_path
                .first()
                .ok_or_else(|| anyhow::format_err!("No validator config path"))?,
        )?;
        for _ in 0..num_nodes {
            let mut fullnode_config = self.template.clone();
            fullnode_config.randomize_ports();
            Self::insert_waypoint_and_genesis(&mut fullnode_config, &validator_config);
            configs.push(fullnode_config);
        }
        Ok(configs)
    }
}

impl BuildSwarm for FullnodeBuilder {
    fn build_swarm(&self) -> anyhow::Result<(Vec<NodeConfig>, Ed25519PrivateKey)> {
        let configs = match self.build_type {
            FullnodeType::ValidatorFullnode => self.build_vfn(),
            FullnodeType::PublicFullnode(num_nodes) => self.build_public_fn(num_nodes),
        }?;
        let diem_root_key_path = generate_key::load_key(&self.diem_root_key_path);
        Ok((configs, diem_root_key_path))
    }
}

pub fn test_config() -> (NodeConfig, Ed25519PrivateKey) {
    let path = TempPath::new();
    path.create_as_dir().unwrap();
    let builder = ValidatorBuilder::new(
        path.path(),
        diem_framework_releases::current_module_blobs().to_vec(),
    )
    .num_validators(1)
    .template(NodeConfig::default_for_validator());
    let (mut configs, key) = builder.build_swarm().unwrap();

    let mut config = configs.swap_remove(0);
    config.set_data_dir(path.path().to_path_buf());
    let backend = &config
        .validator_network
        .as_ref()
        .unwrap()
        .identity_from_storage()
        .backend;
    let storage: Storage = std::convert::TryFrom::try_from(backend).unwrap();
    let mut test = diem_config::config::TestConfig::new_with_temp_dir(Some(path));
    test.execution_key(
        storage
            .export_private_key(diem_global_constants::EXECUTION_KEY)
            .unwrap(),
    );
    test.operator_key(
        storage
            .export_private_key(diem_global_constants::OPERATOR_KEY)
            .unwrap(),
    );
    test.owner_key(
        storage
            .export_private_key(diem_global_constants::OWNER_KEY)
            .unwrap(),
    );
    config.test = Some(test);

    let owner_account = storage
        .get(diem_global_constants::OWNER_ACCOUNT)
        .unwrap()
        .value;
    let mut sr_test = diem_config::config::SafetyRulesTestConfig::new(owner_account);
    sr_test.consensus_key(
        storage
            .export_private_key(diem_global_constants::CONSENSUS_KEY)
            .unwrap(),
    );
    sr_test.execution_key(
        storage
            .export_private_key(diem_global_constants::EXECUTION_KEY)
            .unwrap(),
    );
    config.consensus.safety_rules.test = Some(sr_test);

    (config, key)
}
