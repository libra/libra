// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    aws,
    cluster::Cluster,
    cluster_swarm::{
        cluster_swarm_kube::{ClusterSwarmKube, KubeNode},
        ClusterSwarm,
    },
    genesis_helper::GenesisHelper,
    instance::{
        fullnode_pod_name, lsr_pod_name, validator_pod_name, vault_pod_name,
        ApplicationConfig::{Fullnode, Validator, Vault, LSR},
        FullnodeConfig, Instance, InstanceConfig, LSRConfig, ValidatorConfig, ValidatorGroup,
        VaultConfig,
    },
};
use anyhow::{format_err, Result};
use diem_logger::info;
use futures::future::try_join_all;
use std::{fs::File, io::Write, path::Path};
use structopt::StructOpt;

use consensus_types::safety_data::SafetyData;
use diem_genesis_tool::layout::Layout;
use diem_global_constants::{
    CONSENSUS_KEY, DIEM_ROOT_KEY, EXECUTION_KEY, FULLNODE_NETWORK_KEY, GENESIS_WAYPOINT,
    OPERATOR_KEY, OWNER_KEY, SAFETY_DATA, TREASURY_COMPLIANCE_KEY, VALIDATOR_NETWORK_ADDRESS_KEYS,
    VALIDATOR_NETWORK_KEY, WAYPOINT,
};
use diem_secure_storage::{CryptoStorage, KVStorage, Namespaced, Storage, VaultStorage};
use diem_types::{chain_id::ChainId, network_address::NetworkAddress, waypoint::Waypoint};
use std::str::FromStr;

const VAULT_TOKEN: &str = "root";
const VAULT_PORT: u32 = 8200;
const DIEM_ROOT_NS: &str = "val-0";
const VAULT_BACKEND: &str = "vault";
const GENESIS_PATH: &str = "/tmp/genesis.blob";

#[derive(Clone, StructOpt, Debug)]
pub struct ClusterBuilderParams {
    #[structopt(long, default_value = "1")]
    pub fullnodes_per_validator: u32,
    #[structopt(long, parse(try_from_str), default_value = "30")]
    pub num_validators: u32,
    #[structopt(long)]
    pub enable_lsr: Option<bool>,
    #[structopt(
        long,
        help = "Backend used by lsr. Possible Values are in-memory, on-disk, vault",
        default_value = "vault"
    )]
    pub lsr_backend: String,
    #[structopt(
        long,
        help = "Directory containing Move module bytecodes to be published in genesis"
    )]
    pub move_modules_dir: Option<String>,
}

impl ClusterBuilderParams {
    pub fn enable_lsr(&self) -> bool {
        self.enable_lsr.unwrap_or(true)
    }
}

pub struct ClusterBuilder {
    pub current_tag: String,
    pub cluster_swarm: ClusterSwarmKube,
}

impl ClusterBuilder {
    pub fn new(current_tag: String, cluster_swarm: ClusterSwarmKube) -> Self {
        Self {
            current_tag,
            cluster_swarm,
        }
    }

    pub async fn setup_cluster(
        &self,
        params: &ClusterBuilderParams,
        clean_data: bool,
    ) -> Result<Cluster> {
        self.cluster_swarm
            .cleanup()
            .await
            .map_err(|e| format_err!("cleanup on startup failed: {}", e))?;
        let current_tag = &self.current_tag;
        info!(
            "Deploying with {} tag for validators and fullnodes",
            current_tag
        );
        let asg_name = format!(
            "{}-k8s-testnet-validators",
            self.cluster_swarm
                .get_workspace()
                .await
                .expect("Failed to get workspace")
        );
        let mut instance_count =
            params.num_validators + (params.fullnodes_per_validator * params.num_validators);
        if params.enable_lsr() {
            if params.lsr_backend == "vault" {
                instance_count += params.num_validators * 2;
            } else {
                instance_count += params.num_validators;
            }
        }
        if clean_data {
            // First scale down to zero instances and wait for it to complete so that we don't schedule pods on
            // instances which are going into termination state
            aws::set_asg_size(0, 0.0, &asg_name, true, true)
                .await
                .map_err(|err| format_err!("{} scale down failed: {}", asg_name, err))?;
            // Then scale up and bring up new instances
            aws::set_asg_size(instance_count as i64, 5.0, &asg_name, true, false)
                .await
                .map_err(|err| format_err!("{} scale up failed: {}", asg_name, err))?;
        }
        let modules_dir = if let Some(modules_dir) = &params.move_modules_dir {
            modules_dir.clone()
        } else {
            // No modules specified on command line. Create a tmpdir and populate it with the Diem genesis modules
            let mut tempdir = diem_temppath::TempPath::new();
            tempdir.create_as_dir()?;
            tempdir.persist();
            for b in diem_framework_releases::current_module_blobs() {
                let mut temppath =
                    diem_temppath::TempPath::new_with_temp_dir(tempdir.path().to_path_buf());
                temppath.create_as_file()?;
                temppath.persist(); // otherwise, file will disappear when temppath goes out of scope
                let mut file = File::create(temppath.path())?;
                file.write_all(b)?;
                file.sync_all()?;
            }
            tempdir.path().to_str().unwrap().to_string()
        };

        let (validators, lsrs, vaults, fullnodes, waypoint) = self
            .spawn_validator_and_fullnode_set(
                params.num_validators,
                params.fullnodes_per_validator,
                params.enable_lsr(),
                &params.lsr_backend,
                current_tag,
                &modules_dir,
                clean_data,
            )
            .await
            .map_err(|e| format_err!("Failed to spawn_validator_and_fullnode_set: {}", e))?;
        let cluster = Cluster::new(validators, fullnodes, lsrs, vaults, waypoint);

        info!(
            "Deployed {} validators and {} fns",
            cluster.validator_instances().len(),
            cluster.fullnode_instances().len(),
        );
        Ok(cluster)
    }

    /// Creates a set of validators and fullnodes with the given parameters
    pub async fn spawn_validator_and_fullnode_set(
        &self,
        num_validators: u32,
        num_fullnodes_per_validator: u32,
        enable_lsr: bool,
        lsr_backend: &str,
        image_tag: &str,
        move_modules_dir: &str,
        clean_data: bool,
    ) -> Result<(
        Vec<Instance>,
        Vec<Instance>,
        Vec<Instance>,
        Vec<Instance>,
        Option<Waypoint>,
    )> {
        let vault_nodes;
        let mut lsr_nodes = vec![];
        let mut vaults = vec![];
        let mut lsrs = vec![];
        let mut waypoint = None;

        if enable_lsr {
            if lsr_backend == "vault" {
                vault_nodes = try_join_all((0..num_validators).map(|i| async move {
                    let pod_name = vault_pod_name(i);
                    self.cluster_swarm.allocate_node(&pod_name).await
                }))
                .await?;
                let mut vault_instances: Vec<_> = vault_nodes
                    .iter()
                    .enumerate()
                    .map(|(i, node)| async move {
                        let vault_config = VaultConfig {};
                        if clean_data {
                            self.cluster_swarm.clean_data(&node.name).await?;
                        }
                        self.cluster_swarm
                            .spawn_new_instance(InstanceConfig {
                                validator_group: ValidatorGroup::new_for_index(i as u32),
                                application_config: Vault(vault_config),
                            })
                            .await
                    })
                    .collect();
                vaults.append(&mut vault_instances);
            } else {
                vault_nodes = vec![];
            }
            lsr_nodes = try_join_all((0..num_validators).map(|i| async move {
                let pod_name = lsr_pod_name(i);
                self.cluster_swarm.allocate_node(&pod_name).await
            }))
            .await?;
            let mut lsr_instances: Vec<_> = lsr_nodes
                .iter()
                .enumerate()
                .map(|(i, node)| {
                    let vault_nodes = &vault_nodes;
                    async move {
                        let vault_addr = if enable_lsr && lsr_backend == "vault" {
                            Some(vault_nodes[i].internal_ip.clone())
                        } else {
                            None
                        };
                        let vault_namespace = if enable_lsr && lsr_backend == "vault" {
                            Some(validator_pod_name(i as u32))
                        } else {
                            None
                        };
                        let lsr_config = LSRConfig {
                            image_tag: image_tag.to_string(),
                            lsr_backend: lsr_backend.to_string(),
                            vault_addr,
                            vault_namespace,
                        };
                        if clean_data {
                            self.cluster_swarm.clean_data(&node.name).await?;
                        }
                        self.cluster_swarm
                            .spawn_new_instance(InstanceConfig {
                                validator_group: ValidatorGroup::new_for_index(i as u32),
                                application_config: LSR(lsr_config),
                            })
                            .await
                    }
                })
                .collect();
            lsrs.append(&mut lsr_instances);
        } else {
            vault_nodes = vec![];
        }

        let lsrs = try_join_all(lsrs).await?;
        let vaults = try_join_all(vaults).await?;

        let validator_nodes = try_join_all((0..num_validators).map(|i| async move {
            let pod_name = validator_pod_name(i);
            self.cluster_swarm.allocate_node(&pod_name).await
        }))
        .await?;

        let fullnode_nodes = try_join_all((0..num_validators).flat_map(move |validator_index| {
            (0..num_fullnodes_per_validator).map(move |fullnode_index| async move {
                let pod_name = fullnode_pod_name(validator_index, fullnode_index);
                self.cluster_swarm.allocate_node(&pod_name).await
            })
        }))
        .await?;

        if !vault_nodes.is_empty() {
            info!("Generating genesis with management tool.");
            try_join_all(vault_nodes.iter().enumerate().map(|(i, node)| async move {
                diem_retrier::retry_async(diem_retrier::fixed_retry_strategy(5000, 15), || {
                    Box::pin(async move { self.initialize_vault(i as u32, node).await })
                })
                .await
            }))
            .await?;

            waypoint = Some(
                self.generate_genesis(
                    num_validators,
                    &vault_nodes,
                    &validator_nodes,
                    &fullnode_nodes,
                    move_modules_dir,
                )
                .await?,
            );
            info!("Done generating genesis.");
        }

        let validators = (0..num_validators).map(|i| {
            let validator_nodes = &validator_nodes;
            let lsr_nodes = &lsr_nodes;
            let vault_nodes = &vault_nodes;
            async move {
                let vault_addr = if enable_lsr && lsr_backend == "vault" {
                    Some(vault_nodes[i as usize].internal_ip.clone())
                } else {
                    None
                };
                let vault_namespace = if enable_lsr && lsr_backend == "vault" {
                    Some(validator_pod_name(i))
                } else {
                    None
                };
                let safety_rules_addr = if enable_lsr {
                    Some(lsr_nodes[i as usize].internal_ip.clone())
                } else {
                    None
                };
                let validator_config = ValidatorConfig {
                    enable_lsr,
                    image_tag: image_tag.to_string(),
                    safety_rules_addr,
                    vault_addr,
                    vault_namespace,
                };
                if clean_data {
                    self.cluster_swarm
                        .clean_data(&validator_nodes[i as usize].name)
                        .await?;
                }
                self.cluster_swarm
                    .spawn_new_instance(InstanceConfig {
                        validator_group: ValidatorGroup::new_for_index(i),
                        application_config: Validator(validator_config),
                    })
                    .await
            }
        });

        let fullnodes = (0..num_validators).flat_map(|validator_index| {
            let fullnode_nodes = &fullnode_nodes;
            let validator_nodes = &validator_nodes;
            let vault_nodes = &vault_nodes;
            (0..num_fullnodes_per_validator).map(move |fullnode_index| async move {
                let vault_addr = if enable_lsr && lsr_backend == "vault" {
                    Some(vault_nodes[validator_index as usize].internal_ip.clone())
                } else {
                    None
                };
                let vault_namespace = if enable_lsr && lsr_backend == "vault" {
                    Some(validator_pod_name(validator_index))
                } else {
                    None
                };
                let seed_peer_ip = validator_nodes[validator_index as usize]
                    .internal_ip
                    .clone();
                let fullnode_config = FullnodeConfig {
                    fullnode_index,
                    image_tag: image_tag.to_string(),
                    seed_peer_ip,
                    vault_addr,
                    vault_namespace,
                };
                if clean_data {
                    self.cluster_swarm
                        .clean_data(
                            &fullnode_nodes[(validator_index * num_fullnodes_per_validator
                                + fullnode_index)
                                as usize]
                                .name,
                        )
                        .await?;
                }
                self.cluster_swarm
                    .spawn_new_instance(InstanceConfig {
                        validator_group: ValidatorGroup::new_for_index(validator_index),
                        application_config: Fullnode(fullnode_config),
                    })
                    .await
            })
        });

        let validators = try_join_all(validators).await?;
        let fullnodes = try_join_all(fullnodes).await?;
        Ok((validators, lsrs, vaults, fullnodes, waypoint))
    }

    async fn initialize_vault(&self, validator_index: u32, vault_node: &KubeNode) -> Result<()> {
        let addr = vault_node.internal_ip.clone();
        tokio::task::spawn_blocking(move || {
            let pod_name = validator_pod_name(validator_index);
            let mut vault_storage = Storage::from(Namespaced::new(
                &pod_name,
                Box::new(Storage::from(VaultStorage::new(
                    format!("http://{}:{}", addr, VAULT_PORT),
                    VAULT_TOKEN.to_string(),
                    None,
                    None,
                    true,
                    None,
                    None,
                ))),
            ));
            if validator_index == 0 {
                vault_storage.create_key(DIEM_ROOT_KEY).map_err(|e| {
                    format_err!("Failed to create {}__{} : {}", pod_name, DIEM_ROOT_KEY, e)
                })?;
                let key = vault_storage
                    .export_private_key(DIEM_ROOT_KEY)
                    .map_err(|e| {
                        format_err!("Failed to export {}__{} : {}", pod_name, DIEM_ROOT_KEY, e)
                    })?;
                vault_storage
                    .import_private_key(TREASURY_COMPLIANCE_KEY, key)
                    .map_err(|e| {
                        format_err!(
                            "Failed to import {}__{} : {}",
                            pod_name,
                            TREASURY_COMPLIANCE_KEY,
                            e
                        )
                    })?;
            }
            let keys = vec![
                OWNER_KEY,
                OPERATOR_KEY,
                CONSENSUS_KEY,
                EXECUTION_KEY,
                VALIDATOR_NETWORK_KEY,
                FULLNODE_NETWORK_KEY,
            ];
            for key in keys {
                vault_storage
                    .create_key(key)
                    .map_err(|e| format_err!("Failed to create {}__{} : {}", pod_name, key, e))?;
            }
            vault_storage
                .set(SAFETY_DATA, SafetyData::new(0, 0, 0, 0, None))
                .map_err(|e| format_err!("Failed to create {}/{}: {}", pod_name, SAFETY_DATA, e))?;
            vault_storage
                .set(WAYPOINT, Waypoint::default())
                .map_err(|e| format_err!("Failed to create {}/{} : {}", pod_name, WAYPOINT, e))?;
            vault_storage
                .set(GENESIS_WAYPOINT, Waypoint::default())
                .map_err(|e| format_err!("Failed to create {}/{} : {}", pod_name, WAYPOINT, e))?;
            diem_network_address_encryption::Encryptor::new(vault_storage)
                .initialize_for_testing()
                .map_err(|e| {
                    format_err!(
                        "Failed to create {}/{} : {}",
                        pod_name,
                        VALIDATOR_NETWORK_ADDRESS_KEYS,
                        e
                    )
                })?;
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        Ok(())
    }

    async fn generate_genesis(
        &self,
        num_validators: u32,
        vault_nodes: &[KubeNode],
        validator_nodes: &[KubeNode],
        fullnode_nodes: &[KubeNode],
        move_modules_dir: &str,
    ) -> Result<Waypoint> {
        let genesis_helper = GenesisHelper::new("/tmp/genesis.json");
        let owners: Vec<_> = (0..num_validators).map(validator_pod_name).collect();
        let layout = Layout {
            owners: owners.clone(),
            operators: owners,
            diem_root: DIEM_ROOT_NS.to_string(),
            treasury_compliance: DIEM_ROOT_NS.to_string(),
        };
        let layout_path = "/tmp/layout.yaml";
        write!(
            File::create(layout_path).map_err(|e| format_err!(
                "Failed to create {} : {}",
                layout_path,
                e
            ))?,
            "{}",
            toml::to_string(&layout)?
        )
        .map_err(|e| format_err!("Failed to write {} : {}", layout_path, e))?;
        let token_path = "/tmp/token";
        write!(
            File::create(token_path).map_err(|e| format_err!(
                "Failed to create {} : {}",
                token_path,
                e
            ))?,
            "{}",
            VAULT_TOKEN
        )
        .map_err(|e| format_err!("Failed to write {} : {}", token_path, e))?;
        genesis_helper
            .set_layout(layout_path, "common")
            .await
            .map_err(|e| format_err!("Failed to set_layout : {}", e))?;
        genesis_helper
            .set_move_modules(move_modules_dir, "common")
            .await
            .map_err(|e| format_err!("Failed to set_move_modules : {}", e))?;
        genesis_helper
            .diem_root_key(
                VAULT_BACKEND,
                format!("http://{}:{}", vault_nodes[0].internal_ip, VAULT_PORT).as_str(),
                token_path,
                DIEM_ROOT_NS,
                DIEM_ROOT_NS,
            )
            .await
            .map_err(|e| format_err!("Failed to diem_root_key : {}", e))?;
        genesis_helper
            .treasury_compliance_key(
                VAULT_BACKEND,
                format!("http://{}:{}", vault_nodes[0].internal_ip, VAULT_PORT).as_str(),
                token_path,
                DIEM_ROOT_NS,
                DIEM_ROOT_NS,
            )
            .await
            .map_err(|e| format_err!("Failed to diem_root_key : {}", e))?;

        for (i, node) in vault_nodes.iter().enumerate() {
            let pod_name = validator_pod_name(i as u32);
            genesis_helper
                .owner_key(
                    VAULT_BACKEND,
                    format!("http://{}:{}", node.internal_ip, VAULT_PORT).as_str(),
                    token_path,
                    &pod_name,
                    &pod_name,
                )
                .await
                .map_err(|e| format_err!("Failed to owner_key for {} : {}", pod_name, e))?;
            genesis_helper
                .operator_key(
                    VAULT_BACKEND,
                    format!("http://{}:{}", node.internal_ip, VAULT_PORT).as_str(),
                    token_path,
                    &pod_name,
                    &pod_name,
                )
                .await
                .map_err(|e| format_err!("Failed to operator_key for {} : {}", pod_name, e))?;
            let fullnode_ip = if fullnode_nodes.is_empty() {
                "0.0.0.0"
            } else {
                &fullnode_nodes[i].internal_ip
            };
            genesis_helper
                .validator_config(
                    &pod_name,
                    NetworkAddress::from_str(
                        format!("/ip4/{}/tcp/{}", validator_nodes[i].internal_ip, 6180).as_str(),
                    )
                    .expect("Failed to parse network address"),
                    NetworkAddress::from_str(format!("/ip4/{}/tcp/{}", fullnode_ip, 6182).as_str())
                        .expect("Failed to parse network address"),
                    ChainId::test(),
                    VAULT_BACKEND,
                    format!("http://{}:{}", node.internal_ip, VAULT_PORT).as_str(),
                    token_path,
                    &pod_name,
                    &pod_name,
                )
                .await
                .map_err(|e| format_err!("Failed to validator_config for {} : {}", pod_name, e))?;
            genesis_helper
                .set_operator(&pod_name, &pod_name)
                .await
                .map_err(|e| format_err!("Failed to set_operator for {} : {}", pod_name, e))?;
        }
        genesis_helper
            .genesis(ChainId::test(), Path::new(GENESIS_PATH))
            .await?;
        let waypoint = genesis_helper
            .create_waypoint(ChainId::test())
            .await
            .map_err(|e| format_err!("Failed to create_waypoint : {}", e))?;
        for (i, node) in vault_nodes.iter().enumerate() {
            let pod_name = validator_pod_name(i as u32);
            genesis_helper
                .create_and_insert_waypoint(
                    ChainId::test(),
                    VAULT_BACKEND,
                    format!("http://{}:{}", node.internal_ip, VAULT_PORT).as_str(),
                    token_path,
                    &pod_name,
                )
                .await
                .map_err(|e| {
                    format_err!(
                        "Failed to create_and_insert_waypoint for {} : {}",
                        pod_name,
                        e
                    )
                })?;
        }
        genesis_helper
            .extract_private_key(
                format!("{}__{}", DIEM_ROOT_NS, DIEM_ROOT_KEY).as_str(),
                "/tmp/mint.key",
                VAULT_BACKEND,
                format!("http://{}:{}", vault_nodes[0].internal_ip, VAULT_PORT).as_str(),
                token_path,
            )
            .await
            .map_err(|e| format_err!("Failed to extract_private_key : {}", e))?;
        Ok(waypoint)
    }
}
