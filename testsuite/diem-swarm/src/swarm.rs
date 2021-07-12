// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use debug_interface::NodeDebugClient;
use diem_config::{
    config::{NetworkConfig, NodeConfig},
    network_id::NetworkId,
};
use diem_genesis_tool::{
    config_builder::{FullnodeBuilder, FullnodeType},
    swarm_config::SwarmConfig,
    validator_builder::ValidatorBuilder,
};
use diem_logger::prelude::*;
use diem_temppath::TempPath;
use diem_types::{
    account_address::AccountAddress,
    network_address::{NetworkAddress, Protocol},
    PeerId,
};
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command},
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug)]
struct Process(Child);

impl Drop for Process {
    // When the Process struct goes out of scope we need to kill the child process
    fn drop(&mut self) {
        // check if the process has already been terminated
        match self.0.try_wait() {
            // The child process has already terminated, perhaps due to a crash
            Ok(Some(_)) => {}

            // The process is still running so we need to attempt to kill it
            _ => {
                self.0.kill().expect("Process wasn't running");
                self.0.wait().unwrap();
            }
        }
    }
}

pub struct DiemNode {
    process: Option<Process>,
    node_id: String,
    node_type: NodeType,
    peer_id: AccountAddress,
    debug_client: NodeDebugClient,
    log_path: PathBuf,
    config: NodeConfig,
    config_path: PathBuf,
    diem_node_bin_path: PathBuf,
}

impl DiemNode {
    /// Launch a `DiemNode`
    pub fn launch(
        diem_node_bin_path: &Path,
        node_id: String,
        node_type: NodeType,
        config_path: &Path,
        log_path: PathBuf,
    ) -> Result<Self> {
        let config = NodeConfig::load(&config_path)
            .unwrap_or_else(|_| panic!("Failed to load NodeConfig from file: {:?}", config_path));
        // Ensure log file exists
        let log_file = match File::create(&log_path) {
            Ok(file) => file,
            Err(_) => File::open(&log_path)?,
        };

        let main_network_config = match node_type {
            NodeType::Validator => config.validator_network.as_ref().unwrap(),
            _ => config
                .full_node_networks
                .iter()
                .find(|config| config.network_id == NetworkId::Public)
                .as_ref()
                .unwrap(),
        };

        let peer_id = main_network_config.peer_id();

        // Start node process
        let mut node_command = Command::new(diem_node_bin_path);
        node_command.arg("-f").arg(config_path);
        if env::var("RUST_LOG").is_err() {
            // Only set our RUST_LOG if its not present in environment
            node_command.env("RUST_LOG", "debug");
        }
        node_command
            .stdout(log_file.try_clone()?)
            .stderr(log_file.try_clone()?);
        let process = node_command.spawn().with_context(|| {
            format!(
                "Error launching node process with binary: {:?}",
                diem_node_bin_path
            )
        })?;

        let debug_client = NodeDebugClient::new(
            "localhost",
            config.debug_interface.admission_control_node_debug_port,
        );

        Ok(Self {
            process: Some(Process(process)),
            node_id,
            peer_id,
            node_type,
            debug_client,
            log_path,
            config,
            config_path: PathBuf::from(config_path),
            diem_node_bin_path: PathBuf::from(diem_node_bin_path),
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn start(&mut self) -> Result<()> {
        let log_file = File::open(&self.log_path)?;
        // Start node process
        let mut node_command = Command::new(self.diem_node_bin_path.as_path());
        node_command.arg("-f").arg(self.config_path.as_path());
        if env::var("RUST_LOG").is_err() {
            // Only set our RUST_LOG if its not present in environment
            node_command.env("RUST_LOG", "debug");
        }
        node_command
            .stdout(log_file.try_clone()?)
            .stderr(log_file.try_clone()?);
        let process = node_command.spawn().with_context(|| {
            format!(
                "Error launching node process with binary: {:?}",
                self.diem_node_bin_path.as_path()
            )
        })?;
        self.process = Some(Process(process));

        Ok(())
    }

    pub fn stop(&mut self) {
        self.process = None;
    }

    pub fn port(&self) -> u16 {
        self.config.json_rpc.address.port()
    }

    pub fn debug_port(&self) -> u16 {
        self.config
            .debug_interface
            .admission_control_node_debug_port
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn debug_client(&self) -> &NodeDebugClient {
        &self.debug_client
    }

    pub fn get_log_contents(&self) -> Result<String> {
        let mut log = File::open(&self.log_path)?;
        let mut contents = String::new();
        log.read_to_string(&mut contents)?;
        Ok(contents)
    }

    pub fn get_metric(&mut self, metric_name: &str) -> Option<i64> {
        match self.debug_client.get_node_metric(metric_name) {
            Err(e) => {
                println!(
                    "error getting {} for node: {}; error: {}",
                    metric_name, self.node_id, e
                );
                None
            }
            Ok(maybeval) => {
                if maybeval.is_none() {
                    println!("Node: {} did not report {}", self.node_id, metric_name);
                }
                maybeval
            }
        }
    }

    pub fn get_metric_with_fields(
        &mut self,
        metric_name: &str,
        fields: HashMap<String, String>,
    ) -> Option<i64> {
        let result = self.debug_client.get_node_metric_with_name(metric_name);

        match result {
            Err(e) => {
                println!(
                    "error getting {} for node: {}; error: {}",
                    metric_name, self.node_id, e
                );
                None
            }
            Ok(None) => {
                println!("Node: {} did not report {}", self.node_id, metric_name);
                None
            }
            Ok(Some(map)) => {
                let filtered: Vec<_> = map
                    .iter()
                    .filter_map(|(metric, metric_value)| {
                        if fields
                            .iter()
                            .all(|(key, value)| metric.contains(&format!("{}={}", key, value)))
                        {
                            Some(*metric_value)
                        } else {
                            None
                        }
                    })
                    .collect();

                if filtered.is_empty() {
                    None
                } else {
                    Some(filtered.iter().sum())
                }
            }
        }
    }

    pub fn get_connected_peers(
        &mut self,
        network_id: NetworkId,
        direction: Option<&str>,
    ) -> Option<i64> {
        let mut map = HashMap::new();
        map.insert("network_id".to_string(), network_id.to_string());
        if let Some(direction) = direction {
            map.insert("direction".to_string(), direction.to_string());
        }
        self.get_metric_with_fields("diem_connections", map)
    }

    pub fn check_connectivity(&mut self, expected_peers: usize) -> bool {
        // If for some reason the node isn't supposed to be connected
        if expected_peers == 0 {
            return true;
        }

        const OUTBOUND: &str = "outbound";

        // Determine which networks to check
        let checks: Vec<_> = match self.node_type {
            NodeType::Validator => vec![(NetworkId::Validator, None, expected_peers)],
            NodeType::ValidatorFullNode => vec![
                (NetworkId::vfn_network(), Some(OUTBOUND), 1),
                (NetworkId::Public, Some(OUTBOUND), expected_peers),
            ],
            NodeType::PublicFullNode => {
                vec![(NetworkId::Public, Some(OUTBOUND), expected_peers)]
            }
        };

        // Check all networks and ensure that they match
        checks.iter().all(|(network, direction, expected)| {
            if let Some(num_connected_peers) = self.get_connected_peers(network.clone(), *direction)
            {
                if (num_connected_peers as usize) >= *expected {
                    true
                } else {
                    println!(
                        "Node {:?} '{}' on {} network Expected peers: {}, found peers: {}",
                        self.node_type, self.node_id, network, expected, num_connected_peers
                    );
                    false
                }
            } else {
                false
            }
        })
    }

    pub fn health_check(&mut self) -> HealthStatus {
        println!("Health check on node '{}'", self.node_id);

        if let Some(p) = &mut self.process {
            match p.0.try_wait() {
                // This would mean the child process has crashed
                Ok(Some(status)) => {
                    println!("Node '{}' crashed with: {}", self.node_id, status);
                    return HealthStatus::Crashed(status);
                }

                // This is the case where the node is still running
                Ok(None) => {}

                // Some other unknown error
                Err(e) => {
                    panic!("error attempting to query Node: {}", e);
                }
            }
        } else {
            warn!("Node '{}' is stopped", self.node_id);
            return HealthStatus::Stopped;
        }

        match self.debug_client.get_node_metrics() {
            Ok(_) => {
                println!("Node '{}' is healthy", self.node_id);
                HealthStatus::Healthy
            }
            Err(e) => {
                warn!("Error querying metrics for node '{}'", self.node_id);
                HealthStatus::RpcFailure(e)
            }
        }
    }

    pub fn public_address(&self) -> NetworkAddress {
        self.network_address(&NetworkId::Public)
    }

    pub fn network_address(&self, network_id: &NetworkId) -> NetworkAddress {
        network_address(&self.config, network_id)
    }
}

pub fn network_address(node_config: &NodeConfig, network_id: &NetworkId) -> NetworkAddress {
    let network = network(node_config, network_id);

    let port = network
        .listen_address
        .as_slice()
        .iter()
        .find_map(|proto| {
            if let Protocol::Tcp(port) = proto {
                Some(port)
            } else {
                None
            }
        })
        .unwrap();
    let key = network.identity_key().public_key();
    NetworkAddress::from_str(&format!(
        "/ip4/127.0.0.1/tcp/{}/ln-noise-ik/{}/ln-handshake/0",
        port, key
    ))
    .unwrap()
}

pub fn network<'a>(node_config: &'a NodeConfig, network_id: &NetworkId) -> &'a NetworkConfig {
    match network_id {
        NetworkId::Validator => node_config.validator_network.as_ref().unwrap(),
        _ => node_config
            .full_node_networks
            .iter()
            .find(|network| network.network_id == NetworkId::Public)
            .unwrap(),
    }
}

pub fn modify_network_config<Fn: FnOnce(&mut NetworkConfig)>(
    node_config: &mut NodeConfig,
    network_id: &NetworkId,
    modifier: Fn,
) {
    let network = match network_id {
        NetworkId::Validator => node_config.validator_network.as_mut().unwrap(),
        _ => node_config
            .full_node_networks
            .iter_mut()
            .find(|network| &network.network_id == network_id)
            .unwrap(),
    };

    modifier(network)
}

pub enum HealthStatus {
    Healthy,
    Crashed(::std::process::ExitStatus),
    RpcFailure(anyhow::Error),
    Stopped,
}

/// A wrapper that unifies PathBuf and TempPath.
#[derive(Debug)]
pub enum DiemSwarmDir {
    Persistent(PathBuf),
    Temporary(TempPath),
}

impl AsRef<Path> for DiemSwarmDir {
    fn as_ref(&self) -> &Path {
        match self {
            DiemSwarmDir::Persistent(path_buf) => path_buf.as_path(),
            DiemSwarmDir::Temporary(temp_dir) => temp_dir.path(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Validator,
    ValidatorFullNode,
    PublicFullNode,
}

/// Struct holding instances and information of Diem Swarm
pub struct DiemSwarm {
    label: &'static str,
    diem_node_bin_path: PathBuf,
    // Output log, DiemNodes' config file, diemdb etc, into this dir.
    dir: DiemSwarmDir,
    // Maps the node id of a node to the DiemNode struct
    nodes: HashMap<String, DiemNode>,
    pub config: SwarmConfig,
    pub node_type: NodeType,
}

#[derive(Debug, Error)]
pub enum SwarmLaunchFailure {
    /// Timeout while waiting for nodes to start
    #[error("Node launch check timeout")]
    LaunchTimeout,
    /// Node return status indicates a crash
    #[error("Node crash")]
    NodeCrash,
    /// Timeout while waiting for the nodes to report that they're all interconnected
    #[error("Node connectivity check timeout")]
    ConnectivityTimeout,
    #[error("IO Error: {0}")]
    IoError(#[from] io::Error),
}

impl DiemSwarm {
    /// Either create a persistent directory for swarm or return a temporary one.
    /// If specified persistent directory already exists,
    /// assumably due to previous launch failure, it will be removed.
    /// The directory for the last failed attempt won't be removed.
    fn setup_config_dir(config_dir: &Option<String>) -> DiemSwarmDir {
        if let Some(dir_str) = config_dir {
            let path_buf = PathBuf::from_str(&dir_str).expect("unable to create config dir");
            if path_buf.exists() {
                std::fs::remove_dir_all(dir_str).expect("unable to delete previous config dir");
            }
            std::fs::create_dir_all(dir_str).expect("unable to create config dir");
            DiemSwarmDir::Persistent(path_buf)
        } else {
            let temp_dir = TempPath::new();
            temp_dir
                .create_as_dir()
                .expect("unable to create temporary config dir");
            DiemSwarmDir::Temporary(temp_dir)
        }
    }

    pub fn configure_fn_swarm(
        label: &'static str,
        diem_node_bin_path: &Path,
        config_dir: Option<String>,
        template: Option<NodeConfig>,
        upstream_config: &SwarmConfig,
        fn_type: FullnodeType,
    ) -> Result<DiemSwarm> {
        let swarm_config_dir = Self::setup_config_dir(&config_dir);
        info!("logs for {:?} at {:?}", fn_type, swarm_config_dir);

        let node_config = template.unwrap_or_else(|| match fn_type {
            FullnodeType::ValidatorFullnode => NodeConfig::default_for_validator_full_node(),
            FullnodeType::PublicFullnode(_) => NodeConfig::default_for_public_full_node(),
        });

        let config_path = &swarm_config_dir.as_ref().to_path_buf();
        let builder = FullnodeBuilder::new(
            upstream_config.config_files.clone(),
            upstream_config.diem_root_key_path.clone(),
            node_config,
            fn_type,
        );
        let config = SwarmConfig::build(&builder, config_path)?;
        let node_type = match fn_type {
            FullnodeType::ValidatorFullnode => NodeType::ValidatorFullNode,
            FullnodeType::PublicFullnode(_) => NodeType::PublicFullNode,
        };
        Ok(Self {
            label,
            diem_node_bin_path: diem_node_bin_path.to_path_buf(),
            dir: swarm_config_dir,
            nodes: HashMap::new(),
            config,
            node_type,
        })
    }

    pub fn configure_validator_swarm(
        diem_node_bin_path: &Path,
        num_nodes: usize,
        config_dir: Option<String>,
        template: Option<NodeConfig>,
    ) -> Result<DiemSwarm> {
        let swarm_config_dir = Self::setup_config_dir(&config_dir);
        info!("logs for validator at {:?}", swarm_config_dir);

        let node_config = template.unwrap_or_else(NodeConfig::default_for_validator);

        let config_path = &swarm_config_dir.as_ref().to_path_buf();
        let builder = ValidatorBuilder::new(
            &config_path,
            diem_framework_releases::current_module_blobs().to_vec(),
        )
        .num_validators(num_nodes)
        .template(node_config);
        let config = SwarmConfig::build(&builder, config_path)?;

        Ok(Self {
            label: "Validator",
            diem_node_bin_path: diem_node_bin_path.to_path_buf(),
            dir: swarm_config_dir,
            nodes: HashMap::new(),
            config,
            node_type: NodeType::Validator,
        })
    }

    pub fn launch(&mut self) {
        let num_attempts = 5;
        for _ in 0..num_attempts {
            match self.launch_attempt(true) {
                Ok(_) => return,
                Err(err) => error!("{} Error launching swarm: {}", self.log_header(), err),
            }
        }
        panic!(
            "{} Max out {} attempts to launch test swarm",
            self.log_header(),
            num_attempts
        );
    }

    pub fn launch_attempt(&mut self, check_connectivity: bool) -> Result<(), SwarmLaunchFailure> {
        let logs_dir_path = self.dir.as_ref().join("logs");

        // Make sure the directory exists
        match std::fs::create_dir(&logs_dir_path) {
            Ok(_) => {}
            Err(_) => {
                std::fs::read_dir(&logs_dir_path)?;
            }
        };
        // For each config launch a node
        for (index, path) in self.config.config_files.iter().enumerate() {
            // Use index as node id.
            let node_id = format!("{}", index);
            let node = DiemNode::launch(
                &self.diem_node_bin_path,
                node_id.clone(),
                self.node_type,
                &path,
                logs_dir_path.join(format!("{}.log", index)),
            )
            .unwrap();
            self.nodes.insert(node_id, node);
        }
        self.wait_for_startup()?;

        // TODO: Maybe wait for more than one on full nodes
        let expected_peers = match self.node_type {
            NodeType::Validator => self.nodes.len().saturating_sub(1),
            // for 1 node vfn swarm, it does not have fallback peer
            NodeType::ValidatorFullNode => {
                if self.nodes.len() > 1 {
                    1
                } else {
                    0
                }
            }
            NodeType::PublicFullNode => 1,
        };

        if check_connectivity {
            self.wait_for_connectivity(expected_peers)?;
        }
        println!("{} Successfully launched Swarm", self.log_header());
        Ok(())
    }

    fn wait_for_connectivity(&mut self, expected_peers: usize) -> Result<(), SwarmLaunchFailure> {
        let num_attempts = 60;

        for i in 0..num_attempts {
            println!("{} Wait for connectivity attempt: {}", self.log_header(), i);

            if self
                .nodes
                .values_mut()
                .all(|node| node.check_connectivity(expected_peers))
            {
                return Ok(());
            }

            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }

        Err(SwarmLaunchFailure::ConnectivityTimeout)
    }

    fn wait_for_startup(&mut self) -> Result<(), SwarmLaunchFailure> {
        let num_attempts = 120;
        let mut done = vec![false; self.nodes.len()];
        let log_header = self.log_header();
        for i in 0..num_attempts {
            println!(
                "{} Wait for startup attempt: {} of {}",
                log_header, i, num_attempts
            );
            for (node, done) in self.nodes.values_mut().zip(done.iter_mut()) {
                if *done {
                    continue;
                }
                match node.health_check() {
                    HealthStatus::Healthy => *done = true,
                    HealthStatus::RpcFailure(_) => continue,
                    HealthStatus::Crashed(status) => {
                        error!(
                            "{} Diem node '{}' has crashed with status '{}'. Log output: '''{}'''",
                            log_header,
                            node.node_id(),
                            status,
                            node.get_log_contents().unwrap()
                        );
                        return Err(SwarmLaunchFailure::NodeCrash);
                    }
                    HealthStatus::Stopped => {
                        panic!(
                            "{} Diem node '{} child process is not created",
                            log_header,
                            node.node_id()
                        )
                    }
                }
            }

            // Check if all the nodes have been successfully launched
            if done.iter().all(|status| *status) {
                return Ok(());
            }

            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }

        Err(SwarmLaunchFailure::LaunchTimeout)
    }

    /// This function first checks the last committed round of all the nodes, picks the max
    /// value and then waits for all the nodes to catch up to that round.
    /// Once done, we can guarantee that all the txns committed before the invocation of this
    /// function are now available at all the nodes.
    pub fn wait_for_all_nodes_to_catchup(&mut self) -> bool {
        let num_attempts = 60;
        let last_committed_round_str = "diem_consensus_last_committed_round{}";
        let mut done = vec![false; self.nodes.len()];
        let log_header = self.log_header();

        let mut last_committed_round = 0;
        // First, try to retrieve the max value across all the committed rounds
        println!(
            "{} Calculating max committed round across the validators.",
            log_header
        );
        for node in self.nodes.values_mut() {
            match node.get_metric(last_committed_round_str) {
                Some(val) => {
                    println!(
                        "{} \tNode {} last committed round = {}",
                        log_header,
                        node.node_id(),
                        val
                    );
                    last_committed_round = last_committed_round.max(val);
                }
                None => {
                    println!(
                        "{} \tNode {} last committed round unknown, assuming 0.",
                        log_header,
                        node.node_id()
                    );
                }
            }
        }

        // Now wait for all the nodes to catch up to the max.
        for i in 0..num_attempts {
            println!(
                "{} Wait for catchup, target_commit_round = {}, attempt: {} of {}",
                log_header,
                last_committed_round,
                i + 1,
                num_attempts
            );

            for (node, done) in self.nodes.values_mut().zip(done.iter_mut()) {
                if *done {
                    continue;
                }

                if let Some(val) = node.get_metric(last_committed_round_str) {
                    if val >= last_committed_round {
                        println!(
                            "{} \tNode {} is caught up with last committed round {}",
                            log_header,
                            node.node_id(),
                            val
                        );
                        *done = true;
                    } else {
                        println!(
                            "{} \tNode {} is not caught up yet with last committed round {}",
                            log_header,
                            node.node_id(),
                            val
                        );
                    }
                } else {
                    println!(
                        "{} \tNode {} last committed round unknown, assuming 0.",
                        log_header,
                        node.node_id()
                    );
                }
            }

            // Check if all the nodes have been successfully caught up
            if done.iter().all(|status| *status) {
                return true;
            }

            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }

        false
    }

    /// A specific public JSON RPC port of a validator or a full node.
    pub fn get_client_port(&self, index: usize) -> u16 {
        let node_id = format!("{}", index);
        self.nodes.get(&node_id).map(|node| node.port()).unwrap()
    }

    pub fn get_node(&self, idx: usize) -> Option<&DiemNode> {
        let node_id = format!("{}", idx);
        self.nodes.get(&node_id)
    }

    pub fn mut_node(&mut self, idx: usize) -> Option<&mut DiemNode> {
        let node_id = format!("{}", idx);
        self.nodes.get_mut(&node_id)
    }

    pub fn nodes(&mut self) -> &mut HashMap<String, DiemNode> {
        &mut self.nodes
    }

    pub fn kill_node(&mut self, idx: usize) {
        let node_id = format!("{}", idx);
        self.nodes.remove(&node_id);
    }

    pub fn start_node(&mut self, idx: usize) -> Result<(), SwarmLaunchFailure> {
        // First take the configs out to not keep immutable borrow on self when calling
        // `launch_node`.
        let path = self
            .config
            .config_files
            .get(idx)
            .unwrap_or_else(|| panic!("{} Node at index {} not found", self.log_header(), idx));
        let log_file_path = self.dir.as_ref().join("logs").join(format!("{}.log", idx));
        let node_id = format!("{}", idx);
        let mut node = DiemNode::launch(
            &self.diem_node_bin_path,
            node_id.clone(),
            self.node_type,
            path,
            log_file_path,
        )
        .unwrap();
        for _ in 0..60 {
            if let HealthStatus::Healthy = node.health_check() {
                self.nodes.insert(node_id, node);
                return self.wait_for_connectivity(self.nodes.len() - 1);
            }
            ::std::thread::sleep(::std::time::Duration::from_millis(1000));
        }
        Err(SwarmLaunchFailure::LaunchTimeout)
    }

    fn log_header(&self) -> String {
        format!("[{:?}:{}]", self.node_type, self.label)
    }
}

impl Drop for DiemSwarm {
    fn drop(&mut self) {
        let log_header = self.log_header();
        // If panicking, we don't want to gc the swarm directory.
        if std::thread::panicking() {
            // let dir = self.dir;
            if let DiemSwarmDir::Temporary(temp_dir) = &mut self.dir {
                temp_dir.persist();
                let log_path = temp_dir.path();
                println!("{} logs located at {:?}", log_header, log_path);

                // Dump logs for each validator to stdout when `DIEM_DUMP_LOGS`
                // environment variable is set
                if env::var_os("DIEM_DUMP_LOGS").is_some() {
                    for (peer_id, node) in &mut self.nodes {
                        // Skip dumping logs for healthy nodes
                        if let HealthStatus::Healthy = node.health_check() {
                            continue;
                        }

                        // Grab the contents of the node's logs and skip if we were unable to
                        // grab its logs
                        let log_contents = match node.get_log_contents() {
                            Ok(contents) => contents,
                            Err(_) => continue,
                        };

                        println!();
                        println!();
                        println!("{:=^80}", "");
                        println!("Validator {}", peer_id);
                        println!();
                        println!();
                        println!("{}", log_contents);
                    }
                }
            }
        }
    }
}
