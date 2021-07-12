// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use backup_service::start_backup_service;
use consensus::{consensus_provider::start_consensus, gen_consensus_reconfig_subscription};
use debug_interface::node_debug_service::NodeDebugService;
use diem_config::{
    config::{NetworkConfig, NodeConfig, PersistableConfig},
    network_id::NodeNetworkId,
    utils::get_genesis_txn,
};
use diem_json_rpc::bootstrap_from_config as bootstrap_rpc;
use diem_logger::{prelude::*, Logger};
use diem_mempool::gen_mempool_reconfig_subscription;
use diem_metrics::metric_server;
use diem_time_service::TimeService;
use diem_types::{
    account_config::diem_root_address, account_state::AccountState, chain_id::ChainId,
    move_resource::MoveStorage,
};
use diem_vm::DiemVM;
use diemdb::DiemDB;
use executor::{db_bootstrapper::maybe_bootstrap, Executor};
use executor_types::ChunkExecutor;
use futures::{channel::mpsc::channel, executor::block_on};
use network_builder::builder::NetworkBuilder;
use state_sync::bootstrapper::StateSyncBootstrapper;
use std::{
    boxed::Box,
    convert::TryFrom,
    net::ToSocketAddrs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Instant,
};
use storage_interface::DbReaderWriter;
use storage_service::start_storage_service_with_db;
use tokio::runtime::{Builder, Runtime};
use tokio_stream::wrappers::IntervalStream;

const AC_SMP_CHANNEL_BUFFER_SIZE: usize = 1_024;
const INTRA_NODE_CHANNEL_BUFFER_SIZE: usize = 1;
const MEMPOOL_NETWORK_CHANNEL_BUFFER_SIZE: usize = 1_024;

pub struct DiemHandle {
    _rpc: Runtime,
    _mempool: Runtime,
    _state_sync_bootstrapper: StateSyncBootstrapper,
    _network_runtimes: Vec<Runtime>,
    _consensus_runtime: Option<Runtime>,
    _debug: NodeDebugService,
    _backup: Runtime,
}

pub fn start(config: &NodeConfig, log_file: Option<PathBuf>) {
    crash_handler::setup_panic_handler();

    let mut logger = diem_logger::Logger::new();
    logger
        .channel_size(config.logger.chan_size)
        .is_async(config.logger.is_async)
        .level(config.logger.level)
        .read_env();
    if let Some(log_file) = log_file {
        logger.printer(Box::new(FileWriter::new(log_file)));
    }
    let logger = Some(logger.build());

    // Let's now log some important information, since the logger is set up
    info!(config = config, "Loaded DiemNode config");

    if fail::has_failpoints() {
        warn!("Failpoints is enabled");
        if let Some(failpoints) = &config.failpoints {
            for (point, actions) in failpoints {
                fail::cfg(point, actions).expect("fail to set actions for failpoint");
            }
        }
    } else if config.failpoints.is_some() {
        warn!("failpoints is set in config, but the binary doesn't compile with this feature");
    }

    let _node_handle = setup_environment(&config, logger);
    let term = Arc::new(AtomicBool::new(false));

    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}

pub fn load_test_environment(config_path: Option<PathBuf>, random_ports: bool) {
    // Either allocate a temppath or reuse the passed in path and make sure the directory exists
    let config_temp_path = diem_temppath::TempPath::new();
    let config_path = config_path.unwrap_or_else(|| config_temp_path.as_ref().to_path_buf());
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(&config_path)
        .unwrap();
    let config_path = config_path.canonicalize().unwrap();

    // Build a single validator network
    let mut maybe_config = PathBuf::from(&config_path);
    maybe_config.push("validator_node_template.yaml");
    let template = NodeConfig::load_config(maybe_config)
        .unwrap_or_else(|_| NodeConfig::default_for_validator());
    let builder = diem_genesis_tool::validator_builder::ValidatorBuilder::new(
        &config_path,
        diem_framework_releases::current_module_blobs().to_vec(),
    )
    .num_validators(1)
    .template(template)
    .randomize_first_validator_ports(random_ports);
    let test_config =
        diem_genesis_tool::swarm_config::SwarmConfig::build(&builder, &config_path).unwrap();

    // Prepare log file since we cannot automatically route logs to stderr
    let mut log_file = config_path.clone();
    log_file.push("validator.log");

    // Build a waypoint file so that clients / docker can grab it easily
    let mut waypoint_file_path = config_path;
    waypoint_file_path.push("waypoint.txt");
    std::io::Write::write_all(
        &mut std::fs::File::create(&waypoint_file_path).unwrap(),
        test_config.waypoint.to_string().as_bytes(),
    )
    .unwrap();

    // Intentionally leave out instructions on how to connect with different applications
    println!("Completed generating configuration:");
    println!("\tLog file: {:?}", log_file);
    println!("\tConfig path: {:?}", test_config.config_files[0]);
    println!("\tDiem root key path: {:?}", test_config.diem_root_key_path);
    println!("\tWaypoint: {}", test_config.waypoint);
    // Configure json rpc to bind on 0.0.0.0
    let mut config = NodeConfig::load(&test_config.config_files[0]).unwrap();
    config.json_rpc.address = format!("0.0.0.0:{}", config.json_rpc.address.port())
        .parse()
        .unwrap();
    println!("\tJSON-RPC endpoint: {}", config.json_rpc.address);
    config.json_rpc.stream_rpc.enabled = true;
    println!("\tStream-RPC enabled!");

    println!(
        "\tFullNode network: {}",
        config.full_node_networks[0].listen_address
    );
    println!("\tChainId: {}", ChainId::test());
    println!();
    println!("Diem is running, press ctrl-c to exit");
    println!();

    start(&config, Some(log_file))
}

// Fetch chain ID from on-chain resource
fn fetch_chain_id(db: &DbReaderWriter) -> ChainId {
    let blob = db
        .reader
        .get_account_state_with_proof_by_version(
            diem_root_address(),
            (&*db.reader)
                .fetch_synced_version()
                .expect("[diem-node] failed fetching synced version."),
        )
        .expect("[diem-node] failed to get Diem root address account state")
        .0
        .expect("[diem-node] missing Diem root address account state");
    AccountState::try_from(&blob)
        .expect("[diem-node] failed to convert blob to account state")
        .get_chain_id_resource()
        .expect("[diem-node] failed to get chain ID resource")
        .expect("[diem-node] missing chain ID resource")
        .chain_id()
}

fn setup_chunk_executor(db: DbReaderWriter) -> Box<dyn ChunkExecutor> {
    Box::new(Executor::<DiemVM>::new(db))
}

fn setup_debug_interface(config: &NodeConfig, logger: Option<Arc<Logger>>) -> NodeDebugService {
    let addr = format!(
        "{}:{}",
        config.debug_interface.address, config.debug_interface.admission_control_node_debug_port,
    )
    .to_socket_addrs()
    .unwrap()
    .next()
    .unwrap();

    NodeDebugService::new(addr, logger)
}

async fn periodic_state_dump(node_config: NodeConfig, db: DbReaderWriter) {
    use futures::stream::StreamExt;

    let args: Vec<String> = ::std::env::args().collect();

    // Once an hour
    let mut config_interval = IntervalStream::new(tokio::time::interval(
        std::time::Duration::from_secs(60 * 60),
    ))
    .fuse();
    // Once a minute
    let mut version_interval =
        IntervalStream::new(tokio::time::interval(std::time::Duration::from_secs(60))).fuse();

    info!("periodic_state_dump task started");

    loop {
        futures::select! {
            _ = config_interval.select_next_some() => {
                info!(config = node_config, args = args, "config and command line arguments");
            }
            _ = version_interval.select_next_some() => {
                let chain_id = fetch_chain_id(&db);
                let ledger_info = if let Ok(ledger_info) = db.reader.get_latest_ledger_info() {
                    ledger_info
                } else {
                    warn!("unable to query latest ledger info");
                    continue;
                };

                let latest_ledger_verion = ledger_info.ledger_info().version();
                let root_hash = ledger_info.ledger_info().transaction_accumulator_hash();

                info!(
                    chain_id = chain_id,
                    latest_ledger_verion = latest_ledger_verion,
                    root_hash = root_hash,
                    "latest ledger version and its corresponding root hash"
                );
            }
        }
    }
}

pub fn setup_environment(node_config: &NodeConfig, logger: Option<Arc<Logger>>) -> DiemHandle {
    let debug_if = setup_debug_interface(&node_config, logger);

    let metrics_port = node_config.debug_interface.metrics_server_port;
    let metric_host = node_config.debug_interface.address.clone();
    thread::spawn(move || metric_server::start_server(metric_host, metrics_port, false));
    let public_metrics_port = node_config.debug_interface.public_metrics_server_port;
    let public_metric_host = node_config.debug_interface.address.clone();
    thread::spawn(move || {
        metric_server::start_server(public_metric_host, public_metrics_port, true)
    });

    let mut instant = Instant::now();
    let (diem_db, db_rw) = DbReaderWriter::wrap(
        DiemDB::open(
            &node_config.storage.dir(),
            false, /* readonly */
            node_config.storage.prune_window,
            node_config.storage.rocksdb_config,
        )
        .expect("DB should open."),
    );
    let _simple_storage_service = start_storage_service_with_db(&node_config, Arc::clone(&diem_db));
    let backup_service = start_backup_service(
        node_config.storage.backup_service_address,
        Arc::clone(&diem_db),
    );

    let genesis_waypoint = node_config.base.waypoint.genesis_waypoint();
    // if there's genesis txn and waypoint, commit it if the result matches.
    if let Some(genesis) = get_genesis_txn(&node_config) {
        maybe_bootstrap::<DiemVM>(&db_rw, genesis, genesis_waypoint)
            .expect("Db-bootstrapper should not fail.");
    } else {
        info!("Genesis txn not provided, it's fine if you don't expect to apply it otherwise please double check config");
    }

    debug!(
        "Storage service started in {} ms",
        instant.elapsed().as_millis()
    );

    instant = Instant::now();
    let chunk_executor = setup_chunk_executor(db_rw.clone());
    debug!(
        "ChunkExecutor setup in {} ms",
        instant.elapsed().as_millis()
    );
    let chain_id = fetch_chain_id(&db_rw);
    let mut network_runtimes = vec![];
    let mut state_sync_network_handles = vec![];
    let mut mempool_network_handles = vec![];
    let mut consensus_network_handles = None;
    let mut reconfig_subscriptions = vec![];

    let (mempool_reconfig_subscription, mempool_reconfig_events) =
        gen_mempool_reconfig_subscription();
    reconfig_subscriptions.push(mempool_reconfig_subscription);
    // consensus has to subscribe to ALL on-chain configs
    let (consensus_reconfig_subscription, consensus_reconfig_events) =
        gen_consensus_reconfig_subscription();
    if node_config.base.role.is_validator() {
        reconfig_subscriptions.push(consensus_reconfig_subscription);
    }

    // Gather all network configs into a single vector.
    let mut network_configs: Vec<&NetworkConfig> = node_config.full_node_networks.iter().collect();
    if let Some(network_config) = node_config.validator_network.as_ref() {
        network_configs.push(network_config);
    }

    // Instantiate every network and collect the requisite endpoints for state_sync, mempool, and consensus.
    for (idx, network_config) in network_configs.into_iter().enumerate() {
        debug!("Creating runtime for {}", network_config.network_id);
        let runtime = Builder::new_multi_thread()
            .thread_name(format!("network-{}", network_config.network_id))
            .enable_all()
            .build()
            .expect("Failed to start runtime. Won't be able to start networking.");

        // Entering here gives us a runtime to instantiate all the pieces of the builder
        let _enter = runtime.enter();

        // Perform common instantiation steps
        let mut network_builder = NetworkBuilder::create(
            chain_id,
            node_config.base.role,
            network_config,
            TimeService::real(),
        );
        let network_id = network_config.network_id.clone();

        // Create the endpoints to connect the Network to State Sync.
        let (state_sync_sender, state_sync_events) =
            network_builder.add_protocol_handler(state_sync::network::network_endpoint_config());
        state_sync_network_handles.push((
            NodeNetworkId::new(network_id.clone(), idx),
            state_sync_sender,
            state_sync_events,
        ));

        // Create the endpoints to connect the Network to mempool.
        let (mempool_sender, mempool_events) = network_builder.add_protocol_handler(
            diem_mempool::network::network_endpoint_config(MEMPOOL_NETWORK_CHANNEL_BUFFER_SIZE),
        );
        mempool_network_handles.push((
            NodeNetworkId::new(network_id.clone(), idx),
            mempool_sender,
            mempool_events,
        ));

        // Perform steps relevant specifically to Validator networks.
        if network_id.is_validator_network() {
            // A valid config is allowed to have at most one ValidatorNetwork
            // TODO:  `expect_none` would be perfect here, once it is stable.
            if consensus_network_handles.is_some() {
                panic!("There can be at most one validator network!");
            }

            consensus_network_handles = Some(
                network_builder
                    .add_protocol_handler(consensus::network_interface::network_endpoint_config()),
            );
        }

        reconfig_subscriptions.append(network_builder.reconfig_subscriptions());

        let network_context = network_builder.network_context();
        network_builder.build(runtime.handle().clone());
        network_builder.start();
        debug!("Network built for network context: {}", network_context);
        network_runtimes.push(runtime);
    }

    // TODO set up on-chain discovery network based on UpstreamConfig.fallback_network
    // and pass network handles to mempool/state sync

    // for state sync to send requests to mempool
    let (state_sync_to_mempool_sender, state_sync_requests) =
        channel(INTRA_NODE_CHANNEL_BUFFER_SIZE);
    let state_sync_bootstrapper = StateSyncBootstrapper::bootstrap(
        state_sync_network_handles,
        state_sync_to_mempool_sender,
        Arc::clone(&db_rw.reader),
        chunk_executor,
        node_config,
        genesis_waypoint,
        reconfig_subscriptions,
    );
    let (mp_client_sender, mp_client_events) = channel(AC_SMP_CHANNEL_BUFFER_SIZE);

    let rpc_runtime = bootstrap_rpc(&node_config, chain_id, diem_db.clone(), mp_client_sender);

    let mut consensus_runtime = None;
    let (consensus_to_mempool_sender, consensus_requests) = channel(INTRA_NODE_CHANNEL_BUFFER_SIZE);

    instant = Instant::now();
    let mempool = diem_mempool::bootstrap(
        node_config,
        Arc::clone(&db_rw.reader),
        mempool_network_handles,
        mp_client_events,
        consensus_requests,
        state_sync_requests,
        mempool_reconfig_events,
    );
    debug!("Mempool started in {} ms", instant.elapsed().as_millis());

    // StateSync should be instantiated and started before Consensus to avoid a cyclic dependency:
    // network provider -> consensus -> state synchronizer -> network provider.  This has resulted
    // in a deadlock as observed in GitHub issue #749.
    if let Some((consensus_network_sender, consensus_network_events)) = consensus_network_handles {
        let state_sync_client =
            state_sync_bootstrapper.create_client(node_config.state_sync.client_commit_timeout_ms);

        // Make sure that state synchronizer is caught up at least to its waypoint
        // (in case it's present). There is no sense to start consensus prior to that.
        // TODO: Note that we need the networking layer to be able to discover & connect to the
        // peers with potentially outdated network identity public keys.
        debug!("Wait until state sync is initialized");
        block_on(state_sync_client.wait_until_initialized())
            .expect("State sync initialization failure");
        debug!("State sync initialization complete.");

        // Initialize and start consensus.
        instant = Instant::now();
        consensus_runtime = Some(start_consensus(
            node_config,
            consensus_network_sender,
            consensus_network_events,
            state_sync_client,
            consensus_to_mempool_sender,
            diem_db,
            consensus_reconfig_events,
        ));
        debug!("Consensus started in {} ms", instant.elapsed().as_millis());
    }

    // Spawn a task which will periodically dump some interesting state
    debug_if
        .runtime()
        .handle()
        .spawn(periodic_state_dump(node_config.to_owned(), db_rw));

    DiemHandle {
        _network_runtimes: network_runtimes,
        _rpc: rpc_runtime,
        _mempool: mempool,
        _state_sync_bootstrapper: state_sync_bootstrapper,
        _consensus_runtime: consensus_runtime,
        _debug: debug_if,
        _backup: backup_service,
    }
}
