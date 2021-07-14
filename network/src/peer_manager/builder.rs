// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    counters,
    counters::NETWORK_RATE_LIMIT_METRICS,
    noise::{stream::NoiseStream, HandshakeAuthMode},
    peer_manager::{
        conn_notifs_channel, ConnectionRequest, ConnectionRequestSender, PeerManager,
        PeerManagerNotification, PeerManagerRequest, PeerManagerRequestSender,
    },
    protocols::wire::handshake::v1::SupportedProtocols,
    transport::{self, Connection, DiemNetTransport, DIEM_TCP_TRANSPORT},
    ProtocolId,
};
use channel::{self, diem_channel, message_queues::QueueStyle};
use diem_config::{
    config::{PeerSet, RateLimitConfig, HANDSHAKE_VERSION},
    network_id::NetworkContext,
};
use diem_crypto::x25519;
use diem_infallible::RwLock;
use diem_logger::prelude::*;
use diem_metrics::IntCounterVec;
use diem_rate_limiter::rate_limit::TokenBucketRateLimiter;
use diem_time_service::TimeService;
use diem_types::{chain_id::ChainId, network_address::NetworkAddress, PeerId};
#[cfg(any(test, feature = "testing", feature = "fuzzing"))]
use netcore::transport::memory::MemoryTransport;
use netcore::transport::{
    tcp::{TcpSocket, TcpTransport},
    Transport,
};
use std::{clone::Clone, collections::HashMap, fmt::Debug, net::IpAddr, sync::Arc};
use tokio::runtime::Handle;

/// Inbound and Outbound connections are always secured with NoiseIK.  The dialer
/// will always verify the listener.
#[derive(Debug)]
pub enum AuthenticationMode {
    /// Inbound connections will first be checked against the known peers set, and
    /// if the `PeerId` is known it will be authenticated against it's `PublicKey`
    /// Otherwise, the incoming connections will be allowed through in the common
    /// pool of unknown peers.
    MaybeMutual(x25519::PrivateKey),
    /// Both dialer and listener will verify public keys of each other in the
    /// handshake.
    Mutual(x25519::PrivateKey),
}

struct TransportContext {
    chain_id: ChainId,
    direct_send_protocols: Vec<ProtocolId>,
    rpc_protocols: Vec<ProtocolId>,
    authentication_mode: AuthenticationMode,
    trusted_peers: Arc<RwLock<PeerSet>>,
    enable_proxy_protocol: bool,
}

impl TransportContext {
    pub fn new(
        chain_id: ChainId,
        direct_send_protocols: Vec<ProtocolId>,
        rpc_protocols: Vec<ProtocolId>,
        authentication_mode: AuthenticationMode,
        trusted_peers: Arc<RwLock<PeerSet>>,
        enable_proxy_protocol: bool,
    ) -> Self {
        Self {
            chain_id,
            direct_send_protocols,
            rpc_protocols,
            authentication_mode,
            trusted_peers,
            enable_proxy_protocol,
        }
    }

    fn supported_protocols(&self) -> SupportedProtocols {
        self.direct_send_protocols
            .iter()
            .copied()
            .chain(self.rpc_protocols.iter().copied())
            .collect()
    }

    fn augment_direct_send_protocols(
        &mut self,
        direct_send_protocols: Vec<ProtocolId>,
    ) -> &mut Self {
        self.direct_send_protocols.extend(direct_send_protocols);
        self
    }

    fn augment_rpc_protocols(&mut self, rpc_protocols: Vec<ProtocolId>) -> &mut Self {
        self.rpc_protocols.extend(rpc_protocols);
        self
    }
}

struct PeerManagerContext {
    // TODO(philiphayes): better support multiple listening addrs
    pm_reqs_tx: diem_channel::Sender<(PeerId, ProtocolId), PeerManagerRequest>,
    pm_reqs_rx: diem_channel::Receiver<(PeerId, ProtocolId), PeerManagerRequest>,
    connection_reqs_tx: diem_channel::Sender<PeerId, ConnectionRequest>,
    connection_reqs_rx: diem_channel::Receiver<PeerId, ConnectionRequest>,

    trusted_peers: Arc<RwLock<PeerSet>>,
    upstream_handlers:
        HashMap<ProtocolId, diem_channel::Sender<(PeerId, ProtocolId), PeerManagerNotification>>,
    connection_event_handlers: Vec<conn_notifs_channel::Sender>,

    max_concurrent_network_reqs: usize,
    channel_size: usize,
    max_frame_size: usize,
    inbound_connection_limit: usize,
    inbound_rate_limit_config: Option<RateLimitConfig>,
    outbound_rate_limit_config: Option<RateLimitConfig>,
}

impl PeerManagerContext {
    fn new(
        pm_reqs_tx: diem_channel::Sender<(PeerId, ProtocolId), PeerManagerRequest>,
        pm_reqs_rx: diem_channel::Receiver<(PeerId, ProtocolId), PeerManagerRequest>,
        connection_reqs_tx: diem_channel::Sender<PeerId, ConnectionRequest>,
        connection_reqs_rx: diem_channel::Receiver<PeerId, ConnectionRequest>,

        trusted_peers: Arc<RwLock<PeerSet>>,
        upstream_handlers: HashMap<
            ProtocolId,
            diem_channel::Sender<(PeerId, ProtocolId), PeerManagerNotification>,
        >,
        connection_event_handlers: Vec<conn_notifs_channel::Sender>,

        max_concurrent_network_reqs: usize,
        channel_size: usize,
        max_frame_size: usize,
        inbound_connection_limit: usize,
        inbound_rate_limit_config: Option<RateLimitConfig>,
        outbound_rate_limit_config: Option<RateLimitConfig>,
    ) -> Self {
        Self {
            pm_reqs_tx,
            pm_reqs_rx,
            connection_reqs_tx,
            connection_reqs_rx,

            trusted_peers,
            upstream_handlers,
            connection_event_handlers,

            max_concurrent_network_reqs,
            channel_size,
            max_frame_size,
            inbound_connection_limit,
            inbound_rate_limit_config,
            outbound_rate_limit_config,
        }
    }

    fn add_upstream_handler(
        &mut self,
        protocol_id: ProtocolId,
        channel: diem_channel::Sender<(PeerId, ProtocolId), PeerManagerNotification>,
    ) -> &mut Self {
        self.upstream_handlers.insert(protocol_id, channel);
        self
    }

    pub fn add_connection_event_listener(&mut self) -> conn_notifs_channel::Receiver {
        let (tx, rx) = conn_notifs_channel::new();
        self.connection_event_handlers.push(tx);
        rx
    }
}

#[cfg(any(test, feature = "testing", feature = "fuzzing"))]
type MemoryPeerManager =
    PeerManager<DiemNetTransport<MemoryTransport>, NoiseStream<memsocket::MemorySocket>>;
type TcpPeerManager = PeerManager<DiemNetTransport<TcpTransport>, NoiseStream<TcpSocket>>;

enum TransportPeerManager {
    #[cfg(any(test, feature = "testing", feature = "fuzzing"))]
    Memory(MemoryPeerManager),
    Tcp(TcpPeerManager),
}

pub struct PeerManagerBuilder {
    network_context: Arc<NetworkContext>,
    time_service: TimeService,
    transport_context: Option<TransportContext>,
    peer_manager_context: Option<PeerManagerContext>,
    // TODO(philiphayes): better support multiple listening addrs
    peer_manager: Option<TransportPeerManager>,
    // ListenAddress will be updated when the PeerManager is built
    listen_address: NetworkAddress,
}

impl PeerManagerBuilder {
    pub fn create(
        chain_id: ChainId,
        network_context: Arc<NetworkContext>,
        time_service: TimeService,
        // TODO(philiphayes): better support multiple listening addrs
        listen_address: NetworkAddress,
        trusted_peers: Arc<RwLock<PeerSet>>,
        authentication_mode: AuthenticationMode,
        channel_size: usize,
        max_concurrent_network_reqs: usize,
        max_frame_size: usize,
        enable_proxy_protocol: bool,
        inbound_connection_limit: usize,
        inbound_rate_limit_config: Option<RateLimitConfig>,
        outbound_rate_limit_config: Option<RateLimitConfig>,
    ) -> Self {
        // Setup channel to send requests to peer manager.
        let (pm_reqs_tx, pm_reqs_rx) = diem_channel::new(
            QueueStyle::FIFO,
            channel_size,
            Some(&counters::PENDING_PEER_MANAGER_REQUESTS),
        );
        // Setup channel to send connection requests to peer manager.
        let (connection_reqs_tx, connection_reqs_rx) =
            diem_channel::new(QueueStyle::FIFO, channel_size, None);

        Self {
            network_context,
            time_service,
            transport_context: Some(TransportContext::new(
                chain_id,
                Vec::new(),
                Vec::new(),
                authentication_mode,
                trusted_peers.clone(),
                enable_proxy_protocol,
            )),
            peer_manager_context: Some(PeerManagerContext::new(
                pm_reqs_tx,
                pm_reqs_rx,
                connection_reqs_tx,
                connection_reqs_rx,
                trusted_peers,
                HashMap::new(),
                Vec::new(),
                max_concurrent_network_reqs,
                channel_size,
                max_frame_size,
                inbound_connection_limit,
                inbound_rate_limit_config,
                outbound_rate_limit_config,
            )),
            peer_manager: None,
            listen_address,
        }
    }

    pub fn listen_address(&self) -> NetworkAddress {
        self.listen_address.clone()
    }

    pub fn connection_reqs_tx(&self) -> diem_channel::Sender<PeerId, ConnectionRequest> {
        self.peer_manager_context
            .as_ref()
            .expect("Cannot access connection_reqs once PeerManager has been built")
            .connection_reqs_tx
            .clone()
    }

    /// Create the configured transport and start PeerManager.
    /// Return the actual NetworkAddress over which this peer is listening.
    pub fn build(&mut self, executor: &Handle) -> &mut Self {
        use diem_types::network_address::Protocol::*;

        let transport_context = self
            .transport_context
            .take()
            .expect("PeerManager can only be built once");

        let protos = transport_context.supported_protocols();
        let chain_id = transport_context.chain_id;
        let enable_proxy_protocol = transport_context.enable_proxy_protocol;

        let (key, auth_mode) = match transport_context.authentication_mode {
            AuthenticationMode::MaybeMutual(key) => (
                key,
                HandshakeAuthMode::maybe_mutual(transport_context.trusted_peers),
            ),
            AuthenticationMode::Mutual(key) => (
                key,
                HandshakeAuthMode::mutual(transport_context.trusted_peers),
            ),
        };

        self.peer_manager = match self.listen_address.as_slice() {
            [Ip4(_), Tcp(_)] | [Ip6(_), Tcp(_)] => {
                Some(TransportPeerManager::Tcp(self.build_with_transport(
                    DiemNetTransport::new(
                        DIEM_TCP_TRANSPORT.clone(),
                        self.network_context.clone(),
                        self.time_service.clone(),
                        key,
                        auth_mode,
                        HANDSHAKE_VERSION,
                        chain_id,
                        protos,
                        enable_proxy_protocol,
                    ),
                    executor,
                )))
            }
            #[cfg(any(test, feature = "testing", feature = "fuzzing"))]
            [Memory(_)] => Some(TransportPeerManager::Memory(self.build_with_transport(
                DiemNetTransport::new(
                    MemoryTransport,
                    self.network_context.clone(),
                    self.time_service.clone(),
                    key,
                    auth_mode,
                    HANDSHAKE_VERSION,
                    chain_id,
                    protos,
                    enable_proxy_protocol,
                ),
                executor,
            ))),
            _ => panic!(
                "{} Unsupported listen_address: '{}', expected '/memory/<port>', \
                 '/ip4/<addr>/tcp/<port>', or '/ip6/<addr>/tcp/<port>'.",
                self.network_context, self.listen_address
            ),
        };

        self
    }

    /// Given a transport build and launch PeerManager.
    /// Return the actual NetworkAddress over which this peer is listening.
    fn build_with_transport<TTransport, TSocket>(
        &mut self,
        transport: TTransport,
        executor: &Handle,
    ) -> PeerManager<TTransport, TSocket>
    where
        TTransport: Transport<Output = Connection<TSocket>> + Send + 'static,
        TSocket: transport::TSocket,
    {
        let pm_context = self
            .peer_manager_context
            .take()
            .expect("PeerManager can only be built once");
        let inbound_rate_limiters = token_bucket_rate_limiter(
            &self.network_context,
            "inbound",
            pm_context.inbound_rate_limit_config,
        );
        let outbound_rate_limiters = token_bucket_rate_limiter(
            &self.network_context,
            "outbound",
            pm_context.outbound_rate_limit_config,
        );
        let peer_mgr = PeerManager::new(
            executor.clone(),
            self.time_service.clone(),
            transport,
            self.network_context.clone(),
            // TODO(philiphayes): peer manager should take `Vec<NetworkAddress>`
            // (which could be empty, like in client use case)
            self.listen_address.clone(),
            pm_context.trusted_peers,
            pm_context.pm_reqs_rx,
            pm_context.connection_reqs_rx,
            pm_context.upstream_handlers,
            pm_context.connection_event_handlers,
            pm_context.max_concurrent_network_reqs,
            pm_context.channel_size,
            pm_context.max_frame_size,
            pm_context.inbound_connection_limit,
            inbound_rate_limiters,
            outbound_rate_limiters,
        );

        // PeerManager constructor appends a public key to the listen_address.
        self.listen_address = peer_mgr.listen_addr().clone();

        peer_mgr
    }

    fn start_peer_manager<TTransport, TSocket>(
        &mut self,
        peer_manager: PeerManager<TTransport, TSocket>,
        executor: &Handle,
    ) where
        TTransport: Transport<Output = Connection<TSocket>> + Send + 'static,
        TSocket: transport::TSocket,
    {
        executor.spawn(peer_manager.start());
        debug!("{} Started peer manager", self.network_context);
    }

    pub fn start(&mut self, executor: &Handle) {
        debug!("{} Starting Peer manager", self.network_context);
        match self
            .peer_manager
            .take()
            .expect("Can only start PeerManager once")
        {
            #[cfg(any(test, feature = "testing", feature = "fuzzing"))]
            TransportPeerManager::Memory(pm) => self.start_peer_manager(pm, executor),
            TransportPeerManager::Tcp(pm) => self.start_peer_manager(pm, executor),
        }
    }

    pub fn add_connection_event_listener(&mut self) -> conn_notifs_channel::Receiver {
        self.peer_manager_context
            .as_mut()
            .expect("Cannot add an event listener if PeerManager has already been built.")
            .add_connection_event_listener()
    }

    /// Add a handler for given protocols using raw bytes.
    pub fn add_protocol_handler(
        &mut self,
        rpc_protocols: Vec<ProtocolId>,
        direct_send_protocols: Vec<ProtocolId>,
        queue_preference: QueueStyle,
        max_queue_size_per_peer: usize,
        counter: Option<&'static IntCounterVec>,
    ) -> (
        PeerManagerRequestSender,
        diem_channel::Receiver<(PeerId, ProtocolId), PeerManagerNotification>,
        ConnectionRequestSender,
        conn_notifs_channel::Receiver,
    ) {
        self.transport_context
            .as_mut()
            .expect("Cannot add a protocol handler once PeerManager has been built")
            .augment_direct_send_protocols(direct_send_protocols.clone())
            .augment_rpc_protocols(rpc_protocols.clone());

        let (network_notifs_tx, network_notifs_rx) =
            diem_channel::new(queue_preference, max_queue_size_per_peer, counter);

        let pm_context = self
            .peer_manager_context
            .as_mut()
            .expect("Cannot add a protocol handler once PeerManager has been built");

        for protocol in rpc_protocols
            .iter()
            .chain(direct_send_protocols.iter())
            .cloned()
        {
            pm_context.add_upstream_handler(protocol, network_notifs_tx.clone());
        }
        let connection_notifs_rx = pm_context.add_connection_event_listener();

        (
            PeerManagerRequestSender::new(pm_context.pm_reqs_tx.clone()),
            network_notifs_rx,
            ConnectionRequestSender::new(pm_context.connection_reqs_tx.clone()),
            connection_notifs_rx,
        )
    }
}

/// Builds a token bucket rate limiter with attached metrics
fn token_bucket_rate_limiter(
    network_context: &Arc<NetworkContext>,
    label: &'static str,
    input: Option<RateLimitConfig>,
) -> TokenBucketRateLimiter<IpAddr> {
    if let Some(config) = input {
        if config.enabled {
            return TokenBucketRateLimiter::new(
                label,
                network_context.to_string(),
                config.initial_bucket_fill_percentage,
                config.ip_byte_bucket_size,
                config.ip_byte_bucket_rate,
                Some(NETWORK_RATE_LIMIT_METRICS.clone()),
            );
        }
    }
    TokenBucketRateLimiter::open(label)
}
