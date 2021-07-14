// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::{
        INBOUND_RPC_TIMEOUT_MS, MAX_CONCURRENT_INBOUND_RPCS, MAX_CONCURRENT_OUTBOUND_RPCS,
        MAX_FRAME_SIZE, NETWORK_CHANNEL_SIZE,
    },
    peer::{DisconnectReason, Peer, PeerNotification, PeerRequest},
    peer_manager::TransportNotification,
    protocols::{
        direct_send::Message,
        rpc::{error::RpcError, InboundRpcRequest, OutboundRpcRequest},
        wire::{
            handshake::v1::{MessagingProtocolVersion, SupportedProtocols},
            messaging::v1::{
                DirectSendMsg, NetworkMessage, NetworkMessageSink, NetworkMessageStream,
                RpcRequest, RpcResponse,
            },
        },
    },
    transport::{Connection, ConnectionId, ConnectionMetadata},
    ProtocolId,
};
use bytes::Bytes;
use channel::{self, diem_channel, message_queues::QueueStyle};
use diem_config::{config::PeerRole, network_id::NetworkContext};
use diem_time_service::{MockTimeService, TimeService};
use diem_types::{network_address::NetworkAddress, PeerId};
use futures::{
    channel::oneshot,
    future::{self, FutureExt},
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    stream::{StreamExt, TryStreamExt},
    SinkExt,
};
use memsocket::MemorySocket;
use netcore::transport::ConnectionOrigin;
use std::{collections::HashSet, str::FromStr, time::Duration};
use tokio::runtime::{Handle, Runtime};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt,
};

static PROTOCOL: ProtocolId = ProtocolId::MempoolDirectSend;

fn build_test_peer(
    executor: Handle,
    time_service: TimeService,
    origin: ConnectionOrigin,
) -> (
    Peer<MemorySocket>,
    PeerHandle,
    MemorySocket,
    channel::Receiver<TransportNotification<MemorySocket>>,
    diem_channel::Receiver<ProtocolId, PeerNotification>,
) {
    let (a, b) = MemorySocket::new_pair();
    let peer_id = PeerId::random();
    let connection = Connection {
        metadata: ConnectionMetadata::new(
            peer_id,
            ConnectionId::default(),
            NetworkAddress::from_str("/ip4/127.0.0.1/tcp/8081").unwrap(),
            origin,
            MessagingProtocolVersion::V1,
            SupportedProtocols::empty(),
            PeerRole::Unknown,
        ),
        socket: a,
    };

    let (connection_notifs_tx, connection_notifs_rx) = channel::new_test(1);
    let (peer_reqs_tx, peer_reqs_rx) =
        diem_channel::new(QueueStyle::FIFO, NETWORK_CHANNEL_SIZE, None);
    let (peer_notifs_tx, peer_notifs_rx) =
        diem_channel::new(QueueStyle::FIFO, NETWORK_CHANNEL_SIZE, None);

    let peer = Peer::new(
        NetworkContext::mock(),
        executor,
        time_service,
        connection,
        connection_notifs_tx,
        peer_reqs_rx,
        peer_notifs_tx,
        Duration::from_millis(INBOUND_RPC_TIMEOUT_MS),
        MAX_CONCURRENT_INBOUND_RPCS,
        MAX_CONCURRENT_OUTBOUND_RPCS,
        MAX_FRAME_SIZE,
        None,
        None,
    );
    let peer_handle = PeerHandle(peer_reqs_tx);

    (peer, peer_handle, b, connection_notifs_rx, peer_notifs_rx)
}

fn build_test_connected_peers(
    executor: Handle,
    time_service: TimeService,
) -> (
    (
        Peer<MemorySocket>,
        PeerHandle,
        channel::Receiver<TransportNotification<MemorySocket>>,
        diem_channel::Receiver<ProtocolId, PeerNotification>,
    ),
    (
        Peer<MemorySocket>,
        PeerHandle,
        channel::Receiver<TransportNotification<MemorySocket>>,
        diem_channel::Receiver<ProtocolId, PeerNotification>,
    ),
) {
    let (peer_a, peer_handle_a, connection_a, connection_notifs_rx_a, peer_notifs_rx_a) =
        build_test_peer(
            executor.clone(),
            time_service.clone(),
            ConnectionOrigin::Inbound,
        );
    let (mut peer_b, peer_handle_b, _connection_b, connection_notifs_rx_b, peer_notifs_rx_b) =
        build_test_peer(executor, time_service, ConnectionOrigin::Outbound);

    // Make sure both peers are connected
    peer_b.connection = Some(connection_a);
    (
        (
            peer_a,
            peer_handle_a,
            connection_notifs_rx_a,
            peer_notifs_rx_a,
        ),
        (
            peer_b,
            peer_handle_b,
            connection_notifs_rx_b,
            peer_notifs_rx_b,
        ),
    )
}

fn build_network_sink_stream(
    connection: &mut MemorySocket,
) -> (
    NetworkMessageSink<impl AsyncWrite + '_>,
    NetworkMessageStream<impl AsyncRead + '_>,
) {
    let (read_half, write_half) = tokio::io::split(connection.compat());
    let sink = NetworkMessageSink::new(write_half.compat_write(), MAX_FRAME_SIZE, None);
    let stream = NetworkMessageStream::new(read_half.compat(), MAX_FRAME_SIZE, None);
    (sink, stream)
}

async fn assert_disconnected_event(
    peer_id: PeerId,
    reason: DisconnectReason,
    connection_notifs_rx: &mut channel::Receiver<TransportNotification<MemorySocket>>,
) {
    match connection_notifs_rx.next().await {
        Some(TransportNotification::Disconnected(metadata, actual_reason)) => {
            assert_eq!(metadata.remote_peer_id, peer_id);
            assert_eq!(actual_reason, reason);
        }
        event => panic!("Expected a Disconnected, received: {:?}", event),
    }
}

#[derive(Clone)]
struct PeerHandle(diem_channel::Sender<ProtocolId, PeerRequest>);

impl PeerHandle {
    fn send_direct_send(&mut self, message: Message) {
        self.0
            .push(message.protocol_id, PeerRequest::SendDirectSend(message))
            .unwrap()
    }

    async fn send_rpc_request(
        &mut self,
        protocol_id: ProtocolId,
        data: Bytes,
        timeout: Duration,
    ) -> Result<Bytes, RpcError> {
        let (res_tx, res_rx) = oneshot::channel();
        let request = OutboundRpcRequest {
            protocol_id,
            data,
            res_tx,
            timeout,
        };
        self.0.push(protocol_id, PeerRequest::SendRpc(request))?;
        let response_data = res_rx.await??;
        Ok(response_data)
    }
}

// Sending an outbound DirectSend should write it to the wire.
#[test]
fn peer_send_message() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, mut peer_handle, mut connection, _connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut client_sink, mut client_stream) = build_network_sink_stream(&mut connection);

    let send_msg = Message {
        protocol_id: PROTOCOL,
        mdata: Bytes::from("hello world"),
    };
    let recv_msg = NetworkMessage::DirectSendMsg(DirectSendMsg {
        protocol_id: PROTOCOL,
        priority: 0,
        raw_msg: Vec::from("hello world"),
    });

    let client = async {
        // Client should receive the direct send messages.
        for _ in 0..30 {
            let msg = client_stream.next().await.unwrap().unwrap();
            assert_eq!(msg, recv_msg);
        }
        // Client then closes the connection.
        client_sink.close().await.unwrap();
    };

    let server = async {
        // Server sends some direct send messages.
        for _ in 0..30 {
            peer_handle.send_direct_send(send_msg.clone());
        }
    };
    rt.block_on(future::join3(peer.start(), server, client));
}

// Reading an inbound DirectSendMsg off the wire should notify the PeerManager of
// an inbound DirectSend.
#[test]
fn peer_recv_message() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, _peer_handle, connection, _connection_notifs_rx, mut peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );

    let send_msg = NetworkMessage::DirectSendMsg(DirectSendMsg {
        protocol_id: PROTOCOL,
        priority: 0,
        raw_msg: Vec::from("hello world"),
    });
    let recv_msg = PeerNotification::RecvMessage(Message {
        protocol_id: PROTOCOL,
        mdata: Bytes::from("hello world"),
    });

    let client = async move {
        let mut connection = NetworkMessageSink::new(connection, MAX_FRAME_SIZE, None);
        for _ in 0..30 {
            // The client should then send the network message.
            connection.send(&send_msg).await.unwrap();
        }
        // Client then closes connection.
        connection.close().await.unwrap();
    };

    let server = async move {
        for _ in 0..30 {
            // Wait to receive notification of DirectSendMsg from Peer.
            let received = peer_notifs_rx.next().await.unwrap();
            assert_eq!(recv_msg, received);
        }
    };
    rt.block_on(future::join3(peer.start(), server, client));
}

// Two connected Peer actors should be able to send/recv a DirectSend from each
// other and then shutdown gracefully.
#[test]
fn peers_send_message_concurrent() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (
        (peer_a, mut peer_handle_a, mut connection_notifs_rx_a, mut peer_notifs_rx_a),
        (peer_b, mut peer_handle_b, mut connection_notifs_rx_b, mut peer_notifs_rx_b),
    ) = build_test_connected_peers(rt.handle().clone(), TimeService::mock());

    let remote_peer_id_a = peer_a.remote_peer_id();
    let remote_peer_id_b = peer_b.remote_peer_id();

    let test = async move {
        let msg_a = Message {
            protocol_id: PROTOCOL,
            mdata: Bytes::from("hello world"),
        };
        let msg_b = Message {
            protocol_id: PROTOCOL,
            mdata: Bytes::from("namaste"),
        };

        // Peer A -> msg_a -> Peer B
        peer_handle_a.send_direct_send(msg_a.clone());
        // Peer A <- msg_b <- Peer B
        peer_handle_b.send_direct_send(msg_b.clone());

        // Check that each peer received the other's message
        let notif_a = peer_notifs_rx_a.next().await;
        let notif_b = peer_notifs_rx_b.next().await;
        assert_eq!(notif_a, Some(PeerNotification::RecvMessage(msg_b)));
        assert_eq!(notif_b, Some(PeerNotification::RecvMessage(msg_a)));

        // Shut one peers and the other should shutdown due to ConnectionLost
        drop(peer_handle_a);

        // Check that we received both shutdown events
        assert_disconnected_event(
            remote_peer_id_a,
            DisconnectReason::Requested,
            &mut connection_notifs_rx_a,
        )
        .await;
        assert_disconnected_event(
            remote_peer_id_b,
            DisconnectReason::ConnectionLost,
            &mut connection_notifs_rx_b,
        )
        .await;
    };

    rt.block_on(future::join3(peer_a.start(), peer_b.start(), test));
}

#[test]
fn peer_recv_rpc() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, _peer_handle, mut connection, _connection_notifs_rx, mut peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut client_sink, mut client_stream) = build_network_sink_stream(&mut connection);

    let send_msg = NetworkMessage::RpcRequest(RpcRequest {
        request_id: 123,
        protocol_id: PROTOCOL,
        priority: 0,
        raw_request: Vec::from("hello world"),
    });
    let recv_msg = PeerNotification::RecvRpc(InboundRpcRequest {
        protocol_id: PROTOCOL,
        data: Bytes::from("hello world"),
        res_tx: oneshot::channel().0,
    });
    let resp_msg = NetworkMessage::RpcResponse(RpcResponse {
        request_id: 123,
        priority: 0,
        raw_response: Vec::from("goodbye world"),
    });

    let client = async move {
        for _ in 0..30 {
            // Client should send the rpc request.
            client_sink.send(&send_msg).await.unwrap();
            // Client should then receive the expected rpc response.
            let received = client_stream.next().await.unwrap().unwrap();
            assert_eq!(received, resp_msg);
        }
        // Client then closes connection.
        client_sink.close().await.unwrap();
    };
    let server = async move {
        for _ in 0..30 {
            // Wait to receive RpcRequest from Peer.
            let received = peer_notifs_rx.next().await.unwrap();
            assert_eq!(recv_msg, received);

            // Send response to rpc.
            match received {
                PeerNotification::RecvRpc(req) => {
                    let response = Ok(Bytes::from("goodbye world"));
                    req.res_tx.send(response).unwrap()
                }
                _ => panic!("Unexpected PeerNotification: {:?}", received),
            }
        }
    };
    rt.block_on(future::join3(peer.start(), server, client));
}

#[test]
fn peer_recv_rpc_concurrent() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, _peer_handle, mut connection, _connection_notifs_rx, mut peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut client_sink, mut client_stream) = build_network_sink_stream(&mut connection);

    let send_msg = NetworkMessage::RpcRequest(RpcRequest {
        request_id: 123,
        protocol_id: PROTOCOL,
        priority: 0,
        raw_request: Vec::from("hello world"),
    });
    let recv_msg = PeerNotification::RecvRpc(InboundRpcRequest {
        protocol_id: PROTOCOL,
        data: Bytes::from("hello world"),
        res_tx: oneshot::channel().0,
    });
    let resp_msg = NetworkMessage::RpcResponse(RpcResponse {
        request_id: 123,
        priority: 0,
        raw_response: Vec::from("goodbye world"),
    });

    let client = async move {
        // The client should send many rpc requests.
        for _ in 0..30 {
            client_sink.send(&send_msg).await.unwrap();
        }

        // The client should then receive the expected rpc responses.
        for _ in 0..30 {
            let received = client_stream.next().await.unwrap().unwrap();
            assert_eq!(received, resp_msg);
        }

        // Client then closes connection.
        client_sink.close().await.unwrap();
    };
    let server = async move {
        let mut res_txs = vec![];

        // Wait to receive RpcRequests from Peer.
        for _ in 0..30 {
            let received = peer_notifs_rx.next().await.unwrap();
            assert_eq!(recv_msg, received);
            match received {
                PeerNotification::RecvRpc(req) => res_txs.push(req.res_tx),
                _ => panic!("Unexpected PeerNotification: {:?}", received),
            };
        }

        // Send all rpc responses to client.
        for res_tx in res_txs.into_iter() {
            let response = Bytes::from("goodbye world");
            res_tx.send(Ok(response)).unwrap();
        }
    };
    rt.block_on(future::join3(peer.start(), server, client));
}

#[test]
fn peer_recv_rpc_timeout() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let mock_time = MockTimeService::new();
    let (peer, _peer_handle, mut connection, _connection_notifs_rx, mut peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            mock_time.clone().into(),
            ConnectionOrigin::Inbound,
        );
    let (mut client_sink, client_stream) = build_network_sink_stream(&mut connection);

    let send_msg = NetworkMessage::RpcRequest(RpcRequest {
        request_id: 123,
        protocol_id: PROTOCOL,
        priority: 0,
        raw_request: Vec::from("hello world"),
    });
    let recv_msg = PeerNotification::RecvRpc(InboundRpcRequest {
        protocol_id: PROTOCOL,
        data: Bytes::from("hello world"),
        res_tx: oneshot::channel().0,
    });

    let test = async move {
        // Client sends the rpc request.
        client_sink.send(&send_msg).await.unwrap();

        // Server receives the rpc request from client.
        let received = peer_notifs_rx.next().await.unwrap();
        assert_eq!(received, recv_msg);

        // Pull out the request completion handle.
        let mut res_tx = match received {
            PeerNotification::RecvRpc(req) => req.res_tx,
            _ => panic!("Unexpected PeerNotification: {:?}", received),
        };

        // The rpc response channel should still be open since we haven't timed out yet.
        assert!(!res_tx.is_canceled());

        // Advancing time should trigger the timeout.
        mock_time.advance_ms_async(INBOUND_RPC_TIMEOUT_MS).await;

        // The rpc response channel should be canceled from the timeout.
        assert!(res_tx.is_canceled());
        res_tx.cancellation().await;

        // Client then half-closes write side.
        client_sink.close().await.unwrap();

        // Client shouldn't have received any messages.
        let messages = client_stream.try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(messages, vec![]);
    };
    rt.block_on(future::join(peer.start(), test));
}

#[test]
fn peer_recv_rpc_cancel() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, _peer_handle, mut connection, _connection_notifs_rx, mut peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut client_sink, client_stream) = build_network_sink_stream(&mut connection);

    let send_msg = NetworkMessage::RpcRequest(RpcRequest {
        request_id: 123,
        protocol_id: PROTOCOL,
        priority: 0,
        raw_request: Vec::from("hello world"),
    });
    let recv_msg = PeerNotification::RecvRpc(InboundRpcRequest {
        protocol_id: PROTOCOL,
        data: Bytes::from("hello world"),
        res_tx: oneshot::channel().0,
    });

    let test = async move {
        // Client sends the rpc request.
        client_sink.send(&send_msg).await.unwrap();

        // Server receives the rpc request from client.
        let received = peer_notifs_rx.next().await.unwrap();
        assert_eq!(received, recv_msg);

        // Pull out the request completion handle.
        let res_tx = match received {
            PeerNotification::RecvRpc(req) => req.res_tx,
            _ => panic!("Unexpected PeerNotification: {:?}", received),
        };

        // The rpc response channel should still be open since we haven't timed out yet.
        assert!(!res_tx.is_canceled());

        // Server drops the response completion handle to cancel the request.
        drop(res_tx);

        // Client then half-closes write side.
        client_sink.close().await.unwrap();

        // Client shouldn't have received any messages.
        let messages = client_stream.try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(messages, vec![]);
    };
    rt.block_on(future::join(peer.start(), test));
}

#[test]
fn peer_send_rpc() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, mut peer_handle, mut connection, _connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut server_sink, mut server_stream) = build_network_sink_stream(&mut connection);
    let timeout = Duration::from_millis(10_000);

    let mut request_ids = HashSet::new();

    let client = async move {
        for _ in 0..30 {
            // Send RpcRequest to server and await response data.
            let response = peer_handle
                .send_rpc_request(PROTOCOL, Bytes::from(&b"hello world"[..]), timeout)
                .await
                .unwrap();
            assert_eq!(response, Bytes::from(&b"goodbye world"[..]));
        }
        // Client then closes connection.
    };
    let server = async move {
        for _ in 0..30 {
            // Server should then receive the expected rpc request.
            let received = server_stream.next().await.unwrap().unwrap();
            let received = match received {
                NetworkMessage::RpcRequest(request) => request,
                _ => panic!("Expected RpcRequest; unexpected: {:?}", received),
            };

            assert_eq!(received.protocol_id, PROTOCOL);
            assert_eq!(received.priority, 0);
            assert_eq!(received.raw_request, b"hello world");

            assert!(
                request_ids.insert(received.request_id),
                "should not receive requests with duplicate request ids: {}",
                received.request_id,
            );

            let response = NetworkMessage::RpcResponse(RpcResponse {
                request_id: received.request_id,
                priority: 0,
                raw_response: Vec::from(&b"goodbye world"[..]),
            });

            // Server should send the rpc request.
            server_sink.send(&response).await.unwrap();
        }
        assert!(matches!(server_stream.next().await, None));
    };
    rt.block_on(future::join3(peer.start(), server, client));
}

#[test]
fn peer_send_rpc_concurrent() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, peer_handle, mut connection, _connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut server_sink, mut server_stream) = build_network_sink_stream(&mut connection);
    let timeout = Duration::from_millis(10_000);

    let mut request_ids = HashSet::new();

    let client = async move {
        // Send a batch of RpcRequest to server and await response data.
        let mut send_recv_futures = Vec::new();
        for _ in 0..30 {
            let mut peer_handle = peer_handle.clone();
            let send_recv = async move {
                let response = peer_handle
                    .send_rpc_request(PROTOCOL, Bytes::from(&b"hello world"[..]), timeout)
                    .await
                    .unwrap();
                assert_eq!(response, Bytes::from(&b"goodbye world"[..]));
            };
            send_recv_futures.push(send_recv.boxed());
        }

        // Wait for all the responses.
        future::join_all(send_recv_futures).await;

        // Client then closes connection.
    };
    let server = async move {
        for _ in 0..30 {
            // Server should then receive the expected rpc request.
            let received = server_stream.next().await.unwrap().unwrap();

            let received = match received {
                NetworkMessage::RpcRequest(request) => request,
                _ => panic!("Expected RpcRequest; unexpected: {:?}", received),
            };

            assert_eq!(received.protocol_id, PROTOCOL);
            assert_eq!(received.priority, 0);
            assert_eq!(received.raw_request, b"hello world");

            assert!(
                request_ids.insert(received.request_id),
                "should not receive requests with duplicate request ids: {}",
                received.request_id,
            );

            let response = NetworkMessage::RpcResponse(RpcResponse {
                request_id: received.request_id,
                priority: 0,
                raw_response: Vec::from(&b"goodbye world"[..]),
            });

            // Server should send the rpc request.
            server_sink.send(&response).await.unwrap();
        }
        assert!(matches!(server_stream.next().await, None));
    };
    rt.block_on(future::join3(peer.start(), server, client));
}

#[test]
fn peer_send_rpc_cancel() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, mut peer_handle, mut connection, _connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let (mut server_sink, mut server_stream) = build_network_sink_stream(&mut connection);
    let timeout = Duration::from_millis(10_000);

    let test = async move {
        // Client sends rpc request.
        let (response_tx, mut response_rx) = oneshot::channel();
        let request = PeerRequest::SendRpc(OutboundRpcRequest {
            protocol_id: PROTOCOL,
            data: Bytes::from(&b"hello world"[..]),
            res_tx: response_tx,
            timeout,
        });
        peer_handle.0.push(PROTOCOL, request).unwrap();

        // Server receives the rpc request from client.
        let received = server_stream.next().await.unwrap().unwrap();
        let received = match received {
            NetworkMessage::RpcRequest(request) => request,
            _ => panic!("Expected RpcRequest; unexpected: {:?}", received),
        };

        assert_eq!(received.protocol_id, PROTOCOL);
        assert_eq!(received.priority, 0);
        assert_eq!(received.raw_request, b"hello world");

        // Request should still be live. Ok(_) means the sender is not dropped.
        // Ok(None) means there is no response yet.
        assert!(matches!(response_rx.try_recv(), Ok(None)));

        // Client cancels the request.
        drop(response_rx);

        // Server sending an expired response is fine.
        let response = NetworkMessage::RpcResponse(RpcResponse {
            request_id: received.request_id,
            priority: 0,
            raw_response: Vec::from(&b"goodbye world"[..]),
        });
        server_sink.send(&response).await.unwrap();

        // Make sure the peer actor actually saw the message.
        tokio::task::yield_now().await;

        // Keep the peer_handle alive until the end to avoid prematurely closing
        // the connection.
        drop(peer_handle);
    };
    rt.block_on(future::join(peer.start(), test));
}

#[test]
fn peer_send_rpc_timeout() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let mock_time = MockTimeService::new();
    let (peer, mut peer_handle, mut connection, _connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            mock_time.clone().into(),
            ConnectionOrigin::Inbound,
        );
    let (mut server_sink, mut server_stream) = build_network_sink_stream(&mut connection);
    let timeout = Duration::from_millis(10_000);

    let test = async move {
        // Client sends rpc request.
        let (response_tx, mut response_rx) = oneshot::channel();
        let request = PeerRequest::SendRpc(OutboundRpcRequest {
            protocol_id: PROTOCOL,
            data: Bytes::from(&b"hello world"[..]),
            res_tx: response_tx,
            timeout,
        });
        peer_handle.0.push(PROTOCOL, request).unwrap();

        // Server receives the rpc request from client.
        let received = server_stream.next().await.unwrap().unwrap();
        let received = match received {
            NetworkMessage::RpcRequest(request) => request,
            _ => panic!("Expected RpcRequest; unexpected: {:?}", received),
        };

        assert_eq!(received.protocol_id, PROTOCOL);
        assert_eq!(received.priority, 0);
        assert_eq!(received.raw_request, b"hello world");

        // Request should still be live. Ok(_) means the sender is not dropped.
        // Ok(None) means there is no response yet.
        assert!(matches!(response_rx.try_recv(), Ok(None)));

        // Advancing time should cause the client request timeout to elapse.
        mock_time.advance_async(timeout).await;

        // Client cancels the request.
        assert!(matches!(response_rx.await, Ok(Err(RpcError::TimedOut))));

        // Server sending an expired response is fine.
        let response = NetworkMessage::RpcResponse(RpcResponse {
            request_id: received.request_id,
            priority: 0,
            raw_response: Vec::from(&b"goodbye world"[..]),
        });
        server_sink.send(&response).await.unwrap();

        // Make sure the peer actor actually saw the message.
        tokio::task::yield_now().await;

        // Keep the peer_handle alive until the end to avoid prematurely closing
        // the connection.
        drop(peer_handle);
    };
    rt.block_on(future::join(peer.start(), test));
}

// PeerManager can request a Peer to shutdown.
#[test]
fn peer_disconnect_request() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, peer_handle, _connection, mut connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let remote_peer_id = peer.remote_peer_id();

    let test = async move {
        drop(peer_handle);
        assert_disconnected_event(
            remote_peer_id,
            DisconnectReason::Requested,
            &mut connection_notifs_rx,
        )
        .await;
    };

    rt.block_on(future::join(peer.start(), test));
}

// Peer will shutdown if the underlying connection is lost.
#[test]
fn peer_disconnect_connection_lost() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, _peer_handle, mut connection, mut connection_notifs_rx, _peer_notifs_rx) =
        build_test_peer(
            rt.handle().clone(),
            TimeService::mock(),
            ConnectionOrigin::Inbound,
        );
    let remote_peer_id = peer.remote_peer_id();

    let test = async move {
        connection.close().await.unwrap();
        assert_disconnected_event(
            remote_peer_id,
            DisconnectReason::ConnectionLost,
            &mut connection_notifs_rx,
        )
        .await;
    };
    rt.block_on(future::join(peer.start(), test));
}

#[test]
fn peer_terminates_when_request_tx_has_dropped() {
    ::diem_logger::Logger::init_for_testing();
    let rt = Runtime::new().unwrap();
    let (peer, peer_handle, _connection, _connection_notifs_rx, _peer_notifs_rx) = build_test_peer(
        rt.handle().clone(),
        TimeService::mock(),
        ConnectionOrigin::Inbound,
    );

    let drop = async move {
        // Drop peer handle.
        drop(peer_handle);
    };
    rt.block_on(future::join(peer.start(), drop));
}
