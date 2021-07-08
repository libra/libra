// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Convenience Network API for Diem

pub use crate::protocols::rpc::error::RpcError;
use crate::{
    error::NetworkError,
    peer_manager::{
        ConnectionNotification, ConnectionRequestSender, PeerManagerNotification,
        PeerManagerRequestSender,
    },
    transport::ConnectionMetadata,
    ProtocolId,
};
use bytes::Bytes;
use channel::diem_channel;
use diem_logger::prelude::*;
use diem_types::{network_address::NetworkAddress, PeerId};
use futures::{
    channel::oneshot,
    future,
    stream::{FilterMap, FusedStream, Map, Select, Stream, StreamExt},
    task::{Context, Poll},
};
use pin_project::pin_project;
use serde::{de::DeserializeOwned, Serialize};
use short_hex_str::AsShortHexStr;
use std::{cmp::min, marker::PhantomData, pin::Pin, time::Duration};

pub trait Message: DeserializeOwned + Serialize {}
impl<T: DeserializeOwned + Serialize> Message for T {}

/// Events received by network clients in a validator
///
/// An enumeration of the various types of messages that the network will be sending
/// to its clients. This differs from [`PeerNotification`] since the contents are deserialized
/// into the type `TMessage` over which `Event` is generic. Note that we assume here that for every
/// consumer of this API there's a singleton message type, `TMessage`,  which encapsulates all the
/// messages and RPCs that are received by that consumer.
///
/// [`PeerNotification`]: crate::peer::PeerNotification
#[derive(Debug)]
pub enum Event<TMessage> {
    /// New inbound direct-send message from peer.
    Message(PeerId, TMessage),
    /// New inbound rpc request. The request is fulfilled by sending the
    /// serialized response `Bytes` over the `oneshot::Sender`, where the network
    /// layer will handle sending the response over-the-wire.
    RpcRequest(PeerId, TMessage, oneshot::Sender<Result<Bytes, RpcError>>),
    /// Peer which we have a newly established connection with.
    NewPeer(ConnectionMetadata),
    /// Peer with which we've lost our connection.
    LostPeer(ConnectionMetadata),
}

/// impl PartialEq for simpler testing
impl<TMessage: PartialEq> PartialEq for Event<TMessage> {
    fn eq(&self, other: &Event<TMessage>) -> bool {
        use Event::*;
        match (self, other) {
            (Message(pid1, msg1), Message(pid2, msg2)) => pid1 == pid2 && msg1 == msg2,
            // ignore oneshot::Sender in comparison
            (RpcRequest(pid1, msg1, _), RpcRequest(pid2, msg2, _)) => pid1 == pid2 && msg1 == msg2,
            (NewPeer(metadata1), NewPeer(metadata2)) => metadata1 == metadata2,
            (LostPeer(metadata1), LostPeer(metadata2)) => metadata1 == metadata2,
            _ => false,
        }
    }
}

/// A `Stream` of `Event<TMessage>` from the lower network layer to an upper
/// network application that deserializes inbound network direct-send and rpc
/// messages into `TMessage`. Inbound messages that fail to deserialize are logged
/// and dropped.
///
/// `NetworkEvents` is really just a thin wrapper around a
/// `channel::Receiver<PeerNotification>` that deserializes inbound messages.
#[pin_project]
pub struct NetworkEvents<TMessage> {
    #[pin]
    event_stream: Select<
        FilterMap<
            diem_channel::Receiver<(PeerId, ProtocolId), PeerManagerNotification>,
            future::Ready<Option<Event<TMessage>>>,
            fn(PeerManagerNotification) -> future::Ready<Option<Event<TMessage>>>,
        >,
        Map<
            diem_channel::Receiver<PeerId, ConnectionNotification>,
            fn(ConnectionNotification) -> Event<TMessage>,
        >,
    >,
    _marker: PhantomData<TMessage>,
}

/// Trait specifying the signature for `new()` `NetworkEvents`
pub trait NewNetworkEvents {
    fn new(
        peer_mgr_notifs_rx: diem_channel::Receiver<(PeerId, ProtocolId), PeerManagerNotification>,
        connection_notifs_rx: diem_channel::Receiver<PeerId, ConnectionNotification>,
    ) -> Self;
}

impl<TMessage: Message> NewNetworkEvents for NetworkEvents<TMessage> {
    fn new(
        peer_mgr_notifs_rx: diem_channel::Receiver<(PeerId, ProtocolId), PeerManagerNotification>,
        connection_notifs_rx: diem_channel::Receiver<PeerId, ConnectionNotification>,
    ) -> Self {
        let data_event_stream = peer_mgr_notifs_rx.filter_map(
            peer_mgr_notif_to_event
                as fn(PeerManagerNotification) -> future::Ready<Option<Event<TMessage>>>,
        );
        let control_event_stream = connection_notifs_rx
            .map(control_msg_to_event as fn(ConnectionNotification) -> Event<TMessage>);
        Self {
            event_stream: ::futures::stream::select(data_event_stream, control_event_stream),
            _marker: PhantomData,
        }
    }
}

impl<TMessage> Stream for NetworkEvents<TMessage> {
    type Item = Event<TMessage>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
        self.project().event_stream.poll_next(context)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.event_stream.size_hint()
    }
}

/// Deserialize inbound direct send and rpc messages into the application `TMessage`
/// type, logging and dropping messages that fail to deserialize.
fn peer_mgr_notif_to_event<TMessage: Message>(
    notif: PeerManagerNotification,
) -> future::Ready<Option<Event<TMessage>>> {
    let maybe_event = match notif {
        PeerManagerNotification::RecvRpc(peer_id, rpc_req) => {
            match rpc_req.protocol_id.from_bytes(&rpc_req.data) {
                Ok(req_msg) => Some(Event::RpcRequest(peer_id, req_msg, rpc_req.res_tx)),
                Err(err) => {
                    let data = &rpc_req.data;
                    warn!(
                        SecurityEvent::InvalidNetworkEvent,
                        error = ?err,
                        remote_peer_id = peer_id.short_str(),
                        protocol_id = rpc_req.protocol_id,
                        data_prefix = hex::encode(&data[..min(16, data.len())]),
                    );
                    None
                }
            }
        }
        PeerManagerNotification::RecvMessage(peer_id, msg) => {
            match msg.protocol_id.from_bytes(&msg.mdata) {
                Ok(msg) => Some(Event::Message(peer_id, msg)),
                Err(err) => {
                    let data = &msg.mdata;
                    warn!(
                        SecurityEvent::InvalidNetworkEvent,
                        error = ?err,
                        remote_peer_id = peer_id.short_str(),
                        protocol_id = msg.protocol_id,
                        data_prefix = hex::encode(&data[..min(16, data.len())]),
                    );
                    None
                }
            }
        }
    };
    future::ready(maybe_event)
}

fn control_msg_to_event<TMessage>(notif: ConnectionNotification) -> Event<TMessage> {
    match notif {
        ConnectionNotification::NewPeer(metadata, _context) => Event::NewPeer(metadata),
        ConnectionNotification::LostPeer(metadata, _context, _reason) => Event::LostPeer(metadata),
    }
}

impl<TMessage> FusedStream for NetworkEvents<TMessage> {
    fn is_terminated(&self) -> bool {
        self.event_stream.is_terminated()
    }
}

/// `NetworkSender` is the generic interface from upper network applications to
/// the lower network layer. It provides the full API for network applications,
/// including sending direct-send messages, sending rpc requests, as well as
/// dialing or disconnecting from peers and updating the list of accepted public
/// keys.
///
/// `NetworkSender` is in fact a thin wrapper around a `PeerManagerRequestSender`, which in turn is
/// a thin wrapper on `diem_channel::Sender<(PeerId, ProtocolId), PeerManagerRequest>`,
/// mostly focused on providing a more ergonomic API. However, network applications will usually
/// provide their own thin wrapper around `NetworkSender` that narrows the API to the specific
/// interface they need. For instance, `mempool` only requires direct-send functionality so its
/// `MempoolNetworkSender` only exposes a `send_to` function.
///
/// Provide Protobuf wrapper over `[peer_manager::PeerManagerRequestSender]`
#[derive(Clone)]
pub struct NetworkSender<TMessage> {
    peer_mgr_reqs_tx: PeerManagerRequestSender,
    connection_reqs_tx: ConnectionRequestSender,
    _marker: PhantomData<TMessage>,
}

/// Trait specifying the signature for `new()` `NetworkSender`s
pub trait NewNetworkSender {
    fn new(
        peer_mgr_reqs_tx: PeerManagerRequestSender,
        connection_reqs_tx: ConnectionRequestSender,
    ) -> Self;
}

impl<TMessage> NewNetworkSender for NetworkSender<TMessage> {
    fn new(
        peer_mgr_reqs_tx: PeerManagerRequestSender,
        connection_reqs_tx: ConnectionRequestSender,
    ) -> Self {
        Self {
            peer_mgr_reqs_tx,
            connection_reqs_tx,
            _marker: PhantomData,
        }
    }
}

impl<TMessage> NetworkSender<TMessage> {
    /// Request that a given Peer be dialed at the provided `NetworkAddress` and
    /// synchronously wait for the request to be performed.
    pub async fn dial_peer(
        &mut self,
        peer: PeerId,
        addr: NetworkAddress,
    ) -> Result<(), NetworkError> {
        self.connection_reqs_tx.dial_peer(peer, addr).await?;
        Ok(())
    }

    /// Request that a given Peer be disconnected and synchronously wait for the request to be
    /// performed.
    pub async fn disconnect_peer(&mut self, peer: PeerId) -> Result<(), NetworkError> {
        self.connection_reqs_tx.disconnect_peer(peer).await?;
        Ok(())
    }
}

impl<TMessage: Message> NetworkSender<TMessage> {
    /// Send a protobuf message to a single recipient. Provides a wrapper over
    /// `[peer_manager::PeerManagerRequestSender::send_to]`.
    pub fn send_to(
        &mut self,
        recipient: PeerId,
        protocol: ProtocolId,
        message: TMessage,
    ) -> Result<(), NetworkError> {
        let mdata = protocol.to_bytes(&message)?.into();
        self.peer_mgr_reqs_tx.send_to(recipient, protocol, mdata)?;
        Ok(())
    }

    /// Send a protobuf message to a many recipients. Provides a wrapper over
    /// `[peer_manager::PeerManagerRequestSender::send_to_many]`.
    pub fn send_to_many(
        &mut self,
        recipients: impl Iterator<Item = PeerId>,
        protocol: ProtocolId,
        message: TMessage,
    ) -> Result<(), NetworkError> {
        // Serialize message.
        let mdata = protocol.to_bytes(&message)?.into();
        self.peer_mgr_reqs_tx
            .send_to_many(recipients, protocol, mdata)?;
        Ok(())
    }

    /// Send a protobuf rpc request to a single recipient while handling
    /// serialization and deserialization of the request and response respectively.
    /// Assumes that the request and response both have the same message type.
    pub async fn send_rpc(
        &mut self,
        recipient: PeerId,
        protocol: ProtocolId,
        req_msg: TMessage,
        timeout: Duration,
    ) -> Result<TMessage, RpcError> {
        // serialize request
        let req_data = protocol.to_bytes(&req_msg)?.into();
        let res_data = self
            .peer_mgr_reqs_tx
            .send_rpc(recipient, protocol, req_data, timeout)
            .await?;
        let res_msg: TMessage = protocol.from_bytes(&res_data)?;
        Ok(res_msg)
    }
}
