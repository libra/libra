// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Protocol used to exchange supported protocol information with a remote.

use crate::protocols::wire::handshake::v1::HandshakeMsg;
use bytes::BytesMut;
use futures::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use netcore::framing::{read_u16frame, write_u16frame};
use std::io;

/// The Handshake exchange protocol.
pub async fn exchange_handshake<T>(
    own_handshake: &HandshakeMsg,
    socket: &mut T,
) -> io::Result<HandshakeMsg>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Send serialized handshake message to remote peer.
    let msg = bcs::to_bytes(own_handshake).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize identity msg: {}", e),
        )
    })?;
    write_u16frame(socket, &msg).await?;
    socket.flush().await?;

    // Read handshake message from the Remote
    let mut response = BytesMut::new();
    read_u16frame(socket, &mut response).await?;
    let identity = bcs::from_bytes(&response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse identity msg: {}", e),
        )
    })?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use crate::{
        protocols::{
            identity::exchange_handshake,
            wire::handshake::v1::{HandshakeMsg, MessagingProtocolVersion},
        },
        ProtocolId,
    };
    use diem_config::network_id::NetworkId;
    use diem_types::chain_id::ChainId;
    use futures::{executor::block_on, future::join};
    use memsocket::MemorySocket;
    use std::collections::BTreeMap;

    fn build_test_connection() -> (MemorySocket, MemorySocket) {
        MemorySocket::new_pair()
    }

    #[test]
    fn simple_handshake() {
        let network_id = NetworkId::Validator;
        let chain_id = ChainId::test();
        let (mut outbound, mut inbound) = build_test_connection();

        // Create client and server handshake messages.
        let mut supported_protocols = BTreeMap::new();
        supported_protocols.insert(
            MessagingProtocolVersion::V1,
            [
                ProtocolId::ConsensusDirectSend,
                ProtocolId::MempoolDirectSend,
            ]
            .iter()
            .collect(),
        );
        let server_handshake = HandshakeMsg {
            chain_id,
            network_id: network_id.clone(),
            supported_protocols,
        };
        let mut supported_protocols = BTreeMap::new();
        supported_protocols.insert(
            MessagingProtocolVersion::V1,
            [ProtocolId::ConsensusRpc, ProtocolId::ConsensusDirectSend]
                .iter()
                .collect(),
        );
        let client_handshake = HandshakeMsg {
            supported_protocols,
            chain_id,
            network_id,
        };

        let server_handshake_clone = server_handshake.clone();
        let client_handshake_clone = client_handshake.clone();

        let server = async move {
            let handshake = exchange_handshake(&server_handshake, &mut inbound)
                .await
                .expect("Handshake fails");

            assert_eq!(
                bcs::to_bytes(&handshake).unwrap(),
                bcs::to_bytes(&client_handshake_clone).unwrap()
            );
        };

        let client = async move {
            let handshake = exchange_handshake(&client_handshake, &mut outbound)
                .await
                .expect("Handshake fails");

            assert_eq!(
                bcs::to_bytes(&handshake).unwrap(),
                bcs::to_bytes(&server_handshake_clone).unwrap()
            );
        };

        block_on(join(server, client));
    }

    #[test]
    fn handshake_chain_id_mismatch() {
        let (mut outbound, mut inbound) = MemorySocket::new_pair();

        // server state
        let server_handshake = HandshakeMsg::new_for_testing();

        // client state
        let mut client_handshake = server_handshake.clone();
        client_handshake.chain_id = ChainId::new(client_handshake.chain_id.id() + 1);

        // perform the handshake negotiation
        let server = async move {
            let remote_handshake = exchange_handshake(&server_handshake, &mut inbound)
                .await
                .unwrap();
            server_handshake
                .perform_handshake(&remote_handshake)
                .unwrap_err()
        };

        let client = async move {
            let remote_handshake = exchange_handshake(&client_handshake, &mut outbound)
                .await
                .unwrap();
            client_handshake
                .perform_handshake(&remote_handshake)
                .unwrap_err()
        };

        block_on(join(server, client));
    }

    #[test]
    fn handshake_network_id_mismatch() {
        let (mut outbound, mut inbound) = MemorySocket::new_pair();

        // server state
        let server_handshake = HandshakeMsg::new_for_testing();

        // client state
        let mut client_handshake = server_handshake.clone();
        client_handshake.network_id = NetworkId::Public;

        // perform the handshake negotiation
        let server = async move {
            let remote_handshake = exchange_handshake(&server_handshake, &mut inbound)
                .await
                .unwrap();
            server_handshake
                .perform_handshake(&remote_handshake)
                .unwrap_err()
        };

        let client = async move {
            let remote_handshake = exchange_handshake(&client_handshake, &mut outbound)
                .await
                .unwrap();
            client_handshake
                .perform_handshake(&remote_handshake)
                .unwrap_err()
        };

        block_on(join(server, client));
    }
}
