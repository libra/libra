// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    json_rpc::JsonRpcClientWrapper,
    validator_set::{validator_set_full_node_addresses, validator_set_validator_addresses},
};
use anyhow::{format_err, Context, Result};
use diem_config::{
    config::{RoleType, HANDSHAKE_VERSION},
    network_id::{NetworkContext, NetworkId},
};
use diem_crypto::{
    traits::ValidCryptoMaterialStringExt,
    x25519::{self, PRIVATE_KEY_SIZE},
};
use diem_management::error::Error;
use diem_network_address_encryption::Encryptor;
use diem_secure_storage::{InMemoryStorage, Storage};
use diem_time_service::TimeService;
use diem_types::{
    account_address,
    chain_id::ChainId,
    network_address::{
        encrypted::{Key, KeyVersion, KEY_LEN},
        NetworkAddress,
    },
    PeerId,
};
use fallible::copy_from_slice::copy_slice_to_vec;
use futures::{future, AsyncReadExt, AsyncWriteExt};
use netcore::transport::{tcp::TcpTransport, Transport};
use network::{
    noise::{HandshakeAuthMode, NoiseUpgrader},
    protocols::wire::handshake::v1::SupportedProtocols,
    transport::{DiemNetTransport, DIEM_TCP_TRANSPORT, TRANSPORT_TIMEOUT},
};
use std::sync::Arc;
use structopt::StructOpt;
use tokio::runtime::Runtime;

#[derive(Debug, StructOpt)]
pub struct CheckEndpoint {
    /// `NetworkAddress` of remote server interface
    #[structopt(long)]
    address: NetworkAddress,
    /// `ChainId` of remote server
    #[structopt(long)]
    chain_id: ChainId,
    /// `NetworkId` of remote server interface
    #[structopt(long)]
    network_id: NetworkId,
    /// `PrivateKey` to connect to remote server
    #[structopt(long, parse(try_from_str = parse_private_key_hex))]
    private_key: Option<x25519::PrivateKey>,
    /// Skip handshake for network checking
    #[structopt(long)]
    no_handshake: bool,
}

fn parse_private_key_hex(src: &str) -> Result<x25519::PrivateKey, Error> {
    x25519::PrivateKey::from_encoded_string(src.trim())
        .map_err(|err| Error::CommandArgumentError(format!("{:?}", err)))
}

impl CheckEndpoint {
    pub fn execute(self) -> Result<String, Error> {
        validate_address(&self.address)?;

        let private_key = self.private_key.unwrap_or_else(|| {
            let dummy = [0; PRIVATE_KEY_SIZE];
            x25519::PrivateKey::from(dummy)
        });
        let (peer_id, public_key) = private_key_to_public_info(&private_key);

        // RoleType doesn't matter, but the `NetworkId` and `PeerId` are used in handshakes
        let network_context = Arc::new(NetworkContext::new(
            RoleType::FullNode,
            self.network_id.clone(),
            peer_id,
        ));

        let transport = DiemNetTransport::new(
            DIEM_TCP_TRANSPORT.clone(),
            network_context,
            TimeService::real(),
            private_key,
            HandshakeAuthMode::server_only(),
            HANDSHAKE_VERSION,
            self.chain_id,
            SupportedProtocols::all(),
            false,
        );

        println!(
            "\n[checker] Checking connection to '{}', our peer_id: {}, our pubkey: {}",
            self.address, peer_id, public_key,
        );
        let rt = Runtime::new().unwrap();
        rt.block_on(check_endpoint(&transport, self.address, self.no_handshake))
    }
}

#[derive(Debug, StructOpt)]
pub struct CheckValidatorSetEndpoints {
    /// JSON-RPC Endpoint (e.g. http://localhost:8080)
    #[structopt(long, required_unless = "config")]
    json_server: String,
    /// Specifies whether or not to evaluate validators or fullnodes
    #[structopt(long)]
    role: RoleType,
    /// The expected on-chain key, only required for validator checks
    #[structopt(long, required_if("role", "validator"), parse(try_from_str = parse_validator_key_hex))]
    address_encryption_key: Option<Key>,
    /// The expected on-chain key version, only required for validator checks
    #[structopt(long, required_if("role", "validator"))]
    version: Option<KeyVersion>,
    /// `ChainId` of remote server
    #[structopt(long)]
    chain_id: ChainId,
    /// Private key to connect to remote server
    #[structopt(long, parse(try_from_str = parse_private_key_hex))]
    private_key: Option<x25519::PrivateKey>,
    /// Skip handshake for network checking
    #[structopt(long)]
    no_handshake: bool,
}

fn parse_validator_key_hex(src: &str) -> Result<Key, Error> {
    let value_slice = hex::decode(src.trim())
        .map_err(|_| Error::CommandArgumentError("Not a valid encryption key".to_string()))?;

    let mut value = [0; KEY_LEN];
    copy_slice_to_vec(&value_slice, &mut value)
        .map_err(|e| Error::CommandArgumentError(format!("{}", e)))?;
    Ok(value)
}

impl CheckValidatorSetEndpoints {
    pub fn execute(self) -> Result<String, Error> {
        let is_validator = self.role.is_validator();
        let no_handshake = self.no_handshake;
        let client = JsonRpcClientWrapper::new(self.json_server);

        let private_key = if let Some(private_key) = self.private_key {
            private_key
        } else if is_validator && !self.no_handshake {
            return Err(Error::CommandArgumentError(
                "Must provide a private key for validators".into(),
            ));
        } else {
            let dummy = [0; PRIVATE_KEY_SIZE];
            x25519::PrivateKey::from(dummy)
        };

        let nodes = if is_validator {
            let address_encryption_key = self.address_encryption_key.ok_or_else(|| {
                Error::CommandArgumentError(
                    "Must provide address encryption key for validators".into(),
                )
            })?;
            let version = self.version.ok_or_else(|| {
                Error::CommandArgumentError("Must provide version for validators".into())
            })?;

            // Following unwraps shouldn't fail as it is in memory
            let mut encryptor = Encryptor::new(Storage::InMemoryStorage(InMemoryStorage::new()));
            encryptor.initialize().unwrap();
            encryptor.add_key(version, address_encryption_key).unwrap();
            encryptor.set_current_version(version).unwrap();

            validator_set_validator_addresses(client, &encryptor, None)?
        } else {
            validator_set_full_node_addresses(client, None)?
        };

        println!("[discovery] {} network addresses", self.role);
        println!("{:>15} : Network Addresses", "Node Name");
        for (name, _, addrs) in nodes.iter() {
            println!("{:>15} : {:?}", name, addrs);
        }

        // Build a single upgrade context to run all the checks
        let network_id = if is_validator {
            NetworkId::Validator
        } else {
            NetworkId::Public
        };

        let (peer_id, public_key) = private_key_to_public_info(&private_key);

        // RoleType doesn't matter, but the `NetworkId` and `PeerId` are used in handshakes
        let network_context =
            Arc::new(NetworkContext::new(RoleType::FullNode, network_id, peer_id));

        let transport = DiemNetTransport::new(
            DIEM_TCP_TRANSPORT.clone(),
            network_context,
            TimeService::real(),
            private_key,
            HandshakeAuthMode::server_only(),
            HANDSHAKE_VERSION,
            self.chain_id,
            SupportedProtocols::all(),
            false,
        );

        println!(
            "\n[checker] Checking connections: our peer_id: {}, our public_key: {}",
            peer_id, public_key
        );

        // Check all the addresses accordingly
        let mut tasks = Vec::new();
        for (name, peer_id, addrs) in nodes {
            for addr in addrs {
                let (name, transport) = (name.clone(), &transport);
                let task = async move {
                    match check_endpoint(transport, addr, no_handshake).await {
                        Ok(_) => println!("{} -- good", name),
                        Err(err) => println!("{} : {} -- bad -- {}", name, peer_id, err),
                    }
                };
                tasks.push(task);
            }
        }
        let rt = Runtime::new().unwrap();
        rt.block_on(future::join_all(tasks));

        Ok("Complete!".to_string())
    }
}

fn validate_address(address: &NetworkAddress) -> Result<(), Error> {
    if !address.is_diemnet_addr() {
        Err(Error::CommandArgumentError(
            "Address must have ip+tcp or dns+tcp, noise pubkey, and handshake".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Wrapper for `check_endpoint_inner` to handle runtime
async fn check_endpoint(
    transport: &DiemNetTransport<TcpTransport>,
    address: NetworkAddress,
    no_handshake: bool,
) -> Result<String, Error> {
    let result = if no_handshake {
        check_endpoint_inner_no_handshake(address.clone()).await
    } else {
        check_endpoint_inner(transport, address.clone()).await
    };
    result.map_err(|err| {
        Error::UnexpectedError(format!("Failed check for address {}: {:#}", address, err))
    })
}

/// Connects via the actual production DiemNetTransport. This requires a keypair
/// that the remote will actually accept.
async fn check_endpoint_inner(
    transport: &DiemNetTransport<TcpTransport>,
    address: NetworkAddress,
) -> Result<String> {
    // The peer id doesn't matter because we don't validate it
    let remote_peer_id = PeerId::ZERO;

    let conn = transport
        .dial(remote_peer_id, address)
        .context("Failed to create dialer")?
        .await
        .context("Failed to connect")?;

    Ok(format!("Success: connected to {}", conn.metadata.addr))
}

/// The server waits for the full client's Noise handshake message before
/// potentially responding. We can test the endpoint by sending an invalid client
/// handshake and expecting the server to close the connection with an EOF.
const FAKE_NOISE_HEADER: &[u8; NoiseUpgrader::CLIENT_MESSAGE_SIZE] = &[7; 152];

/// Check that an endpoint looks like a
async fn check_endpoint_inner_no_handshake(address: NetworkAddress) -> Result<String> {
    let connect = async {
        // The peer id doesn't matter because we don't validate it
        let remote_peer_id = PeerId::ZERO;

        let mut socket = DIEM_TCP_TRANSPORT
            .dial(remote_peer_id, address)
            .context("Failed to create dialer")?
            .await
            .context("Failed to connect")?;

        // We should be able to write the full Noise client handshake
        socket
            .write_all(FAKE_NOISE_HEADER)
            .await
            .context("Failed to write fake Noise header")?;

        // The server should then close the connection (Unexpected EOF) because
        // the Noise handshake is invalid.
        let mut buf = [0u8; 1];
        let bytes_read = socket
            .read(&mut buf)
            .await
            .context("Failed to read from socket")?;
        if bytes_read == 0 {
            // Connection is open and server responded with an EOF (since our handshake is invalid).
            // This is the closest we can get to confirming the server is a Noise listener
            Ok("Success: remote accepted write and responded with EOF".to_string())
        } else {
            Err(format_err!(
                "Endpoint {} responded with data when it shouldn't"
            ))
        }
    };

    tokio::time::timeout(TRANSPORT_TIMEOUT, connect)
        .await
        .map_err(|_| format_err!("Connection timed out"))?
}

/// Derive the peer id that we're using.  This is a convenience to only have to provide private key
fn private_key_to_public_info(private_key: &x25519::PrivateKey) -> (PeerId, x25519::PublicKey) {
    let public_key = private_key.public_key();
    let peer_id = account_address::from_identity_public_key(public_key);
    (peer_id, public_key)
}
