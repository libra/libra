// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines the structs transported during the network handshake protocol v1.
//! These should serialize as per the [DiemNet Handshake v1 Specification].
//!
//! During the v1 Handshake protocol, both end-points of a connection send a serialized and
//! length-prefixed [`HandshakeMsg`] to each other. The handshake message contains a map from
//! supported messaging protocol versions to a bit vector representing application protocols
//! supported over that messaging protocol. On receipt, both ends will determine the highest
//! intersecting messaging protocol version and use that for the remainder of the session.
//!
//! [DiemNet Handshake v1 Specification]: https://github.com/diem/diem/blob/main/specifications/network/handshake-v1.md

use anyhow::anyhow;
use diem_config::network_id::NetworkId;
use diem_types::chain_id::ChainId;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryInto, fmt, iter::Iterator};
use thiserror::Error;

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

#[cfg(test)]
mod test;

//
// ProtocolId
//

/// Unique identifier associated with each application protocol.
#[repr(u8)]
#[derive(Clone, Copy, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum ProtocolId {
    ConsensusRpc = 0,
    ConsensusDirectSend = 1,
    MempoolDirectSend = 2,
    StateSyncDirectSend = 3,
    DiscoveryDirectSend = 4,
    HealthCheckerRpc = 5,
    // json provides flexibility for backwards compatible upgrade
    ConsensusDirectSendJSON = 6,
}

impl ProtocolId {
    pub fn as_str(self) -> &'static str {
        use ProtocolId::*;
        match self {
            ConsensusRpc => "ConsensusRpc",
            ConsensusDirectSend => "ConsensusDirectSend",
            MempoolDirectSend => "MempoolDirectSend",
            StateSyncDirectSend => "StateSyncDirectSend",
            DiscoveryDirectSend => "DiscoveryDirectSend",
            HealthCheckerRpc => "HealthCheckerRpc",
            ConsensusDirectSendJSON => "ConsensusDirectSendCbor",
        }
    }

    pub fn all() -> &'static [ProtocolId] {
        &[
            ProtocolId::ConsensusRpc,
            ProtocolId::ConsensusDirectSend,
            ProtocolId::MempoolDirectSend,
            ProtocolId::StateSyncDirectSend,
            ProtocolId::DiscoveryDirectSend,
            ProtocolId::HealthCheckerRpc,
            ProtocolId::ConsensusDirectSendJSON,
        ]
    }

    pub fn to_bytes<T: Serialize>(&self, value: &T) -> anyhow::Result<Vec<u8>> {
        match self {
            ProtocolId::ConsensusDirectSendJSON => {
                serde_json::to_vec(value).map_err(|e| anyhow!("{:?}", e))
            }
            _ => bcs::to_bytes(value).map_err(|e| anyhow! {"{:?}", e}),
        }
    }

    pub fn from_bytes<'a, T: Deserialize<'a>>(&self, bytes: &'a [u8]) -> anyhow::Result<T> {
        match self {
            ProtocolId::ConsensusDirectSendJSON => {
                serde_json::from_slice(bytes).map_err(|e| anyhow!("{:?}", e))
            }
            _ => bcs::from_bytes(bytes).map_err(|e| anyhow! {"{:?}", e}),
        }
    }
}

impl fmt::Debug for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

//
// SupportedProtocols
//

/// A bit vector of supported [`ProtocolId`]s.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct SupportedProtocols(bitvec::BitVec);

impl TryInto<Vec<ProtocolId>> for SupportedProtocols {
    type Error = bcs::Error;

    fn try_into(self) -> bcs::Result<Vec<ProtocolId>> {
        let mut protocols = Vec::with_capacity(self.0.count_ones() as usize);
        if let Some(last_bit) = self.0.last_set_bit() {
            for i in 0..=last_bit {
                if self.0.is_set(i) {
                    let protocol: ProtocolId = bcs::from_bytes(&[i])?;
                    protocols.push(protocol);
                }
            }
        }
        Ok(protocols)
    }
}

impl<'a, T: Iterator<Item = &'a ProtocolId>> From<T> for SupportedProtocols {
    fn from(protocols: T) -> Self {
        let mut bv = bitvec::BitVec::default();
        protocols.for_each(|p| bv.set(*p as u8));
        Self(bv)
    }
}

impl SupportedProtocols {
    /// Returns a new SupportedProtocols struct that is an intersection.
    fn intersection(self, other: SupportedProtocols) -> SupportedProtocols {
        SupportedProtocols(self.0 & other.0)
    }

    /// Returns if the protocol is set.
    pub fn contains(&self, protocol: ProtocolId) -> bool {
        self.0.is_set(protocol as u8)
    }
}

//
// MessageProtocolVersion
//

/// Enum representing different versions of the Diem network protocol. These
/// should be listed from old to new, old having the smallest value.  We derive
/// [`PartialOrd`] since nodes need to find highest intersecting protocol version.
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum MessagingProtocolVersion {
    V1 = 0,
}

impl MessagingProtocolVersion {
    fn as_str(&self) -> &str {
        match self {
            Self::V1 => "V1",
        }
    }
}

impl fmt::Debug for MessagingProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for MessagingProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str(),)
    }
}

//
// HandshakeMsg
//

/// An enum to list the possible errors during the diem handshake negotiation
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("diem-handshake: the received message has a different chain id: {0}, expected: {1}")]
    InvalidChainId(ChainId, ChainId),
    #[error(
        "diem-handshake: the received message has an different network id: {0}, expected: {1}"
    )]
    InvalidNetworkId(NetworkId, NetworkId),
    #[error("diem-handshake: could not find an intersection of supported protocol with the peer")]
    NoCommonProtocols,
}

/// The HandshakeMsg contains a mapping from [`MessagingProtocolVersion`]
/// suppported by the node to a bit-vector specifying application-level protocols
/// supported over that version.
#[derive(Clone, Deserialize, Serialize, Default)]
pub struct HandshakeMsg {
    pub supported_protocols: BTreeMap<MessagingProtocolVersion, SupportedProtocols>,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
}

impl HandshakeMsg {
    /// Useful function for tests
    #[cfg(test)]
    pub fn new_for_testing() -> Self {
        let mut supported_protocols = BTreeMap::new();
        supported_protocols.insert(
            MessagingProtocolVersion::V1,
            [ProtocolId::StateSyncDirectSend].iter().into(),
        );
        Self {
            chain_id: ChainId::test(),
            network_id: NetworkId::Validator,
            supported_protocols,
        }
    }

    /// This function:
    /// 1. verifies that both HandshakeMsg are compatible and
    /// 2. finds out the intersection of protocols that is supported
    pub fn perform_handshake(
        &self,
        other: &HandshakeMsg,
    ) -> Result<(MessagingProtocolVersion, SupportedProtocols), HandshakeError> {
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }

        // verify that both peers are on the same type of network
        if self.network_id != other.network_id {
            return Err(HandshakeError::InvalidNetworkId(
                other.network_id.clone(),
                self.network_id.clone(),
            ));
        }

        // first, find the highest MessagingProtocolVersion supported by both nodes.
        let mut inner = other.supported_protocols.iter().rev().peekable();

        // iterate over all supported protocol versions in decreasing order.
        for (k_outer, _) in self.supported_protocols.iter().rev() {
            // Remove all elements from inner iterator that are larger than the current head of the
            // outer iterator.
            match inner.by_ref().find(|(k_inner, _)| *k_inner <= k_outer) {
                None => {
                    break;
                }
                Some((k_inner, _)) if k_inner == k_outer => {
                    // Find all protocols supported by both nodes for the above protocol version.
                    // Both `self` and `other` shold have entry in map for `key`.
                    let protocols_self = self.supported_protocols.get(k_inner).unwrap();
                    let protocols_other = other.supported_protocols.get(k_inner).unwrap();
                    return Ok((
                        *k_inner,
                        protocols_self.clone().intersection(protocols_other.clone()),
                    ));
                }
                _ => {}
            }
        }

        // no intersection found
        Err(HandshakeError::NoCommonProtocols)
    }
}

impl fmt::Debug for HandshakeMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for HandshakeMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{},{},{:?}]",
            self.chain_id, self.network_id, self.supported_protocols
        )
    }
}
