// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{ChainInfo, FullNode, Result, Validator, Version};
use diem_sdk::types::PeerId;

/// Trait used to represent a running network comprised of Validators and FullNodes
pub trait Swarm {
    /// Performs a health check on the entire swarm, ensuring all Nodes are Live and that no forks
    /// have occurred
    fn health_check(&mut self) -> Result<()>;

    /// Returns an Iterator of references to all the Validators in the Swarm
    fn validators<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a dyn Validator> + 'a>;

    /// Returns an Iterator of mutable references to all the Validators in the Swarm
    fn validators_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut dyn Validator> + 'a>;

    /// Returns a reference to the Validator with the provided PeerId
    fn validator(&self, id: PeerId) -> Option<&dyn Validator>;

    /// Returns a mutable reference to the Validator with the provided PeerId
    fn validator_mut(&mut self, id: PeerId) -> Option<&mut dyn Validator>;

    /// Returns an Iterator of references to all the FullNodes in the Swarm
    fn full_nodes<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a dyn FullNode> + 'a>;

    /// Returns an Iterator of mutable references to all the FullNodes in the Swarm
    fn full_nodes_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut dyn FullNode> + 'a>;

    /// Returns a reference to the FullNode with the provided PeerId
    fn full_node(&self, id: PeerId) -> Option<&dyn FullNode>;

    /// Returns a mutable reference to the FullNode with the provided PeerId
    fn full_node_mut(&mut self, id: PeerId) -> Option<&mut dyn FullNode>;

    /// Adds a Validator to the swarm with the provided PeerId
    fn add_validator(&mut self, id: PeerId) -> Result<PeerId>;

    /// Removes the Validator with the provided PeerId
    fn remove_validator(&mut self, id: PeerId) -> Result<()>;

    /// Adds a FullNode to the swarm with the provided PeerId
    fn add_full_node(&mut self, id: PeerId) -> Result<()>;

    /// Removes the FullNode with the provided PeerId
    fn remove_full_node(&mut self, id: PeerId) -> Result<()>;

    /// Return a list of supported Versions
    fn versions<'a>(&'a self) -> Box<dyn Iterator<Item = Version> + 'a>;

    /// Construct a ChainInfo from this Swarm
    fn chain_info(&mut self) -> ChainInfo<'_>;
}
