// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

mod admin;
pub use admin::*;
mod network;
pub use network::*;
mod test;
pub use test::*;
mod public;
pub use public::*;
mod factory;
pub use factory::*;
mod swarm;
pub use swarm::*;
mod node;
pub use node::*;
mod chain_info;
pub use chain_info::*;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(usize);

impl Version {
    pub fn new(version: usize) -> Self {
        Self(version)
    }
}
