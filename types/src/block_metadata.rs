// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account_config::libra_root_address,
    event::{EventHandle, EventKey},
};
use anyhow::Result;
use move_core_types::move_resource::MoveResource;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// Struct that will be persisted on chain to store the information of the current block.
///
/// The flow will look like following:
/// 1. The executor will pass this struct to VM at the end of a block proposal.
/// 2. The VM will use this struct to create a special system transaction that will emit an event
///    represents the information of the current block. This transaction can't
///    be emitted by regular users and is generated by each of the validators on the fly. Such
///    transaction will be executed before all of the user-submitted transactions in the blocks.
/// 3. Once that special resource is modified, the other user transactions can read the consensus
///    info by calling into the read method of that resource, which would thus give users the
///    information such as who participates in the block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMetadata {
    round: u64,
    timestamp_usecs: u64,
    // masks on the current validator set
    participants: Vec<bool>,
    is_nil: bool,
}

impl BlockMetadata {
    pub fn new(round: u64, timestamp_usecs: u64, participants: Vec<bool>, is_nil: bool) -> Self {
        Self {
            round,
            timestamp_usecs,
            participants,
            is_nil,
        }
    }

    pub fn into_inner(self) -> Result<(u64, u64, Vec<bool>, bool)> {
        Ok((
            self.round,
            self.timestamp_usecs,
            self.participants,
            self.is_nil,
        ))
    }

    pub fn timestamp_usec(&self) -> u64 {
        self.timestamp_usecs
    }
}

pub fn new_block_event_key() -> EventKey {
    EventKey::new_from_address(&libra_root_address(), 17)
}

/// The path to the new block event handle under a LibraBlock::BlockMetadata resource.
pub static NEW_BLOCK_EVENT_PATH: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut path = LibraBlockResource::resource_path();
    // it can be anything as long as it's referenced in AccountState::get_event_handle_by_query_path
    path.extend_from_slice(b"/new_block_event/");
    path
});

#[derive(Deserialize, Serialize)]
pub struct LibraBlockResource {
    height: u64,
    new_block_events: EventHandle,
}

impl LibraBlockResource {
    pub fn new_block_events(&self) -> &EventHandle {
        &self.new_block_events
    }
}

impl MoveResource for LibraBlockResource {
    const MODULE_NAME: &'static str = "LibraBlock";
    const STRUCT_NAME: &'static str = "BlockMetadata";
}
