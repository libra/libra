// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! In a leader based consensus algorithm, each participant maintains a block tree that looks like
//! the following in the executor:
//! ```text
//!  Height      5      6      7      ...
//!
//! Committed -> B5  -> B6  -> B7
//!         |
//!         └--> B5' -> B6' -> B7'
//!                     |
//!                     └----> B7"
//! ```
//! This module implements `SpeculationCache` that is an in-memory representation of this tree.

#[cfg(test)]
mod test;

use crate::{
    logging::{LogEntry, LogSchema},
    types::ProcessedVMOutput,
};
use anyhow::{format_err, Result};
use consensus_types::block::Block;
use diem_crypto::{hash::PRE_GENESIS_BLOCK_ID, HashValue};
use diem_infallible::Mutex;
use diem_logger::prelude::*;
use diem_types::{ledger_info::LedgerInfo, transaction::Transaction};
use executor_types::{Error, ExecutedTrees};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use storage_interface::{StartupInfo, TreeState};

/// The struct that stores all speculation result of its counterpart in consensus.
pub(crate) struct SpeculationBlock {
    // The block id of which the output is computed from.
    id: HashValue,
    // The transactions in the block.
    transactions: Vec<Transaction>,
    // The pointers to all the children blocks.
    children: Vec<Arc<Mutex<SpeculationBlock>>>,
    // The speculative execution result.
    output: ProcessedVMOutput,
    // A pointer to the global block map keyed by id to achieve O(1) lookup time complexity.
    block_map: Arc<Mutex<HashMap<HashValue, Weak<Mutex<SpeculationBlock>>>>>,
}

impl SpeculationBlock {
    pub fn new(
        id: HashValue,
        transactions: Vec<Transaction>,
        output: ProcessedVMOutput,
        block_map: Arc<Mutex<HashMap<HashValue, Weak<Mutex<SpeculationBlock>>>>>,
    ) -> Self {
        Self {
            id,
            transactions,
            children: vec![],
            output,
            block_map,
        }
    }

    pub fn id(&self) -> HashValue {
        self.id
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn add_child(&mut self, child: Arc<Mutex<SpeculationBlock>>) {
        self.children.push(child)
    }

    pub fn output(&self) -> &ProcessedVMOutput {
        &self.output
    }

    pub fn replace(&mut self, transactions: Vec<Transaction>, output: ProcessedVMOutput) {
        self.transactions = transactions;
        self.output = output;
        self.children = vec![];
    }
}

/// drop() will clean the current block entry from the global map.
impl Drop for SpeculationBlock {
    fn drop(&mut self) {
        self.block_map
            .lock()
            .remove(&self.id())
            .expect("Speculation block must exist in block_map before being dropped.");
        debug!(
            LogSchema::new(LogEntry::SpeculationCache).block_id(self.id()),
            "Block dropped"
        );
    }
}

/// SpeculationCache implements the block tree structrue. The tree is reprensented by a root block id,
/// all the children of root and a global block map. Each block is an Arc<Mutx<SpeculationBlock>>
/// with ref_count = 1. For the chidren of the root, the sole owner is `heads`. For the rest, the sole
/// owner is their parent block. So when a block is dropped, all its descendants will be dropped
/// recursively. In the meanwhile, wheir entries in the block map will be removed by each block's drop().
pub(crate) struct SpeculationCache {
    synced_trees: ExecutedTrees,
    committed_trees: ExecutedTrees,
    // The id of root block.
    committed_block_id: HashValue,
    // The chidren of root block.
    heads: Vec<Arc<Mutex<SpeculationBlock>>>,
    // A pointer to the global block map keyed by id to achieve O(1) lookup time complexity.
    // It is optional but an optimization.
    block_map: Arc<Mutex<HashMap<HashValue, Weak<Mutex<SpeculationBlock>>>>>,
}

impl SpeculationCache {
    pub fn new() -> Self {
        Self {
            synced_trees: ExecutedTrees::new_empty(),
            committed_trees: ExecutedTrees::new_empty(),
            heads: vec![],
            block_map: Arc::new(Mutex::new(HashMap::new())),
            committed_block_id: *PRE_GENESIS_BLOCK_ID,
        }
    }

    pub fn new_with_startup_info(startup_info: StartupInfo) -> Self {
        let mut cache = Self::new();
        let ledger_info = startup_info.latest_ledger_info.ledger_info();
        let committed_trees = ExecutedTrees::from(startup_info.committed_tree_state);
        cache.update_block_tree_root(committed_trees, ledger_info);
        if let Some(synced_tree_state) = startup_info.synced_tree_state {
            cache.update_synced_trees(ExecutedTrees::from(synced_tree_state));
        }
        cache
    }

    pub fn new_for_db_bootstrapping(tree_state: TreeState) -> Self {
        // The DB-bootstrapper applies genesis txn on a local DB and create a waypoint,
        // assuming everything is synced and committed.
        let executor_trees = ExecutedTrees::from(tree_state);
        Self {
            synced_trees: executor_trees.clone(),
            committed_trees: executor_trees,
            heads: vec![],
            block_map: Arc::new(Mutex::new(HashMap::new())),
            committed_block_id: *PRE_GENESIS_BLOCK_ID,
        }
    }

    pub fn committed_block_id(&self) -> HashValue {
        self.committed_block_id
    }

    pub fn committed_trees(&self) -> &ExecutedTrees {
        &self.committed_trees
    }

    pub fn synced_trees(&self) -> &ExecutedTrees {
        &self.synced_trees
    }

    pub fn update_block_tree_root(
        &mut self,
        committed_trees: ExecutedTrees,
        committed_ledger_info: &LedgerInfo,
    ) {
        let new_root_block_id = if committed_ledger_info.ends_epoch() {
            // Update the root block id with reconfig virtual block id, to be consistent
            // with the logic of Consensus.
            let id = Block::make_genesis_block_from_ledger_info(committed_ledger_info).id();
            info!(
                LogSchema::new(LogEntry::SpeculationCache)
                    .root_block_id(id)
                    .original_reconfiguration_block_id(committed_ledger_info.consensus_block_id()),
                "Updated with a new root block as a virtual block of reconfiguration block"
            );
            id
        } else {
            let id = committed_ledger_info.consensus_block_id();
            info!(
                LogSchema::new(LogEntry::SpeculationCache).root_block_id(id),
                "Updated with a new root block",
            );
            id
        };
        // prune the previous root state tree
        self.committed_trees.state_tree().prune();
        self.committed_block_id = new_root_block_id;
        self.committed_trees = committed_trees.clone();
        self.synced_trees = committed_trees;
    }

    pub fn update_synced_trees(&mut self, new_trees: ExecutedTrees) {
        self.synced_trees = new_trees;
    }

    pub fn reset(&mut self) {
        self.heads = vec![];
        *self.block_map.lock() = HashMap::new();
    }

    pub fn add_block(
        &mut self,
        parent_block_id: HashValue,
        block: (
            HashValue,         /* block id */
            Vec<Transaction>,  /* block transactions */
            ProcessedVMOutput, /* block execution output */
        ),
    ) -> Result<(), Error> {
        // Check existence first
        let (block_id, txns, output) = block;

        // If block is re-executed, update it.
        let old_block = self
            .block_map
            .lock()
            .get(&block_id)
            .map(|b| {
                b.upgrade().ok_or_else(|| {
                    format_err!(
                        "block {:x} has been deallocated. Something went wrong.",
                        block_id
                    )
                })
            })
            .transpose()?;

        if let Some(old_block) = old_block {
            old_block.lock().replace(txns, output);
            return Ok(());
        }

        let new_block = Arc::new(Mutex::new(SpeculationBlock::new(
            block_id,
            txns,
            output,
            Arc::clone(&self.block_map),
        )));
        // Add to the map
        self.block_map
            .lock()
            .insert(block_id, Arc::downgrade(&new_block));
        // Add to the tree
        if parent_block_id == self.committed_block_id() {
            self.heads.push(new_block);
        } else {
            self.get_block(&parent_block_id)?
                .lock()
                .add_child(new_block);
        }
        Ok(())
    }

    pub fn prune(&mut self, committed_ledger_info: &LedgerInfo) -> Result<(), Error> {
        let arc_latest_committed_block =
            self.get_block(&committed_ledger_info.consensus_block_id())?;
        let latest_committed_block = arc_latest_committed_block.lock();
        self.heads = latest_committed_block.children.clone();
        self.update_block_tree_root(
            latest_committed_block.output().executed_trees().clone(),
            committed_ledger_info,
        );
        Ok(())
    }

    // This function is intended to be called internally.
    pub fn get_block(&self, block_id: &HashValue) -> Result<Arc<Mutex<SpeculationBlock>>, Error> {
        Ok(self
            .block_map
            .lock()
            .get(&block_id)
            .ok_or_else(|| Error::BlockNotFound(*block_id))?
            .upgrade()
            .ok_or_else(|| {
                format_err!(
                    "block {:x} has been deallocated. Something went wrong.",
                    block_id
                )
            })?)
    }
}
