// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use consensus_types::{
    block::{Block, ExecutedBlock},
    common::Round,
    quorum_cert::QuorumCert,
    timeout_certificate::TimeoutCertificate,
};
use libra_crypto::HashValue;
use std::sync::Arc;

mod block_store;
mod block_tree;
mod pending_votes;

pub use block_store::{sync_manager::BlockRetriever, BlockStore};

/// Result of the vote processing. The failure case (Verification error) is returned
/// as the Error part of the result.
#[derive(Debug, PartialEq)]
pub enum VoteReceptionResult {
    /// The vote has been added but QC has not been formed yet. Return the amount of voting power
    /// the given (proposal, execution) pair.
    VoteAdded(u64),
    /// The very same vote message has been processed in past.
    DuplicateVote,
    /// The very same author has already voted for another proposal in this round (equivocation).
    EquivocateVote,
    /// This block has been already certified.
    OldQuorumCertificate(Arc<QuorumCert>),
    /// This block has just been certified after adding the vote.
    NewQuorumCertificate(Arc<QuorumCert>),
    /// The vote completes a new TimeoutCertificate
    NewTimeoutCertificate(Arc<TimeoutCertificate>),
}

pub trait BlockReader: Send + Sync {
    type Payload;

    /// Check if a block with the block_id exist in the BlockTree.
    fn block_exists(&self, block_id: HashValue) -> bool;

    /// Try to get a block with the block_id, return an Arc of it if found.
    fn get_block(&self, block_id: HashValue) -> Option<Arc<ExecutedBlock<Self::Payload>>>;

    /// Get the current root block of the BlockTree.
    fn root(&self) -> Arc<ExecutedBlock<Self::Payload>>;

    fn get_quorum_cert_for_block(&self, block_id: HashValue) -> Option<Arc<QuorumCert>>;

    /// Returns all the blocks between the root and the given block, including the given block
    /// but excluding the root.
    /// In case a given block is not the successor of the root, return None.
    /// For example if a tree is b0 <- b1 <- b2 <- b3, then
    /// path_from_root(b2) -> Some([b2, b1])
    /// path_from_root(b0) -> Some([])
    /// path_from_root(a) -> None
    fn path_from_root(&self, block_id: HashValue)
        -> Option<Vec<Arc<ExecutedBlock<Self::Payload>>>>;

    /// Generates and returns a block with the given parent and payload.
    /// Note that it does not add the block to the tree, just generates it.
    /// The main reason we want this function in the BlockStore is the fact that the signer required
    /// for signing the newly created block is held by the block store.
    /// The function panics in the following cases:
    /// * If the parent or its quorum certificate are not present in the tree,
    /// * If the given round (which is typically calculated by Pacemaker) is not greater than that
    ///   of a parent.
    fn create_block(
        &self,
        parent: &Block<Self::Payload>,
        payload: Self::Payload,
        round: Round,
        timestamp_usecs: u64,
    ) -> Block<Self::Payload>;

    /// Return the certified block with the highest round.
    fn highest_certified_block(&self) -> Arc<ExecutedBlock<Self::Payload>>;

    /// Return the quorum certificate with the highest round
    fn highest_quorum_cert(&self) -> Arc<QuorumCert>;

    /// Return the quorum certificate that carries ledger info with the highest round
    fn highest_ledger_info(&self) -> Arc<QuorumCert>;

    /// Return the highest timeout certificate if available.
    fn highest_timeout_cert(&self) -> Option<Arc<TimeoutCertificate>>;
}
