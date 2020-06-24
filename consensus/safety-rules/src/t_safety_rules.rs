// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{ConsensusState, Error};
use consensus_types::{
    block::Block, block_data::BlockData, common::Round, quorum_cert::QuorumCert, timeout::Timeout,
    vote::Vote, vote_proposal::VoteProposal,
};
use libra_crypto::ed25519::Ed25519Signature;
use libra_types::epoch_change::EpochChangeProof;

/// Interface for SafetyRules
pub trait TSafetyRules<T> {
    /// Provides the internal state of SafetyRules for monitoring / debugging purposes. This does
    /// not include sensitive data like private keys.
    fn consensus_state(&mut self) -> Result<ConsensusState, Error>;

    /// Initialize SafetyRules using an Epoch ending LedgerInfo, this should map to what was
    /// provided in consensus_state. It will be used to initialize the ValidatorSet.
    /// This uses a EpochChangeProof because there's a possibility that consensus migrated to a
    /// new epoch but SafetyRules did not.
    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error>;

    /// Learn about a new quorum certificate. This can lead to updating the preferred round or the
    /// validator verifier if this ends an epoch and increments the epoch as well.
    fn update(&mut self, qc: &QuorumCert) -> Result<(), Error>;

    /// Attempts to vote for a given proposal following the voting rules.
    fn construct_and_sign_vote(&mut self, vote_proposal: &VoteProposal<T>) -> Result<Vote, Error>;

    /// Attempts to strong vote with marker for a given proposal following the voting rules.
    fn construct_and_sign_strong_vote(
        &mut self,
        vote_proposal: &VoteProposal<T>,
        marker: Round,
    ) -> Result<Vote, Error>;

    /// As the holder of the private key, SafetyRules also signs proposals or blocks.
    /// A Block is a signed BlockData along with some additional metadata.
    fn sign_proposal(&mut self, block_data: BlockData<T>) -> Result<Block<T>, Error>;

    /// As the holder of the private key, SafetyRules also signs what is effectively a
    /// timeout message. This returns the signature for that timeout message.
    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error>;
}
