// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    counters, metrics_safety_rules::MetricsSafetyRules, network::NetworkSender,
    network_interface::ConsensusMsg, state_replication::StateComputer,
};
use channel::Receiver;
use consensus_types::{
    common::Author,
    executed_block::ExecutedBlock,
    experimental::{commit_decision::CommitDecision, commit_vote::CommitVote},
};
use core::sync::atomic::Ordering;
use diem_crypto::ed25519::Ed25519Signature;
use diem_infallible::Mutex;
use diem_logger::prelude::*;
use diem_metrics::monitor;
use diem_types::{
    account_address::AccountAddress,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    validator_verifier::ValidatorVerifier,
};
use executor_types::Error as ExecutionError;
use futures::{select, StreamExt};
use safety_rules::TSafetyRules;
use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicU64, Arc},
};
use diem_types::block_info::BlockInfo;
use diem_types::validator_verifier::VerifyError;

/*
Commit phase takes in the executed blocks from the execution
phase and commit them. Specifically, commit phase signs a commit
vote message containing the execution result and broadcast it.
Upon collecting a quorum of agreeing votes to a execution result,
the commit phase commits the blocks as well as broadcasts a commit
decision message together with the quorum of signatures. The commit
decision message helps the slower nodes to quickly catch up without
having to collect the signatures.
*/

struct PendingBlocks {
    vecblocks: Vec<ExecutedBlock>,
    ledger_info_sig: LedgerInfoWithSignatures,
    block_info: BlockInfo,
}

impl PendingBlocks {
    pub fn new(vecblocks: Vec<ExecutedBlock>, ledger_info_sig: LedgerInfoWithSignatures) -> Self {
        assert!(vecblocks.len() > 0); // the commit phase should not accept empty blocks.
        let block_info = vecblocks.last().unwrap().block_info();
        Self {
            vecblocks,
            ledger_info_sig,
            block_info,
        }
    }

    pub fn block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    pub fn round(&self) -> u64 {
        self.block_info().round()
    }

    pub fn vecblocks(&self) -> &Vec<ExecutedBlock> {
        &self.vecblocks
    }

    pub fn ledger_info_sig(&self) -> &LedgerInfoWithSignatures {
        &self.ledger_info_sig
    }

    pub fn ledger_info_sig_mut(&mut self) -> &mut LedgerInfoWithSignatures {
        &mut self.ledger_info_sig
    }

    pub fn replace_ledger_info_sig(&mut self, new_ledger_info_sig: LedgerInfoWithSignatures) {
        self.ledger_info_sig = new_ledger_info_sig
    }

    pub fn verify(&self, verifier: &ValidatorVerifier) -> ::std::result::Result<(), VerifyError> {
        self.ledger_info_sig.verify_signatures(verifier)
    }
}

#[derive(Debug)]
pub enum CommitPhaseMessage {
    CommitVote(Author, LedgerInfo, Ed25519Signature),
    CommitDecision(LedgerInfoWithSignatures),
}

pub struct CommitPhase {
    commit_channel_recv: Receiver<(Vec<ExecutedBlock>, LedgerInfoWithSignatures)>,
    execution_proxy: Arc<dyn StateComputer>,
    blocks: Option<PendingBlocks>,
    commit_msg_receiver: channel::Receiver<ConsensusMsg>,
    verifier: ValidatorVerifier,
    safety_rules: Arc<Mutex<MetricsSafetyRules>>,
    author: Author,
    back_pressure: Arc<AtomicU64>,
    network_sender: NetworkSender,
}

/// Wrapper for ExecutionProxy.commit
pub async fn commit(
    execution_proxy: &Arc<dyn StateComputer>,
    vecblock: &[ExecutedBlock],
    ledger_info: &LedgerInfoWithSignatures,
) -> Result<(), ExecutionError> {
    execution_proxy
        .commit(
            &vecblock
                .iter()
                .map(|eb| Arc::new(eb.clone()))
                .collect::<Vec<Arc<ExecutedBlock>>>(),
            ledger_info.clone(),
        )
        .await
}

macro_rules! report_err {
    ($result:expr, $error_string:literal) => {
        if let Err(err) = $result {
            counters::ERROR_COUNT.inc();
            error!(error = err.to_string(), $error_string,)
        }
    };
}

impl CommitPhase {
    pub fn new(
        commit_channel_recv: Receiver<(Vec<ExecutedBlock>, LedgerInfoWithSignatures)>,
        execution_proxy: Arc<dyn StateComputer>,
        commit_msg_receiver: channel::Receiver<ConsensusMsg>,
        verifier: ValidatorVerifier,
        safety_rules: Arc<Mutex<MetricsSafetyRules>>,
        author: Author,
        back_pressure: Arc<AtomicU64>,
        network_sender: NetworkSender,
    ) -> Self {
        Self {
            commit_channel_recv,
            execution_proxy,
            blocks: None,
            commit_msg_receiver,
            verifier,
            safety_rules,
            author,
            back_pressure,
            network_sender,
        }
    }

    /// Notified when receiving a commit vote message
    pub async fn process_commit_vote(&mut self, commit_vote: &CommitVote) -> anyhow::Result<()> {
        if let Some(pending_blocks) = self.blocks.as_mut() {
            let commit_ledger_info = commit_vote.ledger_info();

            // if the block infos do not match
            if !(commit_ledger_info.commit_info() == pending_blocks.block_info()) {
                return Ok(()); // ignore the message
            }

            commit_vote.verify(&self.verifier)?;

            // add the signature into the signature tree
            pending_blocks.ledger_info_sig_mut().add_signature(commit_vote.author(), commit_vote.signature().clone());
        }

        Ok(())
    }

    pub async fn process_commit_decision(
        &mut self,
        commit_decision: CommitDecision,
    ) -> anyhow::Result<()> {
        if let Some(pending_blocks) = self.blocks.as_mut() {
            let commit_ledger_info = commit_decision.ledger_info();

            // if the block infos do not match
            if !(commit_ledger_info.ledger_info().commit_info()
                == pending_blocks.block_info())
            {
                return Ok(()); // ignore the message
            }

            commit_decision.verify(&self.verifier)?;

            // replace the signature tree
            pending_blocks.replace_ledger_info_sig(commit_ledger_info.clone());
        }

        Ok(())
    }

    pub async fn check_commit(&mut self) -> anyhow::Result<()> {
        if let Some(pending_blocks) = self.blocks.as_ref() {
            if pending_blocks.verify(&self.verifier).is_ok() {

                // asynchronously broadcast the commit decision first to
                // save the time of other nodes.
                self.network_sender
                    .broadcast(ConsensusMsg::CommitDecisionMsg(Box::new(
                        CommitDecision::new(pending_blocks.ledger_info_sig().clone()),
                    )))
                    .await;

                commit(&self.execution_proxy, pending_blocks.vecblocks(), pending_blocks.ledger_info_sig())
                    .await
                    .expect("Failed to commit the executed blocks.");

                // update the back pressure (will appear in later PR)
                self.back_pressure.store(pending_blocks.round(), Ordering::SeqCst);

                self.blocks = None; // prepare for the next batch of blocks
            }
        }

        Ok(())
    }

    pub async fn process_executed_blocks(
        &mut self,
        vecblock: Vec<ExecutedBlock>,
        ordered_ledger_info: LedgerInfoWithSignatures,
    ) -> anyhow::Result<()> {
        let commit_ledger_info = LedgerInfo::new(
            vecblock.last().unwrap().block_info(),
            ordered_ledger_info.ledger_info().consensus_data_hash(),
        );

        let signature = self
            .safety_rules
            .lock()
            .sign_commit_vote(ordered_ledger_info, commit_ledger_info.clone())?;

        // if fails, it needs to resend, otherwise the liveness might compromise.
        let msg = ConsensusMsg::CommitVoteMsg(Box::new(CommitVote::new_with_signature(
            self.author,
            commit_ledger_info.clone(),
            signature.clone(),
        )));

        let mut commit_ledger_info_with_sig = LedgerInfoWithSignatures::new(
            commit_ledger_info,
            BTreeMap::<AccountAddress, Ed25519Signature>::new(),
        );
        commit_ledger_info_with_sig.add_signature(self.author, signature);

        self.blocks = Some(PendingBlocks::new(
            vecblock,
            commit_ledger_info_with_sig,
        ));

        // asynchronously broadcast the message.
        // note that this message will also reach the node itself
        self.network_sender.broadcast(msg).await;

        Ok(())
    }

    pub async fn start(mut self) {
        loop {
            while self.blocks.is_some() {
                // if we are still collecting the signatures
                select! {
                    // process messages dispatched from epoch_manager
                    msg = self.commit_msg_receiver.select_next_some() => {
                        match msg {
                            ConsensusMsg::CommitVoteMsg(request) => {
                                monitor!(
                                    "process_commit_vote",
                                    report_err!(self.process_commit_vote(&*request).await, "Error in processing commit vote.")
                                );
                            }
                            ConsensusMsg::CommitDecisionMsg(request) => {
                                monitor!(
                                    "process_commit_decision",
                                    report_err!(self.process_commit_decision(*request).await, "Error in processing commit decision.")
                                );
                            }
                            _ => {
                                unreachable!("Unexpected messages: something wrong with message dispatching.")
                            }
                        };
                    }
                    // TODO: add a timer to repeat sending commit votes in later PR
                    complete => break,
                }
                report_err!(
                    // check if the blocks are ready to commit
                    self.check_commit().await,
                    "Error in checking whether self.block is ready to commit."
                );
            }
            if let Some((vecblocks, ordered_ledger_info)) = self.commit_channel_recv.next().await {
                report_err!(
                    // receive new blocks from execution phase
                    self.process_executed_blocks(vecblocks, ordered_ledger_info).await,
                    "Error in processing received blocks"
                );
            } else {
                break;
            }
        }
    }
}
