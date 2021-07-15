// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::experimental::commit_phase::CommitPhase;
use diem_metrics::IntGauge;
use consensus_types::executed_block::ExecutedBlock;
use diem_types::ledger_info::{LedgerInfoWithSignatures, LedgerInfo};
use crate::test_utils::{consensus_runtime, MockStateComputer, MockTransactionManager, MockStorage};
use crate::network_tests::{NetworkPlayground, TwinId};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use channel::message_queues::QueueStyle;
use diem_types::epoch_state::EpochState;
use network::peer_manager::{PeerManagerRequestSender, ConnectionRequestSender, conn_notifs_channel};
use crate::network::NetworkSender;
use futures::channel::mpsc;
use crate::util::time_service::ClockTimeService;
use crate::block_storage::BlockStore;
use crate::liveness::proposal_generator::ProposalGenerator;
use crate::metrics_safety_rules::MetricsSafetyRules;
use crate::network_interface::{ConsensusMsg, ConsensusNetworkSender};
use channel::{diem_channel, Sender, Receiver};
use futures::{stream::select, SinkExt, Stream, StreamExt};
use diem_infallible::Mutex;
use futures::channel::mpsc::UnboundedReceiver;
use consensus_types::common::Payload;
use diem_types::validator_verifier::random_validator_verifier;
use safety_rules::{PersistentSafetyStorage, SafetyRulesManager, SafetyRules, TSafetyRules};
use diem_crypto::{ed25519::{Ed25519PrivateKey, Ed25519Signature}, Uniform};
use consensus_types::block::Block;
use diem_types::validator_signer::ValidatorSigner;
use consensus_types::block::block_test_utils::certificate_for_genesis;
use crate::state_replication::StateComputer;
use diem_crypto::hash::ACCUMULATOR_PLACEHOLDER_HASH;
use std::collections::BTreeMap;
use diem_types::account_address::AccountAddress;
use diem_secure_storage::Storage;
use diem_types::waypoint::Waypoint;
use futures::{executor::block_on, future::FutureExt};
use network::{
    protocols::network::{Event, NewNetworkEvents, NewNetworkSender},
};
use std::time::Duration;
use crate::experimental::ordering_state_computer::OrderingStateComputer;
use std::sync::mpsc::RecvTimeoutError;
use futures::channel::mpsc::TryRecvError;
use std::thread::sleep;
use tokio::runtime::{self, Runtime};

fn prepare_commit_phase() -> (
    Sender<(Vec<ExecutedBlock>, LedgerInfoWithSignatures)>,
    Sender<ConsensusMsg>,
    Receiver<(Vec<Block>, LedgerInfoWithSignatures)>,
    Receiver<Event<ConsensusMsg>>,
    Arc<Mutex<MetricsSafetyRules>>,
    Vec<ValidatorSigner>,
    Arc<OrderingStateComputer>,
){
    let num_nodes = 1;

    // constants
    let channel_size = 30;
    let back_pressure = Arc::new(AtomicU64::new(0));

    // environment setup
    let mut runtime = consensus_runtime();
    let executor = runtime.handle().clone();
    let (signers, validators) = random_validator_verifier(num_nodes, None, false);
    let validator_set = (&validators).into();
    let signer = &signers[0];

    let waypoint =
        Waypoint::new_epoch_boundary(&LedgerInfo::mock_genesis(Some(validator_set))).unwrap();

    let safety_storage = PersistentSafetyStorage::initialize(
        Storage::from(diem_secure_storage::InMemoryStorage::new()),
        signer.author(),
        signer.private_key().clone(),
        Ed25519PrivateKey::generate_for_testing(),
        waypoint,
        true,
    );
    let safety_rules_manager =
        SafetyRulesManager::new_local(safety_storage, false, false, true);

    let (_initial_data, storage) = MockStorage::start_for_testing((&validators).into());
    let epoch_state = EpochState {
        epoch: 1,
        verifier: storage.get_validator_set().into(),
    };
    let validators = epoch_state.verifier.clone();
    let (network_reqs_tx, network_reqs_rx) = diem_channel::new(QueueStyle::FIFO, 8, None);
    let (connection_reqs_tx, _) = diem_channel::new(QueueStyle::FIFO, 8, None);

    let network_sender = ConsensusNetworkSender::new(
        PeerManagerRequestSender::new(network_reqs_tx),
        ConnectionRequestSender::new(connection_reqs_tx),
    );
    let author = signer.author();

    let (self_sender, self_receiver) = channel::new_test(1000);
    let network = NetworkSender::new(author, network_sender, self_sender, validators);

    let (commit_result_sender, commit_result_receiver) = channel::new_test::<(Vec<Block>, LedgerInfoWithSignatures)>(channel_size);
    let state_computer = Arc::new(OrderingStateComputer::new(
        commit_result_sender
    ));

    let mut safety_rules =
        MetricsSafetyRules::new(safety_rules_manager.client(), storage.clone());
    safety_rules.perform_initialize().unwrap();

    let safety_rules_container = Arc::new(Mutex::new(safety_rules));

    // Setting up channels

    let (sender_comm, receiver_comm) = channel::new_test::<(
        Vec<ExecutedBlock>,
        LedgerInfoWithSignatures,
    )>(channel_size);

    let (sender_c_msg, receiver_c_msg) =
        channel::new_test::<ConsensusMsg>(channel_size);

    let commit_phase = CommitPhase::new(
        receiver_comm,
        state_computer.clone(),
        receiver_c_msg,
        epoch_state.verifier.clone(),
        safety_rules_container.clone(),
        author,
        back_pressure.clone(),
        network.clone(),
    );

    let runtime = runtime::Builder::new_multi_thread()
        .thread_name("consensus")
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime!");

    runtime.spawn(commit_phase.start());

    (
        sender_comm, // channel to pass executed blocks into the commit phase
        sender_c_msg, // channel to pass commit messages into the commit phase
        commit_result_receiver, // channel to receive commit result from the commit phase
        self_receiver, // channel to receive message from the commit phase itself
        safety_rules_container,
        signers,
        state_computer,
    )
}

/// Send bad commit blocks
fn test_bad_commit_blocks () {
    let (
        mut sender_comm,
        sender_c_msg,
        mut commit_result_receiver,
        mut self_receiver,
        safety_rules_container,
        signers,
        state_computer,
    ) = prepare_commit_phase();

    let genesis_qc = certificate_for_genesis();
    let block = Block::new_proposal(
        vec![],
        1,
        1,
        genesis_qc,
        signers.first().unwrap(),
    );
    let compute_result = state_computer.compute(
        &block, *ACCUMULATOR_PLACEHOLDER_HASH
    ).unwrap();

    // good block
    block_on(sender_comm.send((
        vec![ExecutedBlock::new(
            block.clone(),
            compute_result,
        )],
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(
                block.gen_block_info(*ACCUMULATOR_PLACEHOLDER_HASH, 0, None),
                *ACCUMULATOR_PLACEHOLDER_HASH,
            ),
            BTreeMap::<AccountAddress, Ed25519Signature>::new(),
        )
    )));

    sleep(Duration::from_secs(1));
    // the commit phase should not send message to itself
    assert!(matches!(self_receiver.select_next_some().now_or_never(), None));
    // it does not commit blocks either
    assert_eq!(commit_result_receiver.select_next_some().now_or_never(), None);
}

/// Send bad commit vote
fn test_bad_commit_vote () {
    let (
        mut sender_comm,
        sender_c_msg,
        mut commit_result_receiver,
        mut self_receiver,
        safety_rules_container,
        signers,
        state_computer,
    ) = prepare_commit_phase();

    let signer= &signers[0];

    let genesis_qc = certificate_for_genesis();
    let block = Block::new_proposal(
        vec![],
        1,
        1,
        genesis_qc,
        signers.first().unwrap(),
    );
    let compute_result = state_computer.compute(
        &block, *ACCUMULATOR_PLACEHOLDER_HASH
    ).unwrap();

    let li = LedgerInfo::new(
        block.gen_block_info(*ACCUMULATOR_PLACEHOLDER_HASH, 0, None),
        *ACCUMULATOR_PLACEHOLDER_HASH,
    );

    let mut li_sig = LedgerInfoWithSignatures::new(
        li.clone(),
        BTreeMap::<AccountAddress, Ed25519Signature>::new(),
    );

    li_sig.add_signature(
        signer.author(),
        signer.sign(&li)
    );

    // send good info
    block_on(sender_comm.send((
        vec![ExecutedBlock::new(
            block.clone(),
            compute_result,
        )],
        li_sig,
    )));

    sleep(Duration::from_secs(1));

    // TODO: assert a commit vote message is sent to itself.

    // it does not commit blocks either
    assert_eq!(commit_result_receiver.select_next_some().now_or_never(), None);
}

#[test]
fn test_commit_phase() {
    // Bad blocks
    test_bad_commit_blocks();
    // Bad Commit Vote
    test_bad_commit_vote();

    // Bad commit decision

    // ...

}