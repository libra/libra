// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    block_storage::{BlockReader, BlockStore},
    liveness::{
        proposal_generator::ProposalGenerator,
        proposer_election::ProposerElection,
        rotating_proposer_election::RotatingProposer,
        round_state::{ExponentialTimeInterval, RoundState},
    },
    metrics_safety_rules::MetricsSafetyRules,
    network::{IncomingBlockRetrievalRequest, NetworkSender},
    network_interface::{ConsensusMsg, ConsensusNetworkEvents, ConsensusNetworkSender},
    network_tests::{NetworkPlayground, TwinId},
    persistent_liveness_storage::RecoveryData,
    round_manager::RoundManager,
    test_utils::{
        consensus_runtime, timed_block_on, MockStateComputer, MockStorage, MockTransactionManager,
        TreeInserter,
    },
    util::time_service::{ClockTimeService, TimeService},
};
use channel::{self, diem_channel, message_queues::QueueStyle};
use consensus_types::{
    block::{
        block_test_utils::{certificate_for_genesis, gen_test_certificate},
        Block,
    },
    block_retrieval::{BlockRetrievalRequest, BlockRetrievalStatus},
    common::{Author, Payload},
    proposal_msg::ProposalMsg,
    sync_info::SyncInfo,
    timeout::Timeout,
    timeout_certificate::TimeoutCertificate,
    vote_msg::VoteMsg,
};
use diem_crypto::{ed25519::Ed25519PrivateKey, HashValue, Uniform};
use diem_secure_storage::Storage;
use diem_types::{
    epoch_state::EpochState,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    validator_signer::ValidatorSigner,
    validator_verifier::random_validator_verifier,
    waypoint::Waypoint,
};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    stream::select,
    Stream, StreamExt,
};
use network::{
    peer_manager::{conn_notifs_channel, ConnectionRequestSender, PeerManagerRequestSender},
    protocols::network::{Event, NewNetworkEvents, NewNetworkSender},
    ProtocolId,
};
use safety_rules::{PersistentSafetyStorage, SafetyRulesManager};
use std::{sync::Arc, time::Duration};
use tokio::runtime::Handle;

/// Auxiliary struct that is setting up node environment for the test.
pub struct NodeSetup {
    block_store: Arc<BlockStore>,
    round_manager: RoundManager,
    storage: Arc<MockStorage>,
    signer: ValidatorSigner,
    proposer_author: Author,
    safety_rules_manager: SafetyRulesManager,
    all_events: Box<dyn Stream<Item = Event<ConsensusMsg>> + Send + Unpin>,
    commit_cb_receiver: mpsc::UnboundedReceiver<LedgerInfoWithSignatures>,
    _state_sync_receiver: mpsc::UnboundedReceiver<Payload>,
    id: usize,
}

impl NodeSetup {
    fn create_round_state(time_service: Arc<dyn TimeService>) -> RoundState {
        let base_timeout = Duration::new(60, 0);
        let time_interval = Box::new(ExponentialTimeInterval::fixed(base_timeout));
        let (round_timeout_sender, _) = channel::new_test(1_024);
        RoundState::new(time_interval, time_service, round_timeout_sender)
    }

    fn create_proposer_election(author: Author) -> Box<dyn ProposerElection + Send + Sync> {
        Box::new(RotatingProposer::new(vec![author], 1))
    }

    fn create_nodes(
        playground: &mut NetworkPlayground,
        executor: Handle,
        num_nodes: usize,
    ) -> Vec<Self> {
        let (signers, validators) = random_validator_verifier(num_nodes, None, false);
        let proposer_author = signers[0].author();
        let validator_set = (&validators).into();
        let waypoint =
            Waypoint::new_epoch_boundary(&LedgerInfo::mock_genesis(Some(validator_set))).unwrap();

        let mut nodes = vec![];
        // pre-initialize the mapping to avoid race conditions (peer try to broadcast to someone not added yet)
        let shared_connections = playground.peer_protocols();
        for signer in signers.iter().take(num_nodes) {
            shared_connections.write().insert(
                signer.author(),
                vec![
                    ProtocolId::ConsensusDirectSendJSON,
                    ProtocolId::ConsensusDirectSend,
                    ProtocolId::ConsensusRpc,
                ]
                .iter()
                .into(),
            );
        }
        for (id, signer) in signers.iter().take(num_nodes).enumerate() {
            let (initial_data, storage) = MockStorage::start_for_testing((&validators).into());

            let safety_storage = PersistentSafetyStorage::initialize(
                Storage::from(diem_secure_storage::InMemoryStorage::new()),
                signer.author(),
                signer.private_key().clone(),
                Ed25519PrivateKey::generate_for_testing(),
                waypoint,
                true,
            );
            let safety_rules_manager = SafetyRulesManager::new_local(safety_storage, false, false);

            nodes.push(Self::new(
                playground,
                executor.clone(),
                signer.to_owned(),
                proposer_author,
                storage,
                initial_data,
                safety_rules_manager,
                id,
            ));
        }
        nodes
    }

    fn new(
        playground: &mut NetworkPlayground,
        executor: Handle,
        signer: ValidatorSigner,
        proposer_author: Author,
        storage: Arc<MockStorage>,
        initial_data: RecoveryData,
        safety_rules_manager: SafetyRulesManager,
        id: usize,
    ) -> Self {
        let epoch_state = EpochState {
            epoch: 1,
            verifier: storage.get_validator_set().into(),
        };
        let validators = epoch_state.verifier.clone();
        let (network_reqs_tx, network_reqs_rx) = diem_channel::new(QueueStyle::FIFO, 8, None);
        let (connection_reqs_tx, _) = diem_channel::new(QueueStyle::FIFO, 8, None);
        let (consensus_tx, consensus_rx) = diem_channel::new(QueueStyle::FIFO, 8, None);
        let (_conn_mgr_reqs_tx, conn_mgr_reqs_rx) = channel::new_test(8);
        let (_, conn_status_rx) = conn_notifs_channel::new();
        let mut network_sender = ConsensusNetworkSender::new(
            PeerManagerRequestSender::new(network_reqs_tx),
            ConnectionRequestSender::new(connection_reqs_tx),
        );
        network_sender.initialize(playground.peer_protocols());
        let network_events = ConsensusNetworkEvents::new(consensus_rx, conn_status_rx);
        let author = signer.author();

        let twin_id = TwinId { id, author };

        playground.add_node(twin_id, consensus_tx, network_reqs_rx, conn_mgr_reqs_rx);

        let (self_sender, self_receiver) = channel::new_test(1000);
        let network = NetworkSender::new(author, network_sender, self_sender, validators);

        let all_events = Box::new(select(network_events, self_receiver));

        let last_vote_sent = initial_data.last_vote();
        let (commit_cb_sender, commit_cb_receiver) = mpsc::unbounded::<LedgerInfoWithSignatures>();
        let (state_sync_client, _state_sync_receiver) = mpsc::unbounded();
        let state_computer = Arc::new(MockStateComputer::new(
            state_sync_client,
            commit_cb_sender,
            Arc::clone(&storage),
        ));
        let time_service = Arc::new(ClockTimeService::new(executor));

        let block_store = Arc::new(BlockStore::new(
            storage.clone(),
            initial_data,
            state_computer,
            10, // max pruned blocks in mem
            time_service.clone(),
        ));

        let proposal_generator = ProposalGenerator::new(
            author,
            block_store.clone(),
            Arc::new(MockTransactionManager::new(None)),
            time_service.clone(),
            1,
        );

        let round_state = Self::create_round_state(time_service);
        let proposer_election = Self::create_proposer_election(proposer_author);
        let mut safety_rules =
            MetricsSafetyRules::new(safety_rules_manager.client(), storage.clone());
        safety_rules.perform_initialize().unwrap();

        let mut round_manager = RoundManager::new(
            epoch_state,
            Arc::clone(&block_store),
            round_state,
            proposer_election,
            proposal_generator,
            safety_rules,
            network,
            Arc::new(MockTransactionManager::new(None)),
            storage.clone(),
            false,
        );
        block_on(round_manager.start(last_vote_sent));
        Self {
            block_store,
            round_manager,
            storage,
            signer,
            proposer_author,
            safety_rules_manager,
            all_events,
            commit_cb_receiver,
            _state_sync_receiver,
            id,
        }
    }

    pub fn restart(self, playground: &mut NetworkPlayground, executor: Handle) -> Self {
        let recover_data = self
            .storage
            .try_start()
            .unwrap_or_else(|e| panic!("fail to restart due to: {}", e));
        Self::new(
            playground,
            executor,
            self.signer,
            self.proposer_author,
            self.storage,
            recover_data,
            self.safety_rules_manager,
            self.id,
        )
    }

    pub async fn next_proposal(&mut self) -> ProposalMsg {
        match self.all_events.next().await.unwrap() {
            Event::Message(_, msg) => match msg {
                ConsensusMsg::ProposalMsg(p) => *p,
                msg => panic!("Unexpected Consensus Message: {:?}", msg),
            },
            _ => panic!("Unexpected Network Event"),
        }
    }

    pub async fn next_vote(&mut self) -> VoteMsg {
        match self.all_events.next().await.unwrap() {
            Event::Message(_, msg) => match msg {
                ConsensusMsg::VoteMsg(v) => *v,
                msg => panic!("Unexpected Consensus Message: {:?}", msg),
            },
            _ => panic!("Unexpected Network Event"),
        }
    }

    pub async fn next_sync_info(&mut self) -> SyncInfo {
        match self.all_events.next().await.unwrap() {
            Event::Message(_, msg) => match msg {
                ConsensusMsg::SyncInfo(s) => *s,
                msg => panic!("Unexpected Consensus Message: {:?}", msg),
            },
            _ => panic!("Unexpected Network Event"),
        }
    }

    pub async fn next_message(&mut self) -> ConsensusMsg {
        match self.all_events.next().await.unwrap() {
            Event::Message(_, msg) => msg,
            _ => panic!("Unexpected Network Event"),
        }
    }
}

#[test]
fn new_round_on_quorum_cert() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let node = &mut nodes[0];
    let genesis = node.block_store.root();
    timed_block_on(&mut runtime, async {
        // round 1 should start
        let proposal_msg = node.next_proposal().await;
        assert_eq!(
            proposal_msg.proposal().quorum_cert().certified_block().id(),
            genesis.id()
        );
        let b1_id = proposal_msg.proposal().id();
        assert_eq!(proposal_msg.proposer(), node.signer.author());

        node.round_manager
            .process_proposal_msg(proposal_msg)
            .await
            .unwrap();
        let vote_msg = node.next_vote().await;
        // Adding vote to form a QC
        node.round_manager.process_vote_msg(vote_msg).await.unwrap();

        // round 2 should start
        let proposal_msg = node.next_proposal().await;
        let proposal = proposal_msg.proposal();
        assert_eq!(proposal.round(), 2);
        assert_eq!(proposal.parent_id(), b1_id);
        assert_eq!(proposal.quorum_cert().certified_block().id(), b1_id);
    });
}

#[test]
/// If the proposal is valid, a vote should be sent
fn vote_on_successful_proposal() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    // In order to observe the votes we're going to check proposal processing on the non-proposer
    // node (which will send the votes to the proposer).
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let node = &mut nodes[0];

    let genesis_qc = certificate_for_genesis();
    timed_block_on(&mut runtime, async {
        // Start round 1 and clear the message queue
        node.next_proposal().await;

        let proposal = Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &node.signer);
        let proposal_id = proposal.id();
        node.round_manager.process_proposal(proposal).await.unwrap();
        let vote_msg = node.next_vote().await;
        assert_eq!(vote_msg.vote().author(), node.signer.author());
        assert_eq!(vote_msg.vote().vote_data().proposed().id(), proposal_id);
        let consensus_state = node.round_manager.consensus_state();
        assert_eq!(consensus_state.epoch(), 1);
        assert_eq!(consensus_state.last_voted_round(), 1);
        assert_eq!(consensus_state.preferred_round(), 0);
        assert_eq!(consensus_state.in_validator_set(), true);
    });
}

#[test]
/// If the proposal does not pass voting rules,
/// No votes are sent, but the block is still added to the block tree.
fn no_vote_on_old_proposal() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    // In order to observe the votes we're going to check proposal processing on the non-proposer
    // node (which will send the votes to the proposer).
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let node = &mut nodes[0];
    let genesis_qc = certificate_for_genesis();
    let new_block = Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &node.signer);
    let new_block_id = new_block.id();
    let old_block = Block::new_proposal(vec![], 1, 2, genesis_qc, &node.signer);
    let old_block_id = old_block.id();
    timed_block_on(&mut runtime, async {
        // clear the message queue
        node.next_proposal().await;

        node.round_manager
            .process_proposal(new_block)
            .await
            .unwrap();
        node.round_manager
            .process_proposal(old_block)
            .await
            .unwrap_err();
        let vote_msg = node.next_vote().await;
        assert_eq!(vote_msg.vote().vote_data().proposed().id(), new_block_id);
        assert!(node.block_store.get_block(old_block_id).is_some());
    });
}

#[test]
/// We don't vote for proposals that 'skips' rounds
/// After that when we then receive proposal for correct round, we vote for it
/// Basically it checks that adversary can not send proposal and skip rounds violating round_state
/// rules
fn no_vote_on_mismatch_round() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    // In order to observe the votes we're going to check proposal processing on the non-proposer
    // node (which will send the votes to the proposer).
    let mut node = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1)
        .pop()
        .unwrap();
    let genesis_qc = certificate_for_genesis();
    let correct_block = Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &node.signer);
    let block_skip_round = Block::new_proposal(vec![], 2, 2, genesis_qc.clone(), &node.signer);
    timed_block_on(&mut runtime, async {
        let bad_proposal = ProposalMsg::new(
            block_skip_round,
            SyncInfo::new(genesis_qc.clone(), genesis_qc.clone(), None),
        );
        assert!(node
            .round_manager
            .process_proposal_msg(bad_proposal)
            .await
            .is_err());
        let good_proposal = ProposalMsg::new(
            correct_block.clone(),
            SyncInfo::new(genesis_qc.clone(), genesis_qc.clone(), None),
        );
        node.round_manager
            .process_proposal_msg(good_proposal)
            .await
            .unwrap();
    });
}

#[test]
/// Ensure that after the vote messages are broadcasted upon timeout, the receivers
/// have the highest quorum certificate (carried by the SyncInfo of the vote message)
fn sync_info_carried_on_timeout_vote() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let mut node = nodes.pop().unwrap();

    timed_block_on(&mut runtime, async {
        let proposal_msg = node.next_proposal().await;
        let block_0 = proposal_msg.proposal().clone();
        node.round_manager
            .process_proposal_msg(proposal_msg)
            .await
            .unwrap();
        node.next_vote().await;
        let parent_block_info = block_0.quorum_cert().certified_block();
        // Populate block_0 and a quorum certificate for block_0 on non_proposer
        let block_0_quorum_cert = gen_test_certificate(
            vec![&node.signer],
            // Follow MockStateComputer implementation
            block_0.gen_block_info(
                parent_block_info.executed_state_id(),
                parent_block_info.version(),
                parent_block_info.next_epoch_state().cloned(),
            ),
            parent_block_info.clone(),
            None,
        );
        node.block_store
            .insert_single_quorum_cert(block_0_quorum_cert.clone())
            .unwrap();

        node.round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
        let vote_msg_on_timeout = node.next_vote().await;
        assert!(vote_msg_on_timeout.vote().is_timeout());
        assert_eq!(
            *vote_msg_on_timeout.sync_info().highest_quorum_cert(),
            block_0_quorum_cert
        );
    });
}

#[test]
/// We don't vote for proposals that comes from proposers that are not valid proposers for round
fn no_vote_on_invalid_proposer() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    // In order to observe the votes we're going to check proposal processing on the non-proposer
    // node (which will send the votes to the proposer).
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 2);
    let incorrect_proposer = nodes.pop().unwrap();
    let mut node = nodes.pop().unwrap();
    let genesis_qc = certificate_for_genesis();
    let correct_block = Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &node.signer);
    let block_incorrect_proposer =
        Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &incorrect_proposer.signer);
    timed_block_on(&mut runtime, async {
        let bad_proposal = ProposalMsg::new(
            block_incorrect_proposer,
            SyncInfo::new(genesis_qc.clone(), genesis_qc.clone(), None),
        );
        assert!(node
            .round_manager
            .process_proposal_msg(bad_proposal)
            .await
            .is_err());
        let good_proposal = ProposalMsg::new(
            correct_block.clone(),
            SyncInfo::new(genesis_qc.clone(), genesis_qc.clone(), None),
        );

        node.round_manager
            .process_proposal_msg(good_proposal.clone())
            .await
            .unwrap();
    });
}

#[test]
/// We allow to 'skip' round if proposal carries timeout certificate for next round
fn new_round_on_timeout_certificate() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    // In order to observe the votes we're going to check proposal processing on the non-proposer
    // node (which will send the votes to the proposer).
    let mut node = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1)
        .pop()
        .unwrap();
    let genesis_qc = certificate_for_genesis();
    let correct_block = Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &node.signer);
    let block_skip_round = Block::new_proposal(vec![], 2, 2, genesis_qc.clone(), &node.signer);
    let timeout = Timeout::new(1, 1);
    let timeout_signature = timeout.sign(&node.signer);

    let mut tc = TimeoutCertificate::new(timeout);
    tc.add_signature(node.signer.author(), timeout_signature);

    timed_block_on(&mut runtime, async {
        let skip_round_proposal = ProposalMsg::new(
            block_skip_round,
            SyncInfo::new(genesis_qc.clone(), genesis_qc.clone(), Some(tc)),
        );
        node.round_manager
            .process_proposal_msg(skip_round_proposal)
            .await
            .unwrap();
        let old_good_proposal = ProposalMsg::new(
            correct_block.clone(),
            SyncInfo::new(genesis_qc.clone(), genesis_qc.clone(), None),
        );
        assert!(node
            .round_manager
            .process_proposal_msg(old_good_proposal)
            .await
            .is_err());
    });
}

#[test]
fn response_on_block_retrieval() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut node = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1)
        .pop()
        .unwrap();

    let genesis_qc = certificate_for_genesis();
    let block = Block::new_proposal(vec![], 1, 1, genesis_qc.clone(), &node.signer);
    let block_id = block.id();
    let proposal = ProposalMsg::new(block, SyncInfo::new(genesis_qc.clone(), genesis_qc, None));

    timed_block_on(&mut runtime, async {
        node.round_manager
            .process_proposal_msg(proposal)
            .await
            .unwrap();

        // first verify that we can retrieve the block if it's in the tree
        let (tx1, rx1) = oneshot::channel();
        let single_block_request = IncomingBlockRetrievalRequest {
            req: BlockRetrievalRequest::new(block_id, 1),
            response_sender: tx1,
        };
        node.round_manager
            .process_block_retrieval(single_block_request)
            .await
            .unwrap();
        match rx1.await {
            Ok(Ok(bytes)) => {
                let response = match bcs::from_bytes(&bytes) {
                    Ok(ConsensusMsg::BlockRetrievalResponse(resp)) => *resp,
                    _ => panic!("block retrieval failure"),
                };
                assert_eq!(response.status(), BlockRetrievalStatus::Succeeded);
                assert_eq!(response.blocks().get(0).unwrap().id(), block_id);
            }
            _ => panic!("block retrieval failure"),
        }

        // verify that if a block is not there, return ID_NOT_FOUND
        let (tx2, rx2) = oneshot::channel();
        let missing_block_request = IncomingBlockRetrievalRequest {
            req: BlockRetrievalRequest::new(HashValue::random(), 1),
            response_sender: tx2,
        };

        node.round_manager
            .process_block_retrieval(missing_block_request)
            .await
            .unwrap();
        match rx2.await {
            Ok(Ok(bytes)) => {
                let response = match bcs::from_bytes(&bytes) {
                    Ok(ConsensusMsg::BlockRetrievalResponse(resp)) => *resp,
                    _ => panic!("block retrieval failure"),
                };
                assert_eq!(response.status(), BlockRetrievalStatus::IdNotFound);
                assert!(response.blocks().is_empty());
            }
            _ => panic!("block retrieval failure"),
        }

        // if asked for many blocks, return NOT_ENOUGH_BLOCKS
        let (tx3, rx3) = oneshot::channel();
        let many_block_request = IncomingBlockRetrievalRequest {
            req: BlockRetrievalRequest::new(block_id, 3),
            response_sender: tx3,
        };
        node.round_manager
            .process_block_retrieval(many_block_request)
            .await
            .unwrap();
        match rx3.await {
            Ok(Ok(bytes)) => {
                let response = match bcs::from_bytes(&bytes) {
                    Ok(ConsensusMsg::BlockRetrievalResponse(resp)) => *resp,
                    _ => panic!("block retrieval failure"),
                };
                assert_eq!(response.status(), BlockRetrievalStatus::NotEnoughBlocks);
                assert_eq!(block_id, response.blocks().get(0).unwrap().id());
                assert_eq!(
                    node.block_store.root().id(),
                    response.blocks().get(1).unwrap().id()
                );
            }
            _ => panic!("block retrieval failure"),
        }
    });
}

#[test]
/// rebuild a node from previous storage without violating safety guarantees.
fn recover_on_restart() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut node = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1)
        .pop()
        .unwrap();
    let inserter = TreeInserter::new_with_store(node.signer.clone(), node.block_store.clone());

    let genesis_qc = certificate_for_genesis();
    let mut data = Vec::new();
    let num_proposals = 100;
    // insert a few successful proposals
    for i in 1..=num_proposals {
        let proposal = inserter.create_block_with_qc(genesis_qc.clone(), i, i, vec![]);
        let timeout = Timeout::new(1, i - 1);
        let mut tc = TimeoutCertificate::new(timeout.clone());
        tc.add_signature(inserter.signer().author(), inserter.signer().sign(&timeout));
        data.push((proposal, tc));
    }

    timed_block_on(&mut runtime, async {
        for (proposal, tc) in &data {
            let proposal_msg = ProposalMsg::new(
                proposal.clone(),
                SyncInfo::new(
                    proposal.quorum_cert().clone(),
                    genesis_qc.clone(),
                    Some(tc.clone()),
                ),
            );
            node.round_manager
                .process_proposal_msg(proposal_msg)
                .await
                .unwrap();
        }
    });

    // verify after restart we recover the data
    node = node.restart(&mut playground, runtime.handle().clone());
    let consensus_state = node.round_manager.consensus_state();
    assert_eq!(consensus_state.epoch(), 1);
    assert_eq!(consensus_state.last_voted_round(), num_proposals);
    assert_eq!(consensus_state.preferred_round(), 0);
    assert_eq!(consensus_state.in_validator_set(), true);
    for (block, _) in data {
        assert_eq!(node.block_store.block_exists(block.id()), true);
    }
}

#[test]
/// Generate a NIL vote extending HQC upon timeout if no votes have been sent in the round.
fn nil_vote_on_timeout() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let node = &mut nodes[0];
    let genesis = node.block_store.root();
    timed_block_on(&mut runtime, async {
        node.next_proposal().await;
        // Process the outgoing vote message and verify that it contains a round signature
        // and that the vote extends genesis.
        node.round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
        let vote_msg = node.next_vote().await;

        let vote = vote_msg.vote();

        assert!(vote.is_timeout());
        // NIL block doesn't change timestamp
        assert_eq!(
            vote.vote_data().proposed().timestamp_usecs(),
            genesis.timestamp_usecs()
        );
        assert_eq!(vote.vote_data().proposed().round(), 1);
        assert_eq!(vote.vote_data().parent().id(), node.block_store.root().id());
    });
}

#[test]
/// If the node votes in a round, upon timeout the same vote is re-sent with a timeout signature.
fn vote_resent_on_timeout() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let node = &mut nodes[0];
    timed_block_on(&mut runtime, async {
        let proposal_msg = node.next_proposal().await;
        let id = proposal_msg.proposal().id();
        node.round_manager
            .process_proposal_msg(proposal_msg)
            .await
            .unwrap();
        let vote_msg = node.next_vote().await;
        let vote = vote_msg.vote();
        assert!(!vote.is_timeout());
        assert_eq!(vote.vote_data().proposed().id(), id);
        // Process the outgoing vote message and verify that it contains a round signature
        // and that the vote is the same as above.
        node.round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
        let timeout_vote_msg = node.next_vote().await;
        let timeout_vote = timeout_vote_msg.vote();

        assert!(timeout_vote.is_timeout());
        assert_eq!(timeout_vote.vote_data(), vote.vote_data());
    });
}

#[test]
fn sync_info_sent_on_stale_sync_info() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 2);
    runtime.spawn(playground.start());
    let genesis_qc = certificate_for_genesis();
    let block_0 = Block::new_proposal(vec![], 1, 1, genesis_qc, &nodes[0].signer);
    let parent_block_info = block_0.quorum_cert().certified_block();
    let block_0_quorum_cert = gen_test_certificate(
        vec![&nodes[0].signer, &nodes[1].signer],
        // Follow MockStateComputer implementation
        block_0.gen_block_info(
            parent_block_info.executed_state_id(),
            parent_block_info.version(),
            parent_block_info.next_epoch_state().cloned(),
        ),
        parent_block_info.clone(),
        None,
    );
    let mut behind_node = nodes.pop().unwrap();
    let mut ahead_node = nodes.pop().unwrap();
    // ahead node has one more block
    ahead_node
        .block_store
        .execute_and_insert_block(block_0)
        .unwrap();
    ahead_node
        .block_store
        .insert_single_quorum_cert(block_0_quorum_cert.clone())
        .unwrap();

    timed_block_on(&mut runtime, async {
        ahead_node.next_proposal().await;
        behind_node.next_proposal().await;
        // broadcast timeout
        behind_node
            .round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
        let timeout_vote_msg = behind_node.next_vote().await;
        assert!(timeout_vote_msg.vote().is_timeout());

        // process the stale sync info carried in the vote
        ahead_node
            .round_manager
            .process_vote_msg(timeout_vote_msg)
            .await
            .unwrap();
        let sync_info = behind_node.next_sync_info().await;

        assert_eq!(*sync_info.highest_quorum_cert(), block_0_quorum_cert);
    });
}

#[test]
fn sync_on_partial_newer_sync_info() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let mut node = nodes.pop().unwrap();
    runtime.spawn(playground.start());
    timed_block_on(&mut runtime, async {
        // commit block 1 after 4 rounds
        for _ in 1..=4 {
            let proposal_msg = node.next_proposal().await;

            node.round_manager
                .process_proposal_msg(proposal_msg)
                .await
                .unwrap();
            let vote_msg = node.next_vote().await;
            // Adding vote to form a QC
            node.round_manager.process_vote_msg(vote_msg).await.unwrap();
        }
        let block_4 = node.next_proposal().await;
        node.round_manager
            .process_proposal_msg(block_4.clone())
            .await
            .unwrap();
        // commit genesis and block 1
        for _ in 0..2 {
            let _ = node.commit_cb_receiver.next().await;
        }
        let vote_msg = node.next_vote().await;
        let vote_data = vote_msg.vote().vote_data();
        let block_4_qc = gen_test_certificate(
            vec![&node.signer],
            vote_data.proposed().clone(),
            vote_data.parent().clone(),
            None,
        );
        // Create a sync info with newer quorum cert but older commit cert
        let sync_info = SyncInfo::new(block_4_qc.clone(), certificate_for_genesis(), None);
        node.round_manager
            .ensure_round_and_sync_up(
                sync_info.highest_round() + 1,
                &sync_info,
                node.signer.author(),
                true,
            )
            .await
            .unwrap();
        // QuorumCert added
        assert_eq!(*node.block_store.highest_quorum_cert(), block_4_qc);
        // Help remote message sent
        // Due to the asynchronous channel, the order of the sync info and next proposal is not fixed.
        // We assert one of them is the sync info we expect.
        let m1 = node.next_message().await;
        let m2 = node.next_message().await;
        assert!(matches!(m1, ConsensusMsg::SyncInfo(_)) || matches!(m2, ConsensusMsg::SyncInfo(_)));
    });
}

#[test]
fn safety_rules_crash() {
    let mut runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(&mut playground, runtime.handle().clone(), 1);
    let mut node = nodes.pop().unwrap();
    runtime.spawn(playground.start());

    fn reset_safety_rules(node: &mut NodeSetup) {
        let safety_storage = PersistentSafetyStorage::initialize(
            Storage::from(diem_secure_storage::InMemoryStorage::new()),
            node.signer.author(),
            node.signer.private_key().clone(),
            Ed25519PrivateKey::generate_for_testing(),
            node.round_manager.consensus_state().waypoint(),
            true,
        );

        node.safety_rules_manager = SafetyRulesManager::new_local(safety_storage, false, false);
        let safety_rules =
            MetricsSafetyRules::new(node.safety_rules_manager.client(), node.storage.clone());
        node.round_manager.set_safety_rules(safety_rules);
    }

    timed_block_on(&mut runtime, async {
        for _ in 0..2 {
            let proposal_msg = node.next_proposal().await;

            reset_safety_rules(&mut node);
            // construct_and_sign_vote
            node.round_manager
                .process_proposal_msg(proposal_msg)
                .await
                .unwrap();

            let vote_msg = node.next_vote().await;

            // sign_timeout
            reset_safety_rules(&mut node);
            let round = vote_msg.vote().vote_data().proposed().round();
            node.round_manager
                .process_local_timeout(round)
                .await
                .unwrap_err();
            let vote_msg = node.next_vote().await;

            // sign proposal
            reset_safety_rules(&mut node);
            node.round_manager.process_vote_msg(vote_msg).await.unwrap();
        }

        // verify the last sign proposal happened
        node.next_proposal().await;
    });
}
