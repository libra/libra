// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    sparse_merkle::node::{Node, NodeHandle, SubTree},
    test_utils::{naive_smt::NaiveSmt, proof_reader::ProofReader},
    SparseMerkleTree,
};
use diem_crypto::{hash::SPARSE_MERKLE_PLACEHOLDER_HASH, HashValue};
use diem_types::account_state_blob::AccountStateBlob;
use proptest::{
    collection::{hash_set, vec},
    prelude::*,
    sample::Index,
};
use std::{borrow::Borrow, sync::Arc};

type TxnOutput = Vec<(HashValue, AccountStateBlob)>;
type BlockOutput = Vec<TxnOutput>;

pub fn arb_smt_correctness_case() -> impl Strategy<Value = Vec<(BlockOutput, bool)>> {
    (
        hash_set(any::<HashValue>(), 1..100), // keys
        vec(
            // blocks
            (
                vec(
                    // txns
                    vec(
                        // txn updates
                        (any::<Index>(), any::<Vec<u8>>()),
                        1..4,
                    ),
                    1..10,
                ),
                any::<bool>(), // commit
            ),
            1..10,
        ),
    )
        .prop_map(|(keys, blocks)| {
            let keys: Vec<_> = keys.into_iter().collect();
            blocks
                .into_iter()
                .map(|(txns, commit)| {
                    (
                        txns.into_iter()
                            .map(|updates| {
                                updates
                                    .into_iter()
                                    .map(|(k_idx, v)| (*k_idx.get(&keys), v.to_vec().into()))
                                    .collect()
                            })
                            .collect::<Vec<_>>(),
                        commit,
                    )
                })
                .collect::<Vec<_>>()
        })
}

pub fn test_smt_correctness_impl(input: Vec<(BlockOutput, bool)>) {
    let mut persisted_smt = NaiveSmt::new::<AccountStateBlob>(&[]);
    let mut naive_smt = persisted_smt.clone();

    let mut serial_smt = SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH);
    let mut batches_smt = SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH);
    let mut updater_smt = SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH);

    for (block, commit) in input {
        let updates = block
            .iter()
            .map(|txn_updates| txn_updates.iter().map(|(k, v)| (*k, v)).collect())
            .collect::<Vec<_>>();
        let updates_flat_batch = updates.iter().flatten().cloned().collect::<Vec<_>>();

        let proofs = updates_flat_batch
            .iter()
            .map(|(k, _)| (*k, persisted_smt.get_proof(k)))
            .collect();
        let proof_reader = ProofReader::new(proofs);
        naive_smt = naive_smt.update(&updates_flat_batch);

        let upd_serial_smt = serial_smt
            .serial_update(updates.clone(), &proof_reader)
            .unwrap()
            .1;
        serial_smt.assert_no_external_strong_ref();
        serial_smt = upd_serial_smt;

        let upd_batches_smt = batches_smt
            .batches_update(updates, &proof_reader)
            .unwrap()
            .1;
        batches_smt.assert_no_external_strong_ref();
        batches_smt = upd_batches_smt;

        let upd_updater_smt = updater_smt
            .batch_update(updates_flat_batch, &proof_reader)
            .unwrap();
        updater_smt.assert_no_external_strong_ref();
        updater_smt = upd_updater_smt;

        assert_eq!(serial_smt.root_hash(), naive_smt.get_root_hash());
        assert_eq!(batches_smt.root_hash(), naive_smt.get_root_hash());
        assert_eq!(updater_smt.root_hash(), naive_smt.get_root_hash());

        if commit {
            persisted_smt = naive_smt.clone();
            // TODO(aldenhu): fix logic
        }
    }
}

trait AssertNoExternalStrongRef {
    fn assert_no_external_strong_ref(&self);
}

impl<V> AssertNoExternalStrongRef for SparseMerkleTree<V> {
    fn assert_no_external_strong_ref(&self) {
        assert_subtree_sole_strong_ref(&self.inner.root);
    }
}

fn assert_subtree_sole_strong_ref<V>(subtree: &SubTree<V>) {
    if let SubTree::NonEmpty {
        root: NodeHandle::Shared(arc),
        ..
    } = subtree
    {
        assert_eq!(Arc::strong_count(arc), 1);
        if let Node::Internal(internal_node) = arc.borrow() {
            assert_subtree_sole_strong_ref(&internal_node.left);
            assert_subtree_sole_strong_ref(&internal_node.right);
        }
    }
}
