// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{
    proof_reader::ProofReader,
    proptest_helpers::{arb_smt_correctness_case, test_smt_correctness_impl},
};
use diem_crypto::{
    hash::{CryptoHash, TestOnlyHash, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use diem_types::{
    account_state_blob::AccountStateBlob,
    proof::{SparseMerkleLeafNode, SparseMerkleProof},
};
use proptest::prelude::*;

fn update_byte(original_key: &HashValue, n: usize, byte: u8) -> HashValue {
    let mut key = original_key.to_vec();
    key[n] = byte;
    HashValue::from_slice(&key).unwrap()
}

fn hash_internal(left_child: HashValue, right_child: HashValue) -> HashValue {
    diem_types::proof::SparseMerkleInternalNode::new(left_child, right_child).hash()
}

fn hash_leaf(key: HashValue, value_hash: HashValue) -> HashValue {
    SparseMerkleLeafNode::new(key, value_hash).hash()
}

type SparseMerkleTree = super::SparseMerkleTree<AccountStateBlob>;
type SubTree = super::SubTree<AccountStateBlob>;

#[test]
fn test_replace_in_mem_leaf() {
    let key = b"hello".test_only_hash();
    let value_hash = b"world".test_only_hash();
    let leaf = SubTree::new_leaf_with_value_hash(key, value_hash);
    let smt = SparseMerkleTree::new_with_root(leaf);

    let new_value: AccountStateBlob = vec![1, 2, 3].into();
    let root_hash = hash_leaf(key, new_value.hash());
    let updated = smt
        .batch_update(vec![(key, &new_value)], &ProofReader::default())
        .unwrap();
    assert_eq!(updated.root_hash(), root_hash);
}

#[test]
fn test_split_in_mem_leaf() {
    let key1 = HashValue::from_slice(&[0; 32]).unwrap();
    let value1_hash = b"hello".test_only_hash();
    let leaf1 = SubTree::new_leaf_with_value_hash(key1, value1_hash);
    let smt = SparseMerkleTree::new_with_root(leaf1);

    let key2 = HashValue::from_slice(&[0xff; 32]).unwrap();
    let value2: AccountStateBlob = vec![1, 2, 3].into();

    let root_hash = hash_internal(hash_leaf(key1, value1_hash), hash_leaf(key2, value2.hash()));
    let updated = smt
        .batch_update(vec![(key2, &value2)], &ProofReader::default())
        .unwrap();
    assert_eq!(updated.root_hash(), root_hash);
}

#[test]
fn test_insert_at_in_mem_empty() {
    let key1 = HashValue::from_slice(&[0; 32]).unwrap();
    let value1_hash = b"hello".test_only_hash();
    let key2 = update_byte(&key1, 0, 0b01000000);
    let value2_hash = b"world".test_only_hash();

    let key3 = update_byte(&key1, 0, 0b10000000);
    let value3: AccountStateBlob = vec![1, 2, 3].into();

    let internal = SubTree::new_internal(
        SubTree::new_leaf_with_value_hash(key1, value1_hash),
        SubTree::new_leaf_with_value_hash(key2, value2_hash),
    );
    let internal_hash = internal.hash();
    let root = SubTree::new_internal(internal, SubTree::new_empty());
    let smt = SparseMerkleTree::new_with_root(root);

    let root_hash = hash_internal(internal_hash, hash_leaf(key3, value3.hash()));
    let updated = smt
        .batch_update(vec![(key3, &value3)], &ProofReader::default())
        .unwrap();
    assert_eq!(updated.root_hash(), root_hash);
}

#[test]
fn test_replace_persisted_leaf() {
    let key = b"hello".test_only_hash();
    let value_hash = b"world".test_only_hash();
    let leaf = SparseMerkleLeafNode::new(key, value_hash);
    let proof = SparseMerkleProof::new(Some(leaf), Vec::new());
    let proof_reader = ProofReader::new(vec![(key, proof)]);

    let smt = SparseMerkleTree::new(leaf.hash());
    let new_value: AccountStateBlob = vec![1, 2, 3].into();
    let root_hash = hash_leaf(key, new_value.hash());
    let updated = smt
        .batch_update(vec![(key, &new_value)], &proof_reader)
        .unwrap();
    assert_eq!(updated.root_hash(), root_hash);
}

#[test]
fn test_split_persisted_leaf() {
    let key1 = HashValue::from_slice(&[0; 32]).unwrap();
    let value_hash1 = b"hello".test_only_hash();
    let leaf1 = SparseMerkleLeafNode::new(key1, value_hash1);

    let smt = SparseMerkleTree::new(leaf1.hash());

    let key2 = HashValue::from_slice(&[0xff; 32]).unwrap();
    let value2: AccountStateBlob = vec![1, 2, 3].into();
    let proof = SparseMerkleProof::new(Some(leaf1), Vec::new());
    let proof_reader = ProofReader::new(vec![(key2, proof)]);

    let root_hash = hash_internal(leaf1.hash(), hash_leaf(key2, value2.hash()));
    let updated = smt
        .batch_update(vec![(key2, &value2)], &proof_reader)
        .unwrap();
    assert_eq!(updated.root_hash(), root_hash);
}

#[test]
fn test_insert_at_persisted_empty() {
    let key1 = HashValue::from_slice(&[0; 32]).unwrap();
    let value1_hash = b"hello".test_only_hash();
    let key2 = update_byte(&key1, 0, 0b01000000);
    let value2_hash = b"world".test_only_hash();

    let key3 = update_byte(&key1, 0, 0b10000000);
    let value3: AccountStateBlob = vec![1, 2, 3].into();

    let sibling_hash = hash_internal(hash_leaf(key1, value1_hash), hash_leaf(key2, value2_hash));
    let proof = SparseMerkleProof::new(None, vec![sibling_hash]);
    let proof_reader = ProofReader::new(vec![(key3, proof)]);
    let old_root_hash = hash_internal(sibling_hash, *SPARSE_MERKLE_PLACEHOLDER_HASH);
    let smt = SparseMerkleTree::new(old_root_hash);

    let root_hash = hash_internal(sibling_hash, hash_leaf(key3, value3.hash()));
    let updated = smt
        .batch_update(vec![(key3, &value3)], &proof_reader)
        .unwrap();
    assert_eq!(updated.root_hash(), root_hash);
}

#[test]
fn test_update_256_siblings_in_proof() {
    //                   root
    //                  /    \
    //                 o      placeholder
    //                / \
    //               o   placeholder
    //              / \
    //             .   placeholder
    //             .
    //             . (256 levels)
    //             o
    //            / \
    //        key1   key2
    let key1 = HashValue::new([0; HashValue::LENGTH]);
    let key2 = {
        let mut buf = key1.to_vec();
        *buf.last_mut().unwrap() |= 1;
        HashValue::from_slice(&buf).unwrap()
    };

    let blob1 = AccountStateBlob::from(b"value1".to_vec());
    let blob2 = AccountStateBlob::from(b"value2".to_vec());
    let value1_hash = blob1.hash();
    let value2_hash = blob2.hash();
    let leaf1_hash = hash_leaf(key1, value1_hash);
    let leaf2_hash = hash_leaf(key2, value2_hash);

    let mut siblings: Vec<_> = std::iter::repeat(*SPARSE_MERKLE_PLACEHOLDER_HASH)
        .take(255)
        .collect();
    siblings.push(leaf2_hash);
    siblings.reverse();
    let proof_of_key1 = SparseMerkleProof::new(
        Some(SparseMerkleLeafNode::new(key1, value1_hash)),
        siblings.clone(),
    );

    let old_root_hash = siblings.iter().fold(leaf1_hash, |previous_hash, hash| {
        hash_internal(previous_hash, *hash)
    });
    assert!(proof_of_key1
        .verify(old_root_hash, key1, Some(&blob1))
        .is_ok());

    let new_blob1 = AccountStateBlob::from(b"value1111111111111".to_vec());
    let proof_reader = ProofReader::new(vec![(key1, proof_of_key1)]);
    let smt = SparseMerkleTree::new(old_root_hash);
    let new_smt = smt
        .batch_update(vec![(key1, &new_blob1)], &proof_reader)
        .unwrap();

    let new_blob1_hash = new_blob1.hash();
    let new_leaf1_hash = hash_leaf(key1, new_blob1_hash);
    let new_root_hash = siblings.iter().fold(new_leaf1_hash, |previous_hash, hash| {
        hash_internal(previous_hash, *hash)
    });
    assert_eq!(new_smt.root_hash(), new_root_hash);

    assert_eq!(
        new_smt.get(key1),
        AccountStatus::ExistsInScratchPad(new_blob1)
    );
    assert_eq!(new_smt.get(key2), AccountStatus::Unknown);
}

#[test]
fn test_new_unknown() {
    let root_hash = HashValue::new([1; HashValue::LENGTH]);
    let smt = SparseMerkleTree::new(root_hash);
    assert!(smt.root_weak().is_unknown());
    assert_eq!(smt.root_hash(), root_hash);
}

#[test]
fn test_new_empty() {
    let root_hash = *SPARSE_MERKLE_PLACEHOLDER_HASH;
    let smt = SparseMerkleTree::new(root_hash);
    assert!(smt.root_weak().is_empty());
    assert_eq!(smt.root_hash(), root_hash);
}

#[test]
fn test_update() {
    // Before the update, the tree was:
    //             root
    //            /    \
    //           y      key3
    //          / \
    //         x   placeholder
    //        / \
    //    key1   key2
    let key1 = b"aaaaa".test_only_hash();
    let key2 = b"bb".test_only_hash();
    let key3 = b"cccc".test_only_hash();
    assert_eq!(key1[0], 0b0000_0100);
    assert_eq!(key2[0], 0b0010_0100);
    assert_eq!(key3[0], 0b1110_0111);
    let value1 = AccountStateBlob::from(b"value1".to_vec());
    let value1_hash = value1.hash();
    let value2_hash = AccountStateBlob::from(b"value2".to_vec()).hash();
    let value3_hash = AccountStateBlob::from(b"value3".to_vec()).hash();

    // A new key at the "placeholder" position.
    let key4 = b"d".test_only_hash();
    assert_eq!(key4[0], 0b0100_1100);
    let value4 = AccountStateBlob::from(b"value".to_vec());

    // Create a proof for this new key.
    let leaf1 = SparseMerkleLeafNode::new(key1, value1_hash);
    let leaf1_hash = leaf1.hash();
    let leaf2_hash = hash_leaf(key2, value2_hash);
    let leaf3_hash = hash_leaf(key3, value3_hash);
    let x_hash = hash_internal(leaf1_hash, leaf2_hash);
    let y_hash = hash_internal(x_hash, *SPARSE_MERKLE_PLACEHOLDER_HASH);
    let old_root_hash = hash_internal(y_hash, leaf3_hash);
    let proof = SparseMerkleProof::new(None, vec![x_hash, leaf3_hash]);
    assert!(proof.verify(old_root_hash, key4, None).is_ok());

    // Create the old tree and update the tree with new value and proof.
    let proof_reader = ProofReader::new(vec![(key4, proof)]);
    let old_smt = SparseMerkleTree::new(old_root_hash);
    let smt1 = old_smt
        .batch_update(vec![(key4, &value4)], &proof_reader)
        .unwrap();

    // Now smt1 should look like this:
    //             root
    //            /    \
    //           y      key3 (subtree)
    //          / \
    //         x   key4
    assert_eq!(smt1.get(key1), AccountStatus::Unknown);
    assert_eq!(smt1.get(key2), AccountStatus::Unknown);
    assert_eq!(smt1.get(key3), AccountStatus::Unknown);
    assert_eq!(
        smt1.get(key4),
        AccountStatus::ExistsInScratchPad(value4.clone())
    );

    let non_existing_key = b"foo".test_only_hash();
    assert_eq!(non_existing_key[0], 0b0111_0110);
    assert_eq!(smt1.get(non_existing_key), AccountStatus::DoesNotExist);

    // Verify root hash.
    let value4_hash = value4.hash();
    let leaf4_hash = hash_leaf(key4, value4_hash);
    let y_hash = hash_internal(x_hash, leaf4_hash);
    let root_hash = hash_internal(y_hash, leaf3_hash);
    assert_eq!(smt1.root_hash(), root_hash);

    // Next, we are going to modify key1. Create a proof for key1.
    let proof = SparseMerkleProof::new(
        Some(leaf1),
        vec![leaf2_hash, *SPARSE_MERKLE_PLACEHOLDER_HASH, leaf3_hash],
    );
    assert!(proof.verify(old_root_hash, key1, Some(&value1)).is_ok());

    let value1 = AccountStateBlob::from(b"value11111".to_vec());
    let proof_reader = ProofReader::new(vec![(key1, proof)]);
    let smt2 = smt1
        .batch_update(vec![(key1, &value1)], &proof_reader)
        .unwrap();

    // Now the tree looks like:
    //              root
    //             /    \
    //            y      key3 (subtree)
    //           / \
    //          x   key4 (from smt1)
    //         / \
    //     key1    key2 (subtree)
    assert_eq!(
        smt2.get(key1),
        AccountStatus::ExistsInScratchPad(value1.clone())
    );
    assert_eq!(smt2.get(key2), AccountStatus::Unknown);
    assert_eq!(smt2.get(key3), AccountStatus::Unknown);
    assert_eq!(smt2.get(key4), AccountStatus::ExistsInScratchPad(value4));

    // Verify root hash.
    let value1_hash = value1.hash();
    let leaf1_hash = hash_leaf(key1, value1_hash);
    let x_hash = hash_internal(leaf1_hash, leaf2_hash);
    let y_hash = hash_internal(x_hash, leaf4_hash);
    let root_hash = hash_internal(y_hash, leaf3_hash);
    assert_eq!(smt2.root_hash(), root_hash);

    // We now try to create another branch on top of smt1.
    let value4 = AccountStateBlob::from(b"new value 4444444444".to_vec());
    // key4 already exists in the tree.
    let proof_reader = ProofReader::default();
    let smt22 = smt1
        .batch_update(vec![(key4, &value4)], &proof_reader)
        .unwrap();

    // smt22 is like:
    // Now smt1 should look like this:
    //             root
    //            /    \
    //           y'      key3 (subtree)
    //          / \
    //         x   key4
    assert_eq!(smt22.get(key1), AccountStatus::Unknown);
    assert_eq!(smt22.get(key2), AccountStatus::Unknown);
    assert_eq!(smt22.get(key3), AccountStatus::Unknown);
    assert_eq!(
        smt22.get(key4),
        AccountStatus::ExistsInScratchPad(value4.clone())
    );

    // TODO(aldenhu): reflect new "prune" logic
    // Now prune smt1.
    // smt1.prune();

    // For smt2, only key1 should be available since smt2 was constructed by updating smt1 with
    // key1.
    assert_eq!(smt2.get(key1), AccountStatus::ExistsInScratchPad(value1));
    assert_eq!(smt2.get(key2), AccountStatus::Unknown);
    assert_eq!(smt2.get(key3), AccountStatus::Unknown);
    assert_eq!(smt2.get(key4), AccountStatus::Unknown);

    // For smt22, only key4 should be available since smt22 was constructed by updating smt1 with
    // key4.
    assert_eq!(smt22.get(key1), AccountStatus::Unknown);
    assert_eq!(smt22.get(key2), AccountStatus::Unknown);
    assert_eq!(smt22.get(key3), AccountStatus::Unknown);
    assert_eq!(smt22.get(key4), AccountStatus::ExistsInScratchPad(value4));
}

#[test]
fn test_drop() {
    let proof_reader = ProofReader::default();
    let root_smt = SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH);
    let mut smt = root_smt.clone();
    for _ in 0..100000 {
        smt = smt
            .batch_update(
                vec![(HashValue::zero(), &AccountStateBlob::from(b"zero".to_vec()))],
                &proof_reader,
            )
            .unwrap()
    }

    // TODO(aldenhu): verify
    // root_smt with a long chain of descendants being dropped here. It's a stack overflow if a
    // manual iterative `Drop` implementation is not in place.
    drop(root_smt);
}

proptest! {
    #[test]
    fn test_correctness( input in arb_smt_correctness_case() ) {
        test_smt_correctness_impl(input)
    }
}
