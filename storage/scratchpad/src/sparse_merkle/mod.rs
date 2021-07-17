// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module implements an in-memory Sparse Merkle Tree that is similar to what we use in
//! storage to represent world state. This tree will store only a small portion of the state -- the
//! part of accounts that have been modified by uncommitted transactions. For example, if we
//! execute a transaction T_i on top of committed state and it modified account A, we will end up
//! having the following tree:
//! ```text
//!              S_i
//!             /   \
//!            o     y
//!           / \
//!          x   A
//! ```
//! where A has the new state of the account, and y and x are the siblings on the path from root to
//! A in the tree.
//!
//! This Sparse Merkle Tree is immutable once constructed. If the next transaction T_{i+1} modified
//! another account B that lives in the subtree at y, a new tree will be constructed and the
//! structure will look like the following:
//! ```text
//!                 S_i        S_{i+1}
//!                /   \      /       \
//!               /     y   /          \
//!              / _______/             \
//!             //                       \
//!            o                          y'
//!           / \                        / \
//!          x   A                      z   B
//! ```
//!
//! Using this structure, we are able to query the global state, taking into account the output of
//! uncommitted transactions. For example, if we want to execute another transaction T_{i+1}', we
//! can use the tree S_i. If we look for account A, we can find its new value in the tree.
//! Otherwise, we know the account does not exist in the tree, and we can fall back to storage. As
//! another example, if we want to execute transaction T_{i+2}, we can use the tree S_{i+1} that
//! has updated values for both account A and B.
//!
//! Each version of the tree holds a strong reference (an Arc<Node>) to its root as well as one to
//! its base tree (S_i is the base tree of S_{i+1} in the above example). The root node in turn,
//! recursively holds all descendant nodes created in the same version, and weak references
//! (a Weak<Node>) to all descendant nodes that was created from previous versions.
//! With this construction:
//!     1. Even if a reference to a specific tree is dropped, the nodes belonging to it won't be
//! dropped as long as trees depending on it still hold strong references to it via the chain of
//! "base trees".
//!     2. Even if a tree is not dropped, when nodes it created are persisted to DB, all of them
//! and those created by its previous versions can be dropped, which we express by calling "prune()"
//! on it which replaces the strong references to its root and its base tree with weak references.
//!     3. We can hold strong references to recently accessed nodes that have already been persisted
//! in an LRU flavor cache for less DB reads.
//!
//! This Sparse Merkle Tree serves a dual purpose. First, to support a leader based consensus
//! algorithm, we need to build a tree of transactions like the following:
//! ```text
//! Committed -> T5 -> T6  -> T7
//!              └---> T6' -> T7'
//!                    └----> T7"
//! ```
//! Once T5 is executed, we will have a tree that stores the modified portion of the state. Later
//! when we execute T6 on top of T5, the output of T5 can be visible to T6.
//!
//! Second, given this tree representation it is straightforward to compute the root hash of S_i
//! once T_i is executed. This allows us to verify the proofs we need when executing T_{i+1}.

// See https://play.rust-lang.org/?version=stable&mode=debug&edition=2018&gist=e9c4c53eb80b30d09112fcfb07d481e7
#![allow(clippy::let_and_return)]
// See https://play.rust-lang.org/?version=stable&mode=debug&edition=2018&gist=795cd4f459f1d4a0005a99650726834b
#![allow(clippy::while_let_loop)]

mod node;
mod updater;
mod utils;

#[cfg(test)]
mod sparse_merkle_test;
#[cfg(any(test, feature = "bench", feature = "fuzzing"))]
pub mod test_utils;

use crate::sparse_merkle::{
    node::{LeafValue, Node, SubTree},
    updater::SubTreeUpdater,
    utils::{partition, swap_if},
};
use diem_crypto::{
    hash::{CryptoHash, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use diem_types::{
    nibble::{nibble_path::NibblePath, ROOT_NIBBLE_HEIGHT},
    proof::{SparseMerkleInternalNode, SparseMerkleLeafNode, SparseMerkleProof},
};
use std::{
    borrow::Borrow,
    cmp,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};
use diem_infallible::Mutex;

/// `AccountStatus` describes the result of querying an account from this SparseMerkleTree.
#[derive(Debug, Eq, PartialEq)]
pub enum AccountStatus<V> {
    /// The account exists in the tree, therefore we can give its value.
    ExistsInScratchPad(V),

    /// The account does not exist in the tree, but exists in DB. This happens when the search
    /// reaches a leaf node that has the requested account, but the node has only the value hash
    /// because it was loaded into memory as part of a non-inclusion proof. When we go to DB we
    /// don't need to traverse the tree to find the same leaf, instead we can use the value hash to
    /// look up the account content directly.
    ExistsInDB,

    /// The account does not exist in either the tree or DB. This happens when the search reaches
    /// an empty node, or a leaf node that has a different account.
    DoesNotExist,

    /// We do not know if this account exists or not and need to go to DB to find out. This happens
    /// when the search reaches a subtree node.
    Unknown,
}

/// TODO(aldenhu): update doc
/// The inner content of a sparse merkle tree, we have this so that even if a tree is dropped, the
/// INNER of it can still live if referenced by a previous version.
#[derive(Debug)]
struct Inner<V> {
    root: SubTree<V>,
    children: Mutex<Vec<Arc<Inner<V>>>>,
}

impl<V> Drop for Inner<V> {
    fn drop(&mut self) {
        let mut q: Vec<_> = self.children.lock().drain(..).collect();

        while let Some(descendant) = q.pop() {
            if Arc::strong_count(&descendant) == 1 {
                // The only ref is the one we are now holding, so the structure will be dropped
                // after we free the `Arc`, which results in a chain of such structures being
                // dropped recursively and that might trigger a stack overflow. To prevent that we
                // follow the chain further to disconnect things beforehand.
                q.extend(descendant.children.lock().drain(..));
            }
        }
    }
}

impl<V> Inner<V> {
    fn new(root: SubTree<V>) -> Arc<Self> {
        Arc::new(Self {
            root,
            children: Mutex::new(Vec::new()),
        })
    }

    fn spawn(&self, child_root: SubTree<V>) -> Arc<Self> {
        let child = Self::new(child_root);
        self.children.lock().push(child.clone());
        child
    }
}

/// The Sparse Merkle Tree implementation.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree<V> {
    inner: Arc<Inner<V>>,
}

/// A type for tracking intermediate hashes at sparse merkle tree nodes in between batch
/// updates by transactions. It contains tuple (txn_id, hash_value, single_new_leaf), where
/// hash_value is the value after all the updates by transaction txn_id (txn_id-th batch)
/// and single_new_leaf is a bool that's true if the node subtree contains one new leaf.
/// (this is needed to recursively merge IntermediateHashes).
type IntermediateHashes = Vec<(usize, HashValue, bool)>;

impl<V> SparseMerkleTree<V>
where
    V: Clone + CryptoHash + Send + Sync,
{
    /// Constructs a Sparse Merkle Tree with a root hash. This is often used when we restart and
    /// the scratch pad and the storage have identical state, so we use a single root hash to
    /// represent the entire state.
    pub fn new(root_hash: HashValue) -> Self {
        let root =
            if root_hash != *SPARSE_MERKLE_PLACEHOLDER_HASH {
                SubTree::new_unknown(root_hash)
            } else {
                SubTree::new_empty()
            };

        Self {
            inner: Inner::new(root),
        }
    }

    fn spawn(&self, child_root: SubTree<V>) -> Self {
        Self {
            inner: self.inner.spawn(child_root),
        }
    }

    #[cfg(test)]
    fn new_with_root(root: SubTree<V>) -> Self {
        Self {
            inner: Inner::new(root),
        }
    }

    fn root_weak(&self) -> SubTree<V> {
        self.inner.root.weak()
    }

    /// Constructs a new Sparse Merkle Tree as if we are updating the existing tree multiple
    /// times with the `batch_update`. The function will return the root hash after each
    /// update and a Sparse Merkle Tree of the final state.
    ///
    /// The `serial_update` applies `batch_update' method many times, unlike a more optimized
    /// (and parallelizable) `batches_update' implementation below. It takes in a reference of
    /// value instead of an owned instance to be consistent with the `batches_update' interface.
    pub fn serial_update(
        &self,
        update_batch: Vec<Vec<(HashValue, &V)>>,
        proof_reader: &impl ProofRead<V>,
    ) -> Result<(Vec<(HashValue, HashMap<NibblePath, HashValue>)>, Self), UpdateError> {
        let mut current_state_tree = self.clone();
        let mut result = Vec::with_capacity(update_batch.len());
        for updates in update_batch {
            // sort and dedup the accounts
            let accounts = updates
                .iter()
                .map(|(account, _)| *account)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            current_state_tree = current_state_tree.batch_update(updates, proof_reader)?;
            result.push((
                current_state_tree.root_hash(),
                current_state_tree.generate_node_hashes(accounts),
            ));
        }
        Ok((result, current_state_tree))
    }

    /// This is a helper function that compares an updated in-memory sparse merkle with the
    /// current on-disk jellyfish sparse merkle to get the hashes of newly generated nodes.
    pub fn generate_node_hashes(
        &self,
        // must be sorted
        touched_accounts: Vec<HashValue>,
    ) -> HashMap<NibblePath, HashValue> {
        let mut node_hashes = HashMap::new();
        let mut nibble_path = NibblePath::new(vec![]);
        Self::collect_new_hashes(
            touched_accounts.as_slice(),
            self.root_weak(),
            0, /* depth in nibble */
            0, /* level within a nibble*/
            &mut nibble_path,
            &mut node_hashes,
        );
        node_hashes
    }

    /// Recursively generate the partial node update batch of jellyfish merkle
    fn collect_new_hashes(
        keys: &[HashValue],
        subtree: SubTree<V>,
        depth_in_nibble: usize,
        level_within_nibble: usize,
        cur_nibble_path: &mut NibblePath,
        node_hashes: &mut HashMap<NibblePath, HashValue>,
    ) {
        assert!(depth_in_nibble <= ROOT_NIBBLE_HEIGHT);
        if keys.is_empty() {
            return;
        }

        if level_within_nibble == 0 {
            if depth_in_nibble != 0 {
                cur_nibble_path
                    .push(NibblePath::new(keys[0].to_vec()).get_nibble(depth_in_nibble - 1));
            }
            node_hashes.insert(cur_nibble_path.clone(), subtree.hash());
        }
        match subtree.get_node_if_in_mem().expect("must exist").borrow() {
            Node::Internal(internal_node) => {
                let (next_nibble_depth, next_level_within_nibble) = if level_within_nibble == 3 {
                    (depth_in_nibble + 1, 0)
                } else {
                    (depth_in_nibble, level_within_nibble + 1)
                };
                let pivot = partition(
                    &keys.iter().map(|k| (*k, ())).collect::<Vec<_>>()[..],
                    depth_in_nibble * 4 + level_within_nibble,
                );
                Self::collect_new_hashes(
                    &keys[..pivot],
                    internal_node.left.weak(),
                    next_nibble_depth,
                    next_level_within_nibble,
                    cur_nibble_path,
                    node_hashes,
                );
                Self::collect_new_hashes(
                    &keys[pivot..],
                    internal_node.right.weak(),
                    next_nibble_depth,
                    next_level_within_nibble,
                    cur_nibble_path,
                    node_hashes,
                );
            }
            Node::Leaf(leaf_node) => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0], leaf_node.key);
                matches!(leaf_node.value, LeafValue::Value(_));
                if level_within_nibble != 0 {
                    let mut leaf_nibble_path = cur_nibble_path.clone();
                    leaf_nibble_path
                        .push(NibblePath::new(keys[0].to_vec()).get_nibble(depth_in_nibble));
                    node_hashes.insert(leaf_nibble_path, subtree.hash());
                }
            }
        }
        if level_within_nibble == 0 && depth_in_nibble != 0 {
            cur_nibble_path.pop();
        }
    }
    /// Constructs a new Sparse Merkle Tree, returns the SMT root hash after each update and the
    /// final SMT root. Since the tree is immutable, existing tree remains the same and may
    /// share parts with the new, returned tree. Unlike `serial_update', intermediate trees aren't
    /// constructed, but only root hashes are computed. `batches_update' takes value reference
    /// because the algorithm requires a copy per value at the end of tree traversals. Taking
    /// in a reference avoids double copy (by the caller and by the implementation).
    pub fn batches_update(
        &self,
        update_batch: Vec<Vec<(HashValue, &V)>>,
        proof_reader: &impl ProofRead<V>,
    ) -> Result<(Vec<HashValue>, Self), UpdateError> {
        let num_txns = update_batch.len();
        if num_txns == 0 {
            // No updates.
            return Ok((vec![], self.clone()));
        }

        // Construct (key, txn_id, value) update vector, where 0 <= txn_id < update_batch.len().
        // The entries are sorted and deduplicated, keeping last for each key per batch (txn).
        let updates: Vec<(HashValue, (usize, &V))> = update_batch
            .into_iter()
            .enumerate()
            .flat_map(|(txn_id, batch)| {
                batch
                    .into_iter()
                    .map(move |(hash, value)| ((hash, txn_id), value))
            })
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|((hash, txn_id), value)| (hash, (txn_id, value))) // convert format.
            .collect();
        let root_weak = self.root_weak();
        let mut pre_hash = root_weak.hash();
        let (root, txn_hashes) = Self::batches_update_subtree(
            root_weak,
            /* subtree_depth = */ 0,
            &updates[..],
            proof_reader,
        )?;
        // Convert txn_hashes to the output format, i.e. a Vec<HashValue> holding a hash value
        // after each of the update_batch.len() many transactions.
        // - For transactions with no updates (i.e. root hash unchanged), txn_hashes don't have
        //  entries. So an updated hash value (txn_hashes.0) that remained the same after some
        //  transactions should be added to the result multiple times.
        // - If the first transactions didn't update, then pre-hash needs to be replicated.
        let mut txn_id = 0;
        let mut root_hashes = vec![];
        for txn_hash in &txn_hashes {
            while txn_id < txn_hash.0 {
                root_hashes.push(pre_hash);
                txn_id += 1;
            }
            pre_hash = txn_hash.1;
        }
        while txn_id < num_txns {
            root_hashes.push(pre_hash);
            txn_id += 1;
        }

        Ok((root_hashes, self.spawn(root)))
    }

    /// Given an existing subtree node at a specific depth, recursively apply the updates.
    fn batches_update_subtree(
        subtree: SubTree<V>,
        subtree_depth: usize,
        updates: &[(HashValue, (usize, &V))],
        proof_reader: &impl ProofRead<V>,
    ) -> Result<(SubTree<V>, IntermediateHashes), UpdateError> {
        if updates.is_empty() {
            return Ok((subtree, vec![]));
        }

        if let SubTree::NonEmpty { root, .. } = &subtree {
            match root.get_node_if_in_mem() {
                Some(arc_node) => match arc_node.borrow() {
                    Node::Internal(internal_node) => {
                        let pivot = partition(updates, subtree_depth);
                        let left_weak = internal_node.left.weak();
                        let left_hash = left_weak.hash();
                        let right_weak = internal_node.right.weak();
                        let right_hash = right_weak.hash();
                        // TODO: parallelize calls up to a certain depth.
                        let (left_tree, left_hashes) = Self::batches_update_subtree(
                            left_weak,
                            subtree_depth + 1,
                            &updates[..pivot],
                            proof_reader,
                        )?;
                        let (right_tree, right_hashes) = Self::batches_update_subtree(
                            right_weak,
                            subtree_depth + 1,
                            &updates[pivot..],
                            proof_reader,
                        )?;

                        let merged_hashes = Self::merge_txn_hashes(
                            left_hash,
                            left_hashes,
                            right_hash,
                            right_hashes,
                        );
                        Ok((SubTree::new_internal(left_tree, right_tree), merged_hashes))
                    }
                    Node::Leaf(leaf_node) => Self::batch_create_subtree(
                        subtree.weak(), // 'root' is upgraded: OK to pass weak ptr.
                        /* target_key = */ leaf_node.key,
                        /* siblings = */ vec![],
                        subtree_depth,
                        updates,
                        proof_reader,
                    ),
                },
                // Subtree with hash only, need to use proofs.
                None => {
                    let (subtree, hashes, _) = Self::batch_create_subtree_by_proof(
                        updates,
                        proof_reader,
                        subtree.hash(),
                        subtree_depth,
                        *SPARSE_MERKLE_PLACEHOLDER_HASH,
                    )?;
                    Ok((subtree, hashes))
                }
            }
        } else {
            // Subtree was empty.
            Self::batch_create_subtree(
                subtree.weak(), // 'root' is upgraded: OK to pass weak ptr.
                /* target_key = */ updates[0].0,
                /* siblings = */ vec![],
                subtree_depth,
                updates,
                proof_reader,
            )
        }
    }

    /// Generate a proof based on the first update and call 'batch_create_subtree' based
    /// on the proof's siblings and possibly a leaf. Additionally return the sibling hash of
    /// the subtree based on the proof (caller needs this information to merge hashes).
    fn batch_create_subtree_by_proof(
        updates: &[(HashValue, (usize, &V))],
        proof_reader: &impl ProofRead<V>,
        subtree_hash: HashValue,
        subtree_depth: usize,
        default_sibling_hash: HashValue,
    ) -> Result<(SubTree<V>, IntermediateHashes, HashValue), UpdateError> {
        if updates.is_empty() {
            return Ok((
                SubTree::new_unknown(subtree_hash),
                vec![],
                default_sibling_hash,
            ));
        }

        let update_key = updates[0].0;
        let proof = proof_reader
            .get_proof(update_key)
            .ok_or(UpdateError::MissingProof)?;
        let siblings: Vec<HashValue> = proof.siblings().iter().rev().copied().collect();

        let sibling_hash = if subtree_depth > 0 {
            *siblings
                .get(subtree_depth - 1)
                .unwrap_or(&SPARSE_MERKLE_PLACEHOLDER_HASH)
        } else {
            default_sibling_hash
        };

        let (subtree, hashes) = match proof.leaf() {
            Some(existing_leaf) => Self::batch_create_subtree(
                SubTree::new_leaf_with_value_hash(existing_leaf.key(), existing_leaf.value_hash()),
                /* target_key = */ existing_leaf.key(),
                siblings,
                subtree_depth,
                updates,
                proof_reader,
            )?,
            None => Self::batch_create_subtree(
                SubTree::new_empty(),
                /* target_key = */ update_key,
                siblings,
                subtree_depth,
                updates,
                proof_reader,
            )?,
        };

        Ok((subtree, hashes, sibling_hash))
    }

    /// Creates a new subtree. Important parameters are:
    /// - 'bottom_subtree' will be added at the bottom of the construction. It is either empty
    ///  or a leaf, containing either (a weak pointer to) a node from the previous version
    ///  that's being re-used, or (a strong pointer to) a leaf from a proof.
    /// - 'target_key' is the key of the bottom_subtree when bottom_subtree is a leaf, o.w. it
    ///  is the key of the first (leftmost) update.
    /// - 'siblings' are the siblings if bottom_subtree is a proof leaf, otherwise empty.
    fn batch_create_subtree(
        bottom_subtree: SubTree<V>,
        target_key: HashValue,
        siblings: Vec<HashValue>,
        subtree_depth: usize,
        updates: &[(HashValue, (usize, &V))],
        proof_reader: &impl ProofRead<V>,
    ) -> Result<(SubTree<V>, IntermediateHashes), UpdateError> {
        if updates.is_empty() {
            return Ok((bottom_subtree, vec![]));
        }
        if siblings.len() <= subtree_depth {
            if let Some(res) = Self::leaf_from_updates(target_key, updates) {
                return Ok(res);
            }
        }

        let pivot = partition(updates, subtree_depth);
        let child_is_right = target_key.bit(subtree_depth);
        let (child_updates, sibling_updates) =
            swap_if(&updates[..pivot], &updates[pivot..], child_is_right);

        let mut child_pre_hash = bottom_subtree.hash();
        let sibling_pre_hash = *siblings
            .get(subtree_depth)
            .unwrap_or(&SPARSE_MERKLE_PLACEHOLDER_HASH);

        // TODO: parallelize up to certain depth.
        let (sibling_tree, sibling_hashes) = if siblings.len() <= subtree_depth {
            // Implies sibling_pre_hash is empty.
            if sibling_updates.is_empty() {
                (SubTree::new_empty(), vec![])
            } else {
                Self::batch_create_subtree(
                    SubTree::new_empty(),
                    /* target_key = */ sibling_updates[0].0,
                    /* siblings = */ vec![],
                    subtree_depth + 1,
                    sibling_updates,
                    proof_reader,
                )?
            }
        } else {
            // Only have the sibling hash, need to use proofs.
            let (subtree, hashes, child_hash) = Self::batch_create_subtree_by_proof(
                sibling_updates,
                proof_reader,
                sibling_pre_hash,
                subtree_depth + 1,
                child_pre_hash,
            )?;
            child_pre_hash = child_hash;
            (subtree, hashes)
        };
        let (child_tree, child_hashes) = Self::batch_create_subtree(
            bottom_subtree,
            target_key,
            siblings,
            subtree_depth + 1,
            child_updates,
            proof_reader,
        )?;

        let (left_tree, right_tree) = swap_if(child_tree, sibling_tree, child_is_right);
        let (left_hashes, right_hashes) = swap_if(child_hashes, sibling_hashes, child_is_right);
        let (left_pre_hash, right_pre_hash) =
            swap_if(child_pre_hash, sibling_pre_hash, child_is_right);

        let merged_hashes =
            Self::merge_txn_hashes(left_pre_hash, left_hashes, right_pre_hash, right_hashes);
        Ok((SubTree::new_internal(left_tree, right_tree), merged_hashes))
    }

    /// Given a key and updates, checks if all updates are to this key. If so, generates
    /// a SubTree for a final leaf, and IntermediateHashes. Each intermediate update is by
    /// a different transaction as (key, txn_id) pairs are deduplicated.
    fn leaf_from_updates(
        leaf_key: HashValue,
        updates: &[(HashValue, (usize, &V))],
    ) -> Option<(SubTree<V>, IntermediateHashes)> {
        let first_update = updates.first().unwrap();
        let last_update = updates.last().unwrap();
        // Updates sorted by key: check that all keys are equal to leaf_key.
        if first_update.0 != leaf_key || last_update.0 != leaf_key {
            return None;
        };

        // Updates are to the same key and thus sorted by txn_id.
        let mut hashes: IntermediateHashes = updates
            .iter()
            .take(updates.len() - 1)
            .map(|&(_, (txn_id, value_ref))| {
                let value_hash = value_ref.hash();
                let leaf_hash = SparseMerkleLeafNode::new(leaf_key, value_hash).hash();
                (txn_id, leaf_hash, /* single_new_leaf = */ true)
            })
            .collect();
        let final_leaf =
            SubTree::new_leaf_with_value(leaf_key, last_update.1 .1.clone() /* value */);
        hashes.push((
            last_update.1 .0, /* txn_id */
            final_leaf.hash(),
            /* single_new_leaf = */ true,
        ));

        Some((final_leaf, hashes))
    }

    /// Given the hashes before updates, and IntermediateHashes for left and right Subtrees,
    /// compute IntermediateHashes for the parent node.
    fn merge_txn_hashes(
        left_pre_hash: HashValue,
        left_txn_hashes: IntermediateHashes,
        right_pre_hash: HashValue,
        right_txn_hashes: IntermediateHashes,
    ) -> IntermediateHashes {
        let (mut li, mut ri) = (0, 0);
        // Some lambda expressions for convenience.
        let next_txn_num = |i: usize, txn_hashes: &Vec<(usize, HashValue, bool)>| {
            if i < txn_hashes.len() {
                txn_hashes[i].0
            } else {
                usize::MAX
            }
        };
        let left_prev_txn_hash = |i: usize| {
            if i > 0 {
                left_txn_hashes[i - 1].1
            } else {
                left_pre_hash
            }
        };
        let right_prev_txn_hash = |i: usize| {
            if i > 0 {
                right_txn_hashes[i - 1].1
            } else {
                right_pre_hash
            }
        };

        let mut to_hash = vec![];
        while li < left_txn_hashes.len() || ri < right_txn_hashes.len() {
            let left_txn_num = next_txn_num(li, &left_txn_hashes);
            let right_txn_num = next_txn_num(ri, &right_txn_hashes);
            if left_txn_num <= right_txn_num {
                li += 1;
            }
            if right_txn_num <= left_txn_num {
                ri += 1;
            }

            // If one child was empty (based on previous hash) while the other child was
            // a single new leaf node, then the parent hash mustn't be combined. Instead,
            // it should be the single leaf hash (the leaf would have been added aerlier).
            let override_hash = if li > 0
                && left_txn_hashes[li - 1].2
                && ri == 0
                && right_pre_hash == *SPARSE_MERKLE_PLACEHOLDER_HASH
            {
                Some(left_prev_txn_hash(li))
            } else if ri > 0
                && right_txn_hashes[ri - 1].2
                && li == 0
                && left_pre_hash == *SPARSE_MERKLE_PLACEHOLDER_HASH
            {
                Some(right_prev_txn_hash(ri))
            } else {
                None
            };
            to_hash.push((
                cmp::min(left_txn_num, right_txn_num),
                left_prev_txn_hash(li),
                right_prev_txn_hash(ri),
                override_hash,
            ));
        }

        // TODO: parallelize w. par_iter.
        to_hash
            .iter()
            .map(|&(txn_num, left_hash, right_hash, override_hash)| {
                (
                    txn_num,
                    match override_hash {
                        Some(hash) => hash,
                        None => SparseMerkleInternalNode::new(left_hash, right_hash).hash(),
                    },
                    override_hash.is_some(),
                )
            })
            .collect()
    }

    /// Queries a `key` in this `SparseMerkleTree`.
    pub fn get(&self, key: HashValue) -> AccountStatus<V> {
        let mut cur = self.root_weak();
        let mut bits = key.iter_bits();

        loop {
            if let Some(node) = cur.get_node_if_in_mem() {
                if let Node::Internal(internal_node) = node.borrow() {
                    match bits.next() {
                        Some(bit) => {
                            cur = if bit {
                                internal_node.right.weak()
                            } else {
                                internal_node.left.weak()
                            };
                            continue;
                        }
                        None => panic!("Tree is deeper than {} levels.", HashValue::LENGTH_IN_BITS),
                    }
                }
            }
            break;
        }

        let ret = match cur {
            SubTree::Empty => AccountStatus::DoesNotExist,
            SubTree::NonEmpty { root, .. } => match root.get_node_if_in_mem() {
                None => AccountStatus::Unknown,
                Some(node) => match node.borrow() {
                    Node::Internal(_) => {
                        unreachable!("There is an internal node at the bottom of the tree.")
                    }
                    Node::Leaf(leaf_node) => {
                        if leaf_node.key == key {
                            match &leaf_node.value {
                                LeafValue::Value(value) => {
                                    AccountStatus::ExistsInScratchPad(value.clone())
                                }
                                LeafValue::ValueHash(_) => AccountStatus::ExistsInDB,
                            }
                        } else {
                            AccountStatus::DoesNotExist
                        }
                    }
                },
            },
        };
        ret
    }

    /// Constructs a new Sparse Merkle Tree by applying `updates`, which are considered to happen
    /// all at once. See `serial_update` and `batches_update` which take in multiple batches
    /// of updates and yields intermediate results.
    /// Since the tree is immutable, existing tree remains the same and may share parts with the
    /// new, returned tree.
    pub fn batch_update(
        &self,
        updates: Vec<(HashValue, &V)>,
        proof_reader: &impl ProofRead<V>,
    ) -> Result<Self, UpdateError> {
        // Flatten, dedup and sort the updates with a btree map since the updates between different
        // versions may overlap on the same address in which case the latter always overwrites.
        let kvs = updates
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();

        let current_root = self.root_weak();
        if kvs.is_empty() {
            Ok(self.clone())
        } else {
            let root = SubTreeUpdater::update(current_root, &kvs[..], proof_reader)?;
            Ok(self.spawn(root))
        }
    }

    /// Returns the root hash of this tree.
    pub fn root_hash(&self) -> HashValue {
        self.inner.root.hash()
    }
}

impl<V> Default for SparseMerkleTree<V>
where
    V: Clone + CryptoHash + Send + Sync,
{
    fn default() -> Self {
        SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH)
    }
}

/// A type that implements `ProofRead` can provide proof for keys in persistent storage.
pub trait ProofRead<V>: Sync {
    /// Gets verified proof for this key in persistent storage.
    fn get_proof(&self, key: HashValue) -> Option<&SparseMerkleProof<V>>;
}

/// All errors `update` can possibly return.
#[derive(Debug, Eq, PartialEq)]
pub enum UpdateError {
    /// The update intends to insert a key that does not exist in the tree, so the operation needs
    /// proof to get more information about the tree, but no proof is provided.
    MissingProof,
    /// At `depth` a persisted subtree was encountered and a proof was requested to assist finding
    /// details about the subtree, but the result proof indicates the subtree is empty.
    ShortProof {
        key: HashValue,
        num_siblings: usize,
        depth: usize,
    },
}
