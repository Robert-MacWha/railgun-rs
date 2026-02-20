use std::collections::BTreeSet;

use alloy::primitives::utils::keccak256_cached;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    crypto::{poseidon::poseidon_hash, railgun_zero::SNARK_PRIME},
    railgun::merkle_tree::merkle_proof::{MerkleProof, MerkleRoot},
};

/// A sparse Merkle tree implementation using Poseidon hash function.
/// Works directly with U256 leaf values. Type-safe wrappers (UtxoMerkleTree,
/// TxidMerkleTree) live in their own modules.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    number: u32,
    depth: usize,
    zeros: Vec<U256>,
    tree: Vec<Vec<U256>>,
    dirty_parents: BTreeSet<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeState {
    pub number: u32,
    pub depth: usize,
    pub tree: Vec<Vec<U256>>,
}

#[derive(Debug, Error)]
pub enum MerkleTreeError {
    #[error("Element not found in tree: {0}")]
    ElementNotFound(U256),
    #[error("Invalid proof")]
    InvalidProof,
}

pub const TREE_DEPTH: usize = 16;

impl MerkleTree {
    pub fn new(tree_number: u32) -> Self {
        Self::new_with_depth(tree_number, TREE_DEPTH)
    }

    pub fn from_state(state: MerkleTreeState) -> Self {
        let mut tree = MerkleTree::new_with_depth(state.number, state.depth);
        tree.tree = state.tree;
        tree
    }

    fn new_with_depth(tree_number: u32, depth: usize) -> Self {
        let zeros = zero_value_levels(depth);
        let mut tree: Vec<Vec<U256>> = (0..=depth).map(|_| Vec::new()).collect();

        let root = hash_left_right(zeros[depth - 1], zeros[depth - 1]);
        tree[depth].insert(0, root);

        MerkleTree {
            number: tree_number,
            depth,
            zeros,
            tree,
            dirty_parents: BTreeSet::new(),
        }
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    pub fn root(&self) -> MerkleRoot {
        debug_assert!(
            self.dirty_parents.is_empty(),
            "Merkle tree has dirty parents, root may be outdated"
        );

        self.tree[self.depth][0].into()
    }

    pub fn leaves_len(&self) -> usize {
        self.tree[0].len()
    }

    pub fn state(&self) -> MerkleTreeState {
        self.clone().into_state()
    }

    pub fn into_state(self) -> MerkleTreeState {
        MerkleTreeState {
            number: self.number,
            depth: self.depth,
            tree: self.tree,
        }
    }

    pub fn generate_proof(&self, element: U256) -> Result<MerkleProof, MerkleTreeError> {
        debug_assert!(
            self.dirty_parents.is_empty(),
            "Merkle tree has dirty parents, root may be outdated"
        );

        if !self.dirty_parents.is_empty() {
            warn!("Merkle tree has dirty parents, root may be outdated");
        }

        let initial_index = self.tree[0]
            .iter()
            .position(|val| *val == element)
            .ok_or(MerkleTreeError::ElementNotFound(element))?;

        let mut elements = Vec::with_capacity(self.depth);
        let mut index = initial_index;

        for level in 0..self.depth {
            let is_left_child = index % 2 == 0;
            let siblings_index = if is_left_child { index + 1 } else { index - 1 };

            let sibling = self.tree[level]
                .get(siblings_index)
                .copied()
                .unwrap_or(self.zeros[level]);

            elements.push(sibling);
            index /= 2;
        }

        let proof = MerkleProof::new(element, elements, U256::from(initial_index), self.root());
        if !proof.verify() {
            return Err(MerkleTreeError::InvalidProof);
        }

        Ok(proof)
    }

    /// Insert one leaf and immediately rebuild affected parents.
    pub fn insert_leaf(&mut self, leaf: U256, position: usize) {
        self.insert_leaves_raw(&[leaf], position);
        self.rebuild();
    }

    /// Inserts leaves starting at the given position. Marks parent nodes as dirty
    /// for later rebuilding. Does not rebuild.
    pub fn insert_leaves_raw(&mut self, leaves: &[U256], start_position: usize) {
        if leaves.is_empty() {
            return;
        }

        let end_position = start_position + leaves.len();
        if self.tree[0].len() < end_position {
            self.tree[0].resize(end_position, self.zeros[0]);
        }

        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_index = start_position + i;
            self.tree[0][leaf_index] = *leaf;
            self.dirty_parents.insert(leaf_index / 2);
        }
    }

    /// Rebuild only the nodes whose descendants were modified.
    pub fn rebuild(&mut self) {
        if self.dirty_parents.is_empty() {
            return;
        }

        info!("Rebuilding Merkle tree {}", self.number);
        let mut dirty = std::mem::take(&mut self.dirty_parents);

        for level in 0..self.depth {
            let child_width = self.tree[level].len();
            let parent_width = child_width.div_ceil(2);

            if self.tree[level + 1].len() < parent_width {
                self.tree[level + 1].resize(parent_width, self.zeros[level + 1]);
            }

            let mut next_dirty = BTreeSet::new();

            for &parent_idx in &dirty {
                let left_idx = parent_idx * 2;
                let right_idx = left_idx + 1;

                let left = if left_idx < child_width {
                    self.tree[level][left_idx]
                } else {
                    self.zeros[level]
                };
                let right = if right_idx < child_width {
                    self.tree[level][right_idx]
                } else {
                    self.zeros[level]
                };

                self.tree[level + 1][parent_idx] = hash_left_right(left, right);
                next_dirty.insert(parent_idx / 2);
            }

            dirty = next_dirty;
        }
    }
}


fn hash_left_right(left: U256, right: U256) -> U256 {
    poseidon_hash(&[left, right]).unwrap()
}

fn zero_value_levels(depth: usize) -> Vec<U256> {
    let mut levels = Vec::with_capacity(depth + 1);
    let mut current = railgun_merkle_tree_zero();

    for _ in 0..=depth {
        levels.push(current);
        current = hash_left_right(current, current);
    }

    levels
}

pub fn railgun_merkle_tree_zero() -> U256 {
    let hash = U256::from_be_bytes(*keccak256_cached(b"Railgun"));
    hash % SNARK_PRIME
}

#[cfg(test)]
mod tests {
    use ruint::uint;
    use tracing_test::traced_test;

    use super::*;

    #[test]
    fn test_railgun_merkle_tree_zero() {
        let zero = railgun_merkle_tree_zero();
        let expected = uint!(
            2051258411002736885948763699317990061539314419500486054347250703186609807356_U256
        );
        assert_eq!(zero, expected);
    }

    #[test]
    #[traced_test]
    fn test_empty_merkleroot() {
        let tree = MerkleTree::new(0);
        let expected_root: MerkleRoot = uint!(
            9493149700940509817378043077993653487291699154667385859234945399563579865744_U256
        )
        .into();

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    #[traced_test]
    fn test_merkle_tree_insert_and_proof() {
        let mut tree = MerkleTree::new(0);
        let leaves: Vec<U256> = (0..10u64).map(|i| U256::from(i + 1)).collect();
        let expected_root: MerkleRoot = uint!(
            13360826432759445967430837006844965422592495092152969583910134058984357610665_U256
        )
        .into();

        tree.insert_leaves_raw(&leaves, 0);
        tree.rebuild();

        let root = tree.root();
        assert_eq!(root, expected_root);

        for &leaf in &leaves {
            let proof = tree.generate_proof(leaf).unwrap();
            assert!(proof.verify(), "Proof invalid for leaf: {:?}", leaf);
        }

        let tree_leaves_len = tree.leaves_len();
        assert_eq!(tree_leaves_len, leaves.len());
    }

    #[test]
    #[traced_test]
    fn test_state() {
        let mut tree = MerkleTree::new(0);
        let leaves: Vec<U256> = (0..10u64).map(|i| U256::from(i + 1)).collect();
        tree.insert_leaves_raw(&leaves, 0);
        tree.rebuild();

        let state = tree.state();
        let rebuilt_tree = MerkleTree::from_state(state);

        assert_eq!(tree.root(), rebuilt_tree.root());
    }
}
