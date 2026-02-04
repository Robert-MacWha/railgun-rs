use alloy::primitives::utils::keccak256_cached;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, info_span};

use crate::crypto::{keys::fr_to_bytes_be, poseidon::poseidon_hash};

/// A sparse Merkle tree implementation using Poseidon hash function.
///
/// TODO: Consider using a type state pattern to enforce rebuilding after inserts
/// Would be a little more complex, but means we could drop `&mut self` on read-only
/// operations like `root` and `generate_proof`
#[derive(Debug, Clone)]
pub struct MerkleTree {
    // TODO: Consider moving this elsewhere? It's stored here in the railgun SDK,
    // but not sure why
    pub nullifiers: Vec<[u8; 32]>,

    number: u16,
    depth: usize,
    zeros: Vec<Fr>,
    tree: Vec<Vec<Fr>>,

    rebuild_needed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeState {
    pub nullifiers: Vec<[u8; 32]>,

    pub number: u16,
    pub depth: usize,
    pub tree: Vec<Vec<[u8; 32]>>,
}

pub struct MerkleProof {
    pub element: Fr,
    pub elements: Vec<Fr>,
    pub indices: u32,
    pub root: Fr,
}

#[derive(Debug, Error)]
pub enum MerkleTreeError {
    #[error("Element not found in tree")]
    ElementNotFound,
}

const TREE_DEPTH: usize = 16;

// TODO: Add benchmarks
// TODO: Consider dirty optimizations for sparse trees. Slower while syncing,
// faster for incremental updates.
impl MerkleTree {
    pub fn new(tree_number: u16) -> Self {
        Self::new_with_depth(tree_number, TREE_DEPTH)
    }

    pub fn new_with_depth(tree_number: u16, depth: usize) -> Self {
        let zeros = zero_value_levels(depth);
        let mut tree: Vec<Vec<Fr>> = (0..=depth).map(|_| Vec::new()).collect();

        let root = hash_left_right(zeros[depth - 1], zeros[depth - 1]);
        tree[depth].insert(0, root);

        MerkleTree {
            nullifiers: Vec::new(),
            number: tree_number,
            depth,
            zeros,
            tree,
            rebuild_needed: false,
        }
    }

    /// Creates a Merkle tree from a saved state. Re-builds the sparse tree
    /// from the leaves automatically.
    pub fn new_from_state(state: MerkleTreeState) -> Self {
        let mut tree = MerkleTree::new_with_depth(state.number, state.depth);
        tree.tree = state
            .tree
            .iter()
            .map(|level| {
                level
                    .iter()
                    .map(|bytes| Fr::from_be_bytes_mod_order(bytes))
                    .collect()
            })
            .collect();
        tree.nullifiers = state.nullifiers;

        tree
    }

    pub fn number(&self) -> u16 {
        self.number
    }

    pub fn root(&mut self) -> Fr {
        self.rebuild_sparse_tree();
        self.tree[self.depth][0]
    }

    pub fn state(&self) -> MerkleTreeState {
        self.clone().into_state()
    }

    pub fn into_state(mut self) -> MerkleTreeState {
        self.rebuild_sparse_tree();

        let tree: Vec<Vec<[u8; 32]>> = self
            .tree
            .iter()
            .map(|level| level.iter().map(|fr| fr_to_bytes_be(fr)).collect())
            .collect();

        MerkleTreeState {
            nullifiers: self.nullifiers.clone(),
            number: self.number,
            depth: self.depth,
            tree,
        }
    }

    pub fn insert_leaves(&mut self, leaves: &[Fr], start_position: usize) {
        if leaves.is_empty() {
            return;
        }

        self.rebuild_needed = true;

        let end_position = start_position + leaves.len();
        if self.tree[0].len() < end_position {
            self.tree[0].resize(end_position, self.zeros[0]);
        }

        for (i, &leaf) in leaves.iter().enumerate() {
            self.tree[0][start_position + i] = leaf;
        }
    }

    pub fn generate_proof(&mut self, element: Fr) -> Result<MerkleProof, MerkleTreeError> {
        self.rebuild_sparse_tree();

        let initial_index = self.tree[0]
            .iter()
            .position(|val| *val == element)
            .ok_or(MerkleTreeError::ElementNotFound)?;

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

        Ok(MerkleProof {
            element,
            elements,
            indices: initial_index as u32,
            root: self.root(),
        })
    }

    pub fn validate_proof(proof: &MerkleProof) -> bool {
        let mut indices_bits = Vec::new();
        let mut idx = proof.indices;
        for _ in 0..proof.elements.len() {
            indices_bits.push(idx & 1);
            idx >>= 1;
        }

        let mut current_hash = proof.element;

        for (i, &sibling) in proof.elements.iter().enumerate() {
            let is_left_child = indices_bits[i] == 0;
            current_hash = if is_left_child {
                hash_left_right(current_hash, sibling)
            } else {
                hash_left_right(sibling, current_hash)
            };
        }

        current_hash == proof.root
    }

    fn rebuild_sparse_tree(&mut self) {
        if !self.rebuild_needed {
            return;
        }

        let span = info_span!("Rebuild Sparse Tree").entered();
        info!("Rebuilding sparse Merkle tree number {}", self.number);

        self.rebuild_needed = false;
        let mut width = self.tree[0].len();

        for level in 0..self.depth {
            let next_level_width = (width + 1) / 2;
            self.tree[level + 1].resize(next_level_width, self.zeros[level + 1]);

            for i in 0..next_level_width {
                let left = self.tree[level][i * 2];
                let right = if i * 2 + 1 < width {
                    self.tree[level][i * 2 + 1]
                } else {
                    self.zeros[level]
                };

                self.tree[level + 1][i] = hash_left_right(left, right);
            }
            width = next_level_width;
        }

        info!("Rebuilt Merkle tree root: {:?}", self.tree[self.depth][0]);
        span.exit();
    }
}

fn zero_value_levels(depth: usize) -> Vec<Fr> {
    let mut levels = Vec::with_capacity(depth + 1);
    let mut current = zero_value();

    for _ in 0..=depth {
        levels.push(current);
        current = hash_left_right(current, current);
    }

    levels
}

fn zero_value() -> Fr {
    let hash = keccak256_cached(b"Railgun");
    Fr::from_be_bytes_mod_order(hash.as_slice())
}

fn hash_left_right(left: Fr, right: Fr) -> Fr {
    poseidon_hash(&[left, right])
}

#[cfg(test)]
mod tests {
    use crate::hex_to_fr;

    use super::*;

    #[test]
    fn test_merkle_root() {
        // Expected root, sourced from Railgun SDK to verify correctness
        let mut tree = MerkleTree::new(0);
        let expected_root =
            hex_to_fr("0x14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90");

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_tree_insert_and_proof() {
        // Expected root after inserting leaves 1 to 10
        // Sourced from Railgun SDK to verify correctness
        let mut tree = MerkleTree::new(0);
        let leaves: Vec<Fr> = (0..10).map(|i| Fr::from(i as u64 + 1)).collect();
        let expected_root =
            hex_to_fr("0x1d89f5b3d39b050a5b31be8bdb05fccdf236c038ee5b23e25d61324fca6dc4a9");

        tree.insert_leaves(&leaves, 0);

        let root = tree.root();
        assert_eq!(root, expected_root);

        for &leaf in &leaves {
            let proof = tree.generate_proof(leaf).unwrap();
            assert!(MerkleTree::validate_proof(&proof));
        }
    }

    #[test]
    fn test_state() {
        let mut tree = MerkleTree::new(0);
        let leaves: Vec<Fr> = (0..10).map(|i| Fr::from(i as u64 + 1)).collect();
        tree.insert_leaves(&leaves, 0);

        let state = tree.state();
        let mut rebuilt_tree = MerkleTree::new_from_state(state);

        assert_eq!(tree.root(), rebuilt_tree.root());
    }
}
