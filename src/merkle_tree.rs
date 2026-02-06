use alloy::primitives::utils::keccak256_cached;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::crypto::{keys::fr_to_bytes, poseidon::poseidon_hash};

#[derive(Debug, Clone)]
pub struct MerkleTree {
    number: u32,
    depth: usize,
    zeros: Vec<Fr>,
    tree: Vec<Vec<Fr>>,
    dirty_indices: Vec<Vec<bool>>,
    has_dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeState {
    pub number: u32,
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

impl MerkleTree {
    pub fn new(tree_number: u32) -> Self {
        Self::new_with_depth(tree_number, TREE_DEPTH)
    }

    pub fn new_with_depth(tree_number: u32, depth: usize) -> Self {
        let zeros = zero_value_levels(depth);
        let mut tree: Vec<Vec<Fr>> = (0..=depth).map(|_| Vec::new()).collect();

        let root = hash_left_right(zeros[depth - 1], zeros[depth - 1]);
        tree[depth].push(root);

        // Initialize dirty_indices with proper sizes
        let mut dirty_indices: Vec<Vec<bool>> = Vec::with_capacity(depth + 1);
        for level in 0..=depth {
            dirty_indices.push(vec![false; tree[level].len()]);
        }

        MerkleTree {
            number: tree_number,
            depth,
            zeros,
            tree,
            dirty_indices,
            has_dirty: false,
        }
    }

    pub fn new_from_state(state: MerkleTreeState) -> Self {
        let zeros = zero_value_levels(state.depth);
        let tree: Vec<Vec<Fr>> = state
            .tree
            .iter()
            .map(|level| {
                level
                    .iter()
                    .map(|bytes| Fr::from_be_bytes_mod_order(bytes))
                    .collect()
            })
            .collect();

        // Initialize dirty tracking to match tree structure
        let dirty_indices: Vec<Vec<bool>> =
            tree.iter().map(|level| vec![false; level.len()]).collect();

        MerkleTree {
            number: state.number,
            depth: state.depth,
            zeros,
            tree,
            dirty_indices,
            has_dirty: false,
        }
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    pub fn root(&mut self) -> Fr {
        self.update_dirty_nodes();
        self.tree[self.depth][0]
    }

    pub fn state(&mut self) -> MerkleTreeState {
        self.update_dirty_nodes();
        MerkleTreeState {
            number: self.number,
            depth: self.depth,
            tree: self
                .tree
                .iter()
                .map(|level| level.iter().map(fr_to_bytes).collect())
                .collect(),
        }
    }

    pub fn insert_leaves(&mut self, leaves: &[Fr], start_position: usize) {
        if leaves.is_empty() {
            return;
        }

        let end_position = start_position + leaves.len();

        if self.tree[0].len() < end_position {
            let old_len = self.tree[0].len();
            self.tree[0].resize(end_position, self.zeros[0]);
            self.dirty_indices[0].resize(end_position, false);

            for i in old_len..end_position {
                self.dirty_indices[0][i] = true;
            }
            self.has_dirty = true;
        }

        for (i, &leaf) in leaves.iter().enumerate() {
            let idx = start_position + i;
            self.tree[0][idx] = leaf;
            self.dirty_indices[0][idx] = true;
            self.has_dirty = true;
        }
    }

    pub fn generate_proof(&mut self, element: Fr) -> Result<MerkleProof, MerkleTreeError> {
        self.update_dirty_nodes();

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
            root: self.tree[self.depth][0],
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

    fn update_dirty_nodes(&mut self) {
        if !self.has_dirty {
            return;
        }

        info!("Updating dirty nodes in Merkle tree {}", self.number);

        for level in 0..self.depth {
            if !self.dirty_indices[level].iter().any(|&d| d) {
                continue;
            }

            let current_level_len = self.tree[level].len();
            let next_level_width = current_level_len.div_ceil(2);

            if self.tree[level + 1].len() < next_level_width {
                self.tree[level + 1].resize(next_level_width, self.zeros[level + 1]);
                self.dirty_indices[level + 1].resize(next_level_width, false);
            }

            let mut dirty_parents: Vec<usize> = (0..current_level_len)
                .filter(|&i| self.dirty_indices[level][i])
                .map(|i| i / 2)
                .collect();
            dirty_parents.dedup();

            // Parallel hash computation for dirty parents
            let updates: Vec<_> = dirty_parents
                .into_par_iter()
                .map(|parent_idx| {
                    let left_idx = parent_idx * 2;
                    let right_idx = left_idx + 1;

                    let left = self.tree[level][left_idx];
                    let right = if right_idx < current_level_len {
                        self.tree[level][right_idx]
                    } else {
                        self.zeros[level]
                    };

                    (parent_idx, hash_left_right(left, right))
                })
                .collect();

            // Sequential write
            for (parent_idx, hash) in updates {
                self.tree[level + 1][parent_idx] = hash;
                self.dirty_indices[level + 1][parent_idx] = true;
            }

            // Clear dirty flags
            self.dirty_indices[level].fill(false);
        }

        info!("Updated Merkle tree root: {:?}", self.tree[self.depth][0]);
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
    use tracing_test::traced_test;

    use crate::crypto::keys::hex_to_fr;

    use super::*;

    #[test]
    #[traced_test]
    fn test_merkle_root() {
        // Expected root, sourced from Railgun SDK to verify correctness
        let mut tree = MerkleTree::new(0);
        let expected_root =
            hex_to_fr("0x14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90");

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    #[traced_test]
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
    #[traced_test]
    fn test_state() {
        let mut tree = MerkleTree::new(0);
        let leaves: Vec<Fr> = (0..10).map(|i| Fr::from(i as u64 + 1)).collect();
        tree.insert_leaves(&leaves, 0);

        let state = tree.state();
        let mut rebuilt_tree = MerkleTree::new_from_state(state);

        assert_eq!(tree.root(), rebuilt_tree.root());
    }

    #[test]
    #[traced_test]
    fn test_incremental_inserts_with_rebuild_between() {
        // Reproduces the bug where resizing the leaf array between
        // rebuilds leaves padding nodes unmarked as dirty, causing
        // stale upper levels.
        let mut tree_incremental = MerkleTree::new(0);
        let mut tree_batch = MerkleTree::new(0);

        let leaves_a: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 1)).collect();
        let leaves_b: Vec<Fr> = (5..10).map(|i| Fr::from(i as u64 + 1)).collect();

        tree_incremental.insert_leaves(&leaves_a, 0);
        let _ = tree_incremental.root();
        tree_incremental.insert_leaves(&leaves_b, 5);

        let all_leaves: Vec<Fr> = (0..10).map(|i| Fr::from(i as u64 + 1)).collect();
        tree_batch.insert_leaves(&all_leaves, 0);

        assert_eq!(tree_incremental.root(), tree_batch.root());
    }
}
