use std::collections::BTreeMap;

use alloy::primitives::utils::keccak256_cached;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use thiserror::Error;

use crate::crypto::poseidon::poseidon_hash;

pub struct MerkleTree {
    // TODO: Consider moving this elsewhere? It's stored here in the railgun SDK,
    // but not sure why
    pub nullifiers: Vec<[u8; 32]>,

    number: u64,
    depth: usize,
    zeros: Vec<Fr>,
    tree: Vec<BTreeMap<usize, Fr>>,
    max_leaf_index: Option<usize>,

    rebuild_needed: bool,
}

pub struct MerkleProof {
    pub element: Fr,
    pub elements: Vec<Fr>,
    pub indices: usize,
    pub root: Fr,
}

#[derive(Debug, Error)]
pub enum MerkleTreeError {
    #[error("Element not found in tree")]
    ElementNotFound,
}

const TREE_DEPTH: usize = 16;

impl MerkleTree {
    pub fn new(tree_number: u64) -> Self {
        Self::new_with_depth(tree_number, TREE_DEPTH)
    }

    pub fn new_with_depth(tree_number: u64, depth: usize) -> Self {
        let zeros = zero_value_levels(depth);
        let mut tree: Vec<BTreeMap<usize, Fr>> = (0..=depth).map(|_| BTreeMap::new()).collect();

        let root = hash_left_right(zeros[depth - 1], zeros[depth - 1]);
        tree[depth].insert(0, root);

        MerkleTree {
            nullifiers: Vec::new(),
            number: tree_number,
            depth,
            zeros,
            tree,
            max_leaf_index: None,
            rebuild_needed: false,
        }
    }

    pub fn insert_leaves(&mut self, leaves: &[Fr], start_position: usize) {
        if leaves.is_empty() {
            return;
        }

        for (i, &leaf) in leaves.iter().enumerate() {
            let leaf_index = start_position + i;
            self.tree[0].insert(leaf_index, leaf);
        }

        let last = start_position + leaves.len() - 1;
        self.max_leaf_index = Some(match self.max_leaf_index {
            Some(max) => max.max(last),
            None => last,
        });

        self.rebuild_needed = true;
    }

    pub fn root(&mut self) -> Fr {
        self.rebuild_sparse_tree();

        self.tree[self.depth][&0]
    }

    pub fn generate_proof(&mut self, element: Fr) -> Result<MerkleProof, MerkleTreeError> {
        self.rebuild_sparse_tree();

        let initial_index = self.tree[0]
            .iter()
            .find(|(_, val)| **val == element)
            .map(|(&idx, _)| idx)
            .ok_or(MerkleTreeError::ElementNotFound)?;

        let mut elements = Vec::with_capacity(self.depth);
        let mut index = initial_index;

        for level in 0..self.depth {
            let is_left_child = index % 2 == 0;
            let siblings_index = if is_left_child { index + 1 } else { index - 1 };

            let sibling = self.tree[level]
                .get(&siblings_index)
                .copied()
                .unwrap_or(self.zeros[level]);

            elements.push(sibling);
            index /= 2;
        }

        Ok(MerkleProof {
            element,
            elements,
            indices: initial_index,
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

        self.rebuild_needed = false;

        let Some(max_idx) = self.max_leaf_index else {
            for level in 1..=self.depth {
                self.tree[level].clear();
            }
            let root = hash_left_right(self.zeros[self.depth - 1], self.zeros[self.depth - 1]);
            self.tree[self.depth].insert(0, root);
            return;
        };

        let mut width = max_idx + 1;

        for level in 0..self.depth {
            self.tree[level + 1].clear();

            for pos in (0..width).step_by(2) {
                let left = self.tree[level]
                    .get(&pos)
                    .copied()
                    .unwrap_or(self.zeros[level]);
                let right = self.tree[level]
                    .get(&(pos + 1))
                    .copied()
                    .unwrap_or(self.zeros[level]);

                let parent = hash_left_right(left, right);
                self.tree[level + 1].insert(pos / 2, parent);
            }

            width = (width + 1) / 2;
        }
    }
}

fn zero_value_levels(depth: usize) -> Vec<Fr> {
    let mut levels = Vec::with_capacity(depth);
    levels.push(zero_value());

    for level in 1..depth {
        let prev = levels[level - 1];
        levels.push(hash_left_right(prev, prev));
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
}
