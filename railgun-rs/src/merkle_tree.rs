use ark_bn254::Fr;
use ark_ff::PrimeField;
use poseidon_rust::poseidon_hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use thiserror::Error;
use tracing::info;

use crate::crypto::{
    keys::fr_to_bytes, railgun_txid::Txid, railgun_utxo::Utxo,
    railgun_zero::railgun_merkle_tree_zero,
};

/// UTXO Trees track the state of all notes in railgun. New UTXOs are added as
/// leaves whenever new commitments are observed from the railgun smart contracts.
///
/// The UTXO tree is used to generate Merkle proofs for UTXOs when they are spent,
/// one of the private inputs required for a valid snark proof.
pub type UtxoMerkleTree = MerkleTree<UtxoTreeConfig>;

/// The TxID tree tracks all Operations (`RailgunSmartWallet::Transaction`) in railgun.
/// New TxIDs are added whenever a new Operation event is observed from the railgun
/// smart contracts.
///
/// TXID proofs are used to generate Merkle proofs for TxIDs when submitting a
/// POI (Proof of Innocence) to a POI bundler, or to a broadcaster.
pub type TxidMerkleTree = MerkleTree<TxidTreeConfig>;

/// Configuration trait for different merkle tree types.
pub trait TreeConfig: Clone + Default {
    type LeafType: Clone + From<Fr> + Into<Fr>;
    /// The zero value used for empty leaves in this tree type.
    fn zero_value() -> Fr;
    fn hash_left_right(left: Fr, right: Fr) -> Fr;
}

#[derive(Clone, Default, Debug)]
pub struct UtxoTreeConfig;

#[derive(Clone, Default, Debug)]
pub struct TxidTreeConfig;

impl TreeConfig for UtxoTreeConfig {
    type LeafType = Utxo;

    fn zero_value() -> Fr {
        railgun_merkle_tree_zero()
    }

    fn hash_left_right(left: Fr, right: Fr) -> Fr {
        poseidon_hash(&[left, right]).unwrap()
    }
}

impl TreeConfig for TxidTreeConfig {
    type LeafType = Txid;

    fn zero_value() -> Fr {
        railgun_merkle_tree_zero()
    }

    fn hash_left_right(left: Fr, right: Fr) -> Fr {
        poseidon_hash(&[left, right]).unwrap()
    }
}

/// A sparse Merkle tree implementation using Poseidon hash function.
#[derive(Debug, Clone)]
pub struct MerkleTree<C: TreeConfig> {
    number: u32,
    depth: usize,
    zeros: Vec<Fr>,
    tree: Vec<Vec<Fr>>,
    dirty_parents: BTreeSet<usize>,
    _config: PhantomData<C>,
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

impl<C: TreeConfig> MerkleTree<C> {
    pub fn new(tree_number: u32) -> Self {
        Self::new_with_depth(tree_number, TREE_DEPTH)
    }

    pub fn new_with_depth(tree_number: u32, depth: usize) -> Self {
        let zeros = zero_value_levels::<C>(depth);
        let mut tree: Vec<Vec<Fr>> = (0..=depth).map(|_| Vec::new()).collect();

        let root = C::hash_left_right(zeros[depth - 1], zeros[depth - 1]);
        tree[depth].insert(0, root);

        MerkleTree {
            number: tree_number,
            depth,
            zeros,
            tree,
            dirty_parents: BTreeSet::new(),
            _config: PhantomData,
        }
    }

    /// Creates a Merkle tree from a saved state.
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

        tree
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    pub fn root(&mut self) -> Fr {
        self.rebuild_dirty();
        self.tree[self.depth][0]
    }

    pub fn leaves_len(&self) -> usize {
        self.tree[0].len()
    }

    pub fn state(&self) -> MerkleTreeState {
        self.clone().into_state()
    }

    pub fn into_state(mut self) -> MerkleTreeState {
        self.rebuild_dirty();

        let tree: Vec<Vec<[u8; 32]>> = self
            .tree
            .iter()
            .map(|level| level.iter().map(fr_to_bytes).collect())
            .collect();

        MerkleTreeState {
            number: self.number,
            depth: self.depth,
            tree,
        }
    }

    pub fn insert_leaves(&mut self, leaves: &[C::LeafType], start_position: usize) {
        if leaves.is_empty() {
            return;
        }

        let end_position = start_position + leaves.len();
        if self.tree[0].len() < end_position {
            self.tree[0].resize(end_position, self.zeros[0]);
        }

        for (i, leaf) in leaves.iter().cloned().enumerate() {
            let leaf_index = start_position + i;
            self.tree[0][leaf_index] = leaf.into();
            self.dirty_parents.insert(leaf_index / 2);
        }
    }

    pub fn generate_proof(&mut self, element: C::LeafType) -> Result<MerkleProof, MerkleTreeError> {
        self.rebuild_dirty();

        let initial_index = self.tree[0]
            .iter()
            .position(|val| *val == element.clone().into())
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
            element: element.into(),
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
                C::hash_left_right(current_hash, sibling)
            } else {
                C::hash_left_right(sibling, current_hash)
            };
        }

        current_hash == proof.root
    }

    /// Rebuild only the nodes whose descendants were modified.
    fn rebuild_dirty(&mut self) {
        if self.dirty_parents.is_empty() {
            return;
        }

        info!("Rebuilding Merkle tree {}", self.number,);
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

                self.tree[level + 1][parent_idx] = C::hash_left_right(left, right);
                next_dirty.insert(parent_idx / 2);
            }

            dirty = next_dirty;
        }
    }
}

fn zero_value_levels<C: TreeConfig>(depth: usize) -> Vec<Fr> {
    let mut levels = Vec::with_capacity(depth + 1);
    let mut current = C::zero_value();

    for _ in 0..=depth {
        levels.push(current);
        current = C::hash_left_right(current, current);
    }

    levels
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::crypto::keys::hex_to_fr;

    use super::*;

    /// Test that the empty tree root is correct for the UTXO tree config.
    #[test]
    #[traced_test]
    fn test_merkle_root() {
        let mut tree = MerkleTree::<UtxoTreeConfig>::new(0);
        let expected_root =
            hex_to_fr("0x14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90");

        assert_eq!(tree.root(), expected_root);
    }

    /// Test that inserting leaves produces the expected root and valid proofs.
    #[test]
    #[traced_test]
    fn test_merkle_tree_insert_and_proof() {
        let mut tree = MerkleTree::<UtxoTreeConfig>::new(0);
        let leaves: Vec<Utxo> = (0..10).map(|i| Fr::from(i as u64 + 1).into()).collect();
        let expected_root =
            hex_to_fr("0x1d89f5b3d39b050a5b31be8bdb05fccdf236c038ee5b23e25d61324fca6dc4a9");

        tree.insert_leaves(&leaves, 0);

        let root = tree.root();
        assert_eq!(root, expected_root);

        for &leaf in &leaves {
            let proof = tree.generate_proof(leaf).unwrap();
            assert!(MerkleTree::<UtxoTreeConfig>::validate_proof(&proof));
        }

        let tree_leaves_len = tree.leaves_len();
        assert_eq!(tree_leaves_len, leaves.len());
    }

    #[test]
    #[traced_test]
    fn test_merkle_tree_insert_txid_and_proof() {
        let mut tree = MerkleTree::<TxidTreeConfig>::new(0);

        let leaf_1 = Txid::new(
            &[Fr::from(3), Fr::from(4)],
            &[Fr::from(1), Fr::from(2)],
            Fr::from(5),
        );
        let leaf_2 = Txid::new(
            &[Fr::from(13), Fr::from(14)],
            &[Fr::from(11), Fr::from(12)],
            Fr::from(15),
        );

        info!("Inserting TxIDs into TxidMerkleTree");
        info!("Leaf 1: {:?}", leaf_1);
        info!("Leaf 2: {:?}", leaf_2);

        tree.insert_leaves(&[leaf_1.clone(), leaf_2.clone()], 0);
        let root = tree.root();

        let expected =
            hex_to_fr("0a03b0bf8dc758a3d5dd7f6b8b1974a4b212a0080425740c92cbd0c860ebde33");
        assert_eq!(root, expected);
    }

    /// Test that the tree state can be saved and restored correctly.
    #[test]
    #[traced_test]
    fn test_state() {
        let mut tree = MerkleTree::<UtxoTreeConfig>::new(0);
        let leaves: Vec<Utxo> = (0..10).map(|i| Fr::from(i as u64 + 1).into()).collect();
        tree.insert_leaves(&leaves, 0);

        let state = tree.state();
        let mut rebuilt_tree = MerkleTree::<UtxoTreeConfig>::new_from_state(state);

        assert_eq!(tree.root(), rebuilt_tree.root());
    }
}
