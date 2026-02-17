use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use thiserror::Error;
use tracing::info;

use crate::{
    crypto::{
        poseidon::poseidon_hash, railgun_txid::TxidLeaf, railgun_utxo::UtxoLeaf,
        railgun_zero::railgun_merkle_tree_zero,
    },
    railgun::merkle_tree::merkle_proof::MerkleProof,
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
    type LeafType: Clone + From<U256> + Into<U256>;
    /// The zero value used for empty leaves in this tree type.
    fn zero_value() -> U256;
    fn hash_left_right(left: U256, right: U256) -> U256;
}

#[derive(Clone, Default, Debug)]
pub struct UtxoTreeConfig;

#[derive(Clone, Default, Debug)]
pub struct TxidTreeConfig;

impl TreeConfig for UtxoTreeConfig {
    type LeafType = UtxoLeaf;

    fn zero_value() -> U256 {
        railgun_merkle_tree_zero()
    }

    fn hash_left_right(left: U256, right: U256) -> U256 {
        poseidon_hash(&[left, right]).unwrap()
    }
}

impl TreeConfig for TxidTreeConfig {
    type LeafType = TxidLeaf;

    fn zero_value() -> U256 {
        railgun_merkle_tree_zero()
    }

    fn hash_left_right(left: U256, right: U256) -> U256 {
        poseidon_hash(&[left, right]).unwrap()
    }
}

/// A sparse Merkle tree implementation using Poseidon hash function.
#[derive(Debug, Clone)]
pub struct MerkleTree<C: TreeConfig> {
    number: u32,
    depth: usize,
    zeros: Vec<U256>,
    tree: Vec<Vec<U256>>,
    dirty_parents: BTreeSet<usize>,
    _config: PhantomData<C>,
}

pub struct MerkleTreeMut<'a, C: TreeConfig> {
    tree: &'a mut MerkleTree<C>,
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

const TREE_DEPTH: usize = 16;

impl<C: TreeConfig> MerkleTree<C> {
    pub fn new(tree_number: u32) -> Self {
        Self::new_with_depth(tree_number, TREE_DEPTH)
    }

    pub fn from_state(state: MerkleTreeState) -> Self {
        let mut tree = MerkleTree::new_with_depth(state.number, state.depth);
        tree.tree = state.tree;

        tree
    }

    fn new_with_depth(tree_number: u32, depth: usize) -> Self {
        let zeros = zero_value_levels::<C>(depth);
        let mut tree: Vec<Vec<U256>> = (0..=depth).map(|_| Vec::new()).collect();

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

    pub fn number(&self) -> u32 {
        self.number
    }

    pub fn root(&self) -> U256 {
        debug_assert!(
            self.dirty_parents.is_empty(),
            "Merkle tree has dirty parents, root may be outdated"
        );

        self.tree[self.depth][0]
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

    pub fn generate_proof(&self, element: C::LeafType) -> Result<MerkleProof, MerkleTreeError> {
        debug_assert!(
            self.dirty_parents.is_empty(),
            "Merkle tree has dirty parents, root may be outdated"
        );

        let element = element.into();

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

        let proof = MerkleProof::new(element.into(), elements, initial_index as u32, self.root());
        if !proof.verify() {
            return Err(MerkleTreeError::InvalidProof);
        }

        Ok(proof)
    }

    pub fn edit(&mut self) -> MerkleTreeMut<C> {
        MerkleTreeMut { tree: self }
    }

    /// Inserts leaves starting at the given position. Marks parent nodes as dirty
    /// for later rebuilding.
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

    /// Rebuild only the nodes whose descendants were modified.
    pub fn rebuild(&mut self) {
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

impl<'a, C: TreeConfig> MerkleTreeMut<'a, C> {
    pub fn insert_leaves(&mut self, leaves: &[C::LeafType], start_position: usize) {
        self.tree.insert_leaves(leaves, start_position);
    }
}

impl<'a, C: TreeConfig> Drop for MerkleTreeMut<'a, C> {
    fn drop(&mut self) {
        self.tree.rebuild();
    }
}

fn zero_value_levels<C: TreeConfig>(depth: usize) -> Vec<U256> {
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
    use ruint::uint;
    use tracing_test::traced_test;

    use super::*;

    /// Test that the empty tree root is correct for the UTXO tree config.
    #[test]
    #[traced_test]
    fn test_merkle_root() {
        let tree = MerkleTree::<UtxoTreeConfig>::new(0);
        let expected_root = uint!(
            9493149700940509817378043077993653487291699154667385859234945399563579865744_U256
        );

        assert_eq!(tree.root(), expected_root);
    }

    /// Test that inserting leaves produces the expected root and valid proofs.
    #[test]
    #[traced_test]
    fn test_merkle_tree_insert_and_proof() {
        let mut tree = MerkleTree::<UtxoTreeConfig>::new(0);
        let leaves: Vec<UtxoLeaf> = (0..10).map(|i| U256::from(i + 1).into()).collect();
        let expected_root = uint!(
            13360826432759445967430837006844965422592495092152969583910134058984357610665_U256
        );

        tree.edit().insert_leaves(&leaves, 0);

        let root = tree.root();
        assert_eq!(root, expected_root);

        for &leaf in &leaves {
            let proof = tree.generate_proof(leaf).unwrap();
            assert!(proof.verify(), "Proof invalid for leaf: {:?}", leaf);
        }

        let tree_leaves_len = tree.leaves_len();
        assert_eq!(tree_leaves_len, leaves.len());
    }

    /// Test that the tree state can be saved and restored correctly.
    #[test]
    #[traced_test]
    fn test_state() {
        let mut tree = MerkleTree::<UtxoTreeConfig>::new(0);
        let leaves: Vec<UtxoLeaf> = (0..10).map(|i| U256::from(i + 1).into()).collect();
        tree.edit().insert_leaves(&leaves, 0);

        let state = tree.state();
        let rebuilt_tree = MerkleTree::<UtxoTreeConfig>::from_state(state);

        assert_eq!(tree.root(), rebuilt_tree.root());
    }
}
