use ruint::aliases::U256;

use crate::railgun::merkle_tree::{
    merkle_proof::{MerkleProof, MerkleRoot},
    merkle_tree::{MerkleTree, MerkleTreeBatch, MerkleTreeError, MerkleTreeState},
};

/// Typed leaf hash for UTXO Merkle tree entries.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UtxoLeafHash(U256);

impl From<U256> for UtxoLeafHash {
    fn from(value: U256) -> Self {
        UtxoLeafHash(value)
    }
}

impl From<UtxoLeafHash> for U256 {
    fn from(value: UtxoLeafHash) -> Self {
        value.0
    }
}

/// Type-safe wrapper around [`MerkleTree`] whose leaves are [`UtxoLeafHash`] values.
///
/// UTXO trees track the state of all notes in Railgun. New UTXOs are added as
/// leaves whenever new commitments are observed from the Railgun smart contracts.
///
/// The UTXO tree is used to generate Merkle proofs for UTXOs when they are spent,
/// one of the private inputs required for a valid snark proof.
pub struct UtxoMerkleTree(MerkleTree);

/// RAII batch of [`UtxoLeafHash`] inserts. Rebuild fires on drop.
pub struct UtxoBatch<'a>(MerkleTreeBatch<'a>);

impl UtxoMerkleTree {
    pub fn new(number: u32) -> Self {
        UtxoMerkleTree(MerkleTree::new(number))
    }

    pub fn from_state(state: MerkleTreeState) -> Self {
        UtxoMerkleTree(MerkleTree::from_state(state))
    }

    pub fn number(&self) -> u32 {
        self.0.number()
    }

    pub fn root(&self) -> MerkleRoot {
        self.0.root()
    }

    pub fn leaves_len(&self) -> usize {
        self.0.leaves_len()
    }

    pub fn state(&self) -> MerkleTreeState {
        self.0.state()
    }

    pub fn into_state(self) -> MerkleTreeState {
        self.0.into_state()
    }

    /// Insert one UTXO leaf and immediately rebuild affected parents.
    pub fn insert_leaf(&mut self, leaf: UtxoLeafHash, position: usize) {
        self.0.insert_leaf(leaf.into(), position);
    }

    /// Begin a typed batch of UTXO leaf inserts. Rebuild fires on drop.
    pub fn begin_batch(&mut self) -> UtxoBatch<'_> {
        UtxoBatch(self.0.begin_batch())
    }

    pub fn generate_proof(&self, leaf: UtxoLeafHash) -> Result<MerkleProof, MerkleTreeError> {
        self.0.generate_proof(leaf.into())
    }

    /// Insert leaves without immediately rebuilding. Used by the indexer's bulk
    /// sync path which calls [`Self::rebuild`] once after all events are processed.
    pub(crate) fn insert_leaves(&mut self, leaves: &[UtxoLeafHash], start_position: usize) {
        let u256s: Vec<U256> = leaves.iter().map(|l| (*l).into()).collect();
        self.0.insert_leaves_raw(&u256s, start_position);
    }

    /// Rebuild only the nodes whose descendants were modified since the last rebuild.
    pub fn rebuild(&mut self) {
        self.0.rebuild();
    }
}

impl<'a> UtxoBatch<'a> {
    pub fn insert_leaves(&mut self, leaves: &[UtxoLeafHash], start_position: usize) {
        let u256s: Vec<U256> = leaves.iter().map(|l| (*l).into()).collect();
        self.0.insert_leaves(&u256s, start_position);
    }
}

// Drop delegates automatically to the inner MerkleTreeBatch's Drop, which calls rebuild.
