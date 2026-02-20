use ruint::aliases::U256;
use serde::{Serializer, Serialize};

use crate::crypto::{
    poseidon::poseidon_hash,
    railgun_txid::{Txid, UtxoTreeOut},
};
use crate::railgun::merkle_tree::{
    merkle_proof::{MerkleProof, MerkleRoot},
    merkle_tree::{MerkleTree, MerkleTreeBatch, MerkleTreeError, MerkleTreeState},
};

/// Typed leaf hash for TxID Merkle tree entries.
///
/// Serializes as a hex string WITHOUT a 0x prefix.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TxidLeafHash(U256);

impl TxidLeafHash {
    pub fn new(txid: Txid, utxo_tree_in: u32, utxo_tree_out: UtxoTreeOut) -> Self {
        let global_position = utxo_tree_out.global_index();

        poseidon_hash(&[
            txid.into(),
            U256::from(utxo_tree_in),
            U256::from(global_position),
        ])
        .unwrap()
        .into()
    }
}

impl From<U256> for TxidLeafHash {
    fn from(value: U256) -> Self {
        TxidLeafHash(value)
    }
}

impl From<TxidLeafHash> for U256 {
    fn from(value: TxidLeafHash) -> Self {
        value.0
    }
}

impl Serialize for TxidLeafHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:064x}", self.0))
    }
}

/// Type-safe wrapper around [`MerkleTree`] whose leaves are [`TxidLeafHash`] values.
///
/// The TxID tree tracks all Operations (`RailgunSmartWallet::Transaction`) in Railgun.
/// New TxIDs are added whenever a new Operation event is observed from the Railgun
/// smart contracts.
///
/// TxID proofs are used to generate Merkle proofs for TxIDs when submitting a
/// POI (Proof of Innocence) to a POI bundler, or to a broadcaster.
pub struct TxidMerkleTree(MerkleTree);

/// RAII batch of [`TxidLeafHash`] inserts. Rebuild fires on drop.
pub struct TxidBatch<'a>(MerkleTreeBatch<'a>);

impl TxidMerkleTree {
    pub fn new(number: u32) -> Self {
        TxidMerkleTree(MerkleTree::new(number))
    }

    pub fn from_state(state: MerkleTreeState) -> Self {
        TxidMerkleTree(MerkleTree::from_state(state))
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

    /// Insert one TxID leaf and immediately rebuild affected parents.
    pub fn insert_leaf(&mut self, leaf: TxidLeafHash, position: usize) {
        self.0.insert_leaf(leaf.into(), position);
    }

    /// Begin a typed batch of TxID leaf inserts. Rebuild fires on drop.
    pub fn begin_batch(&mut self) -> TxidBatch<'_> {
        TxidBatch(self.0.begin_batch())
    }

    pub fn generate_proof(&self, leaf: TxidLeafHash) -> Result<MerkleProof, MerkleTreeError> {
        self.0.generate_proof(leaf.into())
    }

    /// Insert leaves without immediately rebuilding. Used by the indexer's bulk
    /// sync path which calls [`Self::rebuild`] once after all events are processed.
    pub(crate) fn insert_leaves(&mut self, leaves: &[TxidLeafHash], start_position: usize) {
        let u256s: Vec<U256> = leaves.iter().map(|l| (*l).into()).collect();
        self.0.insert_leaves_raw(&u256s, start_position);
    }

    /// Rebuild only the nodes whose descendants were modified since the last rebuild.
    pub fn rebuild(&mut self) {
        self.0.rebuild();
    }
}

impl<'a> TxidBatch<'a> {
    pub fn insert_leaves(&mut self, leaves: &[TxidLeafHash], start_position: usize) {
        let u256s: Vec<U256> = leaves.iter().map(|l| (*l).into()).collect();
        self.0.insert_leaves(&u256s, start_position);
    }
}

// Drop delegates automatically to the inner MerkleTreeBatch's Drop, which calls rebuild.
