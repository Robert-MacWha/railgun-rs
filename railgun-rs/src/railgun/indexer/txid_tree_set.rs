use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    crypto::railgun_txid::Txid,
    railgun::{
        indexer::syncer::Operation,
        merkle_tree::{MerkleTreeState, TOTAL_LEAVES, TxidLeafHash, TxidMerkleTree, UtxoTreeIndex},
        poi::{PoiClient, PoiClientError},
    },
};

/// Manages the set of TXID Merkle trees, with a pending queue of operations
/// not yet validated by the POI aggregator.
pub struct TxidTreeSet {
    trees: BTreeMap<u32, TxidMerkleTree>,
    poi_client: PoiClient,

    /// Operations queued but not yet validated by the POI aggregator.
    pending: VecDeque<(Operation, u64)>,

    /// Maps txid → (tree_number, leaf_index) for validated leaves.
    txid_to_position: HashMap<Txid, (u32, u32)>,

    /// The packed validated txid index from the last successful `advance_to_validated()`.
    /// Format: `(tree_number << 16) | leaf_index_within_tree`.
    validated_index: u64,
}

/// Serializable state for `TxidTreeSet`.
#[derive(Clone, Serialize, Deserialize)]
pub struct TxidTreeSetState {
    pub trees: BTreeMap<u32, MerkleTreeState>,
    pub pending: Vec<(Operation, u64)>,
    pub txid_to_position: HashMap<Txid, (u32, u32)>,
    pub validated_index: u64,
}

#[derive(Debug, Error)]
pub enum TxidTreeError {
    #[error("POI client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("TXID tree root mismatch for tree {tree_number}")]
    RootMismatch { tree_number: u32 },
}

impl TxidTreeSet {
    pub fn new(poi_client: PoiClient) -> Self {
        TxidTreeSet {
            trees: BTreeMap::new(),
            pending: VecDeque::new(),
            poi_client,
            txid_to_position: HashMap::new(),
            validated_index: 0,
        }
    }

    pub fn from_state(poi_client: PoiClient, state: TxidTreeSetState) -> Self {
        let trees = state
            .trees
            .into_iter()
            .map(|(k, v)| (k, TxidMerkleTree::from_state(v)))
            .collect();

        TxidTreeSet {
            trees,
            pending: state.pending.into_iter().collect(),
            poi_client,
            txid_to_position: state.txid_to_position,
            validated_index: state.validated_index,
        }
    }

    pub fn state(&self) -> TxidTreeSetState {
        let trees = self.trees.iter().map(|(k, v)| (*k, v.state())).collect();
        TxidTreeSetState {
            trees,
            pending: self.pending.iter().cloned().collect(),
            txid_to_position: self.txid_to_position.clone(),
            validated_index: self.validated_index,
        }
    }

    /// Enqueue an operation to be validated and inserted into the TXID tree.
    pub fn enqueue(&mut self, op: Operation, block: u64) {
        self.pending.push_back((op, block));
    }

    /// Returns the `(tree_number, leaf_index)` of a validated txid, or `None`
    /// if the txid has not yet been inserted into the validated trees.
    pub fn position_of(&self, txid: &Txid) -> Option<(u32, u32)> {
        self.txid_to_position.get(txid).copied()
    }

    /// Returns a reference to the validated TXID tree with the given number.
    pub fn tree(&self, number: u32) -> Option<&TxidMerkleTree> {
        self.trees.get(&number)
    }

    /// Returns the packed validated txid index from the last `advance_to_validated()` call.
    /// Format: `(tree_number << 16) | leaf_index_within_tree`.
    pub fn validated_index(&self) -> u64 {
        self.validated_index
    }

    /// Drains pending operations into the validated trees up to the POI aggregator's
    /// current `validated_txid`, then verifies the computed root matches.
    pub async fn validate(&mut self) -> Result<(), TxidTreeError> {
        let validated = self.poi_client.validated_txid().await?;

        let current_total: usize = self.trees.values().map(|t| t.leaves_len()).sum();
        let target_total =
            (validated.tree() as usize) * TOTAL_LEAVES + validated.leaf_index() as usize + 1;
        let to_drain = target_total.saturating_sub(current_total);

        if to_drain == 0 {
            return Ok(());
        }

        let drain_count = to_drain.min(self.pending.len());
        let drained: Vec<_> = self.pending.drain(..drain_count).collect();

        let mut total = current_total;
        for (op, _block) in drained {
            let txid = Txid::new(&op.nullifiers, &op.commitment_hashes, op.bound_params_hash);
            let included = UtxoTreeIndex::included(op.utxo_tree_out, op.utxo_out_start_index);
            let leaf = TxidLeafHash::new(txid, op.utxo_tree_in, included);

            let tree_number = (total / TOTAL_LEAVES) as u32;
            let position = total % TOTAL_LEAVES;

            self.trees
                .entry(tree_number)
                .or_insert_with(|| TxidMerkleTree::new(tree_number))
                .insert_leaves(&[leaf], position);

            self.txid_to_position
                .insert(txid, (tree_number, position as u32));
            total += 1;
        }

        // Rebuild
        for tree in self.trees.values_mut() {
            tree.rebuild();
        }

        // Validate
        if let Some((tree_number, tree)) = self.trees.last_key_value() {
            let index = tree.leaves_len() as u64 - 1;
            let merkleroot = tree.root();
            let validated = self
                .poi_client
                .validate_txid_merkleroot(*tree_number, index, merkleroot)
                .await?;

            if !validated {
                return Err(TxidTreeError::RootMismatch {
                    tree_number: *tree_number,
                });
            }
        }

        self.validated_index = total as u64;
        Ok(())
    }
}
