use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::railgun::{
    indexer::{
        syncer::TransactionSyncer,
        txid_tree_set::{TxidTreeError, TxidTreeSet, TxidTreeSetState},
    },
    poi::PoiClient,
};

/// TxID indexer that maintains the set of Txid merkle trees.
pub struct TxidIndexer {
    pub txid_set: TxidTreeSet,
    pub synced_block: u64,
    txid_syncer: Arc<dyn TransactionSyncer>,
}

#[derive(Serialize, Deserialize)]
pub struct TxidIndexerState {
    pub txid_tree: TxidTreeSetState,
    pub synced_operations_block: u64,
}

#[derive(Debug, Error)]
pub enum TxidIndexerError {
    #[error("Syncer error: {0}")]
    SyncerError(Box<dyn std::error::Error>),
    #[error("TXID tree error: {0}")]
    TxidTreeError(#[from] TxidTreeError),
}

impl TxidIndexer {
    pub fn new(txid_syncer: Arc<dyn TransactionSyncer>, poi_client: PoiClient) -> Self {
        TxidIndexer {
            txid_set: TxidTreeSet::new(poi_client),
            synced_block: 0,
            txid_syncer,
        }
    }

    pub fn from_state(
        txid_syncer: Arc<dyn TransactionSyncer>,
        poi_client: PoiClient,
        state: TxidIndexerState,
    ) -> Self {
        TxidIndexer {
            txid_set: TxidTreeSet::from_state(poi_client, state.txid_tree),
            synced_block: state.synced_operations_block,
            txid_syncer,
        }
    }

    pub fn state(&self) -> TxidIndexerState {
        TxidIndexerState {
            txid_tree: self.txid_set.state(),
            synced_operations_block: self.synced_block,
        }
    }

    pub fn synced_block(&self) -> u64 {
        self.synced_block
    }

    pub async fn sync(&mut self) -> Result<(), TxidIndexerError> {
        self.sync_to(u64::MAX).await
    }

    #[tracing::instrument(name = "txid_sync", skip_all)]
    pub async fn sync_to(&mut self, to_block: u64) -> Result<(), TxidIndexerError> {
        let from_block = self.synced_block + 1;

        let syncer = self.txid_syncer.clone();
        let latest_block = syncer
            .latest_block()
            .await
            .map_err(TxidIndexerError::SyncerError)?;
        let to_block = to_block.min(latest_block);

        if from_block > to_block {
            info!("Already synced to block {}", to_block);
            return Ok(());
        }

        // Sync
        let ops = syncer
            .sync(from_block, to_block)
            .await
            .map_err(TxidIndexerError::SyncerError)?;
        for (op, block) in ops {
            self.txid_set.enqueue(op, block);
        }
        self.synced_block = to_block;

        // Advance
        self.txid_set.validate().await?;

        Ok(())
    }
}
