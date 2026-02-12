use std::pin::Pin;

use alloy::{
    primitives::FixedBytes,
    providers::{DynProvider, Provider},
    rpc::types::Filter,
};
use alloy_sol_types::SolEvent;
use futures::{Stream, StreamExt, stream};
use ruint::aliases::U256;
use tracing::{info, warn};

use crate::{
    abis::railgun::RailgunSmartWallet,
    chain_config::ChainConfig,
    indexer::syncer::{RootVerifier, SyncEvent, Syncer},
};

pub struct RpcSyncer {
    provider: DynProvider,
    batch_size: u64,
    chain: ChainConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcSyncerError {
    #[error("Error decoding log: {0}")]
    LogDecodeError(#[from] alloy_sol_types::Error),
    #[error("RPC error: {0}")]
    RpcError(String),
}

impl RpcSyncer {
    pub fn new(provider: DynProvider, chain: ChainConfig) -> Self {
        Self {
            provider,
            batch_size: 10000,
            chain,
        }
    }

    pub fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.batch_size = batch_size;
        self
    }

    fn event_stream(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> impl Stream<Item = SyncEvent> + Send + '_ {
        // State for batch fetching: current_block position
        stream::unfold(from_block, move |current_block| async move {
            // If we've processed all blocks, we're done
            if current_block > to_block {
                return None;
            }

            // Fetch the next batch of logs
            let batch_end = std::cmp::min(current_block + self.batch_size - 1, to_block);
            let filter = Filter::new()
                .address(self.chain.railgun_smart_wallet)
                .from_block(current_block)
                .to_block(batch_end);

            let logs = match self.provider.get_logs(&filter).await {
                Ok(logs) => logs,
                Err(e) => {
                    warn!(
                        "Failed to fetch logs from blocks {} to {}: {}",
                        current_block, batch_end, e
                    );
                    return None;
                }
            };

            info!(
                "Fetched {} logs from blocks {} to {}",
                logs.len(),
                current_block,
                batch_end
            );

            // Decode logs into events
            let mut events = Vec::new();
            for log in logs {
                let topic0 = log.topics()[0];
                let block_number = log.block_number.unwrap_or(0);
                let block_timestamp = log.block_timestamp.unwrap_or(0);

                match topic0 {
                    RailgunSmartWallet::Shield::SIGNATURE_HASH => {
                        match RailgunSmartWallet::Shield::decode_log(&log.inner) {
                            Ok(event) => events.push(SyncEvent::Shield(event.data, block_number)),
                            Err(e) => warn!("Failed to decode Shield event: {}", e),
                        }
                    }
                    RailgunSmartWallet::Transact::SIGNATURE_HASH => {
                        match RailgunSmartWallet::Transact::decode_log(&log.inner) {
                            Ok(event) => {
                                events.push(SyncEvent::Transact(event.data, block_timestamp))
                            }
                            Err(e) => warn!("Failed to decode Transact event: {}", e),
                        }
                    }
                    RailgunSmartWallet::Nullified::SIGNATURE_HASH => {
                        match RailgunSmartWallet::Nullified::decode_log(&log.inner) {
                            Ok(event) => {
                                events.push(SyncEvent::Nullified(event.data, block_timestamp))
                            }
                            Err(e) => warn!("Failed to decode Nullified event: {}", e),
                        }
                    }
                    RailgunSmartWallet::Unshield::SIGNATURE_HASH => {
                        // Unshield events are not needed for indexing. Spent notes are
                        // already tracked via Nullified events.
                    }
                    _ => {
                        // Unknown event, skip
                    }
                }
            }

            // TODO: Operation events are not implemented for RPC syncer.
            // Constructing Operations requires call tracing to correlate which events
            // belong to which Railgun transaction within a block.

            // Update state for next iteration
            let next_block = batch_end + 1;

            // Return the events as a stream and the next block to fetch
            Some((stream::iter(events), next_block))
        })
        .flatten()
    }
}

#[async_trait::async_trait]
impl RootVerifier for RpcSyncer {
    async fn seen(
        &self,
        tree_number: u32,
        utxo_merkle_root: U256,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let root: FixedBytes<32> = FixedBytes::from(utxo_merkle_root.to_be_bytes::<32>());
        let contract = RailgunSmartWallet::new(self.chain.railgun_smart_wallet, &self.provider);

        let seen = contract
            .rootHistory(U256::from(tree_number), root)
            .call()
            .await?;
        Ok(seen)
    }
}

#[async_trait::async_trait]
impl Syncer for RpcSyncer {
    async fn latest_block(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let block_number = self.provider.get_block_number().await?;
        Ok(block_number)
    }

    async fn seen(&self, utxo_merkle_root: U256) -> Result<bool, Box<dyn std::error::Error>> {
        let root: FixedBytes<32> = FixedBytes::from(utxo_merkle_root.to_be_bytes::<32>());
        let contract = RailgunSmartWallet::new(self.chain.railgun_smart_wallet, &self.provider);

        // Query rootHistory mapping with tree_number = 0
        let seen = contract.rootHistory(U256::ZERO, root).call().await?;
        Ok(seen)
    }

    async fn sync(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Pin<Box<dyn Stream<Item = SyncEvent> + Send + '_>>, Box<dyn std::error::Error>>
    {
        info!(
            "Starting RPC sync from block {} to block {}",
            from_block, to_block
        );

        Ok(Box::pin(self.event_stream(from_block, to_block)))
    }
}
