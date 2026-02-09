use alloy::{
    providers::{DynProvider, Provider},
    rpc::types::Filter,
};
use alloy_sol_types::SolEvent;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use tracing::{info, warn};

use crate::{
    abis::railgun::RailgunSmartWallet,
    caip::AssetId,
    chain_config::ChainConfig,
    crypto::poseidon::poseidon_hash,
    indexer::syncer::{self, Syncer},
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
}

impl Syncer for RpcSyncer {
    async fn sync<OS, OT, ON>(
        &self,
        from_block: u64,
        to_block: u64,
        on_shield: OS,
        on_transact: OT,
        on_nullified: ON,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        OS: Fn(crate::abis::railgun::RailgunSmartWallet::Shield, u64) + 'static,
        OT: Fn(crate::abis::railgun::RailgunSmartWallet::Transact, u64) + 'static,
        ON: Fn(crate::abis::railgun::RailgunSmartWallet::Nullified, u64) + 'static,
    {
        let mut from_block = from_block;
        while from_block <= to_block {
            let to_block = std::cmp::min(from_block + self.batch_size, to_block);
            let filter = Filter::new()
                .address(self.chain.railgun_smart_wallet)
                .from_block(from_block)
                .to_block(to_block);
            let logs = self.provider.get_logs(&filter).await.unwrap();
            info!(
                "Fetched {} logs from blocks {} to {}",
                logs.len(),
                from_block,
                to_block
            );

            for log in logs {
                let topic0 = log.topics()[0];
                let block_number = log.block_number.unwrap();
                let block_timestamp = log.block_timestamp.unwrap();

                match topic0 {
                    RailgunSmartWallet::Shield::SIGNATURE_HASH => {
                        let event = RailgunSmartWallet::Shield::decode_log(&log.inner)?;
                        on_shield(event.data, block_number);
                    }
                    RailgunSmartWallet::Transact::SIGNATURE_HASH => {
                        let event = RailgunSmartWallet::Transact::decode_log(&log.inner)?;
                        on_transact(event.data, block_timestamp);
                    }
                    RailgunSmartWallet::Nullified::SIGNATURE_HASH => {
                        let event = RailgunSmartWallet::Nullified::decode_log(&log.inner)?;
                        on_nullified(event.data, block_timestamp);
                    }
                    RailgunSmartWallet::Unshield::SIGNATURE_HASH => {
                        // Unshield events are not needed for indexing. Spent notes are
                        // already tracked via Nullified events.
                    }
                    _ => {
                        warn!("Unknown event: {:?}", topic0);
                    }
                }
            }

            // Advance the from_block for the next iteration
            from_block = to_block + 1;
        }
        Ok(())
    }

    async fn quick_sync<OC>(
        &self,
        from_block: u64,
        to_block: u64,
        on_commitment: OC,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        OC: Fn(syncer::Commitment) + 'static,
    {
        let mut from_block = from_block;
        while from_block <= to_block {
            let to_block = std::cmp::min(from_block + self.batch_size, to_block);
            let filter = Filter::new()
                .address(self.chain.railgun_smart_wallet)
                .from_block(from_block)
                .to_block(to_block);
            let logs = self.provider.get_logs(&filter).await.unwrap();
            info!(
                "Fetched {} logs from blocks {} to {} for quick sync",
                logs.len(),
                from_block,
                to_block
            );

            for log in logs {
                let topic0 = log.topics()[0];

                match topic0 {
                    RailgunSmartWallet::Shield::SIGNATURE_HASH => {
                        let event = RailgunSmartWallet::Shield::decode_log(&log.inner)?;
                        for (i, c) in event.data.commitments.iter().enumerate() {
                            let npk = Fr::from_be_bytes_mod_order(c.npk.as_slice());
                            let token_id: AssetId = c.token.clone().into();
                            let token_id = token_id.hash();
                            let value: u128 = c.value.saturating_to();
                            let value = Fr::from(value);

                            let commitment_hash = poseidon_hash(&[npk, token_id, value]);
                            on_commitment(syncer::Commitment {
                                hash: commitment_hash,
                                tree_number: event.data.treeNumber.saturating_to(),
                                leaf_index: event.data.startPosition.saturating_to::<u32>()
                                    + i as u32,
                            });
                        }
                    }
                    RailgunSmartWallet::Transact::SIGNATURE_HASH => {
                        let event = RailgunSmartWallet::Transact::decode_log(&log.inner)?;
                        for (i, c) in event.data.hash.iter().enumerate() {
                            let commitment_hash = Fr::from_be_bytes_mod_order(c.as_slice());
                            on_commitment(syncer::Commitment {
                                hash: commitment_hash,
                                tree_number: event.data.treeNumber.saturating_to(),
                                leaf_index: event.data.startPosition.saturating_to::<u32>()
                                    + i as u32,
                            });
                        }
                    }
                    _ => {
                        // For quick sync, we only care about commitments
                    }
                }
            }

            from_block = to_block + 1;
        }

        Ok(())
    }
}
