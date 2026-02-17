use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::Address;
use futures::StreamExt;
use futures::lock::Mutex;
use thiserror::Error;
use tracing::info;

use crate::railgun::address::RailgunAddress;

use super::broadcaster::{Broadcaster, Fee};
use super::transport::{WakuTransport, WakuTransportError};
use super::types::{
    BROADCASTER_VERSION, BroadcasterFeeMessage, BroadcasterFeeMessageData, WakuMessage,
    fee_content_topic,
};

/// Error type for broadcaster operations.
#[derive(Debug, Error)]
pub enum BroadcastersError {
    #[error("Transport error: {0}")]
    Transport(#[from] WakuTransportError),
    #[error("Message parsing error: {0}")]
    ParseError(String),
    #[error("Invalid broadcaster version: got {got}, expected {expected}")]
    IncompatibleVersion { got: String, expected: String },
}

/// Internal fee data for a specific token.
#[derive(Debug, Clone)]
struct TokenFeeData {
    fee_per_unit_gas: u128,
    expiration: u64,
    fees_id: String,
    available_wallets: u32,
    relay_adapt: Address,
    reliability: u32,
}

/// Internal storage for broadcaster data.
#[derive(Debug, Clone)]
struct BroadcasterData {
    railgun_address: RailgunAddress,
    identifier: Option<String>,
    required_poi_list_keys: Vec<String>,
    token_fees: HashMap<Address, TokenFeeData>,
}

/// Manages broadcaster state and fee information.
///
/// Subscribes to Waku fee messages and maintains a cache of broadcaster
/// information, allowing selection of the best broadcaster for a given token.
#[derive(Clone)]
pub struct BroadcasterManager {
    chain_id: u64,
    transport: Arc<dyn WakuTransport>,
    broadcasters: Arc<Mutex<HashMap<RailgunAddress, BroadcasterData>>>,
}

impl BroadcasterManager {
    pub fn new(chain_id: u64, transport: impl WakuTransport + 'static) -> Self {
        Self {
            chain_id,
            transport: Arc::new(transport),
            broadcasters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start listening for broadcaster fee messages.
    ///
    /// This method subscribes to the fee content topic and processes
    /// incoming messages. It runs until the stream is exhausted or an error occurs.
    pub async fn start(&self) -> Result<(), BroadcastersError> {
        let topic = fee_content_topic(self.chain_id);
        let mut stream = self.transport.subscribe(vec![topic]).await?;

        while let Some(msg) = stream.next().await {
            if let Err(e) = self.handle_fee_message(&msg).await {
                tracing::warn!("Error handling fee message: {}", e);
            }
        }

        Ok(())
    }

    /// Handle a single fee message from the Waku network.
    async fn handle_fee_message(&self, msg: &WakuMessage) -> Result<(), BroadcastersError> {
        let fee_data = decode_fee_message(&msg.payload)?;

        let major_version = fee_data
            .version
            .split('.')
            .next()
            .unwrap_or(&fee_data.version);
        if major_version != BROADCASTER_VERSION {
            return Err(BroadcastersError::IncompatibleVersion {
                got: fee_data.version.clone(),
                expected: BROADCASTER_VERSION.to_string(),
            });
        }

        let railgun_address: RailgunAddress = fee_data.railgun_address.parse().map_err(|e| {
            BroadcastersError::ParseError(format!(
                "Invalid railgun address ({}): {}",
                fee_data.railgun_address, e
            ))
        })?;

        let relay_adapt = fee_data.relay_adapt.parse::<Address>().map_err(|e| {
            BroadcastersError::ParseError(format!(
                "Invalid relay adapt address ({}): {}",
                fee_data.relay_adapt, e
            ))
        })?;

        let mut token_fees = HashMap::new();
        for (token_addr_str, fee_hex) in &fee_data.fees {
            let token_addr = token_addr_str.parse::<Address>().map_err(|e| {
                BroadcastersError::ParseError(format!(
                    "Invalid token address ({}): {}",
                    token_addr_str, e
                ))
            })?;

            let fee_str = fee_hex.trim_start_matches("0x");
            let fee_per_unit_gas = u128::from_str_radix(fee_str, 16).map_err(|e| {
                BroadcastersError::ParseError(format!("Invalid fee hex ({}): {}", fee_hex, e))
            })?;

            token_fees.insert(
                token_addr,
                TokenFeeData {
                    fee_per_unit_gas,
                    expiration: fee_data.fee_expiration,
                    fees_id: fee_data.fees_id.clone(),
                    available_wallets: fee_data.available_wallets,
                    relay_adapt,
                    reliability: (fee_data.reliability * 100.0) as u32,
                },
            );
        }

        let data = BroadcasterData {
            railgun_address,
            identifier: fee_data.identifier.clone(),
            required_poi_list_keys: fee_data.required_poi_list_keys,
            token_fees,
        };

        info!("Updated broadcaster info: {:?}", data);
        self.broadcasters.lock().await.insert(railgun_address, data);

        Ok(())
    }

    /// Find the best broadcaster for a given token.
    /// - Has a valid (non-expired) fee
    /// - Has at least one available wallet
    /// - Has the highest reliability among ties
    pub async fn best_broadcaster_for_token(
        &self,
        token: Address,
        current_time: u64,
    ) -> Option<Broadcaster> {
        let broadcasters = self.broadcasters.lock().await;

        broadcasters
            .values()
            .filter_map(|data| {
                data.token_fees
                    .get(&token)
                    .filter(|f| f.expiration > current_time && f.available_wallets > 0)
                    .map(|f| (data, f))
            })
            .min_by(|(_, a), (_, b)| {
                // Sort by fee ascending, then by reliability descending
                a.fee_per_unit_gas
                    .cmp(&b.fee_per_unit_gas)
                    .then_with(|| b.reliability.cmp(&a.reliability))
            })
            .map(|(data, token_fee)| {
                Broadcaster::new(
                    Arc::clone(&self.transport),
                    self.chain_id,
                    data.identifier.clone(),
                    Fee {
                        token,
                        per_unit_gas: token_fee.fee_per_unit_gas,
                        recipient: data.railgun_address,
                        expiration: token_fee.expiration,
                        fees_id: token_fee.fees_id.clone(),
                        available_wallets: token_fee.available_wallets,
                        relay_adapt: token_fee.relay_adapt,
                        reliability: token_fee.reliability,
                        list_keys: data.required_poi_list_keys.clone(),
                    },
                )
            })
    }

    /// Returns the chain ID this manager operates on.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

/// Decode a fee message payload from the Waku network.
fn decode_fee_message(payload: &[u8]) -> Result<BroadcasterFeeMessageData, BroadcastersError> {
    let msg: BroadcasterFeeMessage = serde_json::from_slice(payload)
        .map_err(|e| BroadcastersError::ParseError(format!("Invalid JSON: {}", e)))?;

    let data_bytes = hex_decode(&msg.data)
        .map_err(|e| BroadcastersError::ParseError(format!("Invalid hex data: {}", e)))?;

    let fee_data: BroadcasterFeeMessageData = serde_json::from_slice(&data_bytes)
        .map_err(|e| BroadcastersError::ParseError(format!("Invalid fee data JSON: {}", e)))?;

    Ok(fee_data)
}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let clean_hex = hex_str.trim_start_matches("0x");
    hex::decode(clean_hex)
}
