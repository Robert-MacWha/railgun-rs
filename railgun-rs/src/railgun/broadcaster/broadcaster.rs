use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::Address;
use futures::StreamExt;
use thiserror::Error;

use super::transport::{WakuTransport, WakuTransportError};
use super::types::{
    BROADCASTER_VERSION, BroadcasterFeeMessage, BroadcasterFeeMessageData, BroadcasterInfo,
    TokenFee, WakuMessage, fee_content_topic,
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

/// Manages broadcaster state and fee information.
///
/// Subscribes to Waku fee messages and maintains a cache of broadcaster
/// information, allowing selection of the best broadcaster for a given token.
pub struct Broadcaster {
    chain_id: u64,
    transport: Arc<dyn WakuTransport>,
    broadcasters: HashMap<String, BroadcasterInfo>,
}

impl Broadcaster {
    pub fn new(chain_id: u64, transport: impl WakuTransport + 'static) -> Self {
        Self {
            chain_id,
            transport: Arc::new(transport),
            broadcasters: HashMap::new(),
        }
    }

    /// Start listening for broadcaster fee messages.
    ///
    /// This method subscribes to the fee content topic and processes
    /// incoming messages. It runs until the stream is exhausted or an error occurs.
    pub async fn start(&mut self) -> Result<(), BroadcastersError> {
        let topic = fee_content_topic(self.chain_id);
        let mut stream = self.transport.subscribe(vec![topic]).await?;

        while let Some(msg) = stream.next().await {
            if let Err(e) = self.handle_fee_message(&msg) {
                tracing::warn!("Error handling fee message: {}", e);
            }
        }

        Ok(())
    }

    /// Handle a single fee message from the Waku network.
    ///
    /// Parses the message, validates the broadcaster version, and updates
    /// the internal state with the broadcaster's fee information.
    pub fn handle_fee_message(&mut self, msg: &WakuMessage) -> Result<(), BroadcastersError> {
        let fee_data = decode_fee_message(&msg.payload)?;

        // Validate version
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

        // Parse relay adapt address
        let relay_adapt = fee_data.relay_adapt.parse::<Address>().map_err(|e| {
            BroadcastersError::ParseError(format!("Invalid relay adapt address: {}", e))
        })?;

        // Build token fees
        let mut token_fees = HashMap::new();
        for (token_addr_str, fee_hex) in &fee_data.fees {
            let token_addr = token_addr_str.parse::<Address>().map_err(|e| {
                BroadcastersError::ParseError(format!("Invalid token address: {}", e))
            })?;

            let fee_str = fee_hex.trim_start_matches("0x");
            let fee_per_unit_gas = u128::from_str_radix(fee_str, 16)
                .map_err(|e| BroadcastersError::ParseError(format!("Invalid fee hex: {}", e)))?;

            token_fees.insert(
                token_addr,
                TokenFee {
                    fee_per_unit_gas,
                    expiration: fee_data.fee_expiration,
                    fees_id: fee_data.fees_id.clone(),
                    available_wallets: fee_data.available_wallets,
                    relay_adapt,
                    reliability: fee_data.reliability,
                },
            );
        }

        let info = BroadcasterInfo {
            railgun_address: fee_data.railgun_address.clone(),
            identifier: fee_data.identifier.clone(),
            version: fee_data.version,
            required_poi_list_keys: fee_data.required_poi_list_keys,
            token_fees,
            last_seen: msg.timestamp.unwrap_or(0),
        };

        self.broadcasters.insert(fee_data.railgun_address, info);

        Ok(())
    }

    /// Find the best broadcaster for a given token.
    ///
    /// Returns the broadcaster with the lowest fee for the token that:
    /// - Has a valid (non-expired) fee
    /// - Has at least one available wallet
    /// - Has the highest reliability among ties
    pub fn best_broadcaster_for_token(
        &self,
        token: Address,
        current_time: u64,
    ) -> Option<&BroadcasterInfo> {
        self.broadcasters
            .values()
            .filter_map(|b| {
                b.fee_for_token(token, current_time)
                    .filter(|f| f.available_wallets > 0)
                    .map(|f| (b, f))
            })
            .min_by(|(_, a), (_, b)| {
                // Sort by fee ascending, then by reliability descending
                a.fee_per_unit_gas
                    .cmp(&b.fee_per_unit_gas)
                    .then_with(|| b.reliability.cmp(&a.reliability))
            })
            .map(|(b, _)| b)
    }

    /// List all known broadcasters.
    pub fn list(&self) -> impl Iterator<Item = &BroadcasterInfo> {
        self.broadcasters.values()
    }

    /// Get the number of known broadcasters.
    pub fn count(&self) -> usize {
        self.broadcasters.len()
    }

    /// Clear all cached broadcaster information.
    pub fn clear(&mut self) {
        self.broadcasters.clear();
    }

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
