use alloy::primitives::ChainId;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::{chain_config::get_chain_config, railgun::poi::poi_client::PoiClient};

#[wasm_bindgen]
pub struct JsPoiClient {
    inner: PoiClient,
}

#[wasm_bindgen]
impl JsPoiClient {
    pub async fn new(chain_id: ChainId) -> Result<Self, JsError> {
        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        let poi_url = chain.poi_endpoint.ok_or_else(|| {
            JsError::new(&format!(
                "Chain ID {} does not have a POI endpoint configured",
                chain_id
            ))
        })?;

        Ok(Self {
            inner: PoiClient::new(poi_url, chain_id)
                .await
                .map_err(|e| JsError::new(&format!("Failed to create POI client: {}", e)))?,
        })
    }
}

impl JsPoiClient {
    pub fn inner_mut(&mut self) -> &mut PoiClient {
        &mut self.inner
    }
}
