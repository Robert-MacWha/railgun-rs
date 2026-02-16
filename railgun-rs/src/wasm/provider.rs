use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct JsProvider {
    inner: DynProvider,
}

#[wasm_bindgen]
impl JsProvider {
    pub async fn with_url(rpc_url: &str) -> Self {
        let provider = ProviderBuilder::new()
            .network::<alloy::network::Ethereum>()
            .connect(rpc_url)
            .await
            .unwrap()
            .erased();

        JsProvider { inner: provider }
    }
}

impl JsProvider {
    pub fn inner_mut(&mut self) -> &mut DynProvider {
        &mut self.inner
    }
}
