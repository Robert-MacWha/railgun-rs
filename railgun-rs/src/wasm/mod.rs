mod bindings;
mod broadcaster;
mod indexer;
mod poi_client;
mod prover;
mod provider;
mod transaction;

pub use bindings::{
    JsChainConfig, JsRailgunAccount, erc20_asset, get_chain_config, init_panic_hook,
};
pub use broadcaster::JsBroadcasterManager;
pub use indexer::{JsIndexer, JsSyncer};
pub use prover::{JsProofResponse, JsProver};
pub use transaction::{JsShieldBuilder, JsTransactionBuilder, JsTxData};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();
}
