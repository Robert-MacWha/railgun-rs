use alloy::{
    network::Ethereum,
    providers::{Provider, ProviderBuilder},
};
use railgun_rs::{
    chain_config::{ChainConfig, MAINNET_CONFIG},
    indexer::indexer::Indexer,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::common;

const STATE_PATH: &str = "./tests/fixtures/state.json";

const FORK_BLOCK: u64 = 24_378_760;
const CHAIN: ChainConfig = MAINNET_CONFIG;

const INDEXER_STATE: &[u8] = include_bytes!("../fixtures/indexer_state.bincode");

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_sync() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init()
        .ok();

    info!("Starting test");
    let fork_url = std::env::var("FORK_URL").expect("Fork URL Must be set");
    let _anvil =
        common::anvil::AnvilInstance::fork_with_state(&fork_url, FORK_BLOCK, STATE_PATH).await;

    // Setup provider, indexer, and accounts
    info!("Setting up provider");
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect("http://localhost:8545")
        .await
        .unwrap()
        .erased();

    info!("Setting up indexer");
    let mut indexer = Indexer::new(provider.clone(), CHAIN);
    indexer.sync_from_subsquid(Some(FORK_BLOCK)).await.unwrap();
    info!("Synced, validating...");
    indexer.validate().await.unwrap();
    // let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    // std::fs::write("./tests/fixtures/indexer_state.bincode", indexer_state).unwrap();
}
