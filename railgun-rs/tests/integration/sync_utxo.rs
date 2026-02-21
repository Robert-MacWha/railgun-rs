use std::sync::Arc;

use alloy::{
    network::Ethereum,
    providers::{DynProvider, Provider, ProviderBuilder},
};
use railgun_rs::{
    chain_config::{ChainConfig, MAINNET_CONFIG},
    railgun::{
        indexer::{UtxoIndexer, syncer::SubsquidSyncer},
        merkle_tree::SmartWalletUtxoVerifier,
    },
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const CHAIN: ChainConfig = MAINNET_CONFIG;
const FORK_BLOCK: u64 = 24379760;

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_sync_utxo() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init()
        .ok();

    info!("Setting up chain client");
    let fork_url = std::env::var("FORK_URL_MAINNET").expect("Fork URL Must be set");
    let provider: DynProvider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect(&fork_url)
        .await
        .unwrap()
        .erased();

    let smart_wallet_verifier = Arc::new(SmartWalletUtxoVerifier::new(
        CHAIN.railgun_smart_wallet,
        provider.clone(),
    ));

    info!("Setting up indexer");
    let endpoint = CHAIN
        .subsquid_endpoint
        .expect("Subsquid endpoint must be set");

    let subsquid_syncer = Arc::new(SubsquidSyncer::new(endpoint));
    let mut indexer = UtxoIndexer::new(subsquid_syncer, smart_wallet_verifier);

    info!("Syncing indexer");
    indexer.sync_to(FORK_BLOCK).await.unwrap();

    let state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./tests/fixtures/indexer_state.bincode", state).unwrap();
}
