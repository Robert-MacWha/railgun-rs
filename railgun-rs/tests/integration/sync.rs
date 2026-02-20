use alloy::{
    network::Ethereum,
    providers::{DynProvider, Provider, ProviderBuilder},
};
use railgun_rs::{
    chain_config::{ChainConfig, MAINNET_CONFIG},
    railgun::{
        indexer::{indexer::Indexer, syncer},
        merkle_tree::SmartWalletVerifier,
        poi::PoiClient,
    },
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const CHAIN: ChainConfig = MAINNET_CONFIG;
const FORK_BLOCK: u64 = 24379760;

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_sync() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init()
        .ok();

    info!("Setting up POI client");
    let poi_client = PoiClient::new(CHAIN.poi_endpoint.unwrap(), CHAIN.id)
        .await
        .unwrap();

    info!("Setting up chain client");
    let fork_url = std::env::var("FORK_URL_MAINNET").expect("Fork URL Must be set");
    let provider: DynProvider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect(&fork_url)
        .await
        .unwrap()
        .erased();

    let smart_wallet_verifier =
        SmartWalletVerifier::new(CHAIN.railgun_smart_wallet, provider.clone());

    info!("Setting up indexer");
    let endpoint = CHAIN
        .subsquid_endpoint
        .expect("Subsquid endpoint must be set");
    let syncer = Box::new(syncer::SubsquidSyncer::new(endpoint));
    let mut indexer =
        Indexer::new_with_verifiers(syncer, CHAIN, smart_wallet_verifier, poi_client);

    info!("Syncing indexer (verification happens inside sync_to)");
    indexer.sync_to(FORK_BLOCK).await.unwrap();

    let state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./tests/fixtures/indexer_state.bincode", state).unwrap();
}
