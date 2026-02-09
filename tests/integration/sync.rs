use railgun_rs::{
    chain_config::{ChainConfig, MAINNET_CONFIG},
    indexer::{indexer::Indexer, subsquid_syncer::SubsquidSyncer},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const CHAIN: ChainConfig = MAINNET_CONFIG;

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_sync() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init()
        .ok();

    info!("Setting up indexer");
    let endpoint = CHAIN
        .subsquid_endpoint
        .expect("Subsquid endpoint must be set");
    let syncer = Box::new(SubsquidSyncer::new(endpoint));
    let mut indexer = Indexer::new(syncer, CHAIN);

    info!("Syncing indexer");
    indexer.sync().await.unwrap();

    info!("Validating indexer");
    indexer.validate().await.unwrap();

    let txid_trees = indexer.txid_trees();
    for (tree_number, tree) in txid_trees {}

    // let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    // std::fs::write("./tests/fixtures/indexer_state.bincode", indexer_state).unwrap();
}
