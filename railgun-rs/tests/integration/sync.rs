use std::collections::BTreeMap;

use railgun_rs::{
    chain_config::{ChainConfig, MAINNET_CONFIG},
    indexer::{indexer::Indexer, subsquid_syncer::SubsquidSyncer},
    merkle_trees::merkle_tree::TxidMerkleTree,
    poi::client::PoiClient,
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

    info!("Setting up indexer");
    let endpoint = CHAIN
        .subsquid_endpoint
        .expect("Subsquid endpoint must be set");
    let syncer = Box::new(SubsquidSyncer::new(endpoint));
    let mut indexer = Indexer::new(syncer, CHAIN);

    info!("Syncing indexer");
    indexer.sync_to(FORK_BLOCK).await.unwrap();
    verify_trees(&mut indexer.txid_trees, &poi_client).await;

    let state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./tests/fixtures/indexer_state.bincode", state).unwrap();
}

async fn verify_trees(trees: &mut BTreeMap<u32, TxidMerkleTree>, poi_client: &PoiClient) {
    info!("Verifying trees: {}", trees.len());
    for (tree_number, tree) in trees.iter_mut() {
        let root = tree.root();
        let leaves = tree.leaves_len();
        info!(
            "Tree number: {}, leaves: {}, tree root: {:?}",
            tree_number, leaves, root
        );

        let valid = poi_client
            .validate_txid_merkleroot(*tree_number, leaves as u64 - 1, root.into())
            .await
            .unwrap();
        assert!(valid, "Tree number {} failed validation", tree_number);
    }
}
