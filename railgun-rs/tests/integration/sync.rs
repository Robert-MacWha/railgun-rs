use std::collections::BTreeMap;

use alloy::{
    network::Ethereum,
    providers::{DynProvider, Provider, ProviderBuilder},
};
use railgun_rs::{
    abis::railgun::RailgunSmartWallet,
    chain_config::{ChainConfig, MAINNET_CONFIG},
    railgun::{
        indexer::{indexer::Indexer, syncer},
        merkle_tree::{TxidMerkleTree, UtxoMerkleTree},
        poi::PoiClient,
    },
};
use ruint::aliases::U256;
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
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect(&fork_url)
        .await
        .unwrap()
        .erased();

    info!("Setting up indexer");
    let endpoint = CHAIN
        .subsquid_endpoint
        .expect("Subsquid endpoint must be set");
    let syncer = Box::new(syncer::SubsquidSyncer::new(endpoint));
    let mut indexer = Indexer::new(syncer, CHAIN);

    info!("Syncing indexer");
    indexer.sync_to(FORK_BLOCK).await.unwrap();
    verify_txid_trees(&mut indexer.txid_trees, &poi_client).await;
    verify_utxo_trees(&mut indexer.utxo_trees, provider.clone()).await;

    let state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./tests/fixtures/indexer_state.bincode", state).unwrap();
}

async fn verify_txid_trees(trees: &mut BTreeMap<u32, TxidMerkleTree>, poi_client: &PoiClient) {
    info!("Verifying TxID trees: {}", trees.len());
    for (tree_number, tree) in trees.iter_mut() {
        let root = tree.root();
        let leaves = tree.leaves_len();
        info!(
            "TxID Tree number: {}, leaves: {}, tree root: {:?}",
            tree_number, leaves, root
        );

        let valid = poi_client
            .validate_txid_merkleroot(*tree_number, leaves as u64 - 1, root.into())
            .await
            .unwrap();
        assert!(valid, "TxID Tree number {} failed validation", tree_number);
    }
}

async fn verify_utxo_trees(trees: &mut BTreeMap<u32, UtxoMerkleTree>, provider: DynProvider) {
    info!("Verifying UTXO trees: {}", trees.len());

    let railgun_contract = RailgunSmartWallet::new(CHAIN.railgun_smart_wallet, provider.clone());

    for (tree_number, tree) in trees.iter_mut() {
        let root = tree.root();
        let leaves = tree.leaves_len();
        info!(
            "UTXO Tree number: {}, leaves: {}, tree root: {:?}",
            tree_number, leaves, root
        );

        let seen = railgun_contract
            .rootHistory(U256::from(*tree_number), root.into())
            .call()
            .await
            .unwrap();
        assert!(seen, "UTXO Tree number {} failed validation", tree_number);
    }
}
