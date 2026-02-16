#![cfg(not(feature = "wasm"))]

use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{Address, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use rand::random;
use tracing::info;

use railgun_rs::{
    abis::erc20::ERC20,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, SEPOLIA_CONFIG},
    circuit::native::Groth16Prover,
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
    railgun::{
        indexer::{indexer::Indexer, subsquid_syncer::SubsquidSyncer},
        poi::poi_client::PoiClient,
        transaction::operation_builder::{FeeInfo, OperationBuilder},
    },
};

const CHAIN: ChainConfig = SEPOLIA_CONFIG;
const USDC_ADDRESS: Address = address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238");
const USDC: AssetId = AssetId::Erc20(USDC_ADDRESS);

const PPOI_URL: &str = "https://ppoi-agg.horsewithsixlegs.xyz/";
const INDEXER_STATE: &str = "./indexer_state_11155111.bincode";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let signer_key = std::env::var("DEV_KEY").expect("DEV_KEY must be set");
    let rpc_url = std::env::var("FORK_URL_SEPOLIA").expect("FORK_URL_SEPOLIA must be set");
    let spending_key = std::env::var("DEV_SPENDING_KEY").expect("DEV_SPENDING_KEY must be set");
    let viewing_key = std::env::var("DEV_VIEWING_KEY").expect("DEV_VIEWING_KEY must be set");

    let signer = PrivateKeySigner::from_str(&signer_key).unwrap();
    let address = signer.address();
    info!("Using EOA: {:?}", address);

    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect(&rpc_url)
        .await
        .unwrap()
        .erased();
    let usdc_contract = ERC20::new(USDC_ADDRESS, provider.clone());

    let spending_key = SpendingKey::from_hex(&spending_key).unwrap();
    let viewing_key = ViewingKey::from_hex(&viewing_key).unwrap();
    let account1 = RailgunAccount::new(spending_key, viewing_key, CHAIN.id);
    let account2 = RailgunAccount::new(random(), random(), CHAIN.id);
    let account3 = RailgunAccount::new(random(), random(), CHAIN.id);

    info!("Account 1: {}", account1.address());
    info!("Account 2: {}", account2.address());
    info!("Account 3: {}", account3.address());

    // info!("Creating indexer");
    let subsquid = Box::new(SubsquidSyncer::new(CHAIN.subsquid_endpoint.unwrap()));
    let indexer_state = bitcode::deserialize(&std::fs::read(INDEXER_STATE).unwrap()).unwrap();
    let mut indexer = Indexer::from_state(subsquid, indexer_state).unwrap();
    // let mut indexer = Indexer::new(subsquid, CHAIN);
    indexer.add_account(&account1);

    // info!("Syncing indexer");
    // indexer.sync_to(10217000).await.unwrap();

    // info!("Saving indexer");
    // let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    // std::fs::write("./indexer_state_11155111.bincode", indexer_state).unwrap();

    let prover = Groth16Prover::new_native("./artifacts");
    let poi_client = PoiClient::new(PPOI_URL, CHAIN.id).await.unwrap();

    let mut builder = OperationBuilder::new();
    // builder.transfer(account1.clone(), account2.address(), USDC, 100, "");
    builder.set_unshield(account1.clone(), address, USDC, 100);
    let prepared = builder
        .build_with_broadcast(
            &mut indexer,
            &prover,
            &poi_client,
            &provider,
            FeeInfo {
                payee: account1,
                asset: USDC_ADDRESS,
                rate: 10000000,
                recipient: account3.address(),
                id: "uuid".to_string(),
                list_keys: vec![
                    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88".to_string(),
                    "55049dc47b4435bca4a8f8ac27b1858e409f9f72b317fde4a442095cfc454893".to_string(),
                ],
            },
            CHAIN,
            &mut rand::rng(),
        )
        .await
        .unwrap();

    info!(
        "Prepared operation with {} operations",
        prepared.operations.len()
    );
}
