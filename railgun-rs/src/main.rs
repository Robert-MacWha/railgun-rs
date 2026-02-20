#![cfg(not(feature = "wasm"))]

use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{Address, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use async_trait::async_trait;
use railgun_rs::{
    abis::erc20::ERC20,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, SEPOLIA_CONFIG},
    circuit::native::Groth16Prover,
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
    railgun::{
        broadcaster::{
            transport::{MessageStream, WakuTransport, WakuTransportError},
            types::WakuMessage,
        },
        indexer::{indexer::Indexer, syncer},
        poi::PoiClient,
        transaction::{
            broadcaster_data::PoiProvedTransaction, operation_builder::OperationBuilder,
        },
    },
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use tracing::info;

const CHAIN: ChainConfig = SEPOLIA_CONFIG;
const USDC_ADDRESS: Address = address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238");
const USDC: AssetId = AssetId::Erc20(USDC_ADDRESS);
const WETH_ADDRESS: Address = address!("0xfff9976782d46cc05630d1f6ebab18b2324d6b14");
const WETH: AssetId = AssetId::Erc20(WETH_ADDRESS);

const PPOI_URL: &str = "https://ppoi-agg.horsewithsixlegs.xyz/";
const INDEXER_STATE: &str = "./indexer_state_11155111.bincode";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let mut rand = ChaChaRng::seed_from_u64(0);

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
    let account2 = RailgunAccount::new(rand.random(), rand.random(), CHAIN.id);
    let account3 = RailgunAccount::new(rand.random(), rand.random(), CHAIN.id);

    info!("Account 1: {}", account1.address());
    info!("Account 2: {}", account2.address());
    info!("Account 3: {}", account3.address());

    info!("Creating indexer");
    let subsquid = Box::new(syncer::SubsquidSyncer::new(
        CHAIN.subsquid_endpoint.unwrap(),
    ));
    let rpc = Box::new(syncer::RpcSyncer::new(provider.clone(), CHAIN).with_batch_size(10));
    let chained = Box::new(syncer::ChainedSyncer::new(vec![subsquid, rpc]));
    let indexer_state = bitcode::deserialize(&std::fs::read(INDEXER_STATE).unwrap()).unwrap();
    let mut indexer = Indexer::from_state(chained, indexer_state).unwrap();
    // let mut indexer = Indexer::new(chained, CHAIN);
    indexer.add_account(&account1);

    info!("Syncing indexer");
    indexer.sync().await.unwrap();

    info!("Saving indexer");
    let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./indexer_state_11155111.bincode", indexer_state).unwrap();

    let prover = Groth16Prover::new_native("./artifacts");
    let poi_client = PoiClient::new(PPOI_URL, CHAIN.id).await.unwrap();

    // let shield = ShieldBuilder::new(CHAIN)
    //     .shield(account1.address(), USDC, 1000)
    //     .build()
    //     .unwrap();
    // provider
    //     .send_transaction(shield.into())
    //     .await
    //     .unwrap()
    //     .get_receipt()
    //     .await
    //     .unwrap();

    // indexer.sync().await.unwrap();
    // let balance_1 = indexer.balance(account1.address());
    // info!("Account 1 balance: {:?}", balance_1);

    // let broadcaster_address = RailgunAddress::from_str("0zk1qyjftlcuuxwjj574e5979wzt5veel9wmnh8peq6slvd668pz9ggzerv7j6fe3z53latpxdq2zqzs7l780x9gu7hfsgn93m27fwx3k6pk8fsrtgrp45ywuctqpkg").unwrap();
    // let fee = Fee {
    //     token: WETH_ADDRESS,
    //     per_unit_gas: 1000000000000000000,
    //     recipient: broadcaster_address,
    //     expiration: 0,
    //     fees_id: "000".to_string(),
    //     available_wallets: 1,
    //     relay_adapt: Address::ZERO,
    //     reliability: 99,
    //     list_keys: vec!["efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88".into()],
    // };

    let mut builder = OperationBuilder::new();
    // builder.transfer(account1.clone(), account2.address(), USDC, 100, "");
    builder.set_unshield(account1.clone(), address, USDC, 100);
    let prepared: PoiProvedTransaction = builder
        .build_with_poi(
            &mut indexer,
            &prover,
            &poi_client,
            // &provider,
            // account1.clone(),
            // &fee,
            CHAIN,
            &mut rand,
        )
        .await
        .unwrap();

    // poi_client.submit(prepared).await.unwrap();

    // let transport = Arc::new(MockTransport);
    // poi_client.submit(prepared).await.unwrap();
    // let broadcaster = Broadcaster::new(transport, CHAIN.id, broadcaster_address, None, fee);
    // broadcaster.broadcast(&prepared, &mut rand).await.unwrap();

    // info!(
    //     "Prepared operation with {} operations",
    //     prepared.operations.len()
    // );
}

struct MockTransport;

#[async_trait]
impl WakuTransport for MockTransport {
    async fn subscribe(&self, _: Vec<String>) -> Result<MessageStream, WakuTransportError> {
        todo!();
    }

    async fn send(&self, _: &str, _: Vec<u8>) -> Result<(), WakuTransportError> {
        todo!();
    }

    async fn retrieve_historical(&self, _: &str) -> Result<Vec<WakuMessage>, WakuTransportError> {
        todo!();
    }
}
