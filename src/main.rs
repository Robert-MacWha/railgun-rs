use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use ark_bn254::Fr;
use tracing::info;

use railgun_rs::{
    abis::erc20::ERC20,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, SEPOLIA_CONFIG},
    crypto::{
        keys::{HexKey, SpendingKey, ViewingKey, fr_to_bytes},
        poseidon::poseidon_hash,
    },
    indexer::indexer::Indexer,
    poi::client::{BlindedCommitmentData, BlindedCommitmentType, PoiClient},
    railgun::address::RailgunAddress,
    transaction::shield_builder::ShieldBuilder,
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
    let account = RailgunAccount::new(spending_key, viewing_key, CHAIN.id);

    info!("Creating indexer");
    // let mut indexer = Indexer::new(provider.clone(), CHAIN);
    // indexer.sync_from_subsquid(Some(10213177)).await.unwrap();
    // let state = indexer.state();
    // std::fs::write(INDEXER_STATE, bitcode::serialize(&state).unwrap()).unwrap();
    let indexer_state = std::fs::read(INDEXER_STATE).unwrap();
    let indexer_state = bitcode::deserialize(&indexer_state).unwrap();
    let mut indexer = Indexer::new_with_state(provider.clone(), indexer_state).unwrap();
    indexer.add_account(&account);

    info!("Syncing indexer");
    indexer.sync().await.unwrap();
    info!("Balance: {:?}", indexer.balance(account.address()));

    info!("Saving indexer");
    let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./indexer_state_11155111.bincode", indexer_state).unwrap();

    let poi_client = PoiClient::new(PPOI_URL, CHAIN.id).await.unwrap();

    let notebooks = indexer.notebooks(account.address()).unwrap();
    for (tree_index, notebook) in notebooks {
        for (leaf_index, note) in notebook.unspent() {
            info!("Unspent note [{}, {}]: {:?}", tree_index, leaf_index, note);

            let commitment_hash = note.hash();
            let npk = note.note_public_key();
            let global_tree_position = Fr::from(tree_index * 65536 + leaf_index);
            let blinded_commitment = fr_to_bytes(&poseidon_hash(&[
                commitment_hash,
                npk,
                global_tree_position,
            ]));

            let pois = poi_client
                .pois(vec![BlindedCommitmentData {
                    blinded_commitment,
                    commitment_type: BlindedCommitmentType::Shield,
                }])
                .await
                .unwrap();

            let merkle_proofs = poi_client
                .merkle_proofs(vec![blinded_commitment])
                .await
                .unwrap();

            info!("POIs: {:?}", pois);
            info!("Merkle Proofs: {:?}", merkle_proofs);
        }
    }
}

async fn shield_usdc(provider: DynProvider, to: RailgunAddress, amount: u128) {
    info!("Approving USDC");
    let usdc_contract = ERC20::new(USDC_ADDRESS, provider.clone());
    usdc_contract
        .approve(CHAIN.railgun_smart_wallet, U256::from(amount))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    info!("Shielding");
    let shield_tx = ShieldBuilder::new(CHAIN)
        .shield(to, USDC, amount)
        .build()
        .unwrap();
    provider
        .send_transaction(shield_tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    info!("Shielded");
}

// let url = "https://ppoi-agg.horsewithsixlegs.xyz";
// let client = PpoiClient::new(url);

// info!("Requesting health");
// let health = client.health().await.unwrap();
// info!("Health: {}", health);

// let commitment_hash = "";
// let npk = "";
// let global_tree_position = "";
// let blinded_commitment = fr_to_u256(&poseidon_hash(&[
//     hex_to_fr(commitment_hash),
//     hex_to_fr(npk),
//     hex_to_fr(global_tree_position),
// ]));

// let pois = client
//     .pois_per_list(GetPoisPerListParams {
//         chain: ChainParams {
//             chain_type: 0.to_string(), // EVM
//             chain_id: 0.to_string(),   // Mainnet
//             txid_version: TxidVersion::V2PoseidonMerkle,
//         },
//         list_keys: vec![
//             "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88".to_string(),
//             "55049dc47b4435bca4a8f8ac27b1858e409f9f72b317fde4a442095cfc454893".to_string(),
//         ],
//         blinded_commitment_datas: vec![BlindedCommitmentData {
//             blinded_commitment: blinded_commitment.to_string(),
//             commitment_type: BlindedCommitmentType::Shield,
//         }],
//     })
//     .await
//     .unwrap();

// println!("POIs: {:?}", pois);

// info!("Creating POI Client");
// let mut headers = HeaderMap::new();
// headers.insert("User-Agent", HeaderValue::from_static("railgun-rs/0.1.0"));
// let poi_client = HttpClientBuilder::default()
//     .set_headers(headers)
//     .build("https://ppoi-agg.horsewithsixlegs.xyz/")
//     .unwrap();
// info!("Requesting health");
// let health = poi_client.health().await.unwrap();
// info!("Health: {}", health);

// info!("Requesting status");
// let status = poi_client.node_status().await.unwrap();
// info!("Status: {:?}", status);
