use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

mod abis;
mod account;
mod caip;
mod chain_config;
mod circuit;
mod crypto;
mod indexer;
mod merkle_tree;
mod note;
mod railgun;
mod tx_data;

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use tracing::info;

use crate::{
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, MAINNET_CONFIG},
    indexer::indexer::Indexer,
};

// Anvil test private key (0)
const TEST_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const USDC_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const INDEXER_STATE_PATH: &str = "indexer_state.json";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let spending_private_key = [1u8; 32];
    let viewing_private_key = [2u8; 32];

    let latest = 24378760;
    let asset = AssetId::Erc20(USDC_ADDRESS);
    let amount = 100 * 10u128.pow(6); // 100 USDC
    let chain = MAINNET_CONFIG;

    let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
    let address = signer.address();

    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect("http://localhost:8545")
        .await
        .unwrap()
        .erased();

    // sync_indexer(provider, chain, latest).await;
    let indexer = load_indexer_from_state(provider.clone()).await;

    let account = RailgunAccount::new(spending_private_key, viewing_private_key, indexer.clone());
    // shield(provider.clone(), &account, asset, amount).await;

    indexer.lock().unwrap().sync().await.unwrap();

    let balance = account.balance();
    info!("Account Balance: {:?}", balance);

    account.unshield(asset, amount / 2, address).unwrap();
}

/// Sync the indexer up to a specific block, saving the state.
async fn sync_indexer(provider: DynProvider, chain: ChainConfig, to_block: u64) {
    info!("Syncing indexer up to block {}", to_block);

    let mut indexer = Indexer::new(provider, chain);
    indexer.sync_from_subsquid(Some(to_block)).await.unwrap();
    indexer.validate().await.unwrap();

    let state = indexer.state();
    let state_json = serde_json::to_string_pretty(&state).unwrap();
    std::fs::write(INDEXER_STATE_PATH, state_json).unwrap();
}

async fn load_indexer_from_state(provider: DynProvider) -> Arc<Mutex<Indexer>> {
    info!("Loading indexer state from {}", INDEXER_STATE_PATH);

    let state_json = std::fs::read_to_string(INDEXER_STATE_PATH).unwrap();
    let state: indexer::indexer::IndexerState = serde_json::from_str(&state_json).unwrap();
    let mut indexer = Indexer::new_with_state(provider, state).unwrap();
    indexer.validate().await.unwrap();
    Arc::new(Mutex::new(indexer))
}

/// Approves and shields a specified asset and amount
async fn shield(provider: DynProvider, account: &RailgunAccount, asset: AssetId, amount: u128) {
    info!("Shielding {} of asset {:?}", amount, asset);

    // Approve
    let erc20_instance = abis::erc20::ERC20::new(
        match asset {
            AssetId::Erc20(addr) => addr,
            _ => panic!("Unsupported asset for shielding"),
        },
        provider.clone(),
    );
    erc20_instance
        .approve(MAINNET_CONFIG.railgun_smart_wallet, U256::from(amount))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Shield
    let shield_tx = account.shield(asset, amount).unwrap();
    let tx = TransactionRequest::default()
        .to(shield_tx.to)
        .value(shield_tx.value)
        .input(shield_tx.data.into());
    provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

/// Convert a hex string (with or without 0x prefix) to Fr
fn hex_to_fr(hex_str: &str) -> Fr {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).unwrap();
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Convert a decimal string to Fr
fn decimal_to_fr(s: &str) -> Fr {
    let big = BigUint::from_str(s).unwrap();
    Fr::from(big)
}

/// Convert Fr to a 0x-prefixed hex string (32 bytes, zero-padded)
fn fr_to_hex(fr: &Fr) -> String {
    let bigint = fr.into_bigint();
    let bytes = bigint.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

// #[cfg(test)]
// mod tests {
//     use std::{collections::HashMap, str::FromStr};

//     use ark_bn254::{Bn254, Fr};
//     use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
//     use ark_groth16::{Groth16, prepare_verifying_key};
//     use ark_std::rand::thread_rng;

//     use crate::{decimal_to_fr, poseidon_hash};

//     const WASM_PATH: &str = "artifacts/01x02/01x02.wasm";
//     const R1CS_PATH: &str = "artifacts/01x02/01x02.r1cs";
//     const ZKEY_PATH: &str = "artifacts/01x02/01x02.zkey";
//     const INPUTS_PATH: &str = "artifacts/01x02/inputs.json";

//     #[tokio::test]
//     async fn test_prove_railgun() {
//         println!("Testing Groth16 proof generation for Railgun circuit");
//         let cfg = CircomConfig::<Fr>::new(WASM_PATH, R1CS_PATH).unwrap();
//         let mut builder = CircomBuilder::new(cfg);

//         println!("Reading inputs from {}", INPUTS_PATH);
//         let inputs = std::fs::read_to_string(INPUTS_PATH).unwrap();
//         let inputs: HashMap<String, Vec<String>> = serde_json::from_str(&inputs).unwrap();

//         let mut big_int_inputs = HashMap::new();
//         for (key, values) in inputs {
//             let big_int_values: Vec<num_bigint::BigInt> = values
//                 .into_iter()
//                 .map(|v| num_bigint::BigInt::from_str(&v).unwrap())
//                 .collect();
//             big_int_inputs.insert(key, big_int_values);
//         }

//         println!("Inputs: {:?}", big_int_inputs);

//         for (name, values) in big_int_inputs.iter() {
//             for value in values {
//                 builder.push_input(name, value.clone());
//             }
//         }

//         let circom = builder.build().unwrap();
//         let public_inputs = circom.get_public_inputs().unwrap();

//         println!("Public Inputs: {:?}", public_inputs);

//         let mut zkey_file = std::fs::File::open(ZKEY_PATH).unwrap();
//         let (params, _matrices) = ark_circom::read_zkey(&mut zkey_file).unwrap();

//         let mut rng = thread_rng();
//         let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
//             circom, &params, &mut rng,
//         )
//         .unwrap();

//         println!("Proof: {:?}", proof);

//         let pvk = prepare_verifying_key(&params.vk);
//         let verified =
//             Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
//         assert!(verified, "Proof verification failed");

//         println!("Proof verified successfully");
//     }

//     /// Test to verify the Poseidon hash is equivalent to the reference circomlibjs implementation.
//     #[test]
//     fn test_poseidon_hash() {
//         let expected = "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
//         let hash = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]);
//         let hash_hex = crate::fr_to_hex(&hash);
//         assert_eq!(hash_hex, expected);
//     }

//     #[test]
//     fn test_poseidon_hash_zero() {
//         let expected = "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";
//         let hash = poseidon_hash(&[Fr::from(0u64), Fr::from(0u64)]);
//         let hash_hex = crate::fr_to_hex(&hash);
//         assert_eq!(hash_hex, expected);
//     }

//     // BlindedCommitment.getForShieldOrTransact
//     #[test]
//     fn test_blinded_commitment() {
//         let expected = decimal_to_fr(
//             "12151255948031648278500231754672666576376002857793985290167262750766640136930",
//         );

//         let shield_commitment = decimal_to_fr(
//             "6442080113031815261226726790601252395803415545769290265212232865825296902085",
//         );
//         let note_public_key = decimal_to_fr(
//             "6401386539363233023821237080626891507664131047949709897410333742190241828916",
//         );
//         let global_tree_position = Fr::from(0u64);

//         let hash = poseidon_hash(&[shield_commitment, note_public_key, global_tree_position]);

//         assert_eq!(hash, expected);
//     }
// }
