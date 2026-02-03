use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

mod account;
mod aes;
mod caip;
mod chain_config;
mod crypto;
mod erc20;
mod indexer;
mod merkle_tree;
mod note;
mod railgun;
mod transaction;
mod tx_data;

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionInput, TransactionRequest},
    signers::local::PrivateKeySigner,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use tracing::info;

use crate::{
    account::RailgunAccount, caip::AssetId, chain_config::MAINNET_CONFIG, indexer::indexer::Indexer,
};

const TEST_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const USDC_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let spending_private_key = [1u8; 32];
    let viewing_private_key = [2u8; 32];

    // Anvil test private key (0)
    let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();

    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect("http://localhost:8545")
        .await
        .unwrap();

    let latest = provider.get_block_number().await.unwrap() - 10;
    let indexer = Indexer::new(provider.clone(), MAINNET_CONFIG, latest);
    let indexer = Arc::new(Mutex::new(indexer));
    let account = RailgunAccount::new(spending_private_key, viewing_private_key, indexer.clone());
    info!("Loaded Account: {}", account.address());

    let asset = AssetId::Erc20(USDC_ADDRESS);
    let amount = 100 * 10u128.pow(6); // 100 USDC

    // ERC20 transfer approval
    let erc20_instance = erc20::ERC20::new(USDC_ADDRESS, provider.clone());
    erc20_instance
        .approve(MAINNET_CONFIG.railgun_smart_wallet, U256::from(amount * 2))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    info!("Approved ERC20 transfer");

    // Shield
    let shield = account.shield(asset, amount).unwrap();
    info!("Created Shield Tx");

    let tx = TransactionRequest::default()
        .to(shield.to)
        .value(shield.value)
        .input(shield.data.into());
    provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    info!("Shielded");

    // Sync
    indexer.lock().unwrap().sync().await.unwrap();
    info!("Synced Indexer");

    let balance = indexer.lock().unwrap().balance(account.address());
    info!("Account Balance: {:?}", balance);
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
