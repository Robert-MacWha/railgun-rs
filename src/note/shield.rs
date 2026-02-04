use alloy::primitives::{U256, Uint};
use alloy_sol_types::SolCall;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_std::rand;
use ed25519_dalek::SigningKey;
use light_poseidon::{Poseidon, PoseidonError, PoseidonHasher};

use crate::{
    abis::railgun::{CommitmentPreimage, RailgunSmartWallet, ShieldCiphertext, ShieldRequest},
    caip::AssetId,
    chain_config::ChainConfig,
    crypto::{
        aes::{encrypt_ctr, encrypt_gcm},
        concat_arrays,
        ed25519::derive_shared_symmetric_key,
    },
    note::ark_to_solidity_bytes,
    railgun::address::RailgunAddress,
    tx_data::TxData,
};

/// ShieldNote represents a note to be shielded into railgun.
///
/// TODO: Refactor me + `create_shield_transaction` into a ShieldBuilder struct
/// that can accumulate multiple notes and create the transaction.
pub struct ShieldNote {
    master_public_key: [u8; 32],
    random_seed: [u8; 16],
    amount: u128,
    asset: AssetId,
    asset_hash: Fr,
    note_public_key: Fr,
}

pub struct ShieldRecipient {
    asset: AssetId,
    recipient: RailgunAddress,
    amount: u128,
}

impl ShieldRecipient {
    pub fn new(asset: AssetId, recipient: RailgunAddress, amount: u128) -> Self {
        ShieldRecipient {
            asset,
            recipient,
            amount,
        }
    }
}

pub fn create_shield_transaction(
    shield_private_key: &[u8; 32],
    chain: ChainConfig,
    recipients: &[ShieldRecipient],
) -> Result<TxData, PoseidonError> {
    let random: [u8; 16] = rand::random();

    let mut shield_inputs = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let note = ShieldNote::new(
            recipient.recipient.master_public_key(),
            &random,
            recipient.amount,
            recipient.asset.clone(),
        );
        let serialized =
            note.serialize(shield_private_key, recipient.recipient.viewing_public_key())?;
        shield_inputs.push(serialized);
    }

    let call = RailgunSmartWallet::shieldCall {
        _shieldRequests: shield_inputs,
    };
    let calldata = call.abi_encode();

    // TODO: Get address from chain config
    Ok(TxData {
        to: chain.railgun_smart_wallet,
        data: calldata,
        value: U256::ZERO,
    })
}

impl ShieldNote {
    pub fn new(
        master_public_key: &[u8; 32],
        random_seed: &[u8; 16],
        amount: u128,
        asset: AssetId,
    ) -> Self {
        let fr_master_public_key = Fr::from_be_bytes_mod_order(master_public_key);
        let fr_random_seed = Fr::from_be_bytes_mod_order(random_seed);

        let asset_hash = asset.hash();
        let note_public_key = poseidon(&[fr_master_public_key, fr_random_seed]).unwrap();
        ShieldNote {
            master_public_key: master_public_key.clone(),
            random_seed: random_seed.clone(),
            amount,
            asset,
            asset_hash,
            note_public_key,
        }
    }

    pub fn serialize(
        &self,
        shield_private_key: &[u8; 32],
        receiver_viewing_key: &[u8; 32],
    ) -> Result<ShieldRequest, PoseidonError> {
        let shared_key =
            derive_shared_symmetric_key(shield_private_key, receiver_viewing_key).unwrap();

        let signing_key = SigningKey::from_bytes(shield_private_key);
        let shield_key = signing_key.verifying_key().to_bytes();

        let npk = ark_to_solidity_bytes(self.note_public_key);

        let gcm = encrypt_gcm(&[self.random_seed.as_slice()], &shared_key).unwrap();
        let ctr = encrypt_ctr(&[receiver_viewing_key], shield_private_key);

        let gcm_random: [u8; 16] = gcm.data[0].clone().try_into().unwrap();
        let ctr_key: [u8; 32] = ctr.data[0].clone().try_into().unwrap();

        return Ok(ShieldRequest {
            preimage: CommitmentPreimage {
                npk: npk.into(),
                token: self.asset.clone().into(),
                value: Uint::from(self.amount),
            },
            ciphertext: ShieldCiphertext {
                // iv (16) | tag (16)
                // random (16) | ctr iv (16)
                // receiver_viewing_key (32)
                encryptedBundle: [
                    concat_arrays(&gcm.iv, &gcm.tag).into(),
                    concat_arrays(&gcm_random, &ctr.iv).into(),
                    ctr_key.into(),
                ],
                shieldKey: shield_key.into(),
            },
        });
    }
}

fn poseidon(inputs: &[Fr]) -> Result<Fr, PoseidonError> {
    Poseidon::<Fr>::new_circom(inputs.len())?.hash(inputs)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use ark_std::rand::random;
    use ed25519_dalek::SigningKey;

    use crate::{
        caip::AssetId,
        crypto::keys::{derive_master_public_key, derive_viewing_public_key, fr_to_bytes_be},
        note::{note::Note, shield::ShieldNote},
    };

    #[test]
    fn test_shared_key_railgun() {
        // Values taken from Railgun tests to ensure compatibility
        let private_key_a = "0303030303030303030303030303030303030303030303030303030303030303";
        let public_key_b = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";
        let expected_shared = "210753a79ae8f30d3221984eb26f1294708ad10ad7eebba64fea186fba052599";

        let private_key_a: [u8; 32] = hex::decode(private_key_a).unwrap().try_into().unwrap();
        let public_key_b: [u8; 32] = hex::decode(public_key_b).unwrap().try_into().unwrap();
        let expected_shared_key: [u8; 32] =
            hex::decode(expected_shared).unwrap().try_into().unwrap();

        let shared_key_ab =
            super::derive_shared_symmetric_key(&private_key_a, &public_key_b).expect("Failed A->B");

        assert_eq!(shared_key_ab, expected_shared_key);
    }

    #[test]
    fn test_shield_encrypt_decrypt() {
        let spending_private_key: [u8; 32] = random();
        let viewing_private_key: [u8; 32] = random();
        let master_pub_key = derive_master_public_key(&spending_private_key, &viewing_private_key);
        let master_pub_key: [u8; 32] = fr_to_bytes_be(&master_pub_key);

        let viewing_key: [u8; 32] = derive_viewing_public_key(&viewing_private_key);
        let random_seed: [u8; 16] = random();
        let value: u128 = 1_000_000;
        let token: AssetId = AssetId::Erc20(Address::from([0u8; 20]));

        let shield_note = ShieldNote::new(&master_pub_key, &random_seed, value, token.clone());
        let req = shield_note
            .serialize(&spending_private_key, &viewing_key)
            .expect("Failed to serialize shield note");

        // Decrypt the note
        let decrypted =
            Note::decrypt_shield_request(req, &viewing_private_key, &spending_private_key)
                .expect("Failed to decrypt shield note");

        assert_eq!(decrypted.value, value);
        assert_eq!(decrypted.token, token);
        assert_eq!(decrypted.random_seed, random_seed);
        assert_eq!(decrypted.memo, "");
    }

    #[test]
    fn test_shield() {
        let shield_signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let shield_priv = shield_signing_key.to_bytes();

        let receiver_signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let receiver_viewing = receiver_signing_key.verifying_key().to_bytes();

        let master_pub = [1u8; 32];
        let random_seed = [2u8; 16];

        let note = super::ShieldNote::new(
            &master_pub,
            &random_seed,
            1000,
            super::AssetId::Erc20([5u8; 20].into()),
        );

        let _request = note
            .serialize(&shield_priv, &receiver_viewing)
            .expect("Failed to serialize shield note");
    }
}
