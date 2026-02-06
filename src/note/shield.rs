use alloy::primitives::Uint;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use rand::random;
use thiserror::Error;

use crate::{
    abis::railgun::{CommitmentPreimage, ShieldCiphertext, ShieldRequest},
    caip::AssetId,
    crypto::{
        concat_arrays,
        keys::{ByteKey, FieldKey, U256Key, ViewingKey},
        poseidon::poseidon_hash,
    },
    note::ark_to_solidity_bytes,
    railgun::address::RailgunAddress,
};

#[derive(Debug, Error)]
pub enum ShieldError {}

pub fn create_shield_request(
    recipient: RailgunAddress,
    asset: AssetId,
    value: u128,
) -> Result<ShieldRequest, ShieldError> {
    let shield_private_key: ViewingKey = random();
    let shared_key = shield_private_key
        .derive_shared_key(recipient.viewing_pubkey())
        .unwrap();

    let random_seed: [u8; 16] = random();
    let npk = ark_to_solidity_bytes(poseidon_hash(&[
        recipient.master_key().to_fr(),
        Fr::from_be_bytes_mod_order(&random_seed),
    ]));
    let gcm = shared_key.encrypt_gcm(&[&random_seed]).unwrap();
    let ctr = shield_private_key.encrypt_ctr(&[recipient.viewing_pubkey().as_bytes()]);

    let gcm_random: [u8; 16] = gcm.data[0].clone().try_into().unwrap();
    let ctr_key: [u8; 32] = ctr.data[0].clone().try_into().unwrap();

    Ok(ShieldRequest {
        preimage: CommitmentPreimage {
            npk: npk.into(),
            token: asset.into(),
            value: Uint::from(value),
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
            shieldKey: shield_private_key.public_key().to_u256().into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use rand::random;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::{SpendingKey, ViewingKey},
        note::{note::Note, shield::create_shield_request},
        railgun::address::RailgunAddress,
    };

    #[test]
    #[traced_test]
    fn test_shield_encrypt_decrypt() {
        let spending_key: SpendingKey = random();
        let viewing_key: ViewingKey = random();

        let recipient = RailgunAddress::from_private_keys(spending_key, viewing_key, 1);
        let asset: AssetId = AssetId::Erc20(Address::from([0u8; 20]));
        let value: u128 = 1_000_000;

        let shield_request = create_shield_request(recipient, asset, value).unwrap();

        // Decrypt the note
        let decrypted = Note::decrypt_shield_request(shield_request, spending_key, viewing_key)
            .expect("Failed to decrypt shield note");

        assert_eq!(decrypted.value, value);
        assert_eq!(decrypted.token, asset);
        assert_eq!(decrypted.memo, "");
    }
}
