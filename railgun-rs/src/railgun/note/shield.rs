use alloy::primitives::{U256, Uint};
use rand::Rng;
use thiserror::Error;

use crate::{
    abis::railgun::{CommitmentPreimage, ShieldCiphertext, ShieldRequest},
    caip::AssetId,
    crypto::{
        concat_arrays,
        keys::{ByteKey, U256Key, ViewingKey},
        poseidon::poseidon_hash,
    },
    railgun::address::RailgunAddress,
};

#[derive(Debug, Error)]
pub enum ShieldError {}

pub fn create_shield_request<R: Rng>(
    recipient: RailgunAddress,
    asset: AssetId,
    value: u128,
    rng: &mut R,
) -> Result<ShieldRequest, ShieldError> {
    let shield_private_key: ViewingKey = rng.random();
    let shared_key = shield_private_key
        .derive_shared_key(recipient.viewing_pubkey())
        .unwrap();

    let random_seed: [u8; 16] = rng.random();
    let mut npk: [u8; 32] = poseidon_hash(&[
        recipient.master_key().to_u256(),
        U256::from_be_slice(&random_seed),
    ])
    .unwrap()
    .to_le_bytes();
    npk.reverse();

    let gcm = shared_key.encrypt_gcm(&[&random_seed], rng).unwrap();
    let ctr = shield_private_key.encrypt_ctr(&[recipient.viewing_pubkey().as_bytes()], rng);

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
    use rand::Rng;
    use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::{SpendingKey, ViewingKey},
        railgun::address::RailgunAddress,
        railgun::note::{Note, shield::create_shield_request, utxo::UtxoNote},
    };

    #[test]
    #[traced_test]
    fn test_shield_snap() {
        let mut rng = ChaChaRng::seed_from_u64(0);

        let spending_key: SpendingKey = rng.random();
        let viewing_key: ViewingKey = rng.random();

        let recipient = RailgunAddress::from_private_keys(spending_key, viewing_key, 1);
        let asset: AssetId = AssetId::Erc20(Address::from([0u8; 20]));
        let value: u128 = 1_000_000;

        let shield_request = create_shield_request(recipient, asset, value, &mut rng).unwrap();
        insta::assert_debug_snapshot!(shield_request);
    }

    #[test]
    #[traced_test]
    fn test_shield_encrypt_decrypt() {
        let mut rng = ChaChaRng::seed_from_u64(0);

        let spending_key: SpendingKey = rng.random();
        let viewing_key: ViewingKey = rng.random();

        let recipient = RailgunAddress::from_private_keys(spending_key, viewing_key, 1);
        let asset: AssetId = AssetId::Erc20(Address::from([0u8; 20]));
        let value: u128 = 1_000_000;

        let shield_request = create_shield_request(recipient, asset, value, &mut rng).unwrap();

        // Decrypt the note
        let decrypted =
            UtxoNote::decrypt_shield_request(spending_key, viewing_key, 1, 0, shield_request)
                .expect("Failed to decrypt shield note");

        assert_eq!(decrypted.value(), value);
        assert_eq!(decrypted.asset(), asset);
        assert_eq!(decrypted.memo(), "");
    }
}
