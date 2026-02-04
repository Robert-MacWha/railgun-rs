use alloy::primitives::{U256, Uint};
use alloy_sol_types::SolCall;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_std::rand::{self, random};
use light_poseidon::{Poseidon, PoseidonError, PoseidonHasher};

use crate::{
    abis::railgun::{CommitmentPreimage, RailgunSmartWallet, ShieldCiphertext, ShieldRequest},
    caip::AssetId,
    chain_config::ChainConfig,
    crypto::{
        concat_arrays,
        keys::{ByteKey, FieldKey, MasterPublicKey, U256Key, ViewingKey, ViewingPublicKey},
        poseidon::poseidon_hash,
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
    master_key: MasterPublicKey,
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
    chain: ChainConfig,
    recipients: &[ShieldRecipient],
) -> Result<TxData, PoseidonError> {
    let random_seed: [u8; 16] = rand::random();

    let mut shield_inputs = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let note = ShieldNote::new(
            recipient.recipient.master_key(),
            &random_seed,
            recipient.amount,
            recipient.asset.clone(),
        );
        let shield_private_key = ViewingKey::from_bytes(random());
        let serialized =
            note.serialize(shield_private_key, recipient.recipient.viewing_pubkey())?;
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
        master_key: MasterPublicKey,
        random_seed: &[u8; 16],
        amount: u128,
        asset: AssetId,
    ) -> Self {
        let fr_random_seed = Fr::from_be_bytes_mod_order(random_seed);

        let asset_hash = asset.hash();
        let note_public_key = poseidon_hash(&[master_key.to_fr(), fr_random_seed]);
        ShieldNote {
            master_key,
            random_seed: random_seed.clone(),
            amount,
            asset,
            asset_hash,
            note_public_key,
        }
    }

    pub fn serialize(
        &self,
        shield_private_key: ViewingKey,
        receiver_pubkey: ViewingPublicKey,
    ) -> Result<ShieldRequest, PoseidonError> {
        let shared_key = shield_private_key
            .derive_shared_key(receiver_pubkey)
            .unwrap();

        let npk = ark_to_solidity_bytes(self.note_public_key);
        let gcm = shared_key
            .encrypt_gcm(&[self.random_seed.as_slice()])
            .unwrap();
        let ctr = shield_private_key.encrypt_ctr(&[receiver_pubkey.as_bytes()]);

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
                shieldKey: shield_private_key.public_key().to_u256().into(),
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use ark_std::rand::random;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::{ByteKey, MasterPublicKey, SpendingKey, ViewingKey},
        note::{note::Note, shield::ShieldNote},
    };

    #[test]
    #[traced_test]
    fn test_shield_encrypt_decrypt() {
        let spending_key = SpendingKey::from_bytes(random());
        let viewing_key = ViewingKey::from_bytes(random());
        let master_key =
            MasterPublicKey::new(spending_key.public_key(), viewing_key.nullifying_key());

        let random_seed: [u8; 16] = random();
        let value: u128 = 1_000_000;
        let token: AssetId = AssetId::Erc20(Address::from([0u8; 20]));

        let shield_note = ShieldNote::new(master_key, &random_seed, value, token.clone());
        let req = shield_note
            .serialize(ViewingKey::from_bytes(random()), viewing_key.public_key())
            .expect("Failed to serialize shield note");

        // Decrypt the note
        let decrypted = Note::decrypt_shield_request(req, spending_key, viewing_key)
            .expect("Failed to decrypt shield note");

        assert_eq!(decrypted.value, value);
        assert_eq!(decrypted.token, token);
        assert_eq!(decrypted.random_seed, random_seed);
        assert_eq!(decrypted.memo, "");
    }

    #[test]
    #[traced_test]
    fn test_shield() {
        let receiver_viewing_key = ViewingKey::from_bytes([2u8; 32]);

        let master_key = MasterPublicKey::from_bytes(random());
        let random_seed = [2u8; 16];

        let note = super::ShieldNote::new(
            master_key,
            &random_seed,
            1000,
            super::AssetId::Erc20([5u8; 20].into()),
        );

        let _request = note
            .serialize(
                ViewingKey::from_bytes(random()),
                receiver_viewing_key.public_key(),
            )
            .expect("Failed to serialize shield note");
    }
}
