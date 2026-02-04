use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::rand::random;
use thiserror::Error;
use tracing::info;

use crate::{
    abis::railgun::{CommitmentCiphertext, ShieldRequest, TokenData, TokenDataError},
    caip::AssetId,
    crypto::{
        aes::{AesError, Ciphertext, decrypt_gcm, encrypt_ctr, encrypt_gcm},
        concat_arrays, concat_arrays_3,
        ed25519::{BlindKeyError, SharedKeyError, blind_keys, derive_shared_symmetric_key},
        keys::{derive_viewing_public_key, fr_to_bytes_be},
        poseidon::poseidon_hash,
        railgun_base_37,
    },
    railgun::address::RailgunAddress,
};

/// Note represents a Railgun from the chain.
/// TODO: Consider adding leaf_index / tree_position to Note struct,
/// so it knows its own index in the tree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub spending_private_key: [u8; 32],
    pub viewing_private_key: [u8; 32],
    pub random_seed: [u8; 16],
    pub value: u128,
    pub token: AssetId,
    pub memo: String,
}

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("AES error: {0}")]
    Aes(#[from] AesError),
    #[error("SharedKey error: {0}")]
    SharedKey(#[from] SharedKeyError),
    #[error("TokenData error: {0}")]
    TokenData(#[from] TokenDataError),
}

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Railgun base37 encoding error: {0}")]
    RailgunBase37(#[from] railgun_base_37::EncodingError),
    #[error("Blinding error: {0}")]
    BlindKey(#[from] BlindKeyError),
    #[error("Shared key error: {0}")]
    SharedKey(#[from] SharedKeyError),
    #[error("AES encryption error: {0}")]
    Aes(#[from] AesError),
}

impl Note {
    pub fn new(
        spending_private_key: &[u8; 32],
        viewing_private_key: &[u8; 32],
        random_seed: &[u8; 16],
        value: u128,
        token: AssetId,
        memo: &str,
    ) -> Self {
        Note {
            spending_private_key: *spending_private_key,
            viewing_private_key: *viewing_private_key,
            random_seed: *random_seed,
            value,
            token,
            memo: memo.to_string(),
        }
    }

    /// Decrypt a note
    pub fn decrypt(
        encrypted: &CommitmentCiphertext,
        viewing_private_key: &[u8; 32],
        spending_private_key: &[u8; 32],
    ) -> Result<Note, NoteError> {
        let shared_key = derive_shared_symmetric_key(
            viewing_private_key,
            &encrypted.blindedSenderViewingKey.into(),
        )?;

        let data: Vec<Vec<u8>> = vec![
            encrypted.ciphertext[1].to_vec(),
            encrypted.ciphertext[2].to_vec(),
            encrypted.ciphertext[3].to_vec(),
            encrypted.memo.to_vec(),
        ];

        let ciphertext = Ciphertext {
            iv: encrypted.ciphertext[0][..16].try_into().unwrap(),
            tag: encrypted.ciphertext[0][16..].try_into().unwrap(),
            data,
        };
        let bundle = decrypt_gcm(&ciphertext, &shared_key)?;

        let random: [u8; 16] = bundle[1][0..16].try_into().unwrap();
        let value: u128 = u128::from_be_bytes(bundle[1][16..32].try_into().unwrap());
        let token_data = TokenData::from_hash(&bundle[2])?;
        let asset_id = AssetId::from(token_data);
        let memo = if bundle.len() > 3 {
            std::str::from_utf8(&bundle[3]).unwrap_or("")
        } else {
            ""
        };

        Ok(Note::new(
            spending_private_key,
            viewing_private_key,
            &random,
            value,
            asset_id,
            memo,
        ))
    }

    /// Decrypts a shield note into a Note
    pub fn decrypt_shield_request(
        req: ShieldRequest,
        viewing_private_key: &[u8; 32],
        spending_private_key: &[u8; 32],
    ) -> Result<Note, NoteError> {
        let encrypted_bundle: [[u8; 32]; 3] = [
            req.ciphertext.encryptedBundle[0].into(),
            req.ciphertext.encryptedBundle[1].into(),
            req.ciphertext.encryptedBundle[2].into(),
        ];

        let shield_key: [u8; 32] = req.ciphertext.shieldKey.into();
        let shared_key = derive_shared_symmetric_key(viewing_private_key, &shield_key)?;

        let ciphertext = Ciphertext {
            iv: encrypted_bundle[0][..16].try_into().unwrap(),
            tag: encrypted_bundle[0][16..].try_into().unwrap(),
            data: vec![encrypted_bundle[1][..16].to_vec()],
        };
        let decrypted = decrypt_gcm(&ciphertext, &shared_key)?;
        let random: [u8; 16] = decrypted[0][0..16].try_into().unwrap();

        Ok(Note::new(
            spending_private_key,
            viewing_private_key,
            &random,
            req.preimage.value.saturating_to(),
            req.preimage.token.clone().into(),
            "",
        ))
    }

    pub fn nullifier(&self, leaf_index: u32) -> [u8; 32] {
        let hash: Fr = poseidon_hash(&[self.nullifying_key(), Fr::from(leaf_index)]);
        hash.into_bigint().to_bytes_be().try_into().unwrap()
    }

    fn nullifying_key(&self) -> Fr {
        poseidon_hash(&[Fr::from_be_bytes_mod_order(&self.viewing_private_key)])
    }
}

pub fn encrypt_note(
    receiver: &RailgunAddress,
    shared_random: &[u8; 16],
    value: u128,
    asset: &AssetId,
    memo: &str,
    sender_viewing_private_key: &[u8; 32],
    blind: bool,
) -> Result<CommitmentCiphertext, EncryptError> {
    let output_type = 0;
    let application_identifier = railgun_base_37::encode("railgun rs")?;
    let viewing_pub_key = derive_viewing_public_key(sender_viewing_private_key);
    let sender_random: [u8; 15] = if blind { random() } else { [0u8; 15] };

    let (blinded_sender_pub_key, blinded_receiver_pub_key) = blind_keys(
        &viewing_pub_key,
        receiver.viewing_public_key(),
        &concat_arrays(&shared_random, &[0u8; 16]),
        &concat_arrays(&sender_random, &[0u8; 17]),
    )?;

    let shared_key =
        derive_shared_symmetric_key(sender_viewing_private_key, &blinded_receiver_pub_key)?;

    let gcm = encrypt_gcm(
        &[
            receiver.master_public_key(),
            &concat_arrays::<16, 16, 32>(&shared_random, &value.to_be_bytes()),
            &fr_to_bytes_be(&asset.hash()),
            memo.as_bytes(),
        ],
        &shared_key,
    )?;

    let ctr = encrypt_ctr(
        &[&concat_arrays_3::<1, 15, 16, 32>(
            &[output_type],
            &sender_random,
            &application_identifier,
        )],
        &viewing_pub_key,
    );

    let bundle_1: [u8; 32] = gcm.data[0].clone().try_into().unwrap();
    let bundle_2: [u8; 32] = gcm.data[1].clone().try_into().unwrap();
    let bundle_3: [u8; 32] = gcm.data[2].clone().try_into().unwrap();

    return Ok(CommitmentCiphertext {
        // iv (16) | tag (16)
        // master_public_key (32)
        // random (16) | value (16)
        // token_hash (32)
        ciphertext: [
            concat_arrays(&gcm.iv, &gcm.tag).into(),
            bundle_1.into(),
            bundle_2.into(),
            bundle_3.into(),
        ],
        blindedSenderViewingKey: blinded_sender_pub_key.into(),
        blindedReceiverViewingKey: blinded_receiver_pub_key.into(),
        // ctr_iv (16) | encrypted_sender_bundle (any)
        annotationData: [ctr.iv.as_slice(), &ctr.data[0]].concat().into(),
        memo: gcm.data[3].clone().into(),
    });
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_note() {
        tracing_subscriber::fmt().init();

        let chain_id = 1;

        // Sender keys
        let sender_viewing_private_key = [2u8; 32];

        // Receiver keys
        let receiver_spending_private_key = [3u8; 32];
        let receiver_viewing_private_key = [4u8; 32];
        let receiver = RailgunAddress::from_private_keys(
            &receiver_spending_private_key,
            &receiver_viewing_private_key,
            chain_id,
        );

        let shared_random = [5u8; 16];
        let value = 1000u128;
        let asset = AssetId::Erc20(address!("0x1234567890123456789012345678901234567890"));
        let memo = "test memo";

        let encrypted = encrypt_note(
            &receiver,
            &shared_random,
            value,
            &asset,
            memo,
            &sender_viewing_private_key,
            false,
        )
        .unwrap();

        // Receiver decrypts with their own keys
        let decrypted = Note::decrypt(
            &encrypted,
            &receiver_viewing_private_key,
            &receiver_spending_private_key,
        )
        .unwrap();

        let expected = Note::new(
            &receiver_spending_private_key,
            &receiver_viewing_private_key,
            &shared_random,
            value,
            asset,
            memo,
        );

        assert_eq!(expected, decrypted);
    }
}
