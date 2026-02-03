use std::collections::BTreeMap;

use alloy::primitives::Address;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::rand::random;
use thiserror::Error;

use crate::{
    caip::AssetId,
    crypto::aes::{AesError, Ciphertext, decrypt_gcm},
    crypto::poseidon::poseidon_hash,
    note::{SharedKeyError, shared_symetric_key},
    railgun::{
        address::RailgunAddress,
        sol::{CommitmentCiphertext, ShieldRequest, TokenData, TokenDataError},
    },
};

#[derive(Clone, Debug)]
pub struct Note {
    pub spending_key: [u8; 32],
    pub viewing_key: [u8; 32],
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

impl Note {
    pub fn new(
        spending_key: &[u8; 32],
        viewing_key: &[u8; 32],
        random_seed: &[u8; 16],
        value: u128,
        token: AssetId,
        memo: &str,
    ) -> Self {
        Note {
            spending_key: *spending_key,
            viewing_key: *viewing_key,
            random_seed: *random_seed,
            value,
            token,
            memo: memo.to_string(),
        }
    }

    /// Decrypt a note
    pub fn decrypt(
        encrypted: &CommitmentCiphertext,
        viewing_key: &[u8; 32],
        spending_key: &[u8; 32],
    ) -> Result<Note, NoteError> {
        let shared_key =
            shared_symetric_key(viewing_key, &encrypted.blindedSenderViewingKey.into())?;

        let data: Vec<Vec<u8>> = vec![
            encrypted.ciphertext[1].to_vec(),
            encrypted.ciphertext[2].to_vec(),
            encrypted.memo.to_vec(),
        ];

        let ciphertext = Ciphertext {
            iv: encrypted.ciphertext[0][..16].try_into().unwrap(),
            tag: encrypted.ciphertext[0][16..].try_into().unwrap(),
            data,
        };
        let bundle = decrypt_gcm(&ciphertext, &shared_key)?;

        let random: [u8; 16] = bundle[1][16..32].try_into().unwrap();
        let value: u128 = u128::from_be_bytes(bundle[1][0..16].try_into().unwrap());
        let token_data = TokenData::from_hash(&bundle[2])?;
        let asset_id = AssetId::from(token_data);
        // TODO: Figure this out - I think it's always false?  Not sure what's
        // happening
        let memo = if bundle.len() > 3 { todo!() } else { "" };

        Ok(Note::new(
            spending_key,
            viewing_key,
            &random,
            value,
            asset_id,
            memo,
        ))
    }

    pub fn decrypt_shield_request(
        req: ShieldRequest,
        viewing_key: &[u8; 32],
        spending_key: &[u8; 32],
    ) -> Result<Note, NoteError> {
        let encrypted_bundle: [[u8; 32]; 3] = [
            req.ciphertext.encryptedBundle[0].into(),
            req.ciphertext.encryptedBundle[1].into(),
            req.ciphertext.encryptedBundle[2].into(),
        ];

        let note = Note::decrypt_shield(
            &req.ciphertext.shieldKey.into(),
            &encrypted_bundle,
            req.preimage.token.clone().into(),
            req.preimage.value.saturating_to(),
            viewing_key,
            spending_key,
        )?;

        Ok(note)
    }

    /// Decrypt a shield note into a Note
    pub fn decrypt_shield(
        shield_key: &[u8; 32],
        encrypted_bundle: &[[u8; 32]; 3],
        asset: AssetId,
        value: u128,
        viewing_key: &[u8; 32],
        spending_key: &[u8; 32],
    ) -> Result<Note, NoteError> {
        let shared_key = shared_symetric_key(viewing_key, shield_key)?;

        let ciphertext = Ciphertext {
            iv: encrypted_bundle[0][..16].try_into().unwrap(),
            tag: encrypted_bundle[0][16..].try_into().unwrap(),
            data: vec![encrypted_bundle[1][..16].to_vec()],
        };
        let decrypted = decrypt_gcm(&ciphertext, &shared_key)?;
        let random: [u8; 16] = decrypted[0][0..16].try_into().unwrap();

        Ok(Note::new(
            spending_key,
            viewing_key,
            &random,
            value,
            asset,
            "",
        ))
    }
}

impl Note {
    pub fn nullifier(&self, leaf_index: u64) -> [u8; 32] {
        let hash: Fr = poseidon_hash(&[self.nullifying_key(), Fr::from(leaf_index)]);
        hash.into_bigint().to_bytes_be().try_into().unwrap()
    }

    /// Encrypt the note's commitment ciphertext. If `blind` is true, uses a random
    /// sender viewing key. Otherwise uses a constant 0-key so the data can be
    /// decrypted.
    pub fn encrypt(&self, sender_viewing_key: [u8; 32], blind: bool) -> Vec<u8> {
        todo!()
    }

    fn nullifying_key(&self) -> Fr {
        poseidon_hash(&[Fr::from_be_bytes_mod_order(&self.viewing_key)])
    }
}

enum Receiver {
    RailgunAddress(RailgunAddress),
    EthAddress(Address),
}

fn get_transact_notes(
    spending_key: &[u8; 32],
    viewing_key: &[u8; 32],
    token: AssetId,
    value: u128,
    receiver: Receiver,
) {
    let unspent_notes = get_unspent_notes(token.clone());
    let is_unshield = match receiver {
        Receiver::RailgunAddress(_) => false,
        Receiver::EthAddress(_) => true,
    };

    let mut notes_in: BTreeMap<u32, Vec<Note>> = BTreeMap::new();
    let mut notes_out: BTreeMap<u32, Vec<Note>> = BTreeMap::new();
    let mut nullifiers: BTreeMap<u32, Vec<[u8; 32]>> = BTreeMap::new();
    let mut total_value: u128 = 0;
    let mut value_spent: u128 = 0;

    for (tree_number, notes) in unspent_notes.iter() {
        let mut tree_value: u128 = 0;
        let mut tree_notes_in: Vec<Note> = Vec::new();
        let mut tree_notes_out: Vec<Note> = Vec::new();
        let mut tree_nullifiers: Vec<[u8; 32]> = Vec::new();

        for note in notes {
            total_value += note.value;
            tree_value += note.value;
            tree_notes_in.push(note.clone());

            // TODO: Get note index
            let note_index = 0;
            let nullifier = note.nullifier(note_index);
            tree_nullifiers.push(nullifier);

            if total_value >= value {
                break;
            }
        }

        if tree_value == 0 {
            continue;
        }

        //? If a note's being partially spent, need to create a change note
        if total_value > value {
            let change_value = total_value - value;
            let change_note = Note::new(
                spending_key,
                viewing_key,
                &random(),
                change_value,
                token.clone(),
                "",
            );
            tree_notes_out.push(change_note);
        }

        // Spend
        let remaining_value = value - value_spent;
    }
}

fn get_unspent_notes(token: AssetId) -> BTreeMap<u32, Vec<Note>> {
    todo!()
}
