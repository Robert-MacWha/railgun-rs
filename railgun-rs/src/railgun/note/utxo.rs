use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    abis::railgun::{CommitmentCiphertext, ShieldRequest, TokenData, TokenDataError},
    caip::AssetId,
    crypto::{
        aes::{AesError, Ciphertext},
        keys::{
            BlindedKey, ByteKey, KeyError, MasterPublicKey, SpendingKey, U256Key, ViewingKey,
            ViewingPublicKey,
        },
        poseidon::poseidon_hash,
    },
    railgun::{
        merkle_tree::UtxoLeafHash,
        note::{IncludedNote, Note},
        poi::BlindedCommitmentType,
    },
};

/// Note represents a Railgun from the chain.
///
/// TODO: Pre-compute all the note's hashes at creation / decryption and
/// store as fields.  Saves compute and makes error handling easier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoNote {
    spending_key: SpendingKey,
    viewing_key: ViewingKey,
    tree_number: u32,
    leaf_index: u32,
    random: [u8; 16],
    value: u128,
    asset: AssetId,
    memo: String,
    type_: UtxoType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UtxoType {
    Shield,
    Transact,
}

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("AES error: {0}")]
    Aes(#[from] AesError),
    #[error("TokenData error: {0}")]
    TokenData(#[from] TokenDataError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
}

impl UtxoNote {
    pub fn new(
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
        tree_number: u32,
        leaf_index: u32,
        asset: AssetId,
        value: u128,
        random: &[u8; 16],
        memo: &str,
        type_: UtxoType,
    ) -> Self {
        UtxoNote {
            spending_key,
            viewing_key,
            tree_number,
            leaf_index,
            random: *random,
            value,
            asset,
            memo: memo.to_string(),
            type_,
        }
    }

    /// Decrypt a note
    pub fn decrypt(
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
        tree_number: u32,
        leaf_index: u32,
        encrypted: &CommitmentCiphertext,
    ) -> Result<UtxoNote, NoteError> {
        let blinded_sender = BlindedKey::from_bytes(encrypted.blindedSenderViewingKey.into());
        let shared_key = viewing_key.derive_shared_key_blinded(blinded_sender)?;

        let data: Vec<Vec<u8>> = vec![
            encrypted.ciphertext[1].to_vec(),
            encrypted.ciphertext[2].to_vec(),
            encrypted.ciphertext[3].to_vec(),
            encrypted.memo.to_vec(),
        ];

        let mut iv = [0u8; 16];
        let mut tag = [0u8; 16];

        iv.copy_from_slice(&encrypted.ciphertext[0][..16]);
        tag.copy_from_slice(&encrypted.ciphertext[0][16..]);

        let ciphertext = Ciphertext { iv, tag, data };

        // iv (16) | tag (16)
        // master_public_key (32)
        // token_hash (32)
        // random (16) | value (16)
        let bundle = shared_key.decrypt_gcm(&ciphertext)?;

        let token_data = TokenData::from_hash(&bundle[1])?;
        let asset_id = AssetId::from(token_data);

        let mut random = [0u8; 16];
        random.copy_from_slice(&bundle[2][..16]);

        let mut value_bytes = [0u8; 16];
        value_bytes.copy_from_slice(&bundle[2][16..]);
        let value = u128::from_be_bytes(value_bytes);

        let memo = if bundle.len() > 3 {
            std::str::from_utf8(&bundle[3]).unwrap_or("")
        } else {
            ""
        };

        Ok(UtxoNote::new(
            spending_key,
            viewing_key,
            tree_number,
            leaf_index,
            asset_id,
            value,
            &random,
            memo,
            UtxoType::Transact,
        ))
    }

    /// Decrypts a shield note into a Note
    pub fn decrypt_shield_request(
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
        tree_number: u32,
        leaf_index: u32,
        req: ShieldRequest,
    ) -> Result<UtxoNote, NoteError> {
        let encrypted_bundle: [[u8; 32]; 3] = [
            req.ciphertext.encryptedBundle[0].into(),
            req.ciphertext.encryptedBundle[1].into(),
            req.ciphertext.encryptedBundle[2].into(),
        ];

        let shield_key = ViewingPublicKey::from_bytes(req.ciphertext.shieldKey.into());
        let shared_key = viewing_key.derive_shared_key(shield_key)?;

        let mut iv = [0u8; 16];
        let mut tag = [0u8; 16];
        iv.copy_from_slice(&encrypted_bundle[0][..16]);
        tag.copy_from_slice(&encrypted_bundle[0][16..]);

        let ciphertext = Ciphertext {
            iv,
            tag,
            data: vec![encrypted_bundle[1][..16].to_vec()],
        };
        let decrypted = shared_key.decrypt_gcm(&ciphertext)?;

        let mut random = [0u8; 16];
        random.copy_from_slice(&decrypted[0][..16]);

        Ok(UtxoNote::new(
            spending_key,
            viewing_key,
            tree_number,
            leaf_index,
            req.preimage.token.clone().into(),
            req.preimage.value.saturating_to(),
            &random,
            "",
            UtxoType::Shield,
        ))
    }
}

impl Note for UtxoNote {
    fn asset(&self) -> AssetId {
        self.asset
    }

    fn value(&self) -> u128 {
        self.value
    }

    fn memo(&self) -> String {
        self.memo.clone()
    }

    fn hash(&self) -> UtxoLeafHash {
        poseidon_hash(&[
            self.note_public_key(),
            self.asset.hash(),
            U256::from(self.value),
        ])
        .unwrap()
        .into()
    }

    fn note_public_key(&self) -> U256 {
        let master_key = MasterPublicKey::new(
            self.spending_key.public_key(),
            self.viewing_key.nullifying_key(),
        );

        poseidon_hash(&[master_key.to_u256(), U256::from_be_slice(&self.random)]).unwrap()
    }
}

impl IncludedNote for UtxoNote {
    fn tree_number(&self) -> u32 {
        self.tree_number
    }

    fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    fn viewing_pubkey(&self) -> ViewingPublicKey {
        self.viewing_key.public_key()
    }

    /// Returns the note's nullifier for a given leaf index
    ///
    /// Hash of (nullifying_key, leaf_index)
    fn nullifier(&self, leaf_index: U256) -> U256 {
        poseidon_hash(&[self.nullifying_key(), leaf_index]).unwrap()
    }

    /// Returns the note's spending public key
    fn spending_pubkey(&self) -> [U256; 2] {
        let pubkey = self.spending_key.public_key();
        [pubkey.x_u256(), pubkey.y_u256()]
    }

    fn sign(&self, inputs: &[U256]) -> [U256; 3] {
        let sig_hash = poseidon_hash(inputs).unwrap();
        let signature = self.spending_key.sign(sig_hash);
        [signature.r8_x, signature.r8_y, signature.s]
    }

    /// Returns the note's nullifying key
    ///
    /// Hash of (viewing_private_key)
    fn nullifying_key(&self) -> U256 {
        poseidon_hash(&[self.viewing_key.to_u256()]).unwrap()
    }

    fn random(&self) -> [u8; 16] {
        self.random
    }
}

impl UtxoNote {
    pub fn utxo_type(&self) -> UtxoType {
        self.type_.clone()
    }

    pub fn blinded_commitment(&self) -> U256 {
        poseidon_hash(&[
            self.hash().into(),
            self.note_public_key(),
            U256::from((self.tree_number as u128) * 65536 + (self.leaf_index as u128)),
        ])
        .unwrap()
    }
}

#[cfg(test)]
impl UtxoNote {
    /// Creates a test note with fixed parameters
    pub fn new_test_note(spending_key: SpendingKey, viewing_key: ViewingKey) -> Self {
        UtxoNote::new(
            spending_key,
            viewing_key,
            1,
            0,
            AssetId::Erc20(alloy::primitives::address!(
                "0x1234567890123456789012345678901234567890"
            )),
            100u128,
            &[3u8; 16],
            "test memo",
            UtxoType::Transact,
        )
    }
}

impl From<UtxoType> for BlindedCommitmentType {
    fn from(utxo_type: UtxoType) -> Self {
        match utxo_type {
            UtxoType::Shield => BlindedCommitmentType::Shield,
            UtxoType::Transact => BlindedCommitmentType::Transact,
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn test_note_hash() {
        let note = test_note();
        let hash: U256 = note.hash().into();

        insta::assert_debug_snapshot!(hash);
    }

    #[test]
    #[traced_test]
    fn test_note_sign() {
        let note = test_note();
        let msg = U256::from_be_slice(&[4u8; 32]);
        let signature = note.sign(&[msg]);

        insta::assert_debug_snapshot!(signature);
    }

    #[test]
    #[traced_test]
    fn test_note_spending_pubkey() {
        let note = test_note();
        let pub_key = note.spending_pubkey();

        insta::assert_debug_snapshot!(pub_key);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifier() {
        let note = test_note();
        let leaf_index = U256::from(5u32);
        let nullifier = note.nullifier(leaf_index);

        insta::assert_debug_snapshot!(nullifier);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifying_key() {
        let note = test_note();
        let nullifying_key = note.nullifying_key();

        insta::assert_debug_snapshot!(nullifying_key);
    }

    #[test]
    #[traced_test]
    fn test_note_public_key() {
        let note = test_note();
        let pub_key = note.note_public_key();

        insta::assert_debug_snapshot!(pub_key);
    }

    fn test_note() -> UtxoNote {
        UtxoNote::new_test_note(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
        )
    }
}
