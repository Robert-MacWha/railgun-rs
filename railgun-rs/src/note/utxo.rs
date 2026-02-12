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
        railgun_utxo::UtxoLeaf,
    },
    note::{IncludedNote, Note},
    poi::client::BlindedCommitmentType,
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

        let ciphertext = Ciphertext {
            iv: encrypted.ciphertext[0][..16].try_into().unwrap(),
            tag: encrypted.ciphertext[0][16..].try_into().unwrap(),
            data,
        };
        let bundle = shared_key.decrypt_gcm(&ciphertext)?;

        let random: [u8; 16] = bundle[1][0..16].try_into().unwrap();
        let value: u128 = u128::from_be_bytes(bundle[1][16..32].try_into().unwrap());
        let token_data = TokenData::from_hash(&bundle[2])?;
        let asset_id = AssetId::from(token_data);
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
        let shared_key = viewing_key.derive_shared_key(shield_key).unwrap();

        let ciphertext = Ciphertext {
            iv: encrypted_bundle[0][..16].try_into().unwrap(),
            tag: encrypted_bundle[0][16..].try_into().unwrap(),
            data: vec![encrypted_bundle[1][..16].to_vec()],
        };
        let decrypted = shared_key.decrypt_gcm(&ciphertext)?;
        let random: [u8; 16] = decrypted[0][0..16].try_into().unwrap();

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

    fn hash(&self) -> UtxoLeaf {
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
}

impl UtxoNote {
    pub fn random(&self) -> [u8; 16] {
        self.random
    }

    pub fn utxo_type(&self) -> UtxoType {
        self.type_.clone()
    }

    pub fn sign_circuit_inputs(
        &self,
        merkle_root: U256,
        bound_params_hash: U256,
        nullifiers: &Vec<U256>,
        commitments: &Vec<U256>,
    ) -> [U256; 3] {
        let mut inputs = vec![merkle_root, bound_params_hash];
        inputs.extend_from_slice(nullifiers);
        inputs.extend_from_slice(commitments);

        self.sign(&inputs)
    }

    pub fn sign(&self, inputs: &[U256]) -> [U256; 3] {
        let sig_hash = poseidon_hash(inputs).unwrap();
        let signature = self.spending_key.sign(sig_hash);
        [signature.r8_x, signature.r8_y, signature.s]
    }

    /// Returns the note's spending public key
    pub fn spending_public_key(&self) -> (U256, U256) {
        let pubkey = self.spending_key.public_key();
        (pubkey.x_u256(), pubkey.y_u256())
    }

    /// Returns the note's nullifier for a given leaf index
    ///
    /// Hash of (nullifying_key, leaf_index)
    pub fn nullifier(&self, leaf_index: u32) -> U256 {
        poseidon_hash(&[self.nullifying_key(), U256::from(leaf_index)]).unwrap()
    }

    /// Returns the note's nullifying key
    ///
    /// Hash of (viewing_private_key)
    pub fn nullifying_key(&self) -> U256 {
        poseidon_hash(&[self.viewing_key.to_u256()]).unwrap()
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
    use ruint::uint;
    use tracing_test::traced_test;

    use super::*;

    // Test note cryptographic functions against known values. Know values
    // were generated using the Railgun JS SDK.

    #[test]
    #[traced_test]
    fn test_note_hash() {
        let note = test_note();
        let hash: U256 = note.hash().into();

        let expected = uint!(
            15652703063364460311785063361754318622468586649506025149049958389572383217849_U256
        );
        assert_eq!(hash, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_sign() {
        let note = test_note();
        let msg = U256::from_be_slice(&[4u8; 32]);
        let signature = note.sign(&[msg]);

        let expected = [
            uint!(
                1867394070987317795558509038826002254704441391366761701569904580090171585252_U256
            ),
            uint!(
                4861768850665346243728274192565754656957922526826151834514482394918148188346_U256
            ),
            uint!(
                1390962826895272931277537517624004721994258503767807739809164177785130454974_U256
            ),
        ];

        assert_eq!(signature, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_spending_public_key() {
        let note = test_note();
        let pub_key = note.spending_public_key();

        let expected = (
            uint!(
                15944627324083773346390189001500210680939402028015651549526524193195473201952_U256
            ),
            uint!(
                17251889856797524237981285661279357764562574766148660962999867467495459148286_U256
            ),
        );
        assert_eq!(pub_key, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifier() {
        let note = test_note();
        let leaf_index = 5u32;
        let nullifier = note.nullifier(leaf_index);

        let expected = uint!(
            7344303769311454485041481768889762774214369760214733867852841155011901210150_U256
        );
        assert_eq!(nullifier, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifying_key() {
        let note = test_note();
        let nullifying_key = note.nullifying_key();

        let expected = uint!(
            11044075259344817595544633535096475825354771420816801683721629142825992460598_U256
        );
        assert_eq!(nullifying_key, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_public_key() {
        let note = test_note();
        let pub_key = note.note_public_key();

        let expected = uint!(
            6115421394727733128036252006164802934954447834850133641440670552529040512894_U256
        );
        assert_eq!(pub_key, expected);
    }

    fn test_note() -> UtxoNote {
        UtxoNote::new_test_note(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
        )
    }
}
