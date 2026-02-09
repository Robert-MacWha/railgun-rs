use ark_bn254::Fr;
use ark_ff::PrimeField;
use poseidon_rust::poseidon_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    abis::railgun::{CommitmentCiphertext, ShieldRequest, TokenData, TokenDataError},
    caip::AssetId,
    crypto::{
        aes::{AesError, Ciphertext},
        keys::{
            BlindedKey, ByteKey, FieldKey, KeyError, MasterPublicKey, SpendingKey, ViewingKey,
            ViewingPublicKey,
        },
        railgun_utxo::Utxo,
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

// impl EncryptableNote for UtxoNote {
//     /// Encrypts the note into a CommitmentCiphertext. Uses this note's spending
//     /// and viewing keys as the receiver's information.
//     ///
//     ///  See `encrypt_note` for more details.
//     fn encrypt(
//         &self,
//         sender_viewing_key: ViewingKey,
//         blind: bool,
//     ) -> Result<CommitmentCiphertext, EncryptError> {
//         //? Encryption doesn't depend on the chain ID, so it can be arbitrary
//         let receiver = RailgunAddress::from_private_keys(self.spending_key, self.viewing_key, 1);
//         encrypt_note(
//             &receiver,
//             &self.random,
//             self.value,
//             &self.asset,
//             &self.memo,
//             sender_viewing_key,
//             blind,
//         )
//     }
// }

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

    fn hash(&self) -> Utxo {
        poseidon_hash(&[
            self.note_public_key(),
            self.asset.hash(),
            Fr::from(self.value),
        ])
        .unwrap()
        .into()
    }

    fn note_public_key(&self) -> Fr {
        let master_key = MasterPublicKey::new(
            self.spending_key.public_key(),
            self.viewing_key.nullifying_key(),
        );

        poseidon_hash(&[
            master_key.to_fr(),
            Fr::from_be_bytes_mod_order(&self.random),
        ])
        .unwrap()
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
        merkle_root: Fr,
        bound_params_hash: Fr,
        nullifiers: &Vec<Fr>,
        commitments: &Vec<Fr>,
    ) -> [Fr; 3] {
        let mut inputs = vec![merkle_root, bound_params_hash];
        inputs.extend_from_slice(nullifiers);
        inputs.extend_from_slice(commitments);

        self.sign(&inputs)
    }

    pub fn sign(&self, inputs: &[Fr]) -> [Fr; 3] {
        let sig_hash = poseidon_hash(inputs).unwrap();
        let signature = self.spending_key.sign(sig_hash);
        [signature.r8_x, signature.r8_y, signature.s]
    }

    /// Returns the note's spending public key
    pub fn spending_public_key(&self) -> (Fr, Fr) {
        let pubkey = self.spending_key.public_key();
        (pubkey.x_fr(), pubkey.y_fr())
    }

    /// Returns the note's nullifier for a given leaf index
    ///
    /// Hash of (nullifying_key, leaf_index)
    pub fn nullifier(&self, leaf_index: u32) -> Fr {
        poseidon_hash(&[self.nullifying_key(), Fr::from(leaf_index)]).unwrap()
    }

    /// Returns the note's nullifying key
    ///
    /// Hash of (viewing_private_key)
    pub fn nullifying_key(&self) -> Fr {
        poseidon_hash(&[self.viewing_key.to_fr()]).unwrap()
    }

    pub fn blinded_commitment(&self) -> Fr {
        poseidon_hash(&[
            self.hash().into(),
            self.note_public_key(),
            Fr::from((self.tree_number as u64) * 65536 + (self.leaf_index as u64)),
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

    use crate::crypto::keys::{bytes_to_fr, hex_to_fr};

    use super::*;

    // Test note cryptographic functions against known values. Know values
    // were generated using the Railgun JS SDK.

    #[test]
    #[traced_test]
    fn test_note_hash() {
        let note = test_note();
        let hash: Fr = note.hash().into();

        let expected =
            hex_to_fr("0x229b1db0c6706d18ff9ce36673185530465d4575d2572b2cfc277262289b18b9");
        assert_eq!(hash, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_sign() {
        let note = test_note();
        // let msg = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)];
        let msg = bytes_to_fr(&[4u8; 32]);
        let signature = note.sign(&[msg]);

        let expected = [
            hex_to_fr("0x0420e857bd171b340ce13449638af4b74945e568ef22186bf923a46753f572e4"),
            hex_to_fr("0x0abfa9e53db7b1525b0b97094631a0ec110c92a1bd81c74d60e00fc6acb528ba"),
            hex_to_fr("0x031341ceba9e1c9a76cabe5b4f9031915b9a8c61cdeb7e0a9ad1804a649a0fbe"),
        ];

        assert_eq!(signature, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_spending_public_key() {
        let note = test_note();
        let pub_key = note.spending_public_key();

        let expected = (
            hex_to_fr("0x234056d968baf183fe8d237d496d1c04188220cd33e8f8d14df9b84479736b20"),
            hex_to_fr("0x2624393fad9b71c04b3b14d8ac45202dbb4eaff4c2d1350c9453fc08d18651fe"),
        );
        assert_eq!(pub_key, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifier() {
        let note = test_note();
        let leaf_index = 5u32;
        let nullifier = note.nullifier(leaf_index);

        let expected =
            hex_to_fr("0x103cba8722ef9b21b85abe6286ec80771c918ff3400ee9d9b0673b98d3193e26");
        assert_eq!(nullifier, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifying_key() {
        let note = test_note();
        let nullifying_key = note.nullifying_key();

        let expected =
            hex_to_fr("0x186ab99ece60e112b37c660eaf7ca6dbcb04dc434e04aa5e106e94abc6c81936");
        assert_eq!(nullifying_key, expected);
    }

    #[test]
    #[traced_test]
    fn test_note_public_key() {
        let note = test_note();
        let pub_key = note.note_public_key();

        let expected =
            hex_to_fr("0x0d8534b283818d7e3c855e07d28d3d6a04c0a88b488516f45c04d71c8833177e");
        assert_eq!(pub_key, expected);
    }

    fn test_note() -> UtxoNote {
        UtxoNote::new_test_note(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
        )
    }
}
