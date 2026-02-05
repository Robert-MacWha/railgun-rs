use ark_bn254::Fr;
use ark_ff::PrimeField;
use rand::random;
use thiserror::Error;

use crate::{
    abis::railgun::{CommitmentCiphertext, ShieldRequest, TokenData, TokenDataError},
    caip::AssetId,
    crypto::{
        aes::{AesError, Ciphertext, encrypt_ctr},
        concat_arrays, concat_arrays_3,
        keys::{
            BlindedKey, ByteKey, FieldKey, KeyError, MasterPublicKey, SpendingKey, U256Key,
            ViewingKey, ViewingPublicKey, blind_viewing_keys, fr_to_bytes,
        },
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
    pub spending_key: SpendingKey,
    pub viewing_key: ViewingKey,
    pub random_seed: [u8; 16],
    pub value: u128,
    pub token: AssetId,
    pub memo: String,
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

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Railgun base37 encoding error: {0}")]
    RailgunBase37(#[from] railgun_base_37::EncodingError),
    #[error("AES encryption error: {0}")]
    Aes(#[from] AesError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
}

impl Note {
    pub fn new(
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
        random_seed: &[u8; 16],
        value: u128,
        token: AssetId,
        memo: &str,
    ) -> Self {
        Note {
            spending_key,
            viewing_key,
            random_seed: *random_seed,
            value,
            token,
            memo: memo.to_string(),
        }
    }

    /// Decrypt a note
    pub fn decrypt(
        encrypted: &CommitmentCiphertext,
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
    ) -> Result<Note, NoteError> {
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

        Ok(Note::new(
            spending_key,
            viewing_key,
            &random,
            value,
            asset_id,
            memo,
        ))
    }

    /// Decrypts a shield note into a Note
    pub fn decrypt_shield_request(
        req: ShieldRequest,
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
    ) -> Result<Note, NoteError> {
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

        Ok(Note::new(
            spending_key,
            viewing_key,
            &random,
            req.preimage.value.saturating_to(),
            req.preimage.token.clone().into(),
            "",
        ))
    }

    /// Encrypts the note into a CommitmentCiphertext. Uses this note's spending
    /// and viewing keys as the receiver's information.
    ///
    ///  See `encrypt_note` for more details.
    pub fn encrypt(
        &self,
        sender_viewing_key: ViewingKey,
        blind: bool,
    ) -> Result<CommitmentCiphertext, EncryptError> {
        //? Encryption doesn't depend on the chain ID, so it can be arbitrary
        let receiver = RailgunAddress::from_private_keys(self.spending_key, self.viewing_key, 1);
        encrypt_note(
            &receiver,
            &self.random_seed,
            self.value,
            &self.token,
            &self.memo,
            sender_viewing_key,
            blind,
        )
    }

    /// Returns the note's hash
    ///
    /// Hash of (note_public_key, token_id, value)
    pub fn hash(&self) -> Fr {
        poseidon_hash(&[
            self.note_public_key(),
            self.token.hash(),
            Fr::from(self.value),
        ])
    }

    pub fn sign_circuit_inputs(
        &self,
        merkle_root: Fr,
        bound_params_hash: Fr,
        nullifiers: &Vec<Fr>,
        commitments_out: &Vec<Fr>,
    ) -> [Fr; 3] {
        let mut inputs = vec![merkle_root, bound_params_hash];
        inputs.extend_from_slice(&nullifiers);
        inputs.extend_from_slice(&commitments_out);

        self.sign(&inputs)
    }

    pub fn sign(&self, inputs: &[Fr]) -> [Fr; 3] {
        let sig_hash = poseidon_hash(&inputs);
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
        poseidon_hash(&[self.nullifying_key(), Fr::from(leaf_index)])
    }

    /// Returns the note's public key
    ///
    /// Hash of (master_public_key, random_seed)
    pub fn note_public_key(&self) -> Fr {
        let master_key = MasterPublicKey::new(
            self.spending_key.public_key(),
            self.viewing_key.nullifying_key(),
        );

        poseidon_hash(&[
            master_key.to_fr(),
            Fr::from_be_bytes_mod_order(&self.random_seed),
        ])
    }

    /// Returns the note's nullifying key
    ///
    /// Hash of (viewing_private_key)
    pub fn nullifying_key(&self) -> Fr {
        poseidon_hash(&[self.viewing_key.to_fr()])
    }
}

/// Encrypts a note into a CommitmentCiphertext
///
/// TODO: Add details on blind
pub fn encrypt_note(
    receiver: &RailgunAddress,
    shared_random: &[u8; 16],
    value: u128,
    asset: &AssetId,
    memo: &str,
    viewing_key: ViewingKey,
    blind: bool,
) -> Result<CommitmentCiphertext, EncryptError> {
    let output_type = 0;
    let application_identifier = railgun_base_37::encode("railgun rs")?;
    let sender_random: [u8; 15] = if blind { random() } else { [0u8; 15] };

    let (blinded_sender, blinded_receiver) = blind_viewing_keys(
        viewing_key.public_key(),
        receiver.viewing_pubkey(),
        &concat_arrays(&shared_random, &[0u8; 16]),
        &concat_arrays(&sender_random, &[0u8; 17]),
    )?;

    let shared_key = viewing_key.derive_shared_key_blinded(blinded_receiver)?;
    let gcm = shared_key.encrypt_gcm(&[
        receiver.master_key().as_bytes(),
        &concat_arrays::<16, 16, 32>(&shared_random, &value.to_be_bytes()),
        &fr_to_bytes(&asset.hash()),
        memo.as_bytes(),
    ])?;

    let ctr = encrypt_ctr(
        &[&concat_arrays_3::<1, 15, 16, 32>(
            &[output_type],
            &sender_random,
            &application_identifier,
        )],
        viewing_key.public_key().as_bytes(),
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
        blindedSenderViewingKey: blinded_sender.to_u256().into(),
        blindedReceiverViewingKey: blinded_receiver.to_u256().into(),
        // ctr_iv (16) | encrypted_sender_bundle (any)
        annotationData: [ctr.iv.as_slice(), &ctr.data[0]].concat().into(),
        memo: gcm.data[3].clone().into(),
    });
}

#[cfg(test)]
impl Note {
    /// Creates a test note with fixed parameters
    pub fn new_test_note(spending_key: SpendingKey, viewing_key: ViewingKey) -> Self {
        Note::new(
            spending_key,
            viewing_key,
            &[3u8; 16],
            100u128,
            AssetId::Erc20(alloy::primitives::address!(
                "0x1234567890123456789012345678901234567890"
            )),
            "test memo",
        )
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use tracing_test::traced_test;

    use crate::{crypto::keys::bytes_to_fr, hex_to_fr};

    use super::*;

    // Test note cryptographic functions against known values. Know values
    // were generated using the Railgun JS SDK.

    #[test]
    #[traced_test]
    fn test_note_hash() {
        let note = test_note();
        let hash = note.hash();

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

    #[test]
    #[traced_test]
    fn test_encrypt_decrypt_note() {
        let chain_id = 1;

        // Sender keys
        let sender_viewing_key = ViewingKey::from_bytes([2u8; 32]);

        // Receiver keys
        let receiver_spending_key = SpendingKey::from_bytes([3u8; 32]);
        let receiver_viewing_key = ViewingKey::from_bytes([4u8; 32]);
        let receiver = RailgunAddress::from_private_keys(
            receiver_spending_key,
            receiver_viewing_key,
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
            sender_viewing_key,
            false,
        )
        .unwrap();

        // Receiver decrypts with their own keys
        let decrypted =
            Note::decrypt(&encrypted, receiver_spending_key, receiver_viewing_key).unwrap();

        let expected = Note::new(
            receiver_spending_key,
            receiver_viewing_key,
            &shared_random,
            value,
            asset,
            memo,
        );

        assert_eq!(expected, decrypted);
    }

    fn test_note() -> Note {
        Note::new_test_note(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
        )
    }
}
