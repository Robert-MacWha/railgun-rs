use alloy::primitives::U256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::SigningKey;
use light_poseidon::PoseidonHasher;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use crate::crypto::aes::{
    AesError, Ciphertext, CiphertextCtr, decrypt_ctr, decrypt_gcm, encrypt_ctr, encrypt_gcm,
};

/// Private key for signing transactions (BabyJubJub curve).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct SpendingKey([u8; 32]);
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct SpendingPublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

pub struct SpendingSignature {
    pub r8_x: Fr,
    pub r8_y: Fr,
    pub s: Fr,
}

/// Private key for viewing transactions and ECDH.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ViewingKey([u8; 32]);
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ViewingPublicKey([u8; 32]);

/// Master public key (wallet identifier).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct MasterPublicKey([u8; 32]);

/// Symmetric key for AES encryption.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct SharedKey([u8; 32]);

/// Key for nullifier derivation.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct NullifyingKey([u8; 32]);

/// Blinded public key for stealth addresses.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct BlindedKey([u8; 32]);

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Failed to decompress public key")]
    DecompressionFailed,
}

pub trait ByteKey: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Self;
    fn as_bytes(&self) -> &[u8; 32];
}

pub trait FieldKey: ByteKey {
    fn from_fr(fr: &Fr) -> Self {
        Self::from_bytes(fr.into_bigint().to_bytes_be().try_into().unwrap())
    }

    fn to_fr(&self) -> Fr {
        Fr::from_be_bytes_mod_order(self.as_bytes())
    }
}

pub trait HexKey: ByteKey {
    fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self::from_bytes(arr))
    }
}

pub trait BigIntKey: ByteKey {
    /// Create from BigInt, converting to big-endian bytes and padding/truncating
    /// to 32 bytes
    fn from_bigint(bi: &BigInt) -> Self {
        let (_sign, bytes) = bi.to_bytes_be();

        //? Debug assert to avoid panics in prod
        debug_assert!(bytes.len() <= 32, "BigInt too large for 32-byte key");

        let mut arr = [0u8; 32];
        let src_start = bytes.len().saturating_sub(32);
        let dst_start = 32usize.saturating_sub(bytes.len());
        arr[dst_start..].copy_from_slice(&bytes[src_start..]);
        Self::from_bytes(arr)
    }

    fn to_bigint(&self) -> BigInt {
        BigInt::from_bytes_be(Sign::Plus, self.as_bytes())
    }
}

pub trait U256Key: ByteKey {
    fn from_u256(value: U256) -> Self {
        let bytes = value.to_be_bytes::<32>();
        Self::from_bytes(bytes)
    }

    fn to_u256(&self) -> U256 {
        U256::from_be_bytes::<32>(*self.as_bytes())
    }
}

macro_rules! impl_byte_key {
    ($name:ident) => {
        impl ByteKey for $name {
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl FieldKey for $name {}
        impl BigIntKey for $name {}
        impl HexKey for $name {}
        impl U256Key for $name {}
    };
}

impl_byte_key!(SpendingKey);
impl_byte_key!(ViewingKey);
impl_byte_key!(ViewingPublicKey);
impl_byte_key!(SharedKey);
impl_byte_key!(NullifyingKey);
impl_byte_key!(BlindedKey);
impl_byte_key!(MasterPublicKey);

impl SpendingKey {
    pub fn public_key(&self) -> SpendingPublicKey {
        let sk = babyjubjub_rs::PrivateKey::import(self.0.to_vec()).unwrap();
        let pk = sk.public();
        let (x, y) = (babyjubjub_to_ark(&pk.x), babyjubjub_to_ark(&pk.y));

        SpendingPublicKey {
            x: x.into_bigint().to_bytes_be().try_into().unwrap(),
            y: y.into_bigint().to_bytes_be().try_into().unwrap(),
        }
    }

    pub fn sign(&self, message: Fr) -> SpendingSignature {
        let sk = babyjubjub_rs::PrivateKey::import(self.0.to_vec()).unwrap();
        let mut msg_bytes = Vec::new();
        message
            .serialize_uncompressed(&mut msg_bytes)
            .map_err(|e: ark_serialize::SerializationError| e.to_string())
            .unwrap();
        let msg_bigint = BigInt::from_bytes_le(Sign::Plus, &msg_bytes);

        let signature = sk.sign(msg_bigint).unwrap();

        SpendingSignature {
            r8_x: babyjubjub_to_ark(&signature.r_b8.x),
            r8_y: babyjubjub_to_ark(&signature.r_b8.y),
            s: bigint_to_fr(&signature.s),
        }
    }
}

impl SpendingPublicKey {
    pub fn new(x: [u8; 32], y: [u8; 32]) -> Self {
        Self { x, y }
    }

    pub fn from_fr(x: Fr, y: Fr) -> Self {
        Self {
            x: fr_to_bytes(&x),
            y: fr_to_bytes(&y),
        }
    }

    pub fn x_bytes(&self) -> &[u8; 32] {
        &self.x
    }

    pub fn y_bytes(&self) -> &[u8; 32] {
        &self.y
    }

    pub fn x_fr(&self) -> Fr {
        bytes_to_fr(&self.x)
    }

    pub fn y_fr(&self) -> Fr {
        bytes_to_fr(&self.y)
    }

    pub fn x_hex(&self) -> String {
        hex::encode(&self.x)
    }

    pub fn y_hex(&self) -> String {
        hex::encode(&self.y)
    }
}

impl ViewingKey {
    pub fn public_key(&self) -> ViewingPublicKey {
        let signing_key = SigningKey::from_bytes(&self.0);
        ViewingPublicKey(signing_key.verifying_key().to_bytes())
    }

    pub fn nullifying_key(&self) -> NullifyingKey {
        NullifyingKey::new(*self)
    }

    pub fn derive_shared_key(&self, their_public: ViewingPublicKey) -> Result<SharedKey, KeyError> {
        let point = CompressedEdwardsY(their_public.0)
            .decompress()
            .ok_or(KeyError::DecompressionFailed)?;
        Ok(SharedKey::new(self, point))
    }

    pub fn derive_shared_key_blinded(&self, blinded: BlindedKey) -> Result<SharedKey, KeyError> {
        let point = CompressedEdwardsY(blinded.0)
            .decompress()
            .ok_or(KeyError::DecompressionFailed)?;
        Ok(SharedKey::new(self, point))
    }

    pub fn encrypt_gcm(&self, plaintext: &[&[u8]]) -> Result<Ciphertext, AesError> {
        encrypt_gcm(plaintext, &self.0)
    }

    pub fn decrypt_gcm(&self, ciphertext: &Ciphertext) -> Result<Vec<Vec<u8>>, AesError> {
        decrypt_gcm(ciphertext, &self.0)
    }

    pub fn encrypt_ctr(&self, plaintext: &[&[u8]]) -> CiphertextCtr {
        encrypt_ctr(plaintext, &self.0)
    }

    pub fn decrypt_ctr(&self, ciphertext: &CiphertextCtr) -> Vec<Vec<u8>> {
        decrypt_ctr(ciphertext, &self.0)
    }

    fn to_curve25519_scalar(&self) -> Scalar {
        let hash = Sha512::digest(&self.0);
        let mut head = [0u8; 32];
        head.copy_from_slice(&hash[..32]);

        // Clamp as per Ed25519
        head[0] &= 248;
        head[31] &= 63;
        head[31] |= 64;

        Scalar::from_bytes_mod_order(head)
    }
}

impl SharedKey {
    pub fn new(viewing_key: &ViewingKey, their_point: EdwardsPoint) -> Self {
        let scalar = viewing_key.to_curve25519_scalar();
        let shared = their_point * scalar;
        let digest = Sha256::digest(shared.compress().to_bytes());
        SharedKey(digest.into())
    }

    pub fn encrypt_gcm(&self, plaintext: &[&[u8]]) -> Result<Ciphertext, AesError> {
        encrypt_gcm(plaintext, &self.0)
    }

    pub fn decrypt_gcm(&self, ciphertext: &Ciphertext) -> Result<Vec<Vec<u8>>, AesError> {
        decrypt_gcm(ciphertext, &self.0)
    }

    pub fn encrypt_ctr(&self, plaintext: &[&[u8]]) -> CiphertextCtr {
        encrypt_ctr(plaintext, &self.0)
    }

    pub fn decrypt_ctr(&self, ciphertext: &CiphertextCtr) -> Vec<Vec<u8>> {
        decrypt_ctr(ciphertext, &self.0)
    }
}

impl MasterPublicKey {
    pub fn new(spending_pubkey: SpendingPublicKey, nullifying_key: NullifyingKey) -> Self {
        let mut poseidon = light_poseidon::Poseidon::<Fr>::new_circom(3).unwrap();
        let hash = poseidon
            .hash(&[
                spending_pubkey.x_fr(),
                spending_pubkey.y_fr(),
                nullifying_key.to_fr(),
            ])
            .unwrap();
        MasterPublicKey(fr_to_bytes(&hash))
    }
}

impl NullifyingKey {
    pub fn new(viewing_key: ViewingKey) -> Self {
        let mut poseidon = light_poseidon::Poseidon::<Fr>::new_circom(1).unwrap();
        let hash = poseidon.hash(&[viewing_key.to_fr()]).unwrap();
        NullifyingKey::from_fr(&hash)
    }
}

pub fn blind_viewing_keys(
    sender: ViewingPublicKey,
    receiver: ViewingPublicKey,
    shared_random: &[u8; 32],
    sender_random: &[u8; 32],
) -> Result<(BlindedKey, BlindedKey), KeyError> {
    let sender_point = CompressedEdwardsY(sender.0)
        .decompress()
        .ok_or(KeyError::DecompressionFailed)?;
    let receiver_point = CompressedEdwardsY(receiver.0)
        .decompress()
        .ok_or(KeyError::DecompressionFailed)?;

    let mut final_random = [0u8; 32];
    for i in 0..32 {
        final_random[i] = shared_random[i] ^ sender_random[i];
    }

    let hash = Sha512::digest(&final_random);
    let mut hash_bytes: [u8; 64] = hash.into();
    hash_bytes.reverse();
    let scalar = Scalar::from_bytes_mod_order_wide(&hash_bytes);

    Ok((
        BlindedKey((sender_point * scalar).compress().to_bytes()),
        BlindedKey((receiver_point * scalar).compress().to_bytes()),
    ))
}

pub fn fr_to_bytes(value: &Fr) -> [u8; 32] {
    value.into_bigint().to_bytes_be().try_into().unwrap()
}

pub fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

pub fn fr_to_bigint(fr: &Fr) -> BigInt {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &fr_to_bytes(&fr))
}

pub fn fr_to_u256(fr: &Fr) -> U256 {
    let bytes = fr_to_bytes(fr);
    U256::from_be_bytes::<32>(bytes)
}

pub fn bigint_to_fr(bi: &BigInt) -> Fr {
    let (_sign, bytes) = bi.to_bytes_be();
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Converts babyjubjub_rs::Fr to arkworks Fr
///
/// Babyjubjub uses an old version of arkworks, and I can't find a way to
/// directly convert between the two types. Ergo this hacky approach.
fn babyjubjub_to_ark(f: &babyjubjub_rs::Fr) -> Fr {
    let s = format!("{:?}", f);
    // Format is "Fr(0x...)"
    let hex = s.trim_start_matches("Fr(0x").trim_end_matches(")");
    let bytes = hex::decode(hex).unwrap();
    Fr::from_be_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    // Test key and key derivation correctness against known values. Known values
    // were generated using the Railgun JS SDK.
    #[test]
    #[traced_test]
    fn test_spending_key() {
        let spending_key = SpendingKey::from_bytes([1u8; 32]);
        assert_eq!(spending_key.as_bytes(), &[1u8; 32]);

        let spending_pubkey = spending_key.public_key();
        let expected_x = "234056d968baf183fe8d237d496d1c04188220cd33e8f8d14df9b84479736b20";
        let expected_y = "2624393fad9b71c04b3b14d8ac45202dbb4eaff4c2d1350c9453fc08d18651fe";

        assert_eq!(expected_x, spending_pubkey.x_hex());
        assert_eq!(expected_y, spending_pubkey.y_hex());
    }

    #[test]
    #[traced_test]
    fn test_viewing_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        assert_eq!(viewing_key.as_bytes(), &[2u8; 32]);

        let viewing_pubkey = viewing_key.public_key();
        let expected_pubkey = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";

        assert_eq!(expected_pubkey, viewing_pubkey.to_hex());
    }

    #[test]
    #[traced_test]
    fn test_master_public_key() {
        let spending_key = SpendingKey::from_bytes([1u8; 32]);
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);

        let master_key =
            MasterPublicKey::new(spending_key.public_key(), viewing_key.nullifying_key());
        let expected_master_key =
            "21532725e608f56b562244d61ef15288a3ab3f01b7790586f9ed0c2e7baa6b29";

        assert_eq!(expected_master_key, master_key.to_hex());
    }

    #[test]
    #[traced_test]
    fn test_shared_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);

        let shared_key_ab = viewing_key
            .derive_shared_key(their_viewing.public_key())
            .unwrap();
        let shared_key_ba = their_viewing
            .derive_shared_key(viewing_key.public_key())
            .unwrap();

        let expected_shared_key =
            "b8d9b27ccb6161ba969a646553ad1b7221b4113ac83bdd603985ce44923456f1";

        assert_eq!(expected_shared_key, shared_key_ab.to_hex());
        assert_eq!(shared_key_ab.to_hex(), shared_key_ba.to_hex());
    }

    #[test]
    #[traced_test]
    fn test_blinded_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);
        let shared_random = [4u8; 32];
        let sender_random = [5u8; 32];

        let (blinded, their_blinded) = blind_viewing_keys(
            viewing_key.public_key(),
            their_viewing.public_key(),
            &shared_random,
            &sender_random,
        )
        .unwrap();

        let expected_blinded = "2ed993356db2b8b5e573da394c2317942c9a1a72eb9a8dfd02705cc56cb1423b";
        let expected_their_blinded =
            "90878634485e306dc7f31840362fc43532313cea73c9006a19b0718e298ffcce";

        assert_eq!(expected_blinded, blinded.to_hex());
        assert_eq!(expected_their_blinded, their_blinded.to_hex());
    }

    #[test]
    #[traced_test]
    fn test_shared_blinded_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);
        let shared_random = [4u8; 32];
        let sender_random = [5u8; 32];

        let (blinded, their_blinded) = blind_viewing_keys(
            viewing_key.public_key(),
            their_viewing.public_key(),
            &shared_random,
            &sender_random,
        )
        .unwrap();

        let shared_key_ab = viewing_key
            .derive_shared_key_blinded(their_blinded)
            .unwrap();
        let shared_key_ba = their_viewing.derive_shared_key_blinded(blinded).unwrap();

        let expected_shared_key =
            "2d33b7ea38413dfd631149f00dd0745f06dc06cd8112a6a174c73fa97af8d5a0";

        assert_eq!(shared_key_ab.to_hex(), shared_key_ba.to_hex());
        assert_eq!(expected_shared_key, shared_key_ab.to_hex());
    }

    #[test]
    #[traced_test]
    fn test_nullifying_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let nullifying_key = viewing_key.nullifying_key();

        let expected = "186ab99ece60e112b37c660eaf7ca6dbcb04dc434e04aa5e106e94abc6c81936";
        assert_eq!(expected, nullifying_key.to_hex());
    }
}
