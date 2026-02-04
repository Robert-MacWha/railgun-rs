use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedKeyError {
    #[error("Failed to derive shared symmetric key")]
    KeyDerivationFailed,
}

#[derive(Debug, Error)]
pub enum BlindKeyError {
    #[error("Failed to blind keys")]
    KeyBlindingFailed,
}

pub fn derive_shared_symmetric_key(
    private_key_a: &[u8; 32],
    blinded_public_key_b: &[u8; 32],
) -> Result<[u8; 32], SharedKeyError> {
    let scalar = private_scalar_from_private_key(private_key_a);

    let public_point = CompressedEdwardsY(*blinded_public_key_b)
        .decompress()
        .ok_or(SharedKeyError::KeyDerivationFailed)?;
    let shared_point = public_point * scalar;
    let digest = Sha256::digest(shared_point.compress().to_bytes());
    return Ok(digest.into());
}

pub fn blind_keys(
    sender_pub_key: &[u8; 32],
    receiver_pub_key: &[u8; 32],
    shared_random: &[u8; 32],
    sender_random: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), BlindKeyError> {
    let sender_pk = CompressedEdwardsY(*sender_pub_key)
        .decompress()
        .ok_or(BlindKeyError::KeyBlindingFailed)?;
    let receiver_pk = CompressedEdwardsY(*receiver_pub_key)
        .decompress()
        .ok_or(BlindKeyError::KeyBlindingFailed)?;

    let mut final_random = [0u8; 32];
    for i in 0..32 {
        final_random[i] = shared_random[i] ^ sender_random[i];
    }

    // Hash and convert to scalar
    let hash = Sha512::digest(&final_random);
    let mut hash_bytes: [u8; 64] = hash.into();
    hash_bytes.reverse(); // BE -> LE for dalek
    let scalar = Scalar::from_bytes_mod_order_wide(&hash_bytes);

    let blinded_sender = sender_pk * scalar;
    let blinded_receiver = receiver_pk * scalar;

    Ok((
        blinded_sender.compress().to_bytes(),
        blinded_receiver.compress().to_bytes(),
    ))
}

fn private_scalar_from_private_key(private_key: &[u8; 32]) -> Scalar {
    let hash = Sha512::digest(private_key);
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);

    // Clamp as per ED25519
    head[0] &= 248;
    head[31] &= 63;
    head[31] |= 64;

    Scalar::from_bytes_mod_order(head)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::crypto::keys::derive_viewing_public_key;

    use super::*;

    #[test]
    fn test_shared_key_expected() {
        let signing_key_a = SigningKey::from_bytes(&[1u8; 32]);
        let private_key_a = signing_key_a.to_bytes();

        let signing_key_b = SigningKey::from_bytes(&[2u8; 32]);
        let public_key_b = signing_key_b.verifying_key().to_bytes();

        // Expected shared key sourced from Railgun SDK to ensure consistency
        let expected_shared: [u8; 32] = [
            32, 193, 214, 200, 71, 221, 178, 159, 154, 85, 23, 145, 61, 240, 3, 55, 179, 227, 174,
            112, 189, 210, 50, 22, 107, 166, 173, 88, 53, 205, 154, 87,
        ];

        let shared_key =
            derive_shared_symmetric_key(&private_key_a, &public_key_b).expect("Failed A->B");
        assert_eq!(shared_key, expected_shared);
    }

    #[test]
    fn test_shared_key() {
        let signing_key_a = SigningKey::from_bytes(&[1u8; 32]);
        let private_key_a = signing_key_a.to_bytes();
        let public_key_a = signing_key_a.verifying_key().to_bytes();

        let signing_key_b = SigningKey::from_bytes(&[2u8; 32]);
        let private_key_b = signing_key_b.to_bytes();
        let public_key_b = signing_key_b.verifying_key().to_bytes();

        let shared_key_ab =
            derive_shared_symmetric_key(&private_key_a, &public_key_b).expect("Failed A->B");
        let shared_key_ba =
            derive_shared_symmetric_key(&private_key_b, &public_key_a).expect("Failed B->A");

        assert_eq!(shared_key_ab, shared_key_ba);
    }

    #[test]
    fn test_blind_keys_expected() {
        let viewing_private_key_a = [1u8; 32];
        let viewing_private_key_b = [2u8; 32];

        let public_key_a = derive_viewing_public_key(&viewing_private_key_a);
        let public_key_b = derive_viewing_public_key(&viewing_private_key_b);

        let shared_random = [3u8; 32];
        let sender_random = [4u8; 32];

        // Expected blinded keys sourced from Railgun SDK to ensure consistency
        let expected_blinded: [u8; 32] = [
            227, 127, 90, 92, 58, 205, 90, 47, 112, 201, 46, 27, 13, 116, 14, 37, 228, 182, 173,
            20, 202, 44, 206, 152, 219, 45, 170, 100, 65, 180, 123, 68,
        ];

        let expected_blinded_b: [u8; 32] = [
            143, 145, 86, 159, 36, 178, 246, 26, 122, 241, 11, 237, 195, 88, 115, 20, 129, 155, 74,
            17, 82, 21, 236, 134, 15, 13, 103, 42, 54, 123, 131, 163,
        ];

        let (blinded_a, blinded_b) =
            blind_keys(&public_key_a, &public_key_b, &shared_random, &sender_random)
                .expect("Failed to blind keys");

        assert_eq!(blinded_a, expected_blinded);
        assert_eq!(blinded_b, expected_blinded_b);
    }
}
