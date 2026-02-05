//! AES encryption and decryption using GCM and CTR modes.

use aes::{
    Aes256,
    cipher::{KeyIvInit, StreamCipher},
};
use aes_gcm::{
    AesGcm, KeyInit, Nonce,
    aead::{Aead, Payload, consts::U16},
};
use ark_std::rand::thread_rng;
use num_bigint::RandBigInt;
use rand::random;

#[derive(Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub iv: [u8; 16],
    pub tag: [u8; 16],
    pub data: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CiphertextCtr {
    pub iv: [u8; 16],
    pub data: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AesError {
    #[error("encrypt error: {0}")]
    Gcm(aes_gcm::Error),
    #[error("decrypt error: {0}")]
    Decrypt(aes_gcm::Error),
    #[error("Encrypted data is too short")]
    DataTooShort,
}

type Aes256GcmU16 = AesGcm<Aes256, U16>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub fn encrypt_gcm(plaintext: &[&[u8]], key: &[u8; 32]) -> Result<Ciphertext, AesError> {
    let iv: [u8; 16] = random();
    encrypt_gcm_with_iv(plaintext, key, &iv)
}

fn encrypt_gcm_with_iv(
    plaintext: &[&[u8]],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Ciphertext, AesError> {
    //? Safe to unwrap as key length is fixed
    let cipher = Aes256GcmU16::new_from_slice(key).unwrap();
    let nonce = Nonce::<U16>::from_slice(iv);

    let mut combined = Vec::new();
    let mut block_lengths = Vec::with_capacity(plaintext.len());
    for block in plaintext {
        block_lengths.push(block.len() as u32);
        combined.extend_from_slice(block);
    }

    let mut encrypted_raw = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &[],
            },
        )
        .map_err(AesError::Gcm)?;

    if encrypted_raw.len() < 16 {
        return Err(AesError::DataTooShort);
    }
    let tag_bytes = encrypted_raw.split_off(encrypted_raw.len() - 16);
    let tag: [u8; 16] = tag_bytes.try_into().unwrap();

    // Split back into per-block hex strings.
    let mut data = Vec::with_capacity(block_lengths.len());
    let mut offset = 0;
    for len in block_lengths {
        data.push(encrypted_raw[offset..offset + len as usize].to_vec());
        offset += len as usize;
    }

    Ok(Ciphertext { iv: *iv, tag, data })
}

pub fn decrypt_gcm(ciphertext: &Ciphertext, key: &[u8; 32]) -> Result<Vec<Vec<u8>>, AesError> {
    //? Safe to unwrap as key length is fixed
    let cipher = Aes256GcmU16::new_from_slice(key).unwrap();
    let nonce = Nonce::<U16>::from_slice(&ciphertext.iv);

    let mut combined = Vec::new();
    for block in &ciphertext.data {
        combined.extend_from_slice(block);
    }
    combined.extend_from_slice(&ciphertext.tag);

    let decrypted = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &[],
            },
        )
        .map_err(AesError::Decrypt)?;

    // Split back into per-block hex strings.
    let mut data = Vec::with_capacity(ciphertext.data.len());
    let mut offset = 0;
    for block in &ciphertext.data {
        let len = block.len();
        data.push(decrypted[offset..offset + len].to_vec());
        offset += len;
    }

    Ok(data)
}

pub fn encrypt_ctr(plaintext: &[&[u8]], key: &[u8; 32]) -> CiphertextCtr {
    let iv: [u8; 16] = random();
    let mut cipher = Aes256Ctr::new(key.into(), &iv.into());
    let mut data = Vec::with_capacity(plaintext.len());

    for block in plaintext {
        let mut buffer = block.to_vec();
        cipher.apply_keystream(&mut buffer);
        data.push(buffer);
    }

    CiphertextCtr { iv, data }
}

pub fn decrypt_ctr(ciphertext: &CiphertextCtr, key: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut cipher = Aes256Ctr::new(key.into(), &ciphertext.iv.into());
    let mut data = Vec::with_capacity(ciphertext.data.len());

    for block in &ciphertext.data {
        let mut buffer = block.to_vec();
        cipher.apply_keystream(&mut buffer);
        data.push(buffer);
    }

    data
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn gcm() {
        let key = [1u8; 32];

        let plaintext: &[&[u8]] = &[b"Hello, world! 1"];

        let ciphertext = super::encrypt_gcm(plaintext, &key).unwrap();
        let decrypted = super::decrypt_gcm(&ciphertext, &key).unwrap();

        for i in 0..plaintext.len() {
            assert_eq!(plaintext[i], &decrypted[i][..]);
        }
    }

    #[test]
    #[traced_test]
    fn railgun_sdk() {
        // Test vectors from Railgun SDK AES-GCM implementation to verify compatibility
        let key = "248e995ff2d51fd056b35c5e1132600c78a7b3b56b56a417ca94e228fb4547d7";
        let plaintext = [
            "554ba3927df1db8b86759f411b4461360a68604ea9197b142f640fe5ea23ece2",
            "55846f6fab65e22b7ae046e76038f030baa735778ef2a9408c7b0a729c1191e5",
            "54ad8402e454e481d0bc3942751ebdfb62f7c6852e52cf6cf877c00bb34affc7",
            "1aceb182eea6c17b3c0a5f41dd5d1a290729895349d6eeb67ad763a13b4d4dc9",
            "026e9e8ab458b9bab5ecbdc3843f122772057bc78214fa307117377523aee761",
            "dd89b83d20a69a8581f8fdf78cf2766e2d30957ac83284f68ee5395c6086d967",
            "0e14c6b4409ed305b646ff7a1c04868e73868bc2f97e6a11c58986bbfc7a676c",
            "dc2a25c9fe3df202b0124249864f6697e0a45cd37906738858097d8c44e68821",
        ];
        //? IV is randomly generated in normal use, but fixed here for test vector
        let iv = "2dd65a0ed18aa4dcbcb9d2655a424f0e";
        let expected_tag = "23a259788bc6e3b4c3c4e07711a7dc47";
        let expected_data = [
            "da377c6a8a976a5f887f3c8c5d54d576c24efcce4486d12fb06fc407fadf83e1",
            "e2864adfdedb42bd7b8ee7b1eee2d999d90563c86d6b80764bc6dc2b5fe2f1f9",
            "ee6c89ffd97df19c8a6984ec3922f3910d28e0533cb6ceb759cfe4d59bf03a60",
            "7360443c0110f34cb97bd213f9d07cf05c4be3da65e3eb870477da9f615e28d6",
            "276eee06999daa62d819340ed651cba314fa8a6901e8f0e994d4331fd40a32b3",
            "0ca415eb0e8b598c466b1b8240476c7815304ef6c6f546c9916432029d8922a4",
            "464d21f0403f639c59c6d5b228b7b4e78d7cbb0bb359ad6f5bf264fd3e68ce92",
            "d694b739e1d7f0f3cdfcca93a25184d46eda50efb7f7154e4d889aef3d91e23f",
        ];

        let key: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
        let plaintext: Vec<Vec<u8>> = plaintext.iter().map(|s| hex::decode(s).unwrap()).collect();
        let plaintext: Vec<&[u8]> = plaintext.iter().map(|v| &v[..]).collect();
        let iv: [u8; 16] = hex::decode(iv).unwrap().try_into().unwrap();

        let ciphertext = super::encrypt_gcm_with_iv(&plaintext, &key, &iv).unwrap();

        let expected_data: Vec<Vec<u8>> = expected_data
            .iter()
            .map(|s| hex::decode(s).unwrap())
            .collect();

        let expected = Ciphertext {
            iv,
            tag: hex::decode(expected_tag).unwrap().try_into().unwrap(),
            data: expected_data,
        };

        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[traced_test]
    fn ctr() {
        let mut key: [u8; 32] = [0u8; 32];
        key[0] = 1;

        let plaintext: [&[u8]; 3] = [b"Hello, world! 1", b"Hello, world! 2", b"Hello, world! 3"];

        let ciphertext = super::encrypt_ctr(&plaintext, &key);
        let decrypted = super::decrypt_ctr(&ciphertext, &key);
        for i in 0..plaintext.len() {
            assert_eq!(plaintext[i], &decrypted[i][..]);
        }
    }
}
