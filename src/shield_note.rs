use alloy::primitives::{Address, Uint};
use alloy_sol_types::SolCall;
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::rand;
use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};
use ed25519_dalek::SigningKey;
use light_poseidon::{Poseidon, PoseidonError, PoseidonHasher};
use sha2::{Digest, Sha256, Sha512};

use crate::{
    aes::{encrypt_ctr, encrypt_gcm},
    caip::{AssetId, ChainId},
    railgun::{CommitmentPreimage, RailgunSmartWallet, ShieldCiphertext, ShieldRequest},
    railgun_address::RailgunAddress,
    tx_data::TxData,
};

pub struct ShieldNote {
    master_public_key: [u8; 32],
    random_seed: [u8; 16],
    value: u128,
    token: AssetId,
    token_hash: Fr,
    note_public_key: Fr,
}

pub struct ShieldRecipient {
    asset: AssetId,
    recipient: RailgunAddress,
    amount: u128,
}

pub fn create_shield_transaction(
    shield_private_key: &[u8; 32],
    chain: ChainId,
    recipients: &[ShieldRecipient],
) -> Result<TxData, PoseidonError> {
    let random: [u8; 16] = rand::random();

    let mut shield_inputs = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let note = ShieldNote::new(
            &recipient.recipient.master_public_key,
            &random,
            recipient.amount,
            recipient.asset,
        );
        let serialized =
            note.serialize(shield_private_key, &recipient.recipient.viewing_public_key)?;
        shield_inputs.push(serialized);
    }

    let call = RailgunSmartWallet::shieldCall {
        _shieldRequests: shield_inputs,
    };
    let calldata = call.abi_encode();

    // TODO: Get address from chain config
    Ok(TxData {
        to: Address::ZERO,
        data: calldata,
        value: num_bigint::BigInt::ZERO,
    })
}

impl ShieldNote {
    pub fn new(
        master_public_key: &[u8; 32],
        random_seed: &[u8; 16],
        value: u128,
        token: AssetId,
    ) -> Self {
        let fr_master_public_key = Fr::from_be_bytes_mod_order(master_public_key);
        let fr_random_seed = Fr::from_be_bytes_mod_order(random_seed);

        let token_hash = token.hash();
        let note_public_key = poseidon(&[fr_master_public_key, fr_random_seed]).unwrap();
        ShieldNote {
            master_public_key: master_public_key.clone(),
            random_seed: random_seed.clone(),
            value,
            token,
            token_hash,
            note_public_key,
        }
    }

    pub fn serialize(
        &self,
        shield_private_key: &[u8; 32],
        receiver_viewing_key: &[u8; 32],
    ) -> Result<ShieldRequest, PoseidonError> {
        let shared_key = shared_symetric_key(shield_private_key, receiver_viewing_key)
            .expect("Failed to compute shared key");

        let encrypted_random = encrypt_gcm(&[self.random_seed.as_slice()], &shared_key).unwrap();
        let encrypted_receiver = encrypt_ctr(&[receiver_viewing_key], shield_private_key);

        let signing_key = SigningKey::from_bytes(shield_private_key);
        let shield_key = signing_key.verifying_key().to_bytes();

        let npk = ark_to_solidity_bytes(self.note_public_key);

        let mut bundle_0 = [0u8; 32];
        bundle_0[..16].copy_from_slice(&encrypted_random.iv);
        bundle_0[16..].copy_from_slice(&encrypted_random.tag);

        let mut bundle_1 = [0u8; 32];
        let gcm_flat: Vec<u8> = encrypted_random.data.into_iter().flatten().collect();
        bundle_1[..16].copy_from_slice(&gcm_flat[..16]);
        bundle_1[16..].copy_from_slice(&encrypted_receiver.iv);

        let mut bundle_2 = [0u8; 32];
        let ctr_flat: Vec<u8> = encrypted_receiver.data.into_iter().flatten().collect();
        bundle_2.copy_from_slice(&ctr_flat[..32]);

        return Ok(ShieldRequest {
            preimage: CommitmentPreimage {
                npk: npk.into(),
                token: self.token.into(),
                value: Uint::from(self.value),
            },
            ciphertext: ShieldCiphertext {
                encryptedBundle: [bundle_0.into(), bundle_1.into(), bundle_2.into()],
                shieldKey: shield_key.into(),
            },
        });
    }
}

fn poseidon(inputs: &[Fr]) -> Result<Fr, PoseidonError> {
    Poseidon::<Fr>::new_circom(inputs.len())?.hash(inputs)
}

fn shared_symetric_key(
    private_key_a: &[u8; 32],
    blinded_public_key_b: &[u8; 32],
) -> Option<[u8; 32]> {
    let scalar = private_scalar_from_private_key(private_key_a);

    let public_point = CompressedEdwardsY(*blinded_public_key_b).decompress()?;
    let shared_point = public_point * scalar;
    let digest = Sha256::digest(shared_point.compress().to_bytes());
    return Some(digest.into());
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

pub fn ark_to_solidity_bytes(fr: Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let mut bytes = [0u8; 32];
    bigint.serialize_compressed(&mut bytes[..]).unwrap();
    bytes.reverse();
    bytes
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_shared_key() {
        let signing_key_a = SigningKey::from_bytes(&[1u8; 32]);
        let private_key_a = signing_key_a.to_bytes();
        let public_key_a = signing_key_a.verifying_key().to_bytes();

        let signing_key_b = SigningKey::from_bytes(&[2u8; 32]);
        let private_key_b = signing_key_b.to_bytes();
        let public_key_b = signing_key_b.verifying_key().to_bytes();

        let shared_key_ab =
            super::shared_symetric_key(&private_key_a, &public_key_b).expect("Failed A->B");
        let shared_key_ba =
            super::shared_symetric_key(&private_key_b, &public_key_a).expect("Failed B->A");

        assert_eq!(shared_key_ab, shared_key_ba);
    }

    #[test]
    fn test_shared_key_railgun() {
        // Values taken from Railgun tests to ensure compatibility
        let private_key_a = "0303030303030303030303030303030303030303030303030303030303030303";
        let public_key_b = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";
        let expected_shared = "210753a79ae8f30d3221984eb26f1294708ad10ad7eebba64fea186fba052599";

        let private_key_a: [u8; 32] = hex::decode(private_key_a).unwrap().try_into().unwrap();
        let public_key_b: [u8; 32] = hex::decode(public_key_b).unwrap().try_into().unwrap();
        let expected_shared_key: [u8; 32] =
            hex::decode(expected_shared).unwrap().try_into().unwrap();

        let shared_key_ab =
            super::shared_symetric_key(&private_key_a, &public_key_b).expect("Failed A->B");

        assert_eq!(shared_key_ab, expected_shared_key);
    }

    #[test]
    fn test_shield() {
        let shield_signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let shield_priv = shield_signing_key.to_bytes();

        let receiver_signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let receiver_viewing = receiver_signing_key.verifying_key().to_bytes();

        let master_pub = [1u8; 32];
        let random_seed = [2u8; 16];

        let note = super::ShieldNote::new(
            &master_pub,
            &random_seed,
            1000,
            super::AssetId::Erc20([5u8; 20].into()),
        );

        let _request = note
            .serialize(&shield_priv, &receiver_viewing)
            .expect("Failed to serialize shield note");
    }
}
