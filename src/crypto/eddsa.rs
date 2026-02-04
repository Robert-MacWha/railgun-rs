//! EdDSA-related functions. Replicates the circomlibjs eddsa.prv2pub function
//! for BabyJubJub curve.
//!
//! TODO: Refactor to remove babyjubjub_rs dependency. It's not audited
//! or maintained. I just can't get ark to work with babyjubjub, nor access
//! the private member of `babyjubjub_rs::Fr` for a conversion.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use babyjubjub_rs::PrivateKey;
use num_bigint::{BigInt, Sign};

use crate::crypto::keys::bigint_to_fr;

pub struct Signature {
    pub r8_x: Fr,
    pub r8_y: Fr,
    pub s: Fr,
}

pub fn prv2pub(prv: &[u8; 32]) -> (Fr, Fr) {
    let sk = PrivateKey::import(prv.to_vec()).unwrap();
    let pk = sk.public();

    (parse_fr(&pk.x), parse_fr(&pk.y))
}

/// Sign a message using EdDSA-Poseidon on BabyJubJub
pub fn sign_poseidon(private_key: &[u8; 32], message: Fr) -> Signature {
    // Safe since the key is 32 bytes
    let sk = PrivateKey::import(private_key.to_vec()).unwrap();

    // Convert arkworks Fr to BigInt
    let mut msg_bytes = Vec::new();
    message
        .serialize_uncompressed(&mut msg_bytes)
        .map_err(|e: ark_serialize::SerializationError| e.to_string())
        .unwrap();

    let msg_bigint = BigInt::from_bytes_le(Sign::Plus, &msg_bytes);

    // Sign using babyjubjub_rs
    let signature = sk.sign(msg_bigint).unwrap();

    Signature {
        r8_x: parse_fr(&signature.r_b8.x),
        r8_y: parse_fr(&signature.r_b8.y),
        s: bigint_to_fr(&signature.s),
    }
}

fn parse_fr(f: &babyjubjub_rs::Fr) -> Fr {
    let s = format!("{:?}", f);
    // Format is "Fr(0x...)"
    let hex = s.trim_start_matches("Fr(0x").trim_end_matches(")");
    let bytes = hex::decode(hex).unwrap();
    Fr::from_be_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::{BigInt, Sign};

    use crate::crypto::{
        eddsa::{prv2pub, sign_poseidon},
        keys::bigint_to_fr,
    };

    #[test]
    fn test_prv2pub() {
        // Test vector from circomlibjs eddsa.prv2pub function, to ensure compatibility
        let prv: [u8; 32] = [1u8; 32];
        let expected_pub_x =
            "15944627324083773346390189001500210680939402028015651549526524193195473201952";
        let expected_pub_y =
            "17251889856797524237981285661279357764562574766148660962999867467495459148286";

        let expected_pub_x = bigint_to_fr(&BigInt::from_str(expected_pub_x).unwrap());
        let expected_pub_y = bigint_to_fr(&BigInt::from_str(expected_pub_y).unwrap());

        let (pub_x, pub_y) = prv2pub(&prv);
        assert_eq!(pub_x, expected_pub_x);
        assert_eq!(pub_y, expected_pub_y);
    }

    #[test]
    fn test_sign_poseidon() {
        // Test vector from railgun's edBabyJubJub.signPoseidon function, to ensure compatibility
        let prv = [1u8; 32];
        let msg = [2u8; 32];

        let msg_fr = bigint_to_fr(&BigInt::from_bytes_le(Sign::Plus, &msg));
        let signed = sign_poseidon(&prv, msg_fr);

        let expected_r8_x: [u8; 32] = [
            25, 42, 98, 77, 152, 207, 73, 244, 123, 147, 180, 56, 47, 156, 62, 175, 199, 132, 56,
            1, 215, 119, 201, 122, 146, 141, 100, 39, 104, 242, 106, 217,
        ];
        let expected_r8_y: [u8; 32] = [
            9, 116, 192, 204, 13, 190, 172, 132, 52, 239, 233, 68, 148, 128, 172, 170, 167, 45,
            194, 217, 208, 252, 102, 20, 44, 42, 211, 242, 210, 73, 255, 12,
        ];
        let expected_s: [u8; 32] = [
            2, 224, 126, 168, 79, 116, 100, 54, 247, 114, 252, 158, 182, 146, 206, 135, 255, 203,
            171, 215, 208, 163, 131, 211, 168, 126, 213, 136, 160, 135, 48, 71,
        ];

        let expected_r8_x = bigint_to_fr(&BigInt::from_bytes_be(Sign::Plus, &expected_r8_x));
        let expected_r8_y = bigint_to_fr(&BigInt::from_bytes_be(Sign::Plus, &expected_r8_y));
        let expected_s = bigint_to_fr(&BigInt::from_bytes_be(Sign::Plus, &expected_s));

        assert_eq!(signed.r8_x, expected_r8_x);
        assert_eq!(signed.r8_y, expected_r8_y);
        assert_eq!(signed.s, expected_s);
    }
}
