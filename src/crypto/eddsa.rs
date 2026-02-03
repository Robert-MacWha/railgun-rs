use ark_bn254::Fr;
use ark_ff::PrimeField;
use babyjubjub_rs::PrivateKey;

// TODO: Refactor to remove babyjubjub_rs dependency. It's not audited
// or maintained. I just can't get ark to work with babyjubjub, nor access
// the private member of `babyjubjub_rs::Fr` for a conversion.
pub fn prv2pub(prv: &[u8; 32]) -> (Fr, Fr) {
    let sk = PrivateKey::import(prv.to_vec()).unwrap();
    let pk = sk.public();

    fn parse_fr(f: &babyjubjub_rs::Fr) -> Fr {
        let s = format!("{:?}", f);
        // Format is "Fr(0x...)"
        let hex = s.trim_start_matches("Fr(0x").trim_end_matches(")");
        let bytes = hex::decode(hex).unwrap();
        Fr::from_be_bytes_mod_order(&bytes)
    }

    (parse_fr(&pk.x), parse_fr(&pk.y))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_ff::BigInt;

    use super::*;

    #[test]
    fn test_prv2pub() {
        // Test vector from circomlibjs eddsa.prv2pub function, to ensure compatibility
        let prv: [u8; 32] = [1u8; 32];
        let expected_pub_x =
            "15944627324083773346390189001500210680939402028015651549526524193195473201952";
        let expected_pub_y =
            "17251889856797524237981285661279357764562574766148660962999867467495459148286";

        let expected_pub_x = Fr::from(BigInt::from_str(expected_pub_x).unwrap());
        let expected_pub_y = Fr::from(BigInt::from_str(expected_pub_y).unwrap());

        let (pub_x, pub_y) = prv2pub(&prv);
        assert_eq!(pub_x, expected_pub_x);
        assert_eq!(pub_y, expected_pub_y);
    }
}
