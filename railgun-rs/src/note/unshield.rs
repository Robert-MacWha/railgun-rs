use alloy::primitives::Address;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use poseidon_rust::poseidon_hash;

use crate::{caip::AssetId, crypto::railgun_utxo::Utxo, note::Note};

/// Unshield notes represent value exiting the Railgun system to an external address.
#[derive(Debug, Clone)]
pub struct UnshieldNote {
    pub receiver: Address,
    pub asset: AssetId,
    pub value: u128,
}

impl UnshieldNote {
    pub fn new(receiver: Address, asset: AssetId, value: u128) -> Self {
        UnshieldNote {
            receiver,
            asset,
            value,
        }
    }
}

impl Note for UnshieldNote {
    fn asset(&self) -> AssetId {
        self.asset
    }

    fn value(&self) -> u128 {
        self.value
    }

    fn memo(&self) -> String {
        String::new()
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
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(self.receiver.as_slice());
        Fr::from_be_bytes_mod_order(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::{keys::hex_to_fr, railgun_utxo::Utxo},
        note::{Note, unshield::UnshieldNote},
    };

    #[test]
    #[traced_test]
    fn test_hash() {
        let note = UnshieldNote::new(
            address!("0x1234567890123456789012345678901234567890"),
            AssetId::Erc20(address!("0x0987654321098765432109876543210987654321")),
            10,
        );
        let hash: Utxo = note.hash();

        let expected: Utxo =
            hex_to_fr("0x12f0c138dd2766eedd92365ec2e1824fc37515d35eea3d2cc8ff1e991007663c").into();
        assert_eq!(hash, expected);
    }
}
