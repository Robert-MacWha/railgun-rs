use alloy::primitives::Address;
use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::{caip::AssetId, crypto::poseidon::poseidon_hash, note::tree_transaction::TransactNote};

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

impl TransactNote for UnshieldNote {
    fn hash(&self) -> Fr {
        poseidon_hash(&[
            self.note_public_key(),
            self.asset.hash(),
            Fr::from(self.value),
        ])
    }

    fn note_public_key(&self) -> Fr {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(self.receiver.as_slice());
        Fr::from_be_bytes_mod_order(&bytes)
    }

    fn value(&self) -> u128 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::hex_to_fr,
        note::{tree_transaction::TransactNote, unshield::UnshieldNote},
    };

    #[test]
    #[traced_test]
    fn test_unshield_note_hash() {
        let note = UnshieldNote::new(
            address!("0x1234567890123456789012345678901234567890"),
            AssetId::Erc20(address!("0x0987654321098765432109876543210987654321")),
            10,
        );
        let hash = note.hash();

        let expected =
            hex_to_fr("0x12f0c138dd2766eedd92365ec2e1824fc37515d35eea3d2cc8ff1e991007663c");
        assert_eq!(hash, expected);
    }
}
