use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::{
    abis::railgun::CommitmentCiphertext,
    caip::AssetId,
    crypto::{
        keys::{FieldKey, ViewingKey},
        poseidon::poseidon_hash,
    },
    note::{
        note::{EncryptError, encrypt_note},
        tree_transaction::{EncryptableNote, TransactNote},
    },
    railgun::address::RailgunAddress,
};

#[derive(Debug, Clone)]
pub struct TransferNote {
    pub from_key: ViewingKey,
    pub to: RailgunAddress,
    pub asset: AssetId,
    pub value: u128,
    pub random: [u8; 16],
    pub memo: String,
}

impl TransferNote {
    pub fn new(
        from_key: ViewingKey,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        random: [u8; 16],
        memo: &str,
    ) -> Self {
        TransferNote {
            from_key,
            to,
            asset,
            value,
            random,
            memo: memo.to_string(),
        }
    }
}

impl EncryptableNote for TransferNote {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError> {
        encrypt_note(
            &self.to,
            &self.random,
            self.value,
            &self.asset,
            &self.memo,
            self.from_key,
            false,
        )
    }
}

impl TransactNote for TransferNote {
    fn hash(&self) -> Fr {
        poseidon_hash(&[
            self.note_public_key(),
            self.asset.hash(),
            Fr::from(self.value),
        ])
    }

    fn note_public_key(&self) -> Fr {
        poseidon_hash(&[
            self.to.master_key().to_fr(),
            Fr::from_be_bytes_mod_order(&self.random),
        ])
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
        crypto::keys::{ByteKey, SpendingKey, ViewingKey, hex_to_fr},
        note::{transfer::TransferNote, tree_transaction::TransactNote},
        railgun::address::RailgunAddress,
    };

    #[test]
    #[traced_test]
    fn test_transfer_note_hash() {
        let note = TransferNote::new(
            ViewingKey::from_bytes([3u8; 32]),
            RailgunAddress::from_private_keys(
                SpendingKey::from_bytes([1u8; 32]),
                ViewingKey::from_bytes([2u8; 32]),
                1,
            ),
            AssetId::Erc20(address!("0x1234567890123456789012345678901234567890")),
            90,
            [2u8; 16],
            "memo",
        );
        let hash = note.hash();

        let expected =
            hex_to_fr("0x0238d33eb654c483bb7beb8dc44f2d364ee415414af794adf3cc40018d1412c1");
        assert_eq!(hash, expected);
    }
}
