use ark_bn254::Fr;

use crate::{
    abis::railgun::CommitmentCiphertext,
    note::{
        note::{EncryptError, Note},
        transfer::TransferNote,
        unshield::UnshieldNote,
    },
};

#[derive(Default, Debug, Clone)]
pub struct Operation {
    pub tree_index: u32,
    pub in_notes: Vec<Note>,
    pub out_notes: Vec<TransferNote>,
    pub unshield_note: Option<UnshieldNote>,
}

pub trait TransactNote {
    fn hash(&self) -> Fr;
    fn note_public_key(&self) -> Fr;
    fn value(&self) -> u128;
}

pub trait EncryptableNote: TransactNote {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError>;
}

impl Operation {
    pub fn new(
        tree_index: u32,
        in_notes: Vec<Note>,
        out_notes: Vec<TransferNote>,
        unshield: Option<UnshieldNote>,
    ) -> Self {
        Operation {
            tree_index,
            in_notes,
            out_notes,
            unshield_note: unshield,
        }
    }

    pub fn in_notes(&self) -> Vec<Note> {
        self.in_notes.to_vec()
    }

    pub fn notes_out(&self) -> Vec<Box<dyn TransactNote>> {
        let mut notes: Vec<Box<dyn TransactNote>> = Vec::new();

        for transfer in &self.out_notes {
            notes.push(Box::new(transfer.clone()));
        }

        if let Some(unshield) = &self.unshield_note {
            notes.push(Box::new(unshield.clone()));
        }

        notes.into_iter().filter(|n| n.value() > 0).collect()
    }

    pub fn encryptable_notes_out(&self) -> Vec<Box<dyn EncryptableNote>> {
        let mut notes: Vec<Box<dyn EncryptableNote>> = Vec::new();

        for transfer in &self.out_notes {
            notes.push(Box::new(transfer.clone()));
        }

        notes.into_iter().filter(|n| n.value() > 0).collect()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::{ByteKey, SpendingKey, ViewingKey},
        note::{
            operation::{self, TransactNote},
            transfer::TransferNote,
            unshield::UnshieldNote,
        },
        railgun::address::RailgunAddress,
    };

    /// Railgun requires that, if a transaction includes an unshield operation,
    /// it must be the last commitment in the transaction.
    #[test]
    #[traced_test]
    fn test_last_commitment_is_unshield() {
        let unshield_note = UnshieldNote::new(
            address!("0x1234567890123456789012345678901234567890"),
            AssetId::Erc20(address!("0x0987654321098765432109876543210987654321")),
            10,
        );
        let transfer_note = TransferNote::new(
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

        let operation = operation::Operation::new(
            1,
            Default::default(),
            vec![transfer_note.clone()],
            Some(unshield_note.clone()),
        );

        let notes_out = operation.notes_out();
        assert_eq!(notes_out.last().unwrap().hash(), unshield_note.hash());
    }
}
