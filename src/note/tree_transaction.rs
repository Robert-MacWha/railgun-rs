use ark_bn254::Fr;

use crate::{
    abis::railgun::CommitmentCiphertext,
    note::{
        change::ChangeNote,
        note::{EncryptError, Note},
        transfer::TransferNote,
        unshield::UnshieldNote,
    },
};

/// TreeTransactions represent a single railgun transaction's worth of notes.
/// They include in_notes (those consumed), transfer_notes (those sent to other accounts),
/// a optional change note (for value returned to the sender), and an optional
/// unshield note (for value exiting the system).
///
/// A completely filled-out TreeTransaction should always satisfy the equation:
/// sum(in_notes.value) = sum(transfer_notes.value) + change_note.value + unshield_note.value.
///
/// DEV: TreeTransactions can only unshield a single note, a limitation of railgun's
/// smart contracts.
///
/// TODO: Make TreeTransaction generic over the note asset.
#[derive(Default, Debug, Clone)]
pub struct TreeTransaction {
    pub notes_in: Vec<Note>,
    pub transfers_out: Vec<TransferNote>,
    pub change: Option<ChangeNote>,
    pub unshield: Option<UnshieldNote>,
}

pub trait TransactNote {
    fn hash(&self) -> Fr;
    fn note_public_key(&self) -> Fr;
    fn value(&self) -> u128;
}

pub trait EncryptableNote: TransactNote {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError>;
}

impl TreeTransaction {
    pub fn new(
        notes_in: Vec<Note>,
        transfers_out: Vec<TransferNote>,
        change: Option<ChangeNote>,
        unshield: Option<UnshieldNote>,
    ) -> Self {
        TreeTransaction {
            notes_in,
            transfers_out,
            change,
            unshield,
        }
    }

    pub fn notes_in(&self) -> Vec<Note> {
        self.notes_in.to_vec()
    }

    pub fn notes_out(&self) -> Vec<Box<dyn TransactNote>> {
        let mut notes: Vec<Box<dyn TransactNote>> = Vec::new();

        if let Some(change) = &self.change {
            notes.push(Box::new(change.clone()));
        }

        for transfer in &self.transfers_out {
            notes.push(Box::new(transfer.clone()));
        }

        if let Some(unshield) = &self.unshield {
            notes.push(Box::new(unshield.clone()));
        }

        notes.into_iter().filter(|n| n.value() > 0).collect()
    }

    pub fn encryptable_notes_out(&self) -> Vec<Box<dyn EncryptableNote>> {
        let mut notes: Vec<Box<dyn EncryptableNote>> = Vec::new();

        if let Some(change) = &self.change {
            notes.push(Box::new(change.clone()));
        }

        for transfer in &self.transfers_out {
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
        note::{transfer::TransferNote, tree_transaction::TransactNote, unshield::UnshieldNote},
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

        let tree_tx = super::TreeTransaction::new(
            Default::default(),
            vec![transfer_note.clone()],
            Default::default(),
            Some(unshield_note.clone()),
        );

        let notes_out = tree_tx.notes_out();
        assert_eq!(notes_out.last().unwrap().hash(), unshield_note.hash());
    }
}
