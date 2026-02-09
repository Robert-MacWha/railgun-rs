use ark_bn254::Fr;

use crate::{
    abis::railgun::CommitmentCiphertext,
    caip::AssetId,
    note::{
        note::{EncryptError, Note},
        transfer::TransferNote,
        unshield::UnshieldNote,
    },
};

/// An Operation represents a single "operation" within a railgun transaction.
/// Otherwise known as the `RailgunSmartWallet::Transaction` struct in solidity.
///
/// - An operation MUST only spend notes from a single tree.
/// - An operation MUST have fewer than to 12 out_notes (13 including unshield),
///   which can be to arbitrary addresses.
/// - An operation MUST only spend a single asset.
///   - The POI proof circuit inputs are designed around this assumption, since the token
///     of the spent notes is a private input.
/// - An operation MUST only spend notes from a single address.
///   - The POI proof circuit inputs are designed around this assumption, since the
///     spender's public and nullifying key are private inputs to the circuit.
/// - An operation MUST only have a single unshield note.
///   - The railgun smart contracts are designed around this assumption, since the
///     `RailgunSmartWallet::Transaction` struct only supports defining a single
///      token/value pair for unshielding.
#[derive(Debug, Clone)]
pub struct Operation<N> {
    /// The number of the tree this operation is spending notes from.
    tree_number: u32,

    /// The asset this operation is spending.
    asset: AssetId,

    in_notes: Vec<N>,
    out_notes: Vec<TransferNote>,
    unshield_note: Option<UnshieldNote>,
}

pub trait TransactNote {
    fn hash(&self) -> Fr;
    fn note_public_key(&self) -> Fr;
    fn value(&self) -> u128;
}

pub trait EncryptableNote: TransactNote {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError>;
}

impl Operation<Note> {
    /// TODO: Add error checking to ensure that the operation is valid.
    ///
    /// - Spending and viewing keys are the same for all notes in
    /// - Tree number is the same for all notes in
    /// - AssetID is the same for all notes
    /// - notes_in.value = notes_out.value + unshield_note.value
    /// - notes_in.len() <= 13
    /// - notes_out.len() + unshield_note.is_some() <= 13
    pub fn new(
        tree_number: u32,
        in_notes: Vec<Note>,
        out_notes: Vec<TransferNote>,
        unshield: Option<UnshieldNote>,
    ) -> Self {
        let asset = in_notes.first().unwrap().asset;

        Operation {
            tree_number,
            asset,
            in_notes,
            out_notes,
            unshield_note: unshield,
        }
    }
}

impl<N> Operation<N> {
    /// Tree number for the in_notes in this operation.
    pub fn tree_number(&self) -> u32 {
        self.tree_number
    }

    /// Asset ID for the notes in this operation.
    pub fn asset(&self) -> AssetId {
        self.asset
    }

    pub fn in_notes(&self) -> &[N] {
        &self.in_notes
    }

    // TODO: Convert me to return &[Box] if possible
    pub fn out_notes(&self) -> Vec<Box<dyn TransactNote>> {
        let mut notes: Vec<Box<dyn TransactNote>> = Vec::new();

        for transfer in &self.out_notes {
            notes.push(Box::new(transfer.clone()));
        }

        if let Some(unshield) = &self.unshield_note {
            notes.push(Box::new(unshield.clone()));
        }

        notes.into_iter().filter(|n| n.value() > 0).collect()
    }

    pub fn unshield_note(&self) -> Option<UnshieldNote> {
        self.unshield_note.clone()
    }

    pub fn out_encryptable_notes(&self) -> Vec<Box<dyn EncryptableNote>> {
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

        let notes_out = operation.out_notes();
        assert_eq!(notes_out.last().unwrap().hash(), unshield_note.hash());
    }
}
