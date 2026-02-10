use std::path::Display;

use crate::{
    caip::AssetId,
    note::{EncryptableNote, Note, transfer::TransferNote, unshield::UnshieldNote, utxo::UtxoNote},
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
    /// The UTXO tree number that the in_notes being spent are from
    utxo_tree_number: u32,

    /// The asset this operation is spending.
    asset: AssetId,

    in_notes: Vec<N>,
    out_notes: Vec<TransferNote>,
    unshield_note: Option<UnshieldNote>,
}

impl<N: Note> Operation<N> {
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
        in_notes: Vec<N>,
        out_notes: Vec<TransferNote>,
        unshield: Option<UnshieldNote>,
    ) -> Self {
        let asset = in_notes.first().unwrap().asset();

        Operation {
            utxo_tree_number: tree_number,
            asset,
            in_notes,
            out_notes,
            unshield_note: unshield,
        }
    }
}

impl<N> Operation<N> {
    /// UTXO tree number for these in_notes
    pub fn utxo_tree_number(&self) -> u32 {
        self.utxo_tree_number
    }

    /// Asset ID for these notes
    pub fn asset(&self) -> AssetId {
        self.asset
    }

    pub fn in_notes(&self) -> &[N] {
        &self.in_notes
    }

    // TODO: Convert me to return &[Box] if possible
    pub fn out_notes(&self) -> Vec<Box<dyn Note>> {
        let mut notes: Vec<Box<dyn Note>> = Vec::new();

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
    use rand::random;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::{ByteKey, SpendingKey, ViewingKey},
        note::{
            Note,
            operation::{self},
            transfer::TransferNote,
            unshield::UnshieldNote,
            utxo::{UtxoNote, UtxoType},
        },
        railgun::address::RailgunAddress,
    };

    /// Railgun requires that, if a transaction includes an unshield operation,
    /// it must be the last commitment in the transaction.
    #[test]
    #[traced_test]
    fn test_last_commitment_is_unshield() {
        let in_note = UtxoNote::new(
            random(),
            random(),
            0,
            0,
            AssetId::Erc20(address!("0x1234567890123456789012345678901234567890")),
            10,
            &random(),
            "",
            UtxoType::Transact,
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
        let unshield_note = UnshieldNote::new(
            address!("0x1234567890123456789012345678901234567890"),
            AssetId::Erc20(address!("0x0987654321098765432109876543210987654321")),
            10,
        );

        let operation = operation::Operation::new(
            1,
            vec![in_note],
            vec![transfer_note],
            Some(unshield_note.clone()),
        );

        let notes_out = operation.out_notes();
        assert_eq!(notes_out.last().unwrap().hash(), unshield_note.hash());
    }
}
