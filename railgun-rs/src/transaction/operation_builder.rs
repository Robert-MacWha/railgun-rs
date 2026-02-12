//! Because Railgun's transaction-within-transaction language is confusing, I'm
//! setting some ground rules.
//!
//! A "Note" is an already-on-chain note, which can be used as an input to an Operation.
//!
//! A "Operation" means a single railgun transaction (IE `RailgunSmartWallet.Transaction` object).
//!  - An operation can have many input notes, but they must all be on the same tree and held by the same address.
//!  - An operation may have many output notes, which can be to different addresses and on different trees.
//!  - An operation may only have one unshield note, since the `RailgunSmartWallet.Transaction` struct only
//!
//! A "Transaction" means an EVM transaction.
//!  - A transaction can have many operations across many trees and addresses.

use std::collections::HashMap;

use alloy::primitives::Address;
use rand::random;
use thiserror::Error;
use tracing::warn;

use crate::{
    account::RailgunAccount,
    caip::AssetId,
    note::{
        IncludedNote, Note, operation::Operation, transfer::TransferNote, unshield::UnshieldNote,
    },
    railgun::address::RailgunAddress,
};

/// A builder for construction railgun transactions
pub struct OperationBuilder {
    transfers: Vec<TransferData>,
    unshields: HashMap<AssetId, UnshieldData>,
}

struct TransferData {
    //? Required for viewing key
    pub from: RailgunAccount,
    pub to: RailgunAddress,
    pub asset: AssetId,
    pub value: u128,
    pub memo: String,
}

struct UnshieldData {
    pub from: RailgunAccount,
    pub to: Address,
    pub asset: AssetId,
    pub value: u128,
}

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("Multiple unshield operations are not supported")]
    MultipleUnshields,
}

impl OperationBuilder {
    pub fn new() -> Self {
        Self {
            transfers: Vec::new(),
            unshields: HashMap::new(),
        }
    }

    pub fn transfer(
        mut self,
        from: RailgunAccount,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
    ) -> Self {
        let transfer_data = TransferData {
            from,
            to,
            asset,
            value,
            memo: memo.to_string(),
        };
        self.transfers.push(transfer_data);
        self
    }

    /// Sets an unshield operation for the transaction.
    pub fn set_unshield(
        mut self,
        from: RailgunAccount,
        to: Address,
        asset: AssetId,
        value: u128,
    ) -> Self {
        let unshield_data = UnshieldData {
            from,
            to,
            asset,
            value,
        };
        let old = self.unshields.insert(asset, unshield_data);
        if old.is_some() {
            warn!(
                "Overwriting existing unshield data for {}",
                old.unwrap().asset
            );
        }

        self
    }

    /// Builds the operations.
    ///
    /// Groups input notes by (tree_number, asset_id) and creates separate operations
    /// for each group. Creates change notes when input value exceeds output value.
    ///
    /// Preserves the ordering of transfers within and across operations. Does not
    /// guarantee any particular ordering of unshield operations relative to transfers.
    pub fn build<N: IncludedNote>(self, in_notes: Vec<N>) -> Result<Vec<Operation<N>>, GroupError> {
        // 1. Group input notes by (tree_number, asset_id)
        let mut grouped: HashMap<(u32, AssetId), Vec<N>> = HashMap::new();
        for note in in_notes {
            let key = (note.tree_number(), note.asset());
            grouped.entry(key).or_default().push(note);
        }

        // 2. Get sender account from first transfer or unshield (needed for change notes)
        let sender = self
            .transfers
            .first()
            .map(|t| &t.from)
            .or_else(|| self.unshields.values().next().map(|u| &u.from));

        // 3. Build operations for each group
        let mut operations = Vec::new();
        for ((tree_number, asset), notes) in grouped {
            let input_sum: u128 = notes.iter().map(|n| n.value()).sum();

            // Filter transfers for this asset
            let mut out_notes: Vec<TransferNote> = self
                .transfers
                .iter()
                .filter(|t| t.asset == asset)
                .map(|t| {
                    TransferNote::new(
                        t.from.viewing_key(),
                        t.to,
                        t.asset,
                        t.value,
                        random(),
                        &t.memo,
                    )
                })
                .collect();

            let transfer_sum: u128 = out_notes.iter().map(|n| n.value()).sum();
            let unshield_value = self.unshields.get(&asset).map(|u| u.value).unwrap_or(0);
            let output_sum = transfer_sum + unshield_value;

            // Add change note if input > output
            if input_sum > output_sum {
                if let Some(sender) = sender {
                    let change_value = input_sum - output_sum;
                    out_notes.push(TransferNote::new(
                        sender.viewing_key(),
                        sender.address(),
                        asset,
                        change_value,
                        random(),
                        "",
                    ));
                }
            }

            let unshield = self
                .unshields
                .get(&asset)
                .map(|u| UnshieldNote::new(u.to, u.asset, u.value));

            operations.push(Operation::new(tree_number, notes, out_notes, unshield));
        }

        Ok(operations)
    }
}
