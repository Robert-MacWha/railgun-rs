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
    note::{note::Note, operation::Operation, transfer::TransferNote, unshield::UnshieldNote},
    railgun::address::RailgunAddress,
};

/// A builder for construction railgun transactions
pub struct OperationBuilder {
    pub transfers: Vec<TransferData>,
    pub unshields: HashMap<AssetId, UnshieldData>,
}

pub struct TransferData {
    //? Required for viewing key
    pub from: RailgunAccount,
    pub to: RailgunAddress,
    pub asset: AssetId,
    pub value: u128,
    pub memo: String,
}

pub struct UnshieldData {
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
    pub fn set_unshield(mut self, to: Address, asset: AssetId, value: u128) -> Self {
        let unshield_data = UnshieldData { to, asset, value };
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
    /// Preserves the ordering of transfers within and across operations. Does not
    /// guarantee any particular ordering of unshield operations relative to transfers.
    pub fn build(self, in_notes: Vec<Note>) -> Result<Vec<Operation<Note>>, GroupError> {
        let unshield_note = if self.unshields.len() > 1 {
            return Err(GroupError::MultipleUnshields);
        } else if self.unshields.len() == 1 {
            Some(self.unshields.into_values().next().unwrap())
        } else {
            None
        };

        let out_notes = self
            .transfers
            .into_iter()
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

        let unshield_note = unshield_note.map(|u| UnshieldNote::new(u.to, u.asset, u.value));

        // TODO: Implement an actual algorithm
        let group = Operation::new(in_notes[0].tree_number, in_notes, out_notes, unshield_note);
        Ok(vec![group])
    }
}
