use std::collections::{BTreeMap, HashMap, HashSet};

use alloy::primitives::{Address, U256};
use alloy_sol_types::SolCall;
use rand::random;
use thiserror::Error;
use tracing::info;

use crate::{
    abis::railgun::RailgunSmartWallet,
    account::RailgunAccount,
    caip::AssetId,
    circuit::{native_prover::NativeProver, prover::TransactProver},
    indexer::{indexer::Indexer, notebook::Notebook},
    note::{
        change::ChangeNote,
        note::{EncryptError, Note},
        transact::create_transaction,
        transfer::TransferNote,
        tree_transaction::{TransactNote, TreeTransaction},
        unshield::UnshieldNote,
    },
    railgun::address::RailgunAddress,
    transaction::tx_data::TxData,
};

#[derive(Debug, Error)]
pub enum TxBuilderError {
    #[error("Untracked address: {0}")]
    UntrackedAddress(RailgunAddress),
    #[error("Insufficient funds in address {0} for asset {1}")]
    InsufficientFunds(RailgunAddress, AssetId),
    #[error("Multiple unshield operations from the same address are not supported: {0}")]
    MultipleUnshieldOperations(RailgunAddress),
    #[error("Encryption Error: {0}")]
    EncryptionError(#[from] EncryptError),
}

pub struct TxBuilder<'a> {
    indexer: &'a mut Indexer,
    tree_txns: HashMap<(RailgunAddress, AssetId), BTreeMap<u32, TreeTransaction>>,
    unshielded: HashSet<RailgunAddress>,

    /// Working set of notebooks that hold unspent notes for addresses involved
    notebooks: HashMap<RailgunAddress, BTreeMap<u32, Notebook>>,
    senders: HashSet<RailgunAccount>,
    prover: Box<dyn TransactProver>,
}

// TODO: Cache and build all at once
impl<'a> TxBuilder<'a> {
    pub fn new(indexer: &'a mut Indexer) -> Self {
        Self {
            indexer,
            tree_txns: HashMap::new(),
            unshielded: HashSet::new(),

            notebooks: HashMap::new(),
            senders: HashSet::new(),
            prover: Box::new(NativeProver::new()),
        }
    }

    pub fn new_with_prover(indexer: &'a mut Indexer, prover: Box<dyn TransactProver>) -> Self {
        let mut builder = Self::new(indexer);
        builder.prover = prover;
        builder
    }

    /// Adds a transfer operation to the transaction builder
    pub fn transfer(
        mut self,
        from: &RailgunAccount,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
    ) -> Result<Self, TxBuilderError> {
        self.drain_notes(from, asset, value, |asset, used, tree| {
            tree.transfers_out.push(TransferNote::new(
                from.viewing_key(),
                to,
                *asset,
                used,
                random(),
                memo,
            ));
        })?;
        Ok(self)
    }

    /// Sets an unshield operation in the transaction builder
    ///
    /// If an unshield from the same address already exists, it will be overwritten.
    /// Railgun cannot reliably support multiple unshield operations from the same
    /// 0zk address in a single transaction, so this API forbids it.
    pub fn set_unshield(
        mut self,
        from: &RailgunAccount,
        to: Address,
        asset: AssetId,
        value: u128,
    ) -> Result<Self, TxBuilderError> {
        if !self.unshielded.insert(from.address()) {
            return Err(TxBuilderError::MultipleUnshieldOperations(from.address()));
        }

        self.drain_notes(from, asset, value, |asset, used, tree| {
            tree.unshield = Some(UnshieldNote::new(to, *asset, used));
        })?;

        Ok(self)
    }

    /// Builds the transaction data
    pub fn build(self) -> Result<TxData, TxBuilderError> {
        let mut transactions = Vec::new();

        let chain = self.indexer.chain();
        let merkle_trees = self.indexer.merkle_trees();
        for (_, tree_txns) in self.tree_txns.into_iter() {
            let txns: Vec<crate::abis::railgun::Transaction> = create_transaction(
                &self.prover,
                merkle_trees,
                0,
                chain,
                Address::ZERO,
                &[0u8; 32],
                tree_txns,
            )?;
            transactions.extend(txns);
        }

        let call = RailgunSmartWallet::transactCall {
            _transactions: transactions,
        };
        let calldata = call.abi_encode();

        Ok(TxData {
            to: chain.railgun_smart_wallet,
            data: calldata,
            value: U256::ZERO,
        })
    }

    /// Drains notes from the given account for the specified asset and value.
    ///
    /// Calls the emit function for each note used.
    fn drain_notes(
        &mut self,
        from: &RailgunAccount,
        asset: AssetId,
        value: u128,
        mut emit: impl FnMut(&AssetId, u128, &mut TreeTransaction),
    ) -> Result<(), TxBuilderError> {
        let mut remaining = value;

        let notebooks = self.notebooks.entry(from.address()).or_insert(
            self.indexer
                .notebooks(from.address())
                .ok_or(TxBuilderError::UntrackedAddress(from.address()))?
                .clone(),
        );

        for (tree_id, notebook) in notebooks {
            let tree = self
                .tree_txns
                .entry((from.address(), asset))
                .or_default()
                .entry(*tree_id)
                .or_insert(new_tree_transaction(from, notebook, asset));

            let change_used = if let Some(change_note) = &mut tree.change {
                let available = change_note.value();
                let used = available.min(remaining);
                change_note.set_value(available - used);
                used
            } else {
                0
            };

            if change_used > 0 {
                emit(&asset, change_used, tree);
                remaining -= change_used;
            }
        }

        if remaining > 0 {
            return Err(TxBuilderError::InsufficientFunds(from.address(), asset));
        }
        Ok(())
    }
}

/// Creates a new TreeTransaction for the given account, notebook, and asset,
/// with all unspent notes as inputs and a change note for the cumulative value.
fn new_tree_transaction(
    from: &RailgunAccount,
    notebook: &Notebook,
    asset: AssetId,
) -> TreeTransaction {
    let notes_in: Vec<Note> = notebook
        .unspent()
        .iter()
        .filter(|(_, n)| n.token == asset)
        .map(|(_, n)| n.clone())
        .collect();

    let cumulative_value: u128 = notes_in.iter().map(|n| n.value).sum();
    info!(
        "Using {} notes from address {} for asset {} with cumulative value {}",
        notes_in.len(),
        from.address(),
        asset,
        cumulative_value
    );

    TreeTransaction {
        notes_in,
        transfers_out: Vec::new(),
        change: Some(ChangeNote::new(
            from,
            asset,
            cumulative_value,
            &random(),
            "",
        )),
        unshield: None,
    }
}
