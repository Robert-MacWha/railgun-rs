use std::collections::{BTreeMap, HashMap};

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    abis::railgun::{RailgunSmartWallet, ShieldRequest},
    account::RailgunAccount,
    caip::AssetId,
    railgun::address::RailgunAddress,
    railgun::indexer::{indexer::TOTAL_LEAVES, notebook::Notebook},
    railgun::note::{
        Note,
        utxo::{NoteError, UtxoNote},
    },
};

/// IndexerAccount represents a Railgun account being tracked by the indexer.
///
/// The indexer will use the held keys to decrypt notes from shield and transact events,
/// storing them in the notebook for reference.
#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedAccount {
    inner: RailgunAccount,

    /// The latest block number that has been processed for this account
    synced_block: u64,
    notebooks: BTreeMap<u32, Notebook>,
}

impl IndexedAccount {
    pub fn new(inner: RailgunAccount) -> Self {
        IndexedAccount {
            inner,
            synced_block: 0,
            notebooks: BTreeMap::new(),
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.inner.address()
    }

    pub fn notebooks(&self) -> BTreeMap<u32, Notebook> {
        self.notebooks.clone()
    }

    pub fn unspent(&self) -> Vec<UtxoNote> {
        let mut unspent = Vec::new();
        for notebook in self.notebooks.values() {
            unspent.extend(notebook.unspent().values().cloned());
        }
        unspent
    }

    /// Calculates the balance of the account by summing up the values of all its notes.
    pub fn balance(&self) -> HashMap<AssetId, u128> {
        let mut balances: HashMap<AssetId, u128> = HashMap::new();

        for (_, notebook) in self.notebooks.iter() {
            for (_, note) in notebook.unspent().iter() {
                match note.asset() {
                    AssetId::Erc20(address) => {
                        balances
                            .entry(AssetId::Erc20(address))
                            .and_modify(|e| *e += note.value())
                            .or_insert(note.value());
                    }
                    _ => todo!(),
                }
            }
        }

        balances
    }

    pub fn handle_shield_event(
        &mut self,
        event: &RailgunSmartWallet::Shield,
        block_number: u64,
    ) -> Result<(), NoteError> {
        let tree_number: u32 = event.treeNumber.saturating_to();
        let start_position: u32 = event.startPosition.saturating_to();

        for (index, ciphertext) in event.shieldCiphertext.iter().enumerate() {
            let shield_request = ShieldRequest {
                preimage: event.commitments[index].clone(),
                ciphertext: ciphertext.clone(),
            };

            let is_crossing_tree = start_position as usize + index >= TOTAL_LEAVES;
            let index = index as u32;
            let (tree_number, leaf_index) = if is_crossing_tree {
                (
                    tree_number + 1,
                    start_position + index - TOTAL_LEAVES as u32,
                )
            } else {
                (tree_number, start_position + index)
            };

            let note = UtxoNote::decrypt_shield_request(
                self.inner.spending_key(),
                self.inner.viewing_key(),
                tree_number,
                leaf_index,
                shield_request,
            );

            let note = match note {
                Err(NoteError::Aes(_e)) => {
                    continue;
                }
                Err(e) => {
                    warn!(
                        "Failed to decrypt Shield note at tree {}, leaf {}: {}",
                        tree_number, leaf_index, e
                    );
                    continue;
                }
                Ok(n) => n,
            };

            info!(
                "Decrypted Shield Note: index={}, value={}, asset={:?}, account={}",
                index,
                note.value(),
                note.asset(),
                self.inner.address()
            );
            self.notebooks
                .entry(tree_number)
                .or_default()
                .add(leaf_index, note);
        }

        self.synced_block = self.synced_block.max(block_number);
        Ok(())
    }

    pub fn handle_transact_event(
        &mut self,
        event: &RailgunSmartWallet::Transact,
        block_number: u64,
    ) -> Result<(), NoteError> {
        let tree_number: u32 = event.treeNumber.saturating_to();
        let start_position: u32 = event.startPosition.saturating_to();

        for (index, ciphertext) in event.ciphertext.iter().enumerate() {
            let is_crossing_tree = start_position as usize + index >= TOTAL_LEAVES;
            let index = index as u32;
            let (tree_number, leaf_index) = if is_crossing_tree {
                (
                    tree_number + 1,
                    start_position + index - TOTAL_LEAVES as u32,
                )
            } else {
                (tree_number, start_position + index)
            };

            let note = UtxoNote::decrypt(
                self.inner.spending_key(),
                self.inner.viewing_key(),
                tree_number,
                leaf_index,
                ciphertext,
            );

            let note = match note {
                Err(NoteError::Aes(_)) => continue,
                Err(e) => {
                    warn!(
                        "Failed to decrypt Transact note at tree {}, leaf {}: {}",
                        tree_number, leaf_index, e
                    );
                    continue;
                }
                Ok(n) => n,
            };

            info!(
                "Decrypted Transact Note: index={}, value={}, asset={:?}",
                index,
                note.value(),
                note.asset()
            );
            self.notebooks
                .entry(tree_number)
                .or_default()
                .add(leaf_index, note);
        }

        self.synced_block = self.synced_block.max(block_number);
        Ok(())
    }

    pub fn handle_nullified_event(
        &mut self,
        event: &RailgunSmartWallet::Nullified,
        timestamp: u64,
    ) {
        let tree_number: u32 = event.treeNumber as u32;

        for nullifier in event.nullifier.iter() {
            self.notebooks
                .entry(tree_number)
                .or_default()
                .nullify(U256::from_be_bytes(**nullifier), timestamp);
        }
    }
}

impl From<&RailgunAccount> for IndexedAccount {
    fn from(account: &RailgunAccount) -> Self {
        IndexedAccount::new(account.clone())
    }
}
