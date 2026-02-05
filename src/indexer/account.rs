use std::collections::HashMap;

use tracing::info;

use crate::{
    abis::railgun::{RailgunSmartWallet, ShieldRequest},
    caip::AssetId,
    crypto::keys::{SpendingKey, ViewingKey},
    indexer::{indexer::TOTAL_LEAVES, notebook::Notebook},
    note::note::{Note, NoteError},
    railgun::address::RailgunAddress,
};

/// IndexerAccount represents a Railgun account being tracked by the indexer.
///
/// The indexer will use the held keys to decrypt notes from shield and transact events,
/// storing them in the notebook for reference.
pub struct IndexerAccount {
    address: RailgunAddress,
    spending_key: SpendingKey,
    viewing_key: ViewingKey,

    /// The latest block number that has been processed for this account
    synced_block: u64,
    notebook: Notebook,
}

impl IndexerAccount {
    pub fn new(
        address: RailgunAddress,
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
    ) -> Self {
        IndexerAccount {
            address,
            spending_key,
            viewing_key,
            synced_block: 0,
            notebook: Notebook::new(),
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    pub fn notebook(&self) -> Notebook {
        self.notebook.clone()
    }

    /// Calculates the balance of the account by summing up the values of all its notes.
    pub fn balance(&self) -> HashMap<AssetId, u128> {
        let mut balances: HashMap<AssetId, u128> = HashMap::new();

        for (_, tree) in self.notebook.unspent().iter() {
            for (_, note) in tree.iter() {
                match note.token {
                    AssetId::Erc20(address) => {
                        balances
                            .entry(AssetId::Erc20(address))
                            .and_modify(|e| *e += note.value)
                            .or_insert(note.value);
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

        info!(
            "Handling Shield Event: tree_number={}, start_position={}, commitments={}",
            tree_number,
            start_position,
            event.commitments.len()
        );
        for (index, ciphertext) in event.shieldCiphertext.iter().enumerate() {
            let shield_request = ShieldRequest {
                preimage: event.commitments[index].clone(),
                ciphertext: ciphertext.clone(),
            };
            let note =
                Note::decrypt_shield_request(shield_request, self.spending_key, self.viewing_key);

            let note = match note {
                Err(NoteError::Aes(e)) => {
                    info!("Failed to decrypt shield note at index {}: {:?}", index, e);
                    continue;
                }
                Err(e) => return Err(e),
                Ok(n) => n,
            };

            info!(
                "Decrypted Shield Note: index={}, value={}, asset={:?}",
                index, note.value, note.token
            );
            let is_crossing_tree = start_position + index as u32 >= TOTAL_LEAVES;
            let index = index as u32;
            let (tree_number, note_position) = if is_crossing_tree {
                (tree_number + 1, start_position + index - TOTAL_LEAVES)
            } else {
                (tree_number, start_position + index)
            };

            self.notebook.add(tree_number, note_position, note);
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
            let note = Note::decrypt(ciphertext, self.spending_key, self.viewing_key);

            let note = match note {
                Err(NoteError::Aes(_)) => continue,
                Err(e) => return Err(e),
                Ok(n) => n,
            };

            let is_crossing_tree = start_position + index as u32 >= TOTAL_LEAVES;
            let index = index as u32;
            let (tree_number, note_position) = if is_crossing_tree {
                (tree_number + 1, start_position + index - TOTAL_LEAVES)
            } else {
                (tree_number, start_position + index)
            };

            self.notebook.add(tree_number, note_position, note);
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
            let nullifier_bytes: &[u8; 32] = &nullifier.clone().into();
            self.notebook
                .nullify(tree_number, nullifier_bytes, timestamp);
        }
    }
}
