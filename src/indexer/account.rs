use std::collections::{BTreeMap, HashMap};

use tracing::info;

use crate::{
    abis::railgun::{RailgunSmartWallet, ShieldRequest},
    caip::AssetId,
    indexer::indexer::TOTAL_LEAVES,
    note::note::{Note, NoteError},
    railgun::address::RailgunAddress,
};

/// IndexerAccount represents a Railgun account being tracked by the indexer.
///
/// The indexer will use the held keys to decrypt notes from shield and transact events,
/// storing them in the notebook for reference.
pub struct IndexerAccount {
    address: RailgunAddress,
    /// Private viewing key
    viewing_key: [u8; 32],
    /// Private spending key
    spending_key: [u8; 32],

    /// The latest block number that has been processed for this account
    synced_block: u64,

    /// The notes held by this account, organized by tree number and note position
    notes: BTreeMap<u32, BTreeMap<u32, Note>>,
}

impl IndexerAccount {
    pub fn new(address: RailgunAddress, viewing_key: [u8; 32], spending_key: [u8; 32]) -> Self {
        IndexerAccount {
            address,
            viewing_key,
            spending_key,
            synced_block: 0,
            notes: BTreeMap::new(),
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    pub fn notebooks(&self) -> &BTreeMap<u32, BTreeMap<u32, Note>> {
        &self.notes
    }

    /// Calculates the balance of the account by summing up the values of all its notes.
    pub fn balance(&self) -> HashMap<AssetId, u128> {
        let mut balances: HashMap<AssetId, u128> = HashMap::new();

        for (_tree_number, tree_notes) in self.notes.iter() {
            for (_note_position, note) in tree_notes.iter() {
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
                Note::decrypt_shield_request(shield_request, &self.viewing_key, &self.spending_key);

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

            self.notes
                .entry(tree_number)
                .or_default()
                .insert(note_position, note);
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
            let note = Note::decrypt(&ciphertext, &self.viewing_key, &self.spending_key);

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

            self.notes
                .entry(tree_number)
                .or_default()
                .insert(note_position, note);
        }

        self.synced_block = self.synced_block.max(block_number);
        Ok(())
    }
}
