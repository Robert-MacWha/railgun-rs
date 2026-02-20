use std::collections::BTreeMap;

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::railgun::note::{IncludedNote, utxo::UtxoNote};

/// A Notebook holds a collection of spent and unspent notes for a Railgun account,
/// on a single tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Notebook {
    pub unspent: BTreeMap<u32, UtxoNote>,
    pub spent: BTreeMap<u32, UtxoNote>,
}

#[derive(Clone, Debug)]
pub struct SpentNote {
    inner: UtxoNote,
}

impl Notebook {
    pub fn new() -> Self {
        Notebook {
            unspent: BTreeMap::new(),
            spent: BTreeMap::new(),
        }
    }

    pub fn unspent(&self) -> &BTreeMap<u32, UtxoNote> {
        &self.unspent
    }

    pub fn spent(&self) -> &BTreeMap<u32, UtxoNote> {
        &self.spent
    }

    pub fn all(&self) -> BTreeMap<u32, UtxoNote> {
        let mut all_notes = BTreeMap::new();

        for (note_position, note) in &self.unspent {
            all_notes.insert(*note_position, note.clone());
        }

        for (note_position, note) in &self.spent {
            all_notes.insert(*note_position, note.clone());
        }

        all_notes
    }

    /// Adds an unspent note to the notebook.
    pub fn add(&mut self, note_position: u32, note: UtxoNote) {
        self.unspent.insert(note_position, note);
    }

    /// Nullifies (spends) a note in the notebook based on its nullifier.
    ///
    /// Returns the spent note if found, otherwise returns None.
    pub fn nullify(&mut self, nullifier: U256, _timestamp: u64) -> Option<SpentNote> {
        let Some((&leaf_index, _)) = self
            .unspent
            .iter()
            .find(|(leaf_index, note)| note.nullifier(U256::from(**leaf_index)) == nullifier)
        else {
            return None;
        };
        let note = self.unspent.remove(&leaf_index).unwrap();

        let spent_note = SpentNote { inner: note };
        self.spent.insert(leaf_index, spent_note.inner.clone());
        Some(spent_note)
    }
}
