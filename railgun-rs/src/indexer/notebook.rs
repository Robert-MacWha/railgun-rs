use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{crypto::keys::bytes_to_fr, note::note::Note};

/// Notebook holds a collection of spent and unspent notes for a Railgun account,
/// on a single tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Notebook {
    pub unspent: BTreeMap<u32, Note>,
    pub spent: BTreeMap<u32, Note>,
}

#[derive(Clone, Debug)]
pub struct SpentNote {
    inner: Note,
    nullifier: [u8; 32],
    /// Unix timestamp
    timestamp: u64,
}

impl Notebook {
    pub fn new() -> Self {
        Notebook {
            unspent: BTreeMap::new(),
            spent: BTreeMap::new(),
        }
    }

    /// Adds an unspent note to the notebook.
    pub fn add(&mut self, note_position: u32, note: Note) {
        self.unspent.insert(note_position, note);
    }

    /// Nullifies (spends) a note in the notebook based on its nullifier.
    ///
    /// Returns the spent note if found and nullified, otherwise returns None.
    pub fn nullify(&mut self, nullifier: &[u8; 32], timestamp: u64) -> Option<SpentNote> {
        let nullifier_fr = bytes_to_fr(nullifier);

        let Some((&leaf_index, _)) = self
            .unspent
            .iter()
            .find(|(leaf_index, note)| note.nullifier(**leaf_index) == nullifier_fr)
        else {
            return None;
        };
        let note = self.unspent.remove(&leaf_index).unwrap();

        let spent_note = SpentNote {
            inner: note,
            nullifier: *nullifier,
            timestamp,
        };
        self.spent.insert(leaf_index, spent_note.inner.clone());
        Some(spent_note)
    }

    /// Removes a note from the unspent notes based on its tree number and position.
    ///
    /// DOES NOT mark it as spent.
    pub fn remove_unspent(&mut self, leaf_index: u32) {
        self.unspent.remove(&leaf_index);
    }

    /// Returns a reference to the unspent notes.
    pub fn unspent(&self) -> &BTreeMap<u32, Note> {
        &self.unspent
    }

    /// Returns a reference to the spent notes.
    pub fn spent(&self) -> &BTreeMap<u32, Note> {
        &self.spent
    }

    /// Returns all notes, both spent and unspent, organized by tree number and
    /// note position.
    pub fn all(&self) -> BTreeMap<u32, Note> {
        let mut all_notes = BTreeMap::new();

        for (note_position, note) in &self.unspent {
            all_notes.insert(*note_position, note.clone());
        }

        for (note_position, note) in &self.spent {
            all_notes.insert(*note_position, note.clone());
        }

        all_notes
    }
}
