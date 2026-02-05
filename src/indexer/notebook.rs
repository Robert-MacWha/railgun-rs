use std::collections::BTreeMap;

use crate::{crypto::keys::bytes_to_fr, note::note::Note};

/// Notebook holds a collection of spent and unspent notes for a Railgun account,
/// organized by tree number and note position.
#[derive(Clone, Debug)]
pub struct Notebook {
    pub unspent: BTreeMap<u32, BTreeMap<u32, Note>>,
    pub spent: BTreeMap<u32, BTreeMap<u32, Note>>,
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
    pub fn add(&mut self, tree_number: u32, note_position: u32, note: Note) {
        self.unspent
            .entry(tree_number)
            .or_insert_with(BTreeMap::new)
            .insert(note_position, note);
    }

    /// Nullifies (spends) a note in the notebook based on its nullifier.
    ///
    /// Returns the spent note if found and nullified, otherwise returns None.
    pub fn nullify(
        &mut self,
        tree_number: u32,
        nullifier: &[u8; 32],
        timestamp: u64,
    ) -> Option<SpentNote> {
        let nullifier_fr = bytes_to_fr(nullifier);

        let Some(tree_note) = self.unspent.get_mut(&tree_number) else {
            return None;
        };

        let Some((&leaf_index, _)) = tree_note
            .iter()
            .find(|(leaf_index, note)| note.nullifier(**leaf_index) == nullifier_fr)
        else {
            return None;
        };
        let note = tree_note.remove(&leaf_index).unwrap();

        let spent_note = SpentNote {
            inner: note,
            nullifier: *nullifier,
            timestamp,
        };
        self.spent
            .entry(tree_number)
            .or_insert_with(BTreeMap::new)
            .insert(leaf_index, spent_note.inner.clone());
        return Some(spent_note);
    }

    /// Returns a reference to the unspent notes.
    pub fn unspent(&self) -> &BTreeMap<u32, BTreeMap<u32, Note>> {
        &self.unspent
    }

    /// Returns a reference to the spent notes.
    pub fn spent(&self) -> &BTreeMap<u32, BTreeMap<u32, Note>> {
        &self.spent
    }

    /// Returns all notes, both spent and unspent, organized by tree number and
    /// note position.
    pub fn all(&self) -> BTreeMap<u32, BTreeMap<u32, Note>> {
        let mut all_notes = BTreeMap::new();

        for (tree_number, tree_notes) in &self.unspent {
            let tree_entry = all_notes.entry(*tree_number).or_insert_with(BTreeMap::new);
            for (note_position, note) in tree_notes {
                tree_entry.insert(*note_position, note.clone());
            }
        }

        for (tree_number, tree_notes) in &self.spent {
            let tree_entry = all_notes.entry(*tree_number).or_insert_with(BTreeMap::new);
            for (note_position, note) in tree_notes {
                tree_entry.insert(*note_position, note.clone());
            }
        }

        all_notes
    }
}
