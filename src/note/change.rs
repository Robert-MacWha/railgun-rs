use ark_bn254::Fr;

use crate::{
    abis::railgun::CommitmentCiphertext,
    account::RailgunAccount,
    caip::AssetId,
    crypto::keys::ViewingKey,
    note::{
        note::{EncryptError, Note},
        tree_transaction::{EncryptableNote, TransactNote},
    },
};

#[derive(Debug, Clone)]
pub struct ChangeNote {
    sender_key: ViewingKey,
    inner: Note,
}

impl ChangeNote {
    pub fn new(
        account: &RailgunAccount,
        asset: AssetId,
        value: u128,
        random_seed: &[u8; 16],
        memo: &str,
    ) -> Self {
        let note = Note::new(
            account.spending_key(),
            account.viewing_key(),
            asset,
            value,
            random_seed,
            memo,
        );

        ChangeNote {
            sender_key: account.viewing_key(),
            inner: note,
        }
    }

    pub fn set_value(&mut self, value: u128) {
        self.inner.value = value;
    }
}

impl EncryptableNote for ChangeNote {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError> {
        self.inner.encrypt(self.sender_key, false)
    }
}

impl TransactNote for ChangeNote {
    fn hash(&self) -> Fr {
        self.inner.hash()
    }

    fn note_public_key(&self) -> Fr {
        self.inner.note_public_key()
    }

    fn value(&self) -> u128 {
        self.inner.value
    }
}
