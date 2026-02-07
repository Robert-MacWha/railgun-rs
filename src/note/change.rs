use ark_bn254::Fr;

use crate::{
    abis::railgun::CommitmentCiphertext,
    account::RailgunAccount,
    caip::AssetId,
    note::{
        note::EncryptError,
        transfer::TransferNote,
        tree_transaction::{EncryptableNote, TransactNote},
    },
};

/// Change notes are special cases of transfer notes that transfer value to and
/// from the same account.
///
/// They're used to recover value from partially consumed notes. If a transaction
/// needs to consume more in_notes than the value being sent, a change note is
/// created to "transfer" the remainder back to the sender's account.
#[derive(Debug, Clone)]
pub struct ChangeNote {
    inner: TransferNote,
}

impl ChangeNote {
    pub fn new(
        account: &RailgunAccount,
        asset: AssetId,
        value: u128,
        random: [u8; 16],
        memo: &str,
    ) -> Self {
        let inner = TransferNote::new(
            account.viewing_key(),
            account.address(),
            asset,
            value,
            random,
            memo,
        );

        ChangeNote { inner }
    }

    pub fn set_value(&mut self, value: u128) {
        self.inner.value = value;
    }
}

impl EncryptableNote for ChangeNote {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError> {
        self.inner.encrypt()
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
