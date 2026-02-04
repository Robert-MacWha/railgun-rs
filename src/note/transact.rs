use std::{collections::BTreeMap, fs};

use alloy::{consensus::error, primitives::Address};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, read_zkey};
use ark_groth16::ProvingKey;
use ark_std::rand::random;
use thiserror::Error;
use tracing::error;

use crate::{
    abis::railgun::CommitmentCiphertext,
    caip::{AccountId, AssetId},
    circuit::format_circuit_inputs,
    crypto::{
        aes::{AesError, encrypt_ctr, encrypt_gcm},
        concat_arrays, concat_arrays_3,
        keys::{SpendingKey, ViewingKey},
        railgun_base_37,
    },
    note::note::{EncryptError, Note, encrypt_note},
    railgun::address::RailgunAddress,
    tx_data::TxData,
};

/// TransactNote represents a note used in a shielded transaction.
#[derive(Debug, Clone)]
pub enum TransactNote {
    Unshield(UnshieldNote),
    Transfer(TransferNote),
    Change(ChangeNote),
}

#[derive(Debug, Clone)]
struct UnshieldNote {
    receiver: Address,
    asset: AssetId,
    value: u128,
}

#[derive(Debug, Clone)]
struct TransferNote {
    receiver: RailgunAddress,
    asset: AssetId,
    value: u128,
    random: [u8; 16],
    memo: String,
}

#[derive(Debug, Clone)]
struct ChangeNote {
    receiver: RailgunAddress,
    asset: AssetId,
    value: u128,
    random: [u8; 16],
    memo: String,
}

pub fn create_transaction(
    notes: BTreeMap<u32, BTreeMap<u32, Note>>,
    sender: &RailgunAddress,
    sender_spending_key: SpendingKey,
    sender_viewing_key: ViewingKey,
    asset: AssetId,
    value: u128,
    receiver: AccountId,
) -> Result<TxData, EncryptError> {
    let (notes_in, notes_out, nullifiers) =
        get_transact_notes(notes, sender, asset, value, receiver);

    println!("Notes In: {:?}", notes_in);
    println!("Notes Out: {:?}", notes_out);
    println!("Nullifiers: {:?}", nullifiers);

    for (tree_number, notes_in) in notes_in {
        let notes_out = notes_out.get(&tree_number).cloned().unwrap_or_default();
        let (builder, proving_key) = load_artifacts(notes_in.len(), notes_out.len());

        let commitment_ciphertext: Vec<CommitmentCiphertext> = notes_out
            .iter()
            .filter_map(|n| n.encrypt(sender_viewing_key, false))
            .collect::<Result<Vec<_>, _>>()?;

        // let inputs = format_circuit_inputs(notes_in, notes_out, commitment_ciphertext);
    }

    todo!()
}

fn load_artifacts(notes_in: usize, notes_out: usize) -> (CircomBuilder<Fr>, ProvingKey<Bn254>) {
    if notes_in != 1 || notes_out != 2 {
        todo!("Only 1 input and 2 output notes are supported currently");
    }

    const WASM_PATH: &str = "artifacts/01x02/01x02.wasm";
    const R1CS_PATH: &str = "artifacts/01x02/01x02.r1cs";
    const ZKEY_PATH: &str = "artifacts/01x02/01x02.zkey";

    let cfg = CircomConfig::<Fr>::new(WASM_PATH, R1CS_PATH).unwrap();
    let builder = CircomBuilder::new(cfg);

    let mut zkey_file = fs::File::open(ZKEY_PATH).unwrap();
    let (params, _matrices) = read_zkey(&mut zkey_file).unwrap();

    (builder, params)
}

impl TransactNote {
    pub fn new_unshield(receiver: Address, value: u128, asset: AssetId) -> Self {
        TransactNote::Unshield(UnshieldNote {
            receiver,
            asset,
            value,
        })
    }

    pub fn new_transfer(receiver: RailgunAddress, value: u128, asset: AssetId, memo: &str) -> Self {
        let random: [u8; 16] = random();

        TransactNote::Transfer(TransferNote {
            receiver,
            asset,
            value,
            random,
            memo: memo.to_string(),
        })
    }

    pub fn new_change(receiver: RailgunAddress, value: u128, asset: AssetId, memo: &str) -> Self {
        let random: [u8; 16] = random();

        TransactNote::Change(ChangeNote {
            receiver,
            asset,
            value,
            random,
            memo: memo.to_string(),
        })
    }

    pub fn encrypt(
        &self,
        viewing_key: ViewingKey,
        blind: bool,
    ) -> Option<Result<CommitmentCiphertext, EncryptError>> {
        match self {
            TransactNote::Unshield(_) => None, // Unshield notes are not encrypted
            TransactNote::Transfer(note) => Some(note.encrypt(viewing_key, blind)),
            TransactNote::Change(note) => Some(note.encrypt(viewing_key, blind)),
        }
    }
}

impl TransferNote {
    /// Encrypts the note into a CommitmentCiphertext
    ///
    /// If `blind` is true, the sender's address will be hidden to the receiver.
    pub fn encrypt(
        &self,
        viewing_key: ViewingKey,
        blind: bool,
    ) -> Result<CommitmentCiphertext, EncryptError> {
        encrypt_note(
            &self.receiver,
            &self.random,
            self.value,
            &self.asset,
            &self.memo,
            viewing_key,
            blind,
        )
    }
}

impl ChangeNote {
    pub fn encrypt(
        &self,
        viewing_key: ViewingKey,
        blind: bool,
    ) -> Result<CommitmentCiphertext, EncryptError> {
        encrypt_note(
            &self.receiver,
            &self.random,
            self.value,
            &self.asset,
            &self.memo,
            viewing_key,
            blind,
        )
    }
}

/// Gets the notes used and created in a transaction
///
/// The notes parameter is the sparse map of notes available to spend
/// for this account.
///
/// TODO: Add internal checks to ensure notes are this account's notes
fn get_transact_notes(
    notes: BTreeMap<u32, BTreeMap<u32, Note>>,
    sender: &RailgunAddress,
    asset: AssetId,
    value: u128,
    receiver: AccountId,
) -> (
    BTreeMap<u32, Vec<Note>>,
    BTreeMap<u32, Vec<TransactNote>>,
    BTreeMap<u32, Vec<Fr>>,
) {
    let is_unshield = match receiver {
        AccountId::Railgun(_) => false,
        AccountId::Eip155(_) => true,
    };

    let mut notes_in: BTreeMap<u32, Vec<Note>> = BTreeMap::new();
    let mut notes_out: BTreeMap<u32, Vec<TransactNote>> = BTreeMap::new();
    let mut nullifiers: BTreeMap<u32, Vec<Fr>> = BTreeMap::new();
    let mut total_value: u128 = 0;

    for (tree_number, notes) in notes.iter() {
        let mut tree_value: u128 = 0;

        for (tree_position, note) in notes {
            if note.token != asset {
                continue;
            }

            tree_value += note.value;
            notes_in.entry(*tree_number).or_default().push(note.clone());

            let nullifier = note.nullifier(*tree_position);
            nullifiers.entry(*tree_number).or_default().push(nullifier);

            if total_value + tree_value >= value {
                break;
            }
        }

        if tree_value == 0 {
            continue;
        }

        //? Determin how much value to use from this tree,
        // and if there is any remainder.
        let needed = value - total_value;
        let used = tree_value.min(needed);
        let remainder = tree_value.saturating_sub(needed);

        if remainder > 0 {
            //? If the tree's notes cover the remaining needed value,
            //? create a change note for the remainder
            let change_note =
                TransactNote::new_change(sender.clone(), remainder, asset.clone(), "");
            notes_out.entry(*tree_number).or_default().push(change_note);
        }

        //? Create the output note based on the used value
        let output_note = if is_unshield {
            let receiver = match receiver {
                AccountId::Eip155(addr) => addr,
                _ => unreachable!(),
            };
            TransactNote::new_unshield(receiver, used, asset.clone())
        } else {
            let receiver = match receiver {
                AccountId::Railgun(addr) => addr,
                _ => unreachable!(),
            };
            TransactNote::new_transfer(receiver, used, asset.clone(), "")
        };

        total_value += used;
        notes_out.entry(*tree_number).or_default().push(output_note);
    }

    (notes_in, notes_out, nullifiers)
}
