use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use crate::{
    abis::railgun::CommitmentCiphertext, caip::AssetId, crypto::railgun_utxo::Utxo,
    note::encrypt::EncryptError,
};

pub mod encrypt;
pub mod operation;
pub mod shield;
pub mod transfer;
pub mod unshield;
pub mod utxo;

/// Included notes are notes that have been included in a transaction and are
/// on-chain in railgun's merkle tree.
pub trait IncludedNote: Note {
    fn tree_number(&self) -> u32;
    fn leaf_index(&self) -> u32;
}

pub trait EncryptableNote: Note {
    fn encrypt(&self) -> Result<CommitmentCiphertext, EncryptError>;
}

pub trait Note {
    fn asset(&self) -> AssetId;
    fn value(&self) -> u128;
    fn memo(&self) -> String;

    /// Commitment Hash
    fn hash(&self) -> Utxo;

    /// NPK
    fn note_public_key(&self) -> Fr;
}

pub fn ark_to_solidity_bytes(fr: Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let mut bytes = [0u8; 32];
    bigint.serialize_compressed(&mut bytes[..]).unwrap();
    bytes.reverse();
    bytes
}
