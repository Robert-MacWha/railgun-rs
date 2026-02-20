use rand::RngCore;
use ruint::aliases::U256;

use crate::{
    abis::railgun::CommitmentCiphertext,
    caip::AssetId,
    crypto::{keys::ViewingPublicKey, railgun_utxo::UtxoLeafHash},
    railgun::note::encrypt::EncryptError,
};

pub mod encrypt;
pub mod operation;
pub mod shield;
pub mod transfer;
pub mod unshield;
pub mod utxo;

/// Included notes are notes that have been included in a transaction and are
/// on-chain in railgun's merkle tree.
pub trait IncludedNote: Note + Clone {
    fn tree_number(&self) -> u32;
    fn leaf_index(&self) -> u32;
    fn viewing_pubkey(&self) -> ViewingPublicKey;
    fn nullifier(&self, leaf_index: U256) -> U256;
    fn spending_pubkey(&self) -> [U256; 2];
    fn sign(&self, inputs: &[U256]) -> [U256; 3];
    fn nullifying_key(&self) -> U256;
    fn random(&self) -> [u8; 16];
}

pub trait EncryptableNote: Note {
    fn encrypt(&self, rng: &mut dyn RngCore) -> Result<CommitmentCiphertext, EncryptError>;
}

pub trait Note {
    fn asset(&self) -> AssetId;
    fn value(&self) -> u128;
    fn memo(&self) -> String;

    /// Commitment Hash
    fn hash(&self) -> UtxoLeafHash;

    /// NPK
    fn note_public_key(&self) -> U256;
}
