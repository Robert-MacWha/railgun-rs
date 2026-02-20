pub mod verifier;

mod merkle_proof;
mod merkle_tree;
mod smart_wallet_verifier;
mod txid_tree;
mod utxo_tree;

pub use merkle_proof::{MerkleProof, MerkleRoot};
pub use merkle_tree::{
    MerkleTree, MerkleTreeError, MerkleTreeState, TREE_DEPTH, railgun_merkle_tree_zero,
};
pub use smart_wallet_verifier::SmartWalletVerifier;
pub use txid_tree::{TxidLeafHash, TxidMerkleTree};
pub use utxo_tree::{UtxoLeafHash, UtxoMerkleTree};
pub use verifier::{MerkleTreeVerifier, VerificationError};
