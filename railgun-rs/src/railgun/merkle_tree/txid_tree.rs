use ruint::aliases::U256;
use serde::{Serialize, Serializer};

use crate::{
    crypto::{
        poseidon::poseidon_hash,
        railgun_txid::{Txid, UtxoTreeOut},
    },
    railgun::merkle_tree::{
        merkle_proof::{MerkleProof, MerkleRoot},
        merkle_tree::{MerkleTree, MerkleTreeError, MerkleTreeState},
        verifier::{ErasedMerkleVerifier, MerkleTreeVerifier, VerificationError},
    },
};

/// Typed leaf hash for TxID Merkle tree entries.
///
/// Serializes as a hex string WITHOUT a 0x prefix.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TxidLeafHash(U256);

impl TxidLeafHash {
    pub fn new(txid: Txid, utxo_tree_in: u32, utxo_tree_out: UtxoTreeOut) -> Self {
        let global_position = utxo_tree_out.global_index();

        poseidon_hash(&[
            txid.into(),
            U256::from(utxo_tree_in),
            U256::from(global_position),
        ])
        .unwrap()
        .into()
    }
}

impl From<U256> for TxidLeafHash {
    fn from(value: U256) -> Self {
        TxidLeafHash(value)
    }
}

impl From<TxidLeafHash> for U256 {
    fn from(value: TxidLeafHash) -> Self {
        value.0
    }
}

impl Serialize for TxidLeafHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:064x}", self.0))
    }
}

/// Type-safe wrapper around [`MerkleTree`] whose leaves are [`TxidLeafHash`] values.
///
/// The TxID tree tracks all Operations (`RailgunSmartWallet::Transaction`) in Railgun.
/// New TxIDs are added whenever a new Operation event is observed from the Railgun
/// smart contracts.
///
/// TxID proofs are used to generate Merkle proofs for TxIDs when submitting a
/// POI (Proof of Innocence) to a POI bundler, or to a broadcaster.
pub struct TxidMerkleTree {
    inner: MerkleTree,
    verifier: Option<ErasedMerkleVerifier>,
}

impl TxidMerkleTree {
    pub fn new(number: u32) -> Self {
        TxidMerkleTree {
            inner: MerkleTree::new(number),
            verifier: None,
        }
    }

    /// Creates a new tree with a typed verifier that will be called after each sync.
    pub fn new_with_verifier<V: MerkleTreeVerifier<TxidLeafHash> + 'static>(
        number: u32,
        verifier: V,
    ) -> Self {
        TxidMerkleTree {
            inner: MerkleTree::new(number),
            verifier: Some(ErasedMerkleVerifier::new::<TxidLeafHash, V>(verifier)),
        }
    }

    /// Creates a new tree with a pre-erased verifier. Used by the indexer when
    /// creating new trees so it can share a single verifier across all trees.
    pub(crate) fn with_erased_verifier(
        number: u32,
        verifier: Option<ErasedMerkleVerifier>,
    ) -> Self {
        TxidMerkleTree {
            inner: MerkleTree::new(number),
            verifier,
        }
    }

    pub fn from_state(state: MerkleTreeState) -> Self {
        TxidMerkleTree {
            inner: MerkleTree::from_state(state),
            verifier: None,
        }
    }

    pub fn number(&self) -> u32 {
        self.inner.number()
    }

    pub fn root(&self) -> MerkleRoot {
        self.inner.root()
    }

    pub fn leaves_len(&self) -> usize {
        self.inner.leaves_len()
    }

    pub fn state(&self) -> MerkleTreeState {
        self.inner.state()
    }

    pub fn into_state(self) -> MerkleTreeState {
        self.inner.into_state()
    }

    /// Insert one TxID leaf and immediately rebuild affected parents.
    pub fn insert_leaf(&mut self, leaf: TxidLeafHash, position: usize) {
        self.inner.insert_leaf(leaf.into(), position);
    }

    pub fn generate_proof(&self, leaf: TxidLeafHash) -> Result<MerkleProof, MerkleTreeError> {
        self.inner.generate_proof(leaf.into())
    }

    /// Insert leaves without immediately rebuilding. Used by the indexer's bulk
    /// sync path which calls [`Self::rebuild`] once after all events are processed.
    pub(crate) fn insert_leaves(&mut self, leaves: &[TxidLeafHash], start_position: usize) {
        let u256s: Vec<U256> = leaves.iter().map(|l| (*l).into()).collect();
        self.inner.insert_leaves_raw(&u256s, start_position);
    }

    /// Rebuild only the nodes whose descendants were modified since the last rebuild.
    pub fn rebuild(&mut self) {
        self.inner.rebuild();
    }

    /// Validates this tree's root against the embedded verifier, if any.
    /// Returns `Ok(())` immediately if no verifier is set or the tree is empty.
    pub async fn verify(&self) -> Result<(), VerificationError> {
        let Some(verifier) = &self.verifier else {
            return Ok(());
        };

        let leaves_len = self.inner.leaves_len();
        if leaves_len == 0 {
            return Ok(());
        }

        let tree_number = self.inner.number();
        let tree_index = leaves_len as u64 - 1;
        let root = self.inner.root();

        verifier
            .verify_root(tree_number, tree_index, root)
            .await
            .map_err(VerificationError::VerifierError)
            .and_then(|valid| {
                if valid {
                    Ok(())
                } else {
                    Err(VerificationError::InvalidRoot { tree_number, root })
                }
            })
    }
}
