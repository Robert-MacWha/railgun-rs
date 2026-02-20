use ruint::aliases::U256;

use crate::railgun::merkle_tree::{
    merkle_proof::{MerkleProof, MerkleRoot},
    merkle_tree::{MerkleTree, MerkleTreeError, MerkleTreeState},
    verifier::{ErasedMerkleVerifier, MerkleTreeVerifier, VerificationError},
};

/// Typed leaf hash for UTXO Merkle tree entries.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UtxoLeafHash(U256);

impl From<U256> for UtxoLeafHash {
    fn from(value: U256) -> Self {
        UtxoLeafHash(value)
    }
}

impl From<UtxoLeafHash> for U256 {
    fn from(value: UtxoLeafHash) -> Self {
        value.0
    }
}

/// Type-safe wrapper around [`MerkleTree`] whose leaves are [`UtxoLeafHash`] values.
///
/// UTXO trees track the state of all notes in Railgun. New UTXOs are added as
/// leaves whenever new commitments are observed from the Railgun smart contracts.
///
/// The UTXO tree is used to generate Merkle proofs for UTXOs when they are spent,
/// one of the private inputs required for a valid snark proof.
pub struct UtxoMerkleTree {
    inner: MerkleTree,
    verifier: Option<ErasedMerkleVerifier>,
}

impl UtxoMerkleTree {
    pub fn new(number: u32) -> Self {
        UtxoMerkleTree {
            inner: MerkleTree::new(number),
            verifier: None,
        }
    }

    /// Creates a new tree with a typed verifier that will be called after each sync.
    pub fn new_with_verifier<V: MerkleTreeVerifier<UtxoLeafHash> + 'static>(
        number: u32,
        verifier: V,
    ) -> Self {
        UtxoMerkleTree {
            inner: MerkleTree::new(number),
            verifier: Some(ErasedMerkleVerifier::new::<UtxoLeafHash, V>(verifier)),
        }
    }

    /// Creates a new tree with a pre-erased verifier. Used by the indexer when
    /// creating new trees so it can share a single verifier across all trees.
    pub(crate) fn with_erased_verifier(
        number: u32,
        verifier: Option<ErasedMerkleVerifier>,
    ) -> Self {
        UtxoMerkleTree {
            inner: MerkleTree::new(number),
            verifier,
        }
    }

    pub fn from_state(state: MerkleTreeState) -> Self {
        UtxoMerkleTree {
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

    /// Insert one UTXO leaf and immediately rebuild affected parents.
    pub fn insert_leaf(&mut self, leaf: UtxoLeafHash, position: usize) {
        self.inner.insert_leaf(leaf.into(), position);
    }

    pub fn generate_proof(&self, leaf: UtxoLeafHash) -> Result<MerkleProof, MerkleTreeError> {
        self.inner.generate_proof(leaf.into())
    }

    /// Insert leaves without immediately rebuilding. Used by the indexer's bulk
    /// sync path which calls [`Self::rebuild`] once after all events are processed.
    pub(crate) fn insert_leaves(&mut self, leaves: &[UtxoLeafHash], start_position: usize) {
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
