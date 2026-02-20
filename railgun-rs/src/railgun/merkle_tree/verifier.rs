use std::sync::Arc;

use thiserror::Error;

use crate::railgun::merkle_tree::MerkleRoot;

/// Validates a Merkle root against an external authority (e.g. on-chain or a POI node).
///
/// Generic over `LeafHash` for type safety: a `PoiClient` verifier (for TXID trees) cannot
/// be passed to a `UtxoMerkleTree`, and vice versa.
#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
pub trait MerkleTreeVerifier<LeafHash>: Send + Sync {
    async fn verify_root(
        &self,
        tree_number: u32,
        tree_index: u64,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

// Private inner trait — same signature without the generic, used only for type erasure.
#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
trait VerifyRoot: Send + Sync {
    async fn verify_root(
        &self,
        tree_number: u32,
        tree_index: u64,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

// Bridges a typed `MerkleTreeVerifier<L>` to the inner `VerifyRoot` trait.
struct VerifyRootWrap<L, V>(V, std::marker::PhantomData<fn() -> L>);

#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
impl<L, V> VerifyRoot for VerifyRootWrap<L, V>
where
    L: Send + Sync + 'static,
    V: MerkleTreeVerifier<L> + Send + Sync,
{
    async fn verify_root(
        &self,
        tree_number: u32,
        tree_index: u64,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.0.verify_root(tree_number, tree_index, root).await
    }
}

/// Type-erased verifier stored inside trees. Cheap to clone — the `Arc` is internal.
#[derive(Clone)]
pub struct ErasedMerkleVerifier(Arc<dyn VerifyRoot>);

impl ErasedMerkleVerifier {
    /// Wraps any `MerkleTreeVerifier<L>` into an erased verifier.
    pub fn new<L, V>(verifier: V) -> Self
    where
        L: Send + Sync + 'static,
        V: MerkleTreeVerifier<L> + 'static,
    {
        ErasedMerkleVerifier(Arc::new(VerifyRootWrap(
            verifier,
            std::marker::PhantomData,
        )))
    }

    pub async fn verify_root(
        &self,
        tree_number: u32,
        tree_index: u64,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.0.verify_root(tree_number, tree_index, root).await
    }
}

/// Error returned when a Merkle tree fails remote verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Tree {tree_number} root {root} is not valid")]
    InvalidRoot {
        tree_number: u32,
        root: MerkleRoot,
    },
    #[error("Verifier error: {0}")]
    VerifierError(Box<dyn std::error::Error + Send + Sync>),
}

/// No-op verifier. `()` means "no verification" — `verify_root` always returns `Ok(true)`.
#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
impl<L: Send + Sync> MerkleTreeVerifier<L> for () {
    async fn verify_root(
        &self,
        _tree_number: u32,
        _tree_index: u64,
        _root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(true)
    }
}
