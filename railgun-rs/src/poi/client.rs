use std::collections::HashMap;

use alloy::primitives::{ChainId, FixedBytes};
use ark_bn254::Fr;

pub use crate::poi::{
    inner_client::ClientError,
    inner_types::{BlindedCommitmentType, ListKey, PoisPerListMap, ValidatedRailgunTxidStatus},
};
use crate::{
    crypto::{keys::fr_to_bytes, railgun_txid::Txid},
    poi::inner_types::MerkleProof,
};

pub struct PoiClient {
    inner: crate::poi::inner_client::InnerPoiClient,
    chain: ChainId,
    list_keys: Vec<ListKey>,
}

pub struct BlindedCommitmentData {
    pub commitment_type: BlindedCommitmentType,
    pub blinded_commitment: [u8; 32],
}

impl PoiClient {
    pub async fn new(url: impl Into<String>, chain: ChainId) -> Result<Self, ClientError> {
        let inner = crate::poi::inner_client::InnerPoiClient::new(url);
        let status = inner.node_status().await?;

        Ok(Self {
            inner,
            chain,
            list_keys: status.list_keys,
        })
    }

    pub async fn health(&self) -> bool {
        match self.inner.health().await {
            Ok(status) if status.to_lowercase() == "ok" => true,
            _ => false,
        }
    }

    /// Returns a map of list keys to their corresponding POIs for the given blinded for all list
    /// keys for the chain.
    pub async fn pois(
        &self,
        blinded_commitment_data: Vec<BlindedCommitmentData>,
    ) -> Result<PoisPerListMap, ClientError> {
        let blinded_commitment_datas: Vec<crate::poi::inner_types::BlindedCommitmentData> =
            blinded_commitment_data
                .into_iter()
                .map(|data| crate::poi::inner_types::BlindedCommitmentData {
                    commitment_type: data.commitment_type,
                    blinded_commitment: format!("0x{}", hex::encode(data.blinded_commitment)),
                })
                .collect();

        self.inner
            .pois_per_list(crate::poi::inner_types::GetPoisPerListParams {
                chain: self.chain(),
                list_keys: self.list_keys.clone(),
                blinded_commitment_datas,
            })
            .await
    }

    pub async fn merkle_proofs(
        &self,
        blinded_commitments: Vec<[u8; 32]>,
    ) -> Result<HashMap<ListKey, Vec<MerkleProof>>, ClientError> {
        let blinded_commitments: Vec<crate::poi::inner_types::BlindedCommitment> =
            blinded_commitments
                .into_iter()
                .map(|bc| format!("0x{}", hex::encode(bc)))
                .collect();

        let mut proofs = HashMap::new();
        for list_key in self.list_keys.iter() {
            let list_key_proofs = self
                .inner
                .merkle_proofs(crate::poi::inner_types::GetMerkleProofsParams {
                    chain: self.chain(),
                    list_key: list_key.clone(),
                    blinded_commitments: blinded_commitments.clone(),
                })
                .await?;

            proofs.insert(list_key.clone(), list_key_proofs);
        }

        Ok(proofs)
    }

    /// Returns the current validated txid status from the POI node.
    pub async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, ClientError> {
        self.inner.validated_txid(self.chain()).await
    }

    /// Validates a txid merkle root against the POI node.
    pub async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u64,
        merkleroot: Txid,
    ) -> Result<bool, ClientError> {
        let txid: Fr = merkleroot.into();

        self.inner
            .validate_txid_merkleroot(crate::poi::inner_types::ValidateTxidMerklerootParams {
                chain: self.chain(),
                tree: tree as u64,
                index,
                merkleroot: FixedBytes::<32>::from(fr_to_bytes(&txid)),
            })
            .await
    }

    fn chain(&self) -> crate::poi::inner_types::ChainParams {
        crate::poi::inner_types::ChainParams {
            chain_type: 0.to_string(), // EVM
            chain_id: self.chain.to_string(),
            txid_version: crate::poi::inner_types::TxidVersion::V2PoseidonMerkle,
        }
    }
}
