use std::collections::HashMap;

use alloy::primitives::ChainId;
use ruint::aliases::U256;
use thiserror::Error;
use tracing::info;

pub use crate::railgun::poi::{
    inner_client::PoiClientError,
    inner_types::{
        BlindedCommitmentType, ListKey, PoisPerListMap, PreTransactionPoi,
        PreTransactionPoisPerTxidLeafPerList, SnarkProof, TxidVersion,
    },
};
use crate::{
    crypto::{keys::hex_to_u256, railgun_txid::Txid},
    railgun::{
        merkle_tree::merkle_proof::MerkleProof, note::utxo::UtxoNote, poi::poi_note::PoiNote,
    },
};

pub struct PoiClient {
    inner: crate::railgun::poi::inner_client::InnerPoiClient,
    chain: ChainId,
    list_keys: Vec<ListKey>,
}

pub struct BlindedCommitmentData {
    pub commitment_type: BlindedCommitmentType,
    pub blinded_commitment: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ValidatedRailgunTxidStatus {
    pub tree: u32,
    pub index: u32,
    pub merkleroot: Txid,
}

#[derive(Debug, Error)]
pub enum PoiMerkleProofError {
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("Integer parsing error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

impl PoiClient {
    pub async fn new(url: impl Into<String>, chain: ChainId) -> Result<Self, PoiClientError> {
        let inner = crate::railgun::poi::inner_client::InnerPoiClient::new(url);
        let status = inner.node_status().await?;
        let list_keys = status.list_keys;
        info!(
            "Initialized POI client for chain {}, found list keys: {:?}",
            chain, list_keys
        );

        Ok(Self {
            inner,
            chain,
            list_keys,
        })
    }

    pub async fn health(&self) -> bool {
        match self.inner.health().await {
            Ok(status) if status.to_lowercase() == "ok" => true,
            _ => false,
        }
    }

    pub fn list_keys(&self) -> Vec<ListKey> {
        self.list_keys.clone()
    }

    /// Returns a map of list keys to their corresponding POIs for the given blinded for all list
    /// keys for the chain.
    pub async fn pois(
        &self,
        blinded_commitment_data: Vec<BlindedCommitmentData>,
    ) -> Result<PoisPerListMap, PoiClientError> {
        let blinded_commitment_datas: Vec<crate::railgun::poi::inner_types::BlindedCommitmentData> =
            blinded_commitment_data
                .into_iter()
                .map(
                    |data| crate::railgun::poi::inner_types::BlindedCommitmentData {
                        commitment_type: data.commitment_type,
                        blinded_commitment: format!("0x{}", hex::encode(data.blinded_commitment)),
                    },
                )
                .collect();

        self.inner
            .pois_per_list(crate::railgun::poi::inner_types::GetPoisPerListParams {
                chain: self.chain(),
                list_keys: self.list_keys.clone(),
                blinded_commitment_datas,
            })
            .await
    }

    pub async fn note_to_poi_note(
        &self,
        notes: Vec<UtxoNote>,
    ) -> Result<Vec<PoiNote>, PoiClientError> {
        let blinded_commitments = notes
            .iter()
            .map(|n| n.blinded_commitment().to_be_bytes())
            .collect();
        let proofs = self.merkle_proofs(blinded_commitments).await?;

        let mut poi_notes = Vec::new();
        for (i, note) in notes.into_iter().enumerate() {
            let mut note_proofs = HashMap::new();

            for (list_key, proofs) in proofs.iter() {
                let proof = proofs.get(i).unwrap();
                note_proofs.insert(list_key.clone(), proof.clone());
            }

            let poi_note = PoiNote::new(note, note_proofs);
            poi_notes.push(poi_note);
        }

        Ok(poi_notes)
    }

    pub async fn merkle_proofs(
        &self,
        blinded_commitments: Vec<[u8; 32]>,
    ) -> Result<HashMap<ListKey, Vec<MerkleProof>>, PoiClientError> {
        let blinded_commitments: Vec<crate::railgun::poi::inner_types::BlindedCommitment> =
            blinded_commitments
                .into_iter()
                .map(|bc| format!("0x{}", hex::encode(bc)))
                .collect();

        let mut proofs = HashMap::new();
        for list_key in self.list_keys.iter() {
            let list_key_proofs = self
                .inner
                .merkle_proofs(crate::railgun::poi::inner_types::GetMerkleProofsParams {
                    chain: self.chain(),
                    list_key: list_key.clone(),
                    blinded_commitments: blinded_commitments.clone(),
                })
                .await?;

            let list_key_proofs = list_key_proofs
                .into_iter()
                .map(|proof| proof.try_into())
                .collect::<Result<Vec<_>, PoiMerkleProofError>>()?;

            proofs.insert(list_key.clone(), list_key_proofs);
        }

        Ok(proofs)
    }

    /// Returns the current validated txid status from the POI node.
    pub async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
        let resp: crate::railgun::poi::inner_types::ValidatedRailgunTxidStatus =
            self.inner.validated_txid(self.chain()).await?;

        let Some(merkle_root) = resp.validated_merkleroot else {
            return Err(PoiClientError::UnexpectedResponse(
                "validated_merkleroot is None".to_string(),
            ));
        };

        let Some(global_index) = resp.validated_txid_index else {
            return Err(PoiClientError::UnexpectedResponse(
                "validated_txid_index is None".to_string(),
            ));
        };

        let tree = (global_index >> 16) as u32;
        let index = (global_index & 0xFFFF) as u32;

        Ok(ValidatedRailgunTxidStatus {
            tree,
            index,
            merkleroot: hex_to_u256(&merkle_root).into(),
        })
    }

    /// Validates a txid merkle root against the POI node.
    pub async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u64,
        merkleroot: Txid,
    ) -> Result<bool, PoiClientError> {
        let txid: U256 = merkleroot.into();

        self.inner
            .validate_txid_merkleroot(
                crate::railgun::poi::inner_types::ValidateTxidMerklerootParams {
                    chain: self.chain(),
                    tree: tree as u64,
                    index,
                    merkleroot: hex::encode(&txid.to_be_bytes::<32>()),
                },
            )
            .await
    }

    fn chain(&self) -> crate::railgun::poi::inner_types::ChainParams {
        crate::railgun::poi::inner_types::ChainParams {
            chain_type: 0.to_string(), // EVM
            chain_id: self.chain.to_string(),
            txid_version: crate::railgun::poi::inner_types::TxidVersion::V2PoseidonMerkle,
        }
    }

    /// Submit POI proofs to the POI node after self-broadcasting.
    ///
    /// Call this after the transaction is confirmed on-chain to register the
    /// POI proofs with the POI node. The `data` should be obtained from
    /// `OperationBuilder::build_self_broadcast_with_poi`.
    pub async fn submit_poi(
        &self,
        data: &crate::railgun::transaction::broadcaster_data::PoiProvedTransaction,
    ) -> Result<(), PoiClientError> {
        for poi_op in &data.operations {
            for (list_key, poi) in &poi_op.pois {
                let params = crate::railgun::poi::inner_types::SubmitTransactProofParams {
                    chain: self.chain(),
                    list_key: list_key.clone(),
                    transact_proof_data: crate::railgun::poi::inner_types::TransactProofData {
                        snark_proof: poi.snark_proof.clone().into(),
                        poi_merkleroots: poi
                            .poi_merkleroots
                            .iter()
                            .map(|r| r.to_string())
                            .collect(),
                        txid_merkleroot: poi.txid_merkleroot.to_string(),
                        // TODO: This index should come from the circuit inputs
                        txid_merkleroot_index: 0,
                        blinded_commitments_out: poi
                            .blinded_commitments_out
                            .iter()
                            .map(|c| c.to_string())
                            .collect(),
                        railgun_txid_if_has_unshield: poi.railgun_txid_if_has_unshield.to_string(),
                    },
                };

                self.inner.submit_transact_proof(params).await?;
                info!("Submitted POI proof for list key {}", list_key);
            }
        }

        Ok(())
    }
}

impl TryFrom<crate::railgun::poi::inner_types::MerkleProof> for MerkleProof {
    type Error = PoiMerkleProofError;

    fn try_from(
        proof: crate::railgun::poi::inner_types::MerkleProof,
    ) -> Result<MerkleProof, Self::Error> {
        Ok(MerkleProof {
            element: hex_to_u256(&proof.leaf),
            elements: proof.elements.iter().map(|s| hex_to_u256(s)).collect(),
            indices: hex_to_u256(&proof.indices).saturating_to(),
            root: hex_to_u256(&proof.root),
        })
    }
}
