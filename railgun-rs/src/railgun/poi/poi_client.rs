use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use alloy::primitives::ChainId;
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tracing::info;

use crate::railgun::{
    merkle_tree::{MerkleProof, MerkleRoot, MerkleTreeVerifier},
    note::{IncludedNote, utxo::UtxoNote},
    poi::{
        poi_note::PoiNote,
        types::{
            BlindedCommitment, BlindedCommitmentData, ChainParams, GetMerkleProofsParams,
            GetPoisPerListParams, ListKey, NodeStatusAllNetworks, PoisPerListMap,
            SubmitTransactProofParams, TransactProofData, TxidVersion,
            ValidatePoiMerklerootsParams, ValidateTxidMerklerootParams, ValidatedRailgunTxidStatus,
        },
    },
};

pub struct PoiClient {
    http: Client,
    url: String,
    next_id: AtomicU64,

    chain: ChainId,
    status: NodeStatusAllNetworks,
}

#[derive(Debug, Error)]
pub enum PoiClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON-RPC error: {0}")]
    Rpc(JsonRpcError),
    #[error("Null result from RPC")]
    NullResult,
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("Invalid POI Merkle root for list key {0:?}: {1}")]
    InvalidPoiMerkleRoot(ListKey, MerkleRoot),
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    id: u64,
    params: P,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<R> {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<R>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl PoiClient {
    pub async fn new(url: impl Into<String>, chain: ChainId) -> Result<Self, PoiClientError> {
        let next_id = AtomicU64::new(1);
        let http = Client::new();
        let url = url.into();

        let status: NodeStatusAllNetworks = call(
            &next_id,
            &http,
            &url,
            "ppoi_node_status",
            serde_json::json!({}),
        )
        .await?;
        // info!("Fetched POI node status: {:#?}", status);

        Ok(Self {
            http,
            url,
            next_id,
            chain,
            status,
        })
    }

    /// Checks the health of the POI node
    pub async fn health(&self) -> bool {
        let resp = self.call::<Vec<()>, String>("ppoi_health", vec![]).await;
        match resp {
            Ok(status) if status.to_lowercase() == "ok" => true,
            _ => false,
        }
    }

    /// Returns the list keys that the POI node is tracking
    pub fn list_keys(&self) -> Vec<ListKey> {
        self.status.list_keys.clone()
    }

    /// Returns the POIs for the given list keys and blinded commitments.
    pub async fn pois(
        &self,
        list_keys: Vec<ListKey>,
        blinded_commitment_datas: Vec<BlindedCommitmentData>,
    ) -> Result<PoisPerListMap, PoiClientError> {
        self.call(
            "ppoi_pois_per_list",
            GetPoisPerListParams {
                chain: self.chain(),
                list_keys,
                blinded_commitment_datas,
            },
        )
        .await
    }

    /// Converts a list of UTXO notes into POI notes by fetching the necessary
    /// merkle proofs from the POI node for the given list keys.
    pub async fn note_to_poi_note<S>(
        &self,
        notes: Vec<UtxoNote<S>>,
        list_keys: &[ListKey],
    ) -> Result<Vec<PoiNote<S>>, PoiClientError> {
        let blinded_commitments = notes
            .iter()
            .map(|n| n.blinded_commitment().into())
            .collect();
        let proofs = self.merkle_proofs(blinded_commitments, list_keys).await?;

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

    /// Fetches the POI merkle proofs for the given blinded commitments and
    /// list keys.
    pub async fn merkle_proofs(
        &self,
        blinded_commitments: Vec<BlindedCommitment>,
        list_keys: &[ListKey],
    ) -> Result<HashMap<ListKey, Vec<MerkleProof>>, PoiClientError> {
        let mut proofs = HashMap::new();
        for list_key in list_keys.iter() {
            let list_key_proofs: Vec<MerkleProof> = self
                .call(
                    "ppoi_merkle_proofs",
                    GetMerkleProofsParams {
                        chain: self.chain(),
                        list_key: list_key.clone(),
                        blinded_commitments: blinded_commitments.clone(),
                    },
                )
                .await?;

            proofs.insert(list_key.clone(), list_key_proofs);
        }

        Ok(proofs)
    }

    /// Submits a proved operation to the POI node.
    /// TODO: Update this to accept a new IncludedOperation or IndexedOperation that
    /// comes from txid syncing. We need to provide real txid merkle root / merkle root index,
    /// not the dummy values used for broadcasting / proving.
    pub async fn submit_operation(
        &self,
        op: HashMap<ListKey, TransactProofData>,
    ) -> Result<(), PoiClientError> {
        for (list_key, proof_data) in op {
            let resp: serde_json::Value = self
                .call(
                    "ppoi_submit_transact_proof",
                    SubmitTransactProofParams {
                        chain: self.chain(),
                        list_key: list_key.clone(),
                        transact_proof_data: proof_data,
                    },
                )
                .await?;

            info!("Submitted proof for list key {}: {}", list_key, resp);
        }

        Ok(())
    }

    /// Returns the current validated txid status from the POI node.
    pub async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
        self.call("ppoi_validated_txid", self.chain()).await
    }

    /// Validates a txid merkle root against the POI node.
    pub async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u64,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError> {
        self.call(
            "ppoi_validate_txid_merkleroot",
            ValidateTxidMerklerootParams {
                chain: self.chain(),
                tree,
                index,
                merkleroot,
            },
        )
        .await
    }

    /// Validates a POI merkle root against the POI node.
    pub async fn validate_poi_merkleroot(
        &self,
        list_key: ListKey,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError> {
        self.call(
            "ppoi_validate_poi_merkleroots",
            ValidatePoiMerklerootsParams {
                chain: self.chain(),
                list_key,
                poi_merkleroots: vec![merkleroot],
            },
        )
        .await
    }

    fn chain(&self) -> ChainParams {
        ChainParams {
            chain_type: 0.to_string(), // EVM
            chain_id: self.chain.to_string(),
            txid_version: TxidVersion::V2PoseidonMerkle,
        }
    }
}

impl PoiClient {
    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, PoiClientError> {
        call(&self.next_id, &self.http, &self.url, method, params).await
    }
}

async fn call<P: Serialize, R: DeserializeOwned>(
    next_id: &AtomicU64,
    http: &Client,
    url: &str,
    method: &'static str,
    params: P,
) -> Result<R, PoiClientError> {
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method,
        id,
        params,
    };

    info!("Calling RPC method: {}", method);
    info!("Request: {}", serde_json::to_string(&req).unwrap());

    let resp: JsonRpcResponse<R> = http
        .post(url)
        .header("connection", "close")
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = resp.error {
        return Err(PoiClientError::Rpc(err));
    }
    resp.result.ok_or(PoiClientError::NullResult)
}

#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
impl MerkleTreeVerifier for PoiClient {
    async fn verify_root(
        &self,
        tree_number: u32,
        tree_index: u64,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .validate_txid_merkleroot(tree_number, tree_index, root)
            .await?)
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}
