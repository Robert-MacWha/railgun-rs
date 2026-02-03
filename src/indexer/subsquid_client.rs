use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

pub struct SubsquidClient {
    client: Client,
    endpoint: String,
}

#[derive(Debug, Serialize)]
struct GraphQLRequest {
    query: String,
}

#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitmentsData {
    commitments: Vec<Commitment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Commitment {
    pub hash: String,
    pub tree_number: i32,
    pub tree_position: i32,
    pub block_number: String,
    pub commitment_type: String,
    pub transaction_hash: String,
}

#[derive(Debug, Error)]
pub enum SubsquidError {
    #[error("HTTP request error: {0}")]
    HttpRequestError(#[from] reqwest::Error),
}

impl SubsquidClient {
    pub fn new(endpoint: &str) -> Self {
        SubsquidClient {
            client: Client::new(),
            endpoint: endpoint.to_string(),
        }
    }

    /// Fetch all commitments, auto-paginating
    pub async fn fetch_all_commitments(
        &self,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<Commitment>, SubsquidError> {
        let mut all = Vec::new();
        let mut offset = 0u32;
        let limit = 10000u32;

        loop {
            info!(
                "Fetching commitments: from_block={}, to_block={:?}, limit={}, offset={}",
                from_block, to_block, limit, offset
            );
            let batch = self
                .fetch_commitments(from_block, to_block, limit, offset)
                .await?;
            let batch_len = batch.len();
            all.extend(batch);

            if batch_len < limit as usize {
                break;
            }
            offset += limit;
        }

        Ok(all)
    }

    pub async fn fetch_commitments(
        &self,
        from_block: u64,
        to_block: Option<u64>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Commitment>, SubsquidError> {
        let block_filter = match to_block {
            Some(to) => format!(
                "blockNumber_gte: \"{}\", blockNumber_lte: \"{}\"",
                from_block, to
            ),
            None => format!("blockNumber_gte: \"{}\"", from_block),
        };

        let query = format!(
            r#"{{
                commitments(
                    orderBy: treePosition_ASC,
                    limit: {limit},
                    offset: {offset},
                    where: {{ {block_filter} }}
                ) {{
                    hash
                    treeNumber
                    treePosition
                    blockNumber
                    commitmentType
                    transactionHash
                }}
            }}"#
        );

        let resp: GraphQLResponse<CommitmentsData> = self
            .client
            .post(&self.endpoint)
            .json(&GraphQLRequest { query })
            .send()
            .await?
            .json()
            .await?;

        Ok(resp.data.commitments)
    }
}
