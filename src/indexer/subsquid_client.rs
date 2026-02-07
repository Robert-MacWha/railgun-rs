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
    pub tree_number: u32,
    pub tree_position: u32,
    pub id: String,
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
        let mut last_id: Option<String> = None;
        let limit = 10000u32;

        loop {
            let batch = self
                .fetch_commitments(from_block, to_block, limit, last_id.as_deref())
                .await?;
            let batch_len = batch.len();

            if let Some(last) = batch.last() {
                last_id = Some(last.id.clone());
            }

            all.extend(batch);

            if batch_len < limit as usize {
                break;
            }
        }

        Ok(all)
    }

    pub async fn fetch_commitments(
        &self,
        from_block: u64,
        to_block: Option<u64>,
        limit: u32,
        after_id: Option<&str>,
    ) -> Result<Vec<Commitment>, SubsquidError> {
        let block_filter = match to_block {
            Some(to) => format!(
                "blockNumber_gte: \"{}\", blockNumber_lte: \"{}\"",
                from_block, to
            ),
            None => format!("blockNumber_gte: \"{}\"", from_block),
        };

        let id_filter = match after_id {
            Some(id) => format!(", id_gt: \"{}\"", id),
            None => String::new(),
        };

        let query = format!(
            r#"{{
            commitments(
                orderBy: id_ASC,
                limit: {limit},
                where: {{ {block_filter}{id_filter} }}
            ) {{
                id
                treeNumber
                treePosition
                hash
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
