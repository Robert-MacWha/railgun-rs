pub const WAKU_RAILGUN_PUB_SUB_TOPIC: &str = "/waku/2/rs/1/1";

pub fn fee_content_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{}-fees/json", chain_id)
}

pub fn transact_content_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{}-transact/json", chain_id)
}

pub fn transact_response_content_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{}-transact-response/json", chain_id)
}
