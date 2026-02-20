use serde::{Deserialize, Serialize};

use crate::{
    crypto::keys::{SpendingKey, ViewingKey},
    railgun::address::RailgunAddress,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RailgunAccount {
    address: RailgunAddress,
    viewing_key: ViewingKey,
    spending_key: SpendingKey,
}

impl RailgunAccount {
    pub fn new(spending_key: SpendingKey, viewing_key: ViewingKey, chain_id: u64) -> Self {
        RailgunAccount {
            address: RailgunAddress::from_private_keys(spending_key, viewing_key, chain_id),
            spending_key,
            viewing_key,
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    pub fn spending_key(&self) -> SpendingKey {
        self.spending_key
    }

    pub fn viewing_key(&self) -> ViewingKey {
        self.viewing_key
    }
}
