use crate::crypto::keys::SpendingKey;
use crate::crypto::keys::ViewingKey;
use crate::railgun::address::RailgunAddress;

#[derive(Clone)]
pub struct RailgunAccount {
    address: RailgunAddress,
    viewing_key: ViewingKey,
    spending_key: SpendingKey,
}

const SPENDING_DERIVATION_PATH: &str = "m/44'/1984'/0'/0'/";
const VIEWING_DERIVATION_PATH: &str = "m/420'/1984'/0'/0'/";

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
