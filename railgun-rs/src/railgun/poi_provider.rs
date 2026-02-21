use std::sync::Arc;

use crate::railgun::{indexer::TxidIndexer, poi::PoiClient, provider::RailgunProvider};

pub struct PoiProvider {
    inner: RailgunProvider,

    txid_indexer: Arc<TxidIndexer>,
    poi_client: Arc<PoiClient>,
}

impl PoiProvider {
    /// Returns POI augmented balance, with metadata on the POI status for notes
    pub fn balance(&self) {
        todo!()
    }

    pub fn shield(&self) {
        todo!()
    }

    pub fn transact(&self) {
        todo!()
    }

    pub fn sync(&mut self) {
        todo!()
    }
}
