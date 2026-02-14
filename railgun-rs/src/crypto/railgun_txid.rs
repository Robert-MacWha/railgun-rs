use ruint::{aliases::U256};

use crate::{
    crypto::{poseidon::poseidon_hash, railgun_zero::railgun_merkle_tree_zero},
    railgun::indexer::indexer::TOTAL_LEAVES,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TxidLeaf(U256);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Txid(U256);

pub enum UtxoTreeOut {
    /// Transactions that have been included in the UTXO merkle tree (IE those
    /// that have been submitted on-chain to the RailgunSmartWallet) will have a
    /// defined position in the tree.
    Included { tree_number: u32, start_index: u32 },
    /// Transactions that have been generated but not yet included on-chain (
    /// IE those being prepared for POI proof generation) use the pre-inclusion
    /// constants.
    PreInclusion,
    /// Transactions that only involve unshielding (IE those with no commitments)
    /// do not add any leaves to the UTXO tree, so they use the unshield-only constants.
    UnshieldOnly,
}

const GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE: u64 = 99999;
const GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE: u64 = 99999;
const GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE: u64 = 199999;
const GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE: u64 = 199999;

impl UtxoTreeOut {
    pub fn included(tree_number: u32, start_index: u32) -> Self {
        UtxoTreeOut::Included {
            tree_number,
            start_index,
        }
    }

    pub fn pre_inclusion() -> Self {
        UtxoTreeOut::PreInclusion
    }

    pub fn unshield_only() -> Self {
        UtxoTreeOut::UnshieldOnly
    }

    /// TODO: Add tests for me
    pub fn global_index(&self) -> u64 {
        let (tree_number, start_index) = match self {
            UtxoTreeOut::Included {
                tree_number,
                start_index,
            } => (*tree_number as u64, *start_index as u64),
            UtxoTreeOut::PreInclusion => (
                GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
                GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
            ),
            UtxoTreeOut::UnshieldOnly => (
                GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE,
                GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
            ),
        };

        tree_number * (TOTAL_LEAVES as u64) + start_index
    }
}

impl TxidLeaf {
    pub fn new(txid: Txid, utxo_tree_in: u32, utxo_tree_out: UtxoTreeOut) -> Self {
        let global_position = utxo_tree_out.global_index();

        poseidon_hash(&[
            txid.into(),
            U256::from(utxo_tree_in),
            U256::from(global_position),
        ])
        .unwrap()
        .into()
    }
}

impl From<U256> for TxidLeaf {
    fn from(value: U256) -> Self {
        TxidLeaf(value)
    }
}

impl Into<U256> for TxidLeaf {
    fn into(self) -> U256 {
        self.0
    }
}

impl Txid {
    pub fn new(nullifiers: &[U256], commitments: &[U256], bound_params_hash: U256) -> Self {
        let max_nullifiers = 13; // Max circuit inputs
        let max_commitments = 13; // Max circuit outputs

        // This is deeply unfortunate given the performance implications
        let mut nullifiers_padded = [railgun_merkle_tree_zero(); 13];
        let mut commitments_padded = [railgun_merkle_tree_zero(); 13];

        for (i, &nullifier) in nullifiers.iter().take(max_nullifiers).enumerate() {
            nullifiers_padded[i] = nullifier;
        }
        for (i, &commitment) in commitments.iter().take(max_commitments).enumerate() {
            commitments_padded[i] = commitment;
        }

        let nullifiers_hash = poseidon_hash(&nullifiers_padded).unwrap();
        let commitments_hash = poseidon_hash(&commitments_padded).unwrap();

        poseidon_hash(&[nullifiers_hash, commitments_hash, bound_params_hash])
            .unwrap()
            .into()
    }
}

impl From<U256> for Txid {
    fn from(value: U256) -> Self {
        Txid(value)
    }
}

impl Into<U256> for Txid {
    fn into(self) -> U256 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ruint::uint;

    #[test]
    fn test_txid() {
        let txid = Txid::new(
            &[
                uint!(13715694855377408371089601959277332264580227086500088662374474180290571297793_U256),
                uint!(4879960293526035536337105771650901564439892825648159183025591237708347140334_U256),
            ],
            &[
uint!(12207157656628265423438060380057846656543786903997769688185483156243865679225_U256),            
uint!(21704732194337337773381894542943230082317724786316223111256657768939470463625_U256),
uint!(3419899127455500147715903774774198308673930432280940502846714726325919416502_U256),
            ],
            uint!(20104295272660775597730850404771326812479727572119535488383037433725311268740_U256),
        );

        assert_eq!(
            txid.0,
            uint!(16377560740762083297602124407587012236402803616921752695154194813882621728488_U256),
        );
    }

    #[test]
    fn test_txid_leaf_hash() {
        let txid = Txid(uint!(0_U256));
        let leaf_hash = TxidLeaf::new(
            txid,
            1,
            UtxoTreeOut::Included {
                tree_number: 2,
                start_index: 3,
            },
        );

        assert_eq!(
            leaf_hash.0,
            uint!(6745812227361017099581501373645245177541765188484161512119790239305301021488_U256),
        );
    }
}
