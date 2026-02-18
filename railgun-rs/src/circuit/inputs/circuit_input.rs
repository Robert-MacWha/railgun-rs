use ruint::aliases::U256;

use crate::{
    crypto::railgun_txid::{Txid, TxidLeafHash},
    railgun::merkle_tree::merkle_proof::MerkleRoot,
};

pub trait IntoU256 {
    fn into_u256(self) -> U256;
}

pub trait FromU256: Sized {
    fn from_u256(u: U256) -> Self;
}

impl IntoU256 for U256 {
    fn into_u256(self) -> U256 {
        self
    }
}

impl FromU256 for U256 {
    fn from_u256(u: U256) -> Self {
        u
    }
}

impl IntoU256 for u64 {
    fn into_u256(self) -> U256 {
        U256::from(self)
    }
}

impl IntoU256 for u32 {
    fn into_u256(self) -> U256 {
        U256::from(self)
    }
}

impl IntoU256 for MerkleRoot {
    fn into_u256(self) -> U256 {
        self.into()
    }
}

impl FromU256 for MerkleRoot {
    fn from_u256(u: U256) -> Self {
        u.into()
    }
}

impl IntoU256 for Txid {
    fn into_u256(self) -> U256 {
        self.into()
    }
}

impl FromU256 for Txid {
    fn from_u256(u: U256) -> Self {
        u.into()
    }
}

impl IntoU256 for TxidLeafHash {
    fn into_u256(self) -> U256 {
        self.into()
    }
}

impl FromU256 for TxidLeafHash {
    fn from_u256(u: U256) -> Self {
        u.into()
    }
}

pub trait IntoSignalVec {
    fn into_signal_vec(self) -> Vec<U256>;
}

impl<T> IntoSignalVec for T
where
    T: IntoU256,
{
    fn into_signal_vec(self) -> Vec<U256> {
        vec![self.into_u256()]
    }
}

impl<T, const N: usize> IntoSignalVec for [T; N]
where
    T: IntoU256,
{
    fn into_signal_vec(self) -> Vec<U256> {
        self.into_iter().map(|x| x.into_u256()).collect()
    }
}

impl<T> IntoSignalVec for Vec<T>
where
    T: IntoU256,
{
    fn into_signal_vec(self) -> Vec<U256> {
        self.into_iter().map(|x| x.into_u256()).collect()
    }
}

impl<T> IntoSignalVec for Vec<Vec<T>>
where
    T: IntoU256,
{
    fn into_signal_vec(self) -> Vec<U256> {
        self.into_iter().flatten().map(|x| x.into_u256()).collect()
    }
}

/// A macro to generate the `as_flat_map` method for circuit inputs.
#[macro_export]
macro_rules! circuit_inputs {
    ($($field:ident => $key:literal),* $(,)?) => {
        /// Flattens the circuit inputs into a map of string keys to []U256 values
        /// for proof generation.
        pub fn as_flat_map(&self) -> HashMap<String, Vec<U256>> {
            let mut m = HashMap::new();
            $(m.insert($key.into(), self.$field.clone().into_signal_vec());)*
            m
        }
    };
}
