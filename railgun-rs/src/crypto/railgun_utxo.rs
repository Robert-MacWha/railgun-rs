use ruint::aliases::U256;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UtxoLeafHash(U256);

impl From<U256> for UtxoLeafHash {
    fn from(value: U256) -> Self {
        UtxoLeafHash(value)
    }
}

impl Into<U256> for UtxoLeafHash {
    fn into(self) -> U256 {
        self.0
    }
}
