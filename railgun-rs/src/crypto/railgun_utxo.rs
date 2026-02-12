use ruint::aliases::U256;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UtxoLeaf(U256);

impl From<U256> for UtxoLeaf {
    fn from(value: U256) -> Self {
        UtxoLeaf(value)
    }
}

impl Into<U256> for UtxoLeaf {
    fn into(self) -> U256 {
        self.0
    }
}
