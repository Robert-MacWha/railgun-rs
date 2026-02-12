use ruint::aliases::U256;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Utxo(U256);

impl From<U256> for Utxo {
    fn from(value: U256) -> Self {
        Utxo(value)
    }
}

impl Into<U256> for Utxo {
    fn into(self) -> U256 {
        self.0
    }
}
