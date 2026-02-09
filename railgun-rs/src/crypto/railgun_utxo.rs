use ark_bn254::Fr;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Utxo(Fr);

impl From<Fr> for Utxo {
    fn from(value: Fr) -> Self {
        Utxo(value)
    }
}

impl Into<Fr> for Utxo {
    fn into(self) -> Fr {
        self.0
    }
}
