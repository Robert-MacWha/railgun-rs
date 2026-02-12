use ruint::aliases::U256;

/// U256 wrapper for GraphQL serialization/deserialization as decimal string
#[derive(Debug, Clone)]
pub struct BigInt(pub U256);

impl std::fmt::Display for BigInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<U256> for BigInt {
    fn from(v: U256) -> Self {
        BigInt(v)
    }
}

impl From<u64> for BigInt {
    fn from(v: u64) -> Self {
        BigInt(U256::from(v))
    }
}

impl From<BigInt> for U256 {
    fn from(b: BigInt) -> Self {
        b.0
    }
}

// For serde serialization as decimal string
impl serde::Serialize for BigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let u = U256::from_str_radix(&s, 10).map_err(serde::de::Error::custom)?;
        Ok(BigInt(u))
    }
}
