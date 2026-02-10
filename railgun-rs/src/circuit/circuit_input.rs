use num_bigint::BigInt;

pub trait IntoSignalVec {
    fn into_signal_vec(self) -> Vec<BigInt>;
}

impl IntoSignalVec for BigInt {
    fn into_signal_vec(self) -> Vec<BigInt> {
        vec![self]
    }
}

impl<const N: usize> IntoSignalVec for [BigInt; N] {
    fn into_signal_vec(self) -> Vec<BigInt> {
        self.into()
    }
}

impl IntoSignalVec for Vec<BigInt> {
    fn into_signal_vec(self) -> Vec<BigInt> {
        self
    }
}

impl IntoSignalVec for Vec<Vec<BigInt>> {
    fn into_signal_vec(self) -> Vec<BigInt> {
        self.into_iter().flatten().collect()
    }
}

#[macro_export]
macro_rules! circuit_inputs {
    ($($field:ident => $key:literal),* $(,)?) => {
        pub fn as_flat_map(&self) -> HashMap<String, Vec<BigInt>> {
            let mut m = HashMap::new();
            $(m.insert($key.into(), self.$field.clone().into_signal_vec());)*
            m
        }
    };
}
