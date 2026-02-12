use ruint::aliases::U256;

pub trait IntoSignalVec {
    fn into_signal_vec(self) -> Vec<U256>;
}

impl IntoSignalVec for U256 {
    fn into_signal_vec(self) -> Vec<U256> {
        vec![self]
    }
}

impl<const N: usize> IntoSignalVec for [U256; N] {
    fn into_signal_vec(self) -> Vec<U256> {
        self.into()
    }
}

impl IntoSignalVec for Vec<U256> {
    fn into_signal_vec(self) -> Vec<U256> {
        self
    }
}

impl IntoSignalVec for Vec<Vec<U256>> {
    fn into_signal_vec(self) -> Vec<U256> {
        self.into_iter().flatten().collect()
    }
}

#[macro_export]
macro_rules! circuit_inputs {
    ($($field:ident => $key:literal),* $(,)?) => {
        pub fn as_flat_map(&self) -> HashMap<String, Vec<U256>> {
            let mut m = HashMap::new();
            $(m.insert($key.into(), self.$field.clone().into_signal_vec());)*
            m
        }
    };
}
