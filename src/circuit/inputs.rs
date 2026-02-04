use num_bigint::BigInt;

pub struct CircuitInputs {
    // Public Inputs
    merkle_root: BigInt,
    bound_params_hash: BigInt,
    nullifiers: Vec<BigInt>,
    commitments_out: Vec<BigInt>,

    // Private Inputs
    token: BigInt,
    public_key: [BigInt; 2],
    signature: [BigInt; 3],
    random_in: Vec<BigInt>,
    value_in: Vec<BigInt>,
    path_elements: Vec<Vec<BigInt>>,
    leaves_indices: Vec<BigInt>,
    nullifying_key: BigInt,
    npk_out: Vec<BigInt>,
    value_out: Vec<BigInt>,
}

impl CircuitInputs {
    pub fn new(
        merkle_root: BigInt,
        bound_params_hash: BigInt,
        nullifiers: Vec<BigInt>,
        commitments_out: Vec<BigInt>,
        token: BigInt,
        public_key: [BigInt; 2],
        signature: [BigInt; 3],
        random_in: Vec<BigInt>,
        value_in: Vec<BigInt>,
        path_elements: Vec<Vec<BigInt>>,
        leaves_indices: Vec<BigInt>,
        nullifying_key: BigInt,
        npk_out: Vec<BigInt>,
        value_out: Vec<BigInt>,
    ) -> Self {
        CircuitInputs {
            merkle_root,
            bound_params_hash,
            nullifiers,
            commitments_out,
            token,
            public_key,
            signature,
            random_in,
            value_in,
            path_elements,
            leaves_indices,
            nullifying_key,
            npk_out,
            value_out,
        }
    }
}
