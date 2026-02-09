use ark_bn254::Fr;
use poseidon_rust::poseidon_hash;

#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf element
    pub element: Fr,
    /// Sibling elements along the proof path
    pub elements: Vec<Fr>,
    /// Bit-packed indices of the proof path
    pub indices: u32,
    /// The expected Merkle root
    pub root: Fr,
}

impl MerkleProof {
    pub fn new(element: Fr, elements: Vec<Fr>, indices: u32, root: Fr) -> Self {
        Self {
            element,
            elements,
            indices,
            root,
        }
    }

    /// Creates a deterministic proof for a given Txid leaf. This proof is
    /// used when computing inputs for the POI circuit, where we need a Txid leaf
    /// for a txid that has not yet been submitted on-chain (and consequentially
    /// has not been added to the TXID merkle tree).
    pub fn new_pre_inclusion(element: Fr) -> Self {
        Self::new_deterministic(element)
    }

    /// Creates a deterministic proof with a given element where the proof path is all zeros.
    pub fn new_deterministic(element: Fr) -> Self {
        let indices = 0;
        let elements = [Fr::from(0); 16].to_vec();

        let mut root = element;
        for e in elements.iter() {
            root = hash_left_right(root, *e);
        }

        Self {
            element,
            elements,
            indices,
            root,
        }
    }

    pub fn verify(&self) -> bool {
        let mut indices_bits = Vec::new();
        let mut idx = self.indices;
        for _ in 0..self.elements.len() {
            indices_bits.push(idx & 1);
            idx >>= 1;
        }

        let mut current_hash = self.element;

        for (i, &sibling) in self.elements.iter().enumerate() {
            let is_left_child = indices_bits[i] == 0;
            current_hash = if is_left_child {
                hash_left_right(current_hash, sibling)
            } else {
                hash_left_right(sibling, current_hash)
            };
        }

        current_hash == self.root
    }
}

fn hash_left_right(left: Fr, right: Fr) -> Fr {
    poseidon_hash(&[left, right]).unwrap()
}
