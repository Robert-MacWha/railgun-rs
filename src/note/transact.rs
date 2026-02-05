use std::{collections::BTreeMap, fs};

use alloy::primitives::{Address, FixedBytes, U256, aliases::U120};
use alloy_sol_types::SolCall;
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction, read_zkey};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use num_bigint::BigInt;
use rand::random;
use tracing::info;

use crate::{
    abis::railgun::{
        CommitmentCiphertext, CommitmentPreimage, G1Point, G2Point,
        RailgunSmartWallet::transactCall, SnarkProof, Transaction, UnshieldType,
    },
    caip::{AccountId, AssetId},
    chain_config::ChainConfig,
    circuit::inputs::CircuitInputs,
    crypto::{
        keys::{FieldKey, SpendingKey, ViewingKey, bigint_to_fr, fq_to_u256, fr_to_u256},
        poseidon::poseidon_hash,
    },
    indexer::notebook::Notebook,
    merkle_tree::MerkleTree,
    note::note::{EncryptError, Note, encrypt_note},
    railgun::address::RailgunAddress,
    tx_data::TxData,
};

pub trait TransactNote {
    fn hash(&self) -> Fr;
    fn note_public_key(&self) -> Fr;
    fn value(&self) -> u128;
}

trait EncryptableNote {
    fn encrypt(
        &self,
        viewing_key: ViewingKey,
        blind: bool,
    ) -> Result<CommitmentCiphertext, EncryptError>;
}

/// TreeTransaction represents a full transaction on a single Merkle tree.
///
/// Supports many input notes, many transfer notes, a single unshield note,
/// and a single change note.
///
/// Note: The railgun contracts currently only support a single unshield operation
/// per transaction. This is because there's only one unshield preimage in the
/// transaction data.
#[derive(Debug, Clone)]
struct TreeTransaction {
    /// (note_in, nullifier)
    notes_in: Vec<(Note, Fr)>,
    transfers_out: Vec<TransferNote>,
    unshield: Option<UnshieldNote>,
    change: Option<Note>,
}

#[derive(Debug, Clone)]
struct UnshieldNote {
    receiver: Address,
    asset: AssetId,
    value: u128,
}

#[derive(Debug, Clone)]
struct TransferNote {
    receiver: RailgunAddress,
    asset: AssetId,
    value: u128,
    random: [u8; 16],
    memo: String,
}

pub fn create_transaction(
    merkle_trees: &mut BTreeMap<u32, MerkleTree>,
    min_gas_price: u128,
    chain: ChainConfig,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    sender_spending_key: SpendingKey,
    sender_viewing_key: ViewingKey,
    notebook: &mut Notebook,
    asset: AssetId,
    value: u128,
    receiver: AccountId,
) -> Result<TxData, EncryptError> {
    // TODO: Figure out under what conditions this should be `UnshieldType::REDIRECT`
    let unshield = match receiver {
        AccountId::Railgun(_) => UnshieldType::NONE,
        AccountId::Eip155(_) => UnshieldType::NORMAL,
    };

    info!("Selecting notes for transaction...");
    let tree_txns = get_transact_notes(
        notebook,
        sender_spending_key,
        sender_viewing_key,
        asset.clone(),
        value,
        receiver,
    );

    let mut transactions = Vec::new();
    for (tree_number, tree_tx) in tree_txns {
        info!("Processing tree {}", tree_number);
        let merkle_tree = merkle_trees.get_mut(&tree_number).unwrap();

        // Load circuit artifacts
        let notes_in: Vec<Note> = tree_tx.notes_in().clone();
        let notes_out = tree_tx.notes_out();
        let (mut builder, params) = load_artifacts(notes_in.len(), notes_out.len());

        // Construct circuit inputs
        let commitment_ciphertexts: Vec<CommitmentCiphertext> = tree_tx
            .encryptable_notes_out()
            .iter()
            .map(|n| n.encrypt(sender_viewing_key, false))
            .collect::<Result<Vec<_>, _>>()?;
        let inputs = CircuitInputs::format(
            merkle_tree,
            min_gas_price,
            unshield,
            chain.id,
            adapt_contract,
            adapt_input,
            notes_in,
            notes_out,
            commitment_ciphertexts,
        )
        .unwrap();

        // Build the circuit
        info!("Building circuit for tree {}", tree_number);

        for (name, values) in inputs.as_flat_map() {
            for value in values {
                builder.push_input(&name, value);
            }
        }

        let circom = builder.build().unwrap();
        let public_inputs = circom.get_public_inputs().unwrap();

        info!("Generating proof for tree {}", tree_number);

        let mut rng = ark_std::rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circom, &params, &mut rng,
        )
        .unwrap();

        info!("Verifying proof for tree {}", tree_number);

        let pvk = prepare_verifying_key(&params.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        assert!(verified, "Proof verification failed");
        info!("Proof verified successfully for tree {}", tree_number);

        let transaction = Transaction {
            proof: SnarkProof {
                a: G1Point {
                    x: fq_to_u256(&proof.a.x().unwrap()),
                    y: fq_to_u256(&proof.a.y().unwrap()),
                },
                b: G2Point {
                    x: [
                        fq_to_u256(&proof.b.x().unwrap().c1),
                        fq_to_u256(&proof.b.x().unwrap().c0),
                    ],
                    y: [
                        fq_to_u256(&proof.b.y().unwrap().c1),
                        fq_to_u256(&proof.b.y().unwrap().c0),
                    ],
                },
                c: G1Point {
                    x: fq_to_u256(&proof.c.x().unwrap()),
                    y: fq_to_u256(&proof.c.y().unwrap()),
                },
            },
            merkleRoot: bigint_to_bytes(&inputs.merkle_root),
            nullifiers: inputs.nullifiers.iter().map(bigint_to_bytes).collect(),
            commitments: inputs.commitments_out.iter().map(bigint_to_bytes).collect(),
            boundParams: inputs.bound_params,
            unshieldPreimage: match tree_tx.unshield {
                Some(unshield) => {
                    info!(
                        "Unshield npk: {:?}",
                        fr_to_u256(&unshield.note_public_key())
                    );
                    info!(
                        "Unshield token_id: {:?}",
                        fr_to_u256(&unshield.asset.hash())
                    );
                    info!("Unshield value: {:?}", unshield.value);
                    info!("Unshield hash: {:?}", fr_to_u256(&unshield.hash()));
                    info!("Last commitment_out: {:?}", &inputs.commitments_out.last());
                    CommitmentPreimage {
                        npk: fr_to_u256(&unshield.note_public_key()).into(),
                        token: unshield.asset.into(),
                        value: U120::saturating_from(unshield.value),
                    }
                }
                //? If there's no unshield note, the preimage is ignored by the
                //? contract so we can just return a zeroed preimage. Just using
                //? `asset` for convenience.
                None => CommitmentPreimage {
                    npk: FixedBytes::ZERO,
                    token: asset.clone().into(),
                    value: U120::saturating_from(0),
                },
            },
        };

        transactions.push(transaction);
    }

    let call = transactCall {
        _transactions: transactions,
    };
    let calldata = call.abi_encode();

    Ok(TxData {
        to: chain.railgun_smart_wallet,
        data: calldata,
        value: U256::ZERO,
    })
}

fn bigint_to_bytes(value: &BigInt) -> FixedBytes<32> {
    fr_to_u256(&bigint_to_fr(value)).into()
}

fn load_artifacts(notes_in: usize, notes_out: usize) -> (CircomBuilder<Fr>, ProvingKey<Bn254>) {
    if notes_in != 1 || notes_out != 2 {
        todo!("Only 1 input and 2 output notes are supported currently");
    }

    const WASM_PATH: &str = "artifacts/01x02/01x02.wasm";
    const R1CS_PATH: &str = "artifacts/01x02/01x02.r1cs";
    const ZKEY_PATH: &str = "artifacts/01x02/01x02.zkey";

    let cfg = CircomConfig::<Fr>::new(WASM_PATH, R1CS_PATH).unwrap();
    let builder = CircomBuilder::new(cfg);

    let mut zkey_file = fs::File::open(ZKEY_PATH).unwrap();
    let (params, _matrices) = read_zkey(&mut zkey_file).unwrap();

    (builder, params)
}

impl TreeTransaction {
    pub fn new(
        notes_in: Vec<(Note, Fr)>,
        transfers_out: Vec<TransferNote>,
        unshield: Option<UnshieldNote>,
        change: Option<Note>,
    ) -> Self {
        TreeTransaction {
            notes_in,
            transfers_out,
            unshield,
            change,
        }
    }

    pub fn notes_in(&self) -> Vec<Note> {
        self.notes_in.iter().map(|(note, _)| note.clone()).collect()
    }

    pub fn nullifiers(&self) -> Vec<Fr> {
        self.notes_in
            .iter()
            .map(|(_, nullifier)| *nullifier)
            .collect()
    }

    pub fn notes_out(&self) -> Vec<Box<dyn TransactNote>> {
        let mut notes: Vec<Box<dyn TransactNote>> = Vec::new();

        if let Some(change) = &self.change {
            notes.push(Box::new(change.clone()));
        }

        for transfer in &self.transfers_out {
            notes.push(Box::new(transfer.clone()));
        }

        if let Some(unshield) = &self.unshield {
            notes.push(Box::new(unshield.clone()));
        }

        notes
    }

    pub fn encryptable_notes_out(&self) -> Vec<Box<dyn EncryptableNote>> {
        let mut notes: Vec<Box<dyn EncryptableNote>> = Vec::new();

        for transfer in &self.transfers_out {
            notes.push(Box::new(transfer.clone()));
        }

        if let Some(change) = &self.change {
            notes.push(Box::new(change.clone()));
        }

        notes
    }
}

impl UnshieldNote {
    pub fn new(receiver: Address, asset: AssetId, value: u128) -> Self {
        UnshieldNote {
            receiver,
            asset,
            value,
        }
    }
}

impl TransactNote for UnshieldNote {
    fn hash(&self) -> Fr {
        poseidon_hash(&[
            self.note_public_key(),
            self.asset.hash(),
            Fr::from(self.value),
        ])
    }

    fn note_public_key(&self) -> Fr {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(self.receiver.as_slice());
        Fr::from_be_bytes_mod_order(&bytes)
    }

    fn value(&self) -> u128 {
        self.value
    }
}

impl TransferNote {
    pub fn new(
        receiver: RailgunAddress,
        asset: AssetId,
        value: u128,
        random: [u8; 16],
        memo: &str,
    ) -> Self {
        TransferNote {
            receiver,
            asset,
            value,
            random,
            memo: memo.to_string(),
        }
    }
}

impl EncryptableNote for TransferNote {
    /// Encrypts the note into a CommitmentCiphertext
    ///
    /// If `blind` is true, the sender's address will be hidden to the receiver.
    fn encrypt(
        &self,
        viewing_key: ViewingKey,
        blind: bool,
    ) -> Result<CommitmentCiphertext, EncryptError> {
        encrypt_note(
            &self.receiver,
            &self.random,
            self.value,
            &self.asset,
            &self.memo,
            viewing_key,
            blind,
        )
    }
}

impl TransactNote for TransferNote {
    fn hash(&self) -> Fr {
        poseidon_hash(&[
            self.note_public_key(),
            self.asset.hash(),
            Fr::from(self.value),
        ])
    }

    fn note_public_key(&self) -> Fr {
        poseidon_hash(&[
            self.receiver.master_key().to_fr(),
            Fr::from_be_bytes_mod_order(&self.random),
        ])
    }

    fn value(&self) -> u128 {
        self.value
    }
}

impl EncryptableNote for Note {
    /// Encrypts the note into a CommitmentCiphertext
    ///
    /// If `blind` is true, the sender's address will be hidden to the receiver.
    fn encrypt(
        &self,
        viewing_key: ViewingKey,
        blind: bool,
    ) -> Result<CommitmentCiphertext, EncryptError> {
        self.encrypt(viewing_key, blind)
    }
}

impl TransactNote for Note {
    fn hash(&self) -> Fr {
        self.hash()
    }

    fn note_public_key(&self) -> Fr {
        self.note_public_key()
    }

    fn value(&self) -> u128 {
        self.value
    }
}

/// Gets the notes used and created in a transaction
///
/// The notes parameter is the sparse map of notes available to spend
/// for this account.
///
/// TODO: Add internal checks to ensure notes are this account's notes
fn get_transact_notes(
    notebook: &mut Notebook,
    sender_spending_key: SpendingKey,
    sender_viewing_key: ViewingKey,
    asset: AssetId,
    value: u128,
    receiver: AccountId,
) -> BTreeMap<u32, TreeTransaction> {
    let is_unshield = match receiver {
        AccountId::Railgun(_) => false,
        AccountId::Eip155(_) => true,
    };

    let mut tree_transactions = BTreeMap::new();
    let mut total_value: u128 = 0;

    // TODO: Mutate the notebook to mark notes as spent. Unfortunately we can't
    // add newly created notes to the notebook here because we don't know what
    // their leaf indices will be until they're inserted into the on-chain Merkle
    // tree.
    //
    // Note for future Robert: Consequentially this also means we're practically
    // limited to a single unshield per EVM transaction. In theory we could stuff
    // multiple unshields into multiple railgun transactions, but since each railgun
    // tx can only contain a single unshield AND we can't use notes created in the
    // same EVM tx, we'd be limited to unshielding the set of notes available at the
    // start of the EVM tx. So if you have 3 notes with each 5 WETH, you'd be able to
    // unshield 5 WETH to 3 people, or 15 to 1 person, but not 2 WETH to 5 people since
    // that would require using the newly created change notes. This API-error-dependant-
    // on-internal-state error is a bad code smell, so it's best to limit the API
    // to a single unshield per EVM tx.
    for (tree_number, notes) in notebook.unspent().iter() {
        let mut notes_in = Vec::new();
        let mut nullifiers = Vec::new();

        //? Technically I believe we could have multiple transfer notes per
        //? transaction per tree. However, for API simplicity I'm asserting
        //? that each `transaction` will only transfer to a single recipient.
        //? This can be revisited later and would result in more gas-efficient
        //? operations when privately transferring to multiple recipients.
        let mut transfer_note = Vec::new();
        let mut unshield_note = None;
        let mut change_note = None;
        let mut tree_value: u128 = 0;

        for (tree_position, note) in notes {
            if note.token != asset {
                continue;
            }

            tree_value += note.value;
            notes_in.push(note.clone());

            let nullifier = note.nullifier(*tree_position);
            nullifiers.push(nullifier);

            if total_value + tree_value >= value {
                break;
            }
        }

        if tree_value == 0 {
            continue;
        }

        //? Determin how much value to use from this tree,
        // and if there is any remainder.
        let needed = value - total_value;
        let used = tree_value.min(needed);
        let remainder = tree_value.saturating_sub(needed);

        if remainder > 0 {
            //? If the tree's notes cover the remaining needed value,
            //? create a change note for the remainder
            change_note = Some(Note::new(
                sender_spending_key,
                sender_viewing_key,
                &random(),
                remainder,
                asset.clone(),
                "",
            ));
        }

        //? Create the output note based on the used value
        if is_unshield {
            let receiver = match receiver {
                AccountId::Eip155(addr) => addr,
                _ => unreachable!(),
            };
            unshield_note = Some(UnshieldNote::new(receiver, asset.clone(), used));
        } else {
            let receiver = match receiver {
                AccountId::Railgun(addr) => addr,
                _ => unreachable!(),
            };
            transfer_note.push(TransferNote::new(
                receiver,
                asset.clone(),
                used,
                random(),
                "",
            ));
        };

        total_value += used;

        tree_transactions.insert(
            *tree_number,
            TreeTransaction {
                notes_in: notes_in
                    .into_iter()
                    .zip(nullifiers.iter().cloned())
                    .collect(),
                transfers_out: transfer_note,
                unshield: unshield_note,
                change: change_note,
            },
        );
    }

    tree_transactions
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use tracing_test::traced_test;

    use crate::{
        caip::AssetId,
        crypto::keys::{ByteKey, SpendingKey, ViewingKey, hex_to_fr},
        note::transact::{TransactNote, TransferNote, UnshieldNote},
        railgun::address::RailgunAddress,
    };

    #[test]
    #[traced_test]
    fn test_unshield_note_hash() {
        let note = UnshieldNote::new(
            address!("0x1234567890123456789012345678901234567890"),
            AssetId::Erc20(address!("0x0987654321098765432109876543210987654321")),
            10,
        );
        let hash = note.hash();

        let expected =
            hex_to_fr("0x12f0c138dd2766eedd92365ec2e1824fc37515d35eea3d2cc8ff1e991007663c");
        assert_eq!(hash, expected);
    }

    #[test]
    #[traced_test]
    fn test_transfer_note_hash() {
        let note = TransferNote::new(
            RailgunAddress::from_private_keys(
                SpendingKey::from_bytes([1u8; 32]),
                ViewingKey::from_bytes([2u8; 32]),
                1,
            ),
            AssetId::Erc20(address!("0x1234567890123456789012345678901234567890")),
            90,
            [2u8; 16],
            "memo",
        );
        let hash = note.hash();

        let expected =
            hex_to_fr("0x0238d33eb654c483bb7beb8dc44f2d364ee415414af794adf3cc40018d1412c1");
        assert_eq!(hash, expected);
    }

    /// Railgun requires that, if a transaction includes an unshield operation,
    /// it must be the last commitment in the transaction.
    #[test]
    #[traced_test]
    fn test_last_commitment_is_unshield() {
        let unshield_note = UnshieldNote::new(
            address!("0x1234567890123456789012345678901234567890"),
            AssetId::Erc20(address!("0x0987654321098765432109876543210987654321")),
            10,
        );
        let transfer_note = TransferNote::new(
            RailgunAddress::from_private_keys(
                SpendingKey::from_bytes([1u8; 32]),
                ViewingKey::from_bytes([2u8; 32]),
                1,
            ),
            AssetId::Erc20(address!("0x1234567890123456789012345678901234567890")),
            90,
            [2u8; 16],
            "memo",
        );

        let tree_tx = super::TreeTransaction::new(
            vec![],
            vec![transfer_note],
            Some(unshield_note.clone()),
            None,
        );

        let notes_out = tree_tx.notes_out();
        assert_eq!(notes_out.last().unwrap().hash(), unshield_note.hash());
    }
}
