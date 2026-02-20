use criterion::{Criterion, criterion_group, criterion_main};
use railgun_rs::railgun::merkle_tree::MerkleTree;
use ruint::aliases::U256;

const TREE_DEPTH: usize = 14;
const FULL_TREE_SIZE: usize = 1 << TREE_DEPTH;

fn bench_full_tree_fill(c: &mut Criterion) {
    c.bench_function("fill_full_16depth_tree", |b| {
        b.iter(|| {
            let mut tree = MerkleTree::new(0);
            let leaves: Vec<U256> = (1..=FULL_TREE_SIZE as u64).map(U256::from).collect();
            let mut batch = tree.begin_batch();
            batch.insert_leaves(&leaves, 0);
            // drop commits and rebuilds
        });
    });
}

fn bench_single_leaf_edit(c: &mut Criterion) {
    let mut tree = MerkleTree::new(0);
    let leaves: Vec<U256> = (1..=FULL_TREE_SIZE as u64).map(U256::from).collect();
    {
        let mut batch = tree.begin_batch();
        batch.insert_leaves(&leaves, 0);
    }

    c.bench_function("single_leaf_edit_16depth_tree", |b| {
        b.iter(|| {
            tree.insert_leaf(U256::from(42u64), 0);
        });
    });
}

criterion_group!(benches, bench_full_tree_fill, bench_single_leaf_edit);
criterion_main!(benches);
