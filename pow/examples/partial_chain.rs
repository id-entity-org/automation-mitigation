//! Demonstrates root grinding with an incomplete chain. This is a correctness
//! demonstration at small sizes, not a benchmark of the cheapest attack.
//! cargo run -p automation-mitigation-pow --example partial_chain --release
use automation_mitigation_pow::{Challenge, DebugPrinter, ProgressReporter};

#[derive(Clone, Copy)]
struct Quiet;
impl DebugPrinter for Quiet {
    fn debug_println(&self, _: &str) {}
}
impl ProgressReporter for Quiet {
    fn increment(&self, _: u8) {}
}

fn main() {
    type Prefix = Challenge<1, 10, 128, 256, 8, 16>;
    type Full = Challenge<1, 10, 256, 256, 8, 16>;
    let nonce = [42; 16];
    let prefix = Prefix::generate_chain(0, &nonce, Quiet, Quiet);
    let prefix_hashes = Prefix::hash_chain(&prefix);
    let mut hashes = [[0; 16]; 256];
    hashes[..128].copy_from_slice(prefix_hashes.as_slice());
    for trial in 0u64..100_000 {
        // Change an uncomputed leaf to obtain a new root and new sample indices.
        hashes[255][..8].copy_from_slice(&trial.to_le_bytes());
        let state = Full::build_state(&[&hashes], Quiet);
        let root = state.root();
        let indices = Full::select_indices(&root);
        if indices.iter().any(|&i| i >= 128) {
            continue;
        }
        let parents = std::array::from_fn(|i| &prefix[indices[i] - 1]);
        let references = Full::select_reference_indices(&indices, &parents);
        let blocks = std::array::from_fn(|i| &prefix[references[i]]);
        let proof = Full::combine(
            state,
            &root,
            &indices,
            &references,
            &parents,
            &blocks,
            Quiet,
        );
        assert!(Full::verify_proof(&nonce, &proof).is_some());
        println!(
            "Accepted proof after {} roots, with only 126 of 254 nonzero-chain steps computed.",
            trial + 1
        );
        return;
    }
    panic!("No suitable root in the trial budget");
}
