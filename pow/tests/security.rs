#![cfg(all(feature = "generate", feature = "verify"))]

use automation_mitigation_pow::{Challenge, DebugPrinter, ProgressReporter};
use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct Quiet;
impl DebugPrinter for Quiet {
    fn debug_println(&self, _: &str) {}
}
impl ProgressReporter for Quiet {
    fn increment(&self, _: u8) {}
}

type Small = Challenge<1, 3, 32, 32, 1, 16>;

#[test]
fn nonzero_initial_blocks_are_allowed_but_the_transition_must_be_valid() {
    use tiny_keccak::{CShake, Hasher};

    // With three blocks, the sample is always block 2, its parent is block 1,
    // and its reference is block 0. Both initial blocks are deliberately nonzero.
    type Tiny = Challenge<1, 1, 3, 32, 0, 16>;
    let nonce = [7; 16];
    let mut chain = [[0x23; 32], [0x45; 32], [0; 32]];
    let mut intermediate = [0; 64];
    let mut initial = CShake::v256(b"pow", b"initial");
    initial.update(&chain[1]);
    initial.update(&chain[0]);
    initial.finalize(&mut intermediate);
    let mut final_hash = CShake::v256(b"pow", b"final");
    final_hash.update(&nonce);
    final_hash.update(&intermediate);
    final_hash.finalize(&mut chain[2]);

    let proof = Tiny::combine_chains(&[&chain], Quiet);
    assert!(Tiny::verify_proof(&nonce, &proof).is_some());
    assert!(Tiny::verify_proof(&[8; 16], &proof).is_none());

    chain[2][0] ^= 1;
    let invalid = Tiny::combine_chains(&[&chain], Quiet);
    assert!(Tiny::verify_proof(&nonce, &invalid).is_none());
}

#[test]
fn initializes_both_starting_blocks_without_overwriting_the_allocation() {
    // The old write_bytes count overwrote a tiny chain allocation and depended
    // on the previous heap contents. Keep sentinel bytes around the chain.
    type Tiny = Challenge<1, 3, 3, 32, 1, 16>;
    let mut storage = [[MaybeUninit::new([0xa5; 32]); 3]; 3];
    Tiny::generate_allocated_chain(0, &[7; 16], &mut storage[1], Quiet, Quiet);
    assert_eq!(unsafe { storage[0][2].assume_init() }, [0xa5; 32]);
    assert_eq!(unsafe { storage[2][0].assume_init() }, [0xa5; 32]);
    assert_eq!(unsafe { storage[1][0].assume_init() }, [0; 32]);
    assert_eq!(unsafe { storage[1][1].assume_init() }, [0; 32]);
    let chain = Tiny::generate_chain(0, &[7; 16], Quiet, Quiet);
    assert_eq!(unsafe { storage[1][2].assume_init() }, chain[2]);
    let proof = Tiny::combine_chains(&[&chain], Quiet);
    assert!(Tiny::verify_proof(&[7; 16], &proof).is_some());
}

#[test]
fn rejects_wrong_nonce_truncation_mutation_and_padding() {
    let nonce = [42; 16];
    let chain = Small::generate_chain(0, &nonce, Quiet, Quiet);
    let proof = Small::combine_chains(&[&chain], Quiet);
    assert!(Small::verify_proof(&nonce, &proof).is_some());
    assert!(Small::verify_proof(&[43; 16], &proof).is_none());
    for end in 0..proof.len() {
        assert!(Small::verify_proof(&nonce, &proof[..end]).is_none());
    }
    for i in 0..proof.len() {
        let mut changed = proof.to_vec();
        changed[i] ^= 1;
        assert!(Small::verify_proof(&nonce, &changed).is_none(), "byte {i}");
    }
    let mut padded = proof.to_vec();
    padded.push(0);
    assert!(Small::verify_proof(&nonce, &padded).is_none());
    assert!(Small::verify_proof(&nonce, &vec![0; Small::MAX_PROOF_BYTES + 1]).is_none());

    let length_offset = 16 + 8 + 16 + 2 * 32;
    let mut oversized = proof.to_vec();
    oversized[length_offset..length_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Small::verify_proof(&nonce, &oversized).is_none());
}

#[test]
fn non_power_of_two_tree_roundtrip() {
    type Uneven = Challenge<3, 10, 17, 32, 2, 16>;
    let nonce = [99; 16];
    let chains = Uneven::generate_chains(&nonce, Quiet, Quiet);
    let proof = Uneven::combine_chains(&[&chains[0], &chains[1], &chains[2]], Quiet);
    assert!(proof.len() <= Uneven::MAX_PROOF_BYTES);
    assert!(Uneven::verify_proof(&nonce, &proof).is_some());
}

#[test]
fn custom_parameters_without_extra_passes_remain_supported() {
    // These settings still perform the initial/final hashes. They are caller
    // difficulty choices, not malformed parameters that must be forbidden.
    type Custom = Challenge<1, 3, 17, 32, 0, 8>;
    let nonce = [17; 16];
    let chain = Custom::generate_chain(0, &nonce, Quiet, Quiet);
    let proof = Custom::combine_chains(&[&chain], Quiet);
    assert!(Custom::verify_proof(&nonce, &proof).is_some());
}
