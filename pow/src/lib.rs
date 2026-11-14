extern crate rs_merkle;

/// Fixed block and intermediate-hash size in bytes.
pub const BLOCK_SIZE: usize = 192;
#[cfg(feature = "high-memory")]
pub const DEFAULT_CHAIN_BLOCK_COUNT: usize = 2_097_152;
#[cfg(not(feature = "high-memory"))]
pub const DEFAULT_CHAIN_BLOCK_COUNT: usize = 1_048_576;
pub const DEFAULT_CHAIN_COUNT: usize = 2;
pub const DEFAULT_STEP_COUNT: usize = 7;
pub const DEFAULT_HASH_LENGTH: usize = 16;
pub const DEFAULT_COMPUTED_BLOCK_COUNT: usize = DefaultGenerator::COMPUTED_BLOCK_COUNT;

pub type Nonce = [u8; 16];
pub type Block = [u8; BLOCK_SIZE];

#[derive(Copy, Clone)]
pub struct Challenge<
    const CHAIN_COUNT: usize = DEFAULT_CHAIN_COUNT,
    const STEP_COUNT: usize = DEFAULT_STEP_COUNT,
    const CHAIN_BLOCK_COUNT: usize = DEFAULT_CHAIN_BLOCK_COUNT,
    const HASH_LENGTH: usize = DEFAULT_HASH_LENGTH,
>;

pub type DefaultGenerator = Challenge<
    DEFAULT_CHAIN_COUNT,
    DEFAULT_STEP_COUNT,
    DEFAULT_CHAIN_BLOCK_COUNT,
    DEFAULT_HASH_LENGTH,
>;

impl<
    const CHAIN_COUNT: usize,
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const HASH_LENGTH: usize,
> Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, HASH_LENGTH>
{
    const TOTAL_BLOCK_COUNT: usize = CHAIN_BLOCK_COUNT * CHAIN_COUNT;
    /// The solver retains a quarter-prefix; indices still address the full chain.
    pub const COMPUTED_BLOCK_COUNT: usize = {
        assert!(CHAIN_BLOCK_COUNT >= 4);
        if CHAIN_BLOCK_COUNT / 4 < 3 {
            3
        } else {
            CHAIN_BLOCK_COUNT / 4
        }
    };
    pub const SEARCH_PATH_LENGTH: usize = (Self::TOTAL_BLOCK_COUNT - 1).count_ones() as usize;
    pub const MAX_MERKLE_PROOF_BYTES: usize =
        3 * (usize::BITS - (Self::TOTAL_BLOCK_COUNT - 1).leading_zeros()) as usize * HASH_LENGTH;
    pub const MAX_PROOF_BYTES: usize = HASH_LENGTH
        + STEP_COUNT
            * (3 * size_of::<u32>() + HASH_LENGTH + 2 * BLOCK_SIZE + Self::MAX_MERKLE_PROOF_BYTES);
    pub const fn chain_count() -> usize {
        CHAIN_COUNT
    }
}

pub(crate) mod chains;
pub(crate) mod hasher;

#[cfg(any(test, feature = "debug"))]
pub mod hex;

pub trait ProgressReporter: Copy {
    fn increment(&self, i: u8);
}

pub trait DebugPrinter: Copy {
    #[inline(always)]
    #[allow(unused_variables)]
    fn debug_println(&self, message: &str) {
        #[cfg(feature = "debug")]
        println!("{message}")
    }
}
#[cfg(feature = "debug")]
#[derive(Copy, Clone)]
pub struct StdDebugPrinter;

#[cfg(feature = "debug")]
impl DebugPrinter for StdDebugPrinter {}

#[cfg(not(feature = "debug"))]
#[derive(Copy, Clone)]
pub struct NoDebugPrinter;

#[cfg(not(feature = "debug"))]
impl DebugPrinter for NoDebugPrinter {}

#[cfg(feature = "generate")]
mod generator;

#[cfg(feature = "generate")]
mod generate {
    use super::*;
    pub use crate::chains::*;
    pub use crate::generator::State;
    use rs_merkle::Hasher;
    use std::mem::MaybeUninit;

    pub fn hash(payload: &[u8]) -> [u8; DEFAULT_HASH_LENGTH] {
        MerkleHasher::<DEFAULT_HASH_LENGTH>::hash(payload)
    }

    pub fn generate_proof(
        nonce: &Nonce,
        printer: impl DebugPrinter,
        progress: impl ProgressReporter,
    ) -> Box<[u8]> {
        let chains = DefaultGenerator::generate_chains(nonce, printer, progress);
        DefaultGenerator::combine_chains(&std::array::from_fn(|i| chains[i].as_ref()), printer)
    }

    pub fn generate_chain(
        i: usize,
        nonce: &Nonce,
        printer: impl DebugPrinter,
        progress: impl ProgressReporter,
    ) -> Box<[Block; DEFAULT_COMPUTED_BLOCK_COUNT]> {
        assert!(i < DEFAULT_CHAIN_COUNT);
        DefaultGenerator::generate_chain(i, nonce, printer, progress)
            .try_into()
            .unwrap()
    }

    pub fn generate_allocated_chain(
        i: usize,
        nonce: &Nonce,
        blocks: &mut [Block; DEFAULT_COMPUTED_BLOCK_COUNT],
        printer: impl DebugPrinter,
        progress: impl ProgressReporter,
    ) {
        assert!(i < DEFAULT_CHAIN_COUNT);
        // SAFETY: we just convert valid allocated memory into MaybeUninit
        let blocks = unsafe {
            &mut *(blocks as *mut _ as *mut [MaybeUninit<Block>; DEFAULT_COMPUTED_BLOCK_COUNT])
        };
        DefaultGenerator::generate_allocated_chain(i, nonce, blocks, printer, progress)
    }

    pub fn combine_chains(
        chains: &[&[Block; DEFAULT_COMPUTED_BLOCK_COUNT]; DEFAULT_CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        DefaultGenerator::combine_chains(&std::array::from_fn(|i| chains[i].as_slice()), printer)
    }

    pub fn hash_chain(
        chain: &[Block; DEFAULT_COMPUTED_BLOCK_COUNT],
    ) -> Box<[[u8; DEFAULT_HASH_LENGTH]; DEFAULT_COMPUTED_BLOCK_COUNT]> {
        DefaultGenerator::hash_chain(chain).try_into().unwrap()
    }

    pub fn build_state(
        hash_chains: &[&[[u8; DEFAULT_HASH_LENGTH]; DEFAULT_COMPUTED_BLOCK_COUNT];
             DEFAULT_CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<State<DEFAULT_HASH_LENGTH>> {
        DefaultGenerator::build_state(&std::array::from_fn(|i| hash_chains[i].as_slice()), printer)
    }

    pub fn select_indices(root: &[u8; DEFAULT_HASH_LENGTH]) -> Box<[usize; DEFAULT_STEP_COUNT]> {
        DefaultGenerator::select_indices(root)
    }

    pub fn root(state: &State<DEFAULT_HASH_LENGTH>) -> Box<[u8; DEFAULT_HASH_LENGTH]> {
        state.root()
    }

    pub fn select_reference_indices(
        indices: &[usize; DEFAULT_STEP_COUNT],
        parent_blocks: &[&Block; DEFAULT_STEP_COUNT],
    ) -> Box<[usize; DEFAULT_STEP_COUNT]> {
        DefaultGenerator::select_reference_indices(indices, parent_blocks)
    }

    pub fn combine(
        state: Box<State<DEFAULT_HASH_LENGTH>>,
        root: &[u8; DEFAULT_HASH_LENGTH],
        indices: &[usize; DEFAULT_STEP_COUNT],
        reference_indices: &[usize; DEFAULT_STEP_COUNT],
        parent_blocks: &[&Block; DEFAULT_STEP_COUNT],
        reference_blocks: &[&Block; DEFAULT_STEP_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        DefaultGenerator::combine(
            state,
            root,
            indices,
            reference_indices,
            parent_blocks,
            reference_blocks,
            printer,
        )
    }
}

#[cfg(feature = "generate")]
pub use generate::*;

#[cfg(feature = "verify")]
mod verifier;

#[cfg(feature = "verify")]
mod verify {
    use super::*;

    pub fn verify_proof(nonce: &Nonce, proof: &[u8]) -> Option<()> {
        DefaultGenerator::verify_proof(nonce, proof)
    }
}

use crate::hasher::MerkleHasher;
#[cfg(feature = "verify")]
pub use verify::*;

pub fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
        .rotate_left(13)
        .wrapping_add(b)
        .rotate_left(32)
        ^ b
}

const U64_VALUE_COUNT: u128 = u64::MAX as u128 + 1;

pub(crate) fn challenge_index<const CHAIN_BLOCK_COUNT: usize, const CHAIN_COUNT: usize>(
    merkle_root: &[u8],
    i: usize,
) -> usize {
    let hash: [u8; 16] = MerkleHasher::<16>::custom_domain_hash_with_prefix(
        b"challenge_index",
        merkle_root,
        (i as u64).to_le_bytes().as_slice(),
    );
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) as u128;
    let chain_seed = u64::from_le_bytes(hash[8..16].try_into().unwrap()) as u128;
    let chain = ((chain_seed * CHAIN_COUNT as u128) / U64_VALUE_COUNT) as usize;
    let offset = chain * CHAIN_BLOCK_COUNT;
    (((seed * (CHAIN_BLOCK_COUNT - 2) as u128) / U64_VALUE_COUNT) as usize) + 2 + offset
}

pub(crate) fn reference_block_index<const CHAIN_BLOCK_COUNT: usize>(
    index: usize,
    parent_block: &Block,
) -> usize {
    let offset = index / CHAIN_BLOCK_COUNT * CHAIN_BLOCK_COUNT;
    let i = (index % CHAIN_BLOCK_COUNT) as u64;
    let r1 = mix(
        u64::from_le_bytes(parent_block[0..8].try_into().unwrap()),
        i,
    );
    let r2 = mix(
        u64::from_le_bytes(parent_block[8..16].try_into().unwrap()),
        i,
    );
    let r = mix(r1, r2) as u128;
    let j = (i - 1) as u128;
    ((r * j) >> 64) as usize + offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::Hex;
    use sha2::{Digest, Sha256};
    use std::mem::MaybeUninit;
    use std::sync::atomic::AtomicU8;
    use std::thread;

    #[derive(Copy, Clone)]
    pub struct NoDebugPrinter;

    pub static PROGRESS: AtomicU8 = AtomicU8::new(0);

    #[derive(Copy, Clone)]
    pub struct ProgressPrinter;

    #[derive(Copy, Clone)]
    struct StdDebugPrinter;

    impl DebugPrinter for StdDebugPrinter {}
    impl DebugPrinter for NoDebugPrinter {
        #[inline(always)]
        fn debug_println(&self, _message: &str) {}
    }

    impl ProgressReporter for ProgressPrinter {
        #[inline(always)]
        fn increment(&self, i: u8) {
            println!(
                "progress: {}",
                PROGRESS.fetch_add(i, std::sync::atomic::Ordering::Relaxed)
            );
        }
    }

    #[test]
    fn test_select_indices() {
        let root = 0x920eb8ea58ee2654f6363b99e7da4e62_u128.to_be_bytes();
        let indices = DefaultGenerator::select_indices(&root);
        assert_eq!(indices.len(), DEFAULT_STEP_COUNT);
        #[cfg(not(feature = "high-memory"))]
        {
            println!("low");
            assert_eq!(indices[0], 354308);
            assert_eq!(indices[1], 209408);
            assert_eq!(indices[2], 1190);
            assert_eq!(indices[3], 61910);
            assert_eq!(indices[4], 1688458);
            assert_eq!(indices[5], 212409);
            assert_eq!(indices[6], 843900);
        }
        #[cfg(feature = "high-memory")]
        {
            println!("high memory");
            assert_eq!(indices[0], 708614);
            assert_eq!(indices[1], 418815);
            assert_eq!(indices[2], 2378);
            assert_eq!(indices[3], 123819);
            assert_eq!(indices[4], 3376916);
            assert_eq!(indices[5], 424816);
            assert_eq!(indices[6], 1687800);
        }
    }

    #[test]
    fn test_generate_chain_default() {
        #[cfg(not(feature = "high-memory"))]
        let (hash_chain_0, hash_chain_1, hash_proof) = {
            let hash_chain_0 = "04a298888aff1301568f058ce6e445997afa170b484672329d6bfb11a086084a";
            let hash_chain_1 = "20297bd24861efed36cc749176cf353c8b76ff21888f7549eab3fd42ce14a12d";
            let hash_proof = "1cd4d20f292ecfd183ef090b71c716b1ced8986aff386cb5b8bc7c2e03acb9e1";
            (hash_chain_0, hash_chain_1, hash_proof)
        };
        #[cfg(feature = "high-memory")]
        let (hash_chain_0, hash_chain_1, hash_proof) = {
            let hash_chain_0 = "c278190a01e2bb7b8a3d99cbab05ff77a339e3c2a8917b970def7e48ec8f0983";
            let hash_chain_1 = "4156efb22bc8c39290808eb53611eb1af81fb391241fed147b2fd478c42e6df6";
            let hash_proof = "ab076454f1fad6cfa4464425c36de0907e0e269071b9a7691cbd881bb8615ae0";
            (hash_chain_0, hash_chain_1, hash_proof)
        };

        let nonce = 0x8b7df143d91c716ecfa5fc1730022f6b_u128.to_be_bytes();
        let mut chain = vec![0u8; BLOCK_SIZE * DEFAULT_COMPUTED_BLOCK_COUNT];
        let ptr = chain.as_mut_ptr() as *mut [u8; BLOCK_SIZE];
        let ptr: &mut [[u8; BLOCK_SIZE]; DEFAULT_COMPUTED_BLOCK_COUNT] =
            unsafe { std::slice::from_raw_parts_mut(ptr, DEFAULT_COMPUTED_BLOCK_COUNT) }
                .try_into()
                .unwrap();
        let blocks = unsafe {
            &mut *(ptr as *mut _ as *mut [MaybeUninit<Block>; DEFAULT_COMPUTED_BLOCK_COUNT])
        };
        DefaultGenerator::generate_allocated_chain(
            0,
            &nonce,
            blocks,
            StdDebugPrinter,
            ProgressPrinter,
        );
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_chain_0);
        DefaultGenerator::generate_allocated_chain(
            1,
            &nonce,
            blocks,
            StdDebugPrinter,
            ProgressPrinter,
        );
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_chain_1);
        let chain1 = DefaultGenerator::generate_chain(0, &nonce, StdDebugPrinter, ProgressPrinter);
        let chain2 = DefaultGenerator::generate_chain(1, &nonce, StdDebugPrinter, ProgressPrinter);
        let proof = DefaultGenerator::combine_chains(&[&chain1, &chain2], StdDebugPrinter);
        let chain = Box::into_raw(chain1) as *mut u8;
        let chain =
            unsafe { Box::from_raw(chain as *mut [u8; BLOCK_SIZE * DEFAULT_COMPUTED_BLOCK_COUNT]) };
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_chain_0);
        let chain = Box::into_raw(chain2) as *mut u8;
        let chain =
            unsafe { Box::from_raw(chain as *mut [u8; BLOCK_SIZE * DEFAULT_COMPUTED_BLOCK_COUNT]) };
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_chain_1);
        let hash = Sha256::default().chain_update(proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_proof,);
    }

    #[test]
    fn test_generate_serial_and_verify_proof_default() {
        let nonce = 0x0b206ed758abdcb0d43c9bb3e7808495_u128.to_be_bytes();
        #[cfg(not(feature = "high-memory"))]
        let hash_proof = "60232bc8fa20f574a491739bab53a9e3370f57b173193f7ece662735f6d0296e";
        #[cfg(feature = "high-memory")]
        let hash_proof = "25efbcf645919c0d3a1e75494a6f97c8e91aa57ac4d19625c782caa7d9f9065e";

        let proof = generate_proof(&nonce, StdDebugPrinter, ProgressPrinter);
        let hash = Sha256::default().chain_update(&proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_proof,);
        let verified = verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_parallel_and_verify_proof_default() {
        type TestChallenge = Challenge;
        let nonce = 0x0b206ed758abdcb0d43c9bb3e7808495_u128.to_be_bytes();
        #[cfg(not(feature = "high-memory"))]
        let hash_proof = "60232bc8fa20f574a491739bab53a9e3370f57b173193f7ece662735f6d0296e";
        #[cfg(feature = "high-memory")]
        let hash_proof = "25efbcf645919c0d3a1e75494a6f97c8e91aa57ac4d19625c782caa7d9f9065e";

        let proof =
            TestChallenge::generate_proof_in_parallel(&nonce, NoDebugPrinter, ProgressPrinter);
        let hash = Sha256::default().chain_update(&proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_proof);
        let verified = verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_in_parallel_and_verify_proof() {
        type TestChallenge =
            Challenge<4, DEFAULT_STEP_COUNT, DEFAULT_CHAIN_BLOCK_COUNT, DEFAULT_HASH_LENGTH>;
        let nonce = 0xcc6b01afc72f00a711f2a41277e05c6a_u128.to_be_bytes();
        let proof =
            TestChallenge::generate_proof_in_parallel(&nonce, StdDebugPrinter, ProgressPrinter);

        let verified = TestChallenge::verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_in_parallel_and_verify_proof_non_default() {
        type TestChallenge = Challenge<4, 5, 262_144, 32>;
        let nonce = 0xdb7149f937648e7b5a5e3fe726d42b24_u128.to_be_bytes();
        let hash_proof = "60651b2b684c4355baaa26f583e53adada81a2f5935b0dc5e6f3e5a89aae2546";

        let proof =
            TestChallenge::generate_proof_in_parallel(&nonce, StdDebugPrinter, ProgressPrinter);
        let hash = Sha256::default().chain_update(&proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(hash, hash_proof);
        let verified = TestChallenge::verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    impl<
        const CHAIN_COUNT: usize,
        const STEP_COUNT: usize,
        const CHAIN_BLOCK_COUNT: usize,
        const HASH_LENGTH: usize,
    > Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, HASH_LENGTH>
    where
        Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, HASH_LENGTH>:
            ValidChainCount<CHAIN_COUNT>,
    {
        fn generate_proof_in_parallel(
            nonce: &Nonce,
            printer: impl DebugPrinter + Send + Sync,
            progress: impl ProgressReporter + Send + Sync,
        ) -> Box<[u8]> {
            thread::scope(move |scope| {
                let joins = (0..CHAIN_COUNT)
                    .map(|i| {
                        scope.spawn(move || Self::generate_chain(i, &nonce, printer, progress))
                    })
                    .collect::<Vec<_>>();
                let chains = joins
                    .into_iter()
                    .map(|it| it.join().unwrap())
                    .collect::<Vec<_>>();
                let chains: [&[Block]; CHAIN_COUNT] = chains
                    .iter()
                    .map(|b| &**b)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                Self::combine_chains(&chains, printer)
            })
        }
    }
}
