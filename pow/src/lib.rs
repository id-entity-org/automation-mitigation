extern crate rs_merkle;

pub const DEFAULT_BLOCK_SIZE: usize = 256;
pub const DEFAULT_CHAIN_BLOCK_COUNT: usize = 524_288;
pub const DEFAULT_CHAIN_COUNT: usize = 2;
pub const DEFAULT_STEP_COUNT: usize = 10;
pub const DEFAULT_ITERATION_COUNT: usize = 8;
pub const DEFAULT_HASH_LENGTH: usize = 16;

pub type Nonce = [u8; 16];
pub type Block<const BLOCK_SIZE: usize = DEFAULT_BLOCK_SIZE> = [u8; BLOCK_SIZE];

#[derive(Copy, Clone)]
pub struct Challenge<
    const CHAIN_COUNT: usize = DEFAULT_CHAIN_COUNT,
    const STEP_COUNT: usize = DEFAULT_STEP_COUNT,
    const CHAIN_BLOCK_COUNT: usize = DEFAULT_CHAIN_BLOCK_COUNT,
    const BLOCK_SIZE: usize = DEFAULT_BLOCK_SIZE,
    const ITERATION_COUNT: usize = DEFAULT_ITERATION_COUNT,
    const HASH_LENGTH: usize = DEFAULT_HASH_LENGTH,
>;

pub type DefaultGenerator = Challenge<
    DEFAULT_CHAIN_COUNT,
    DEFAULT_STEP_COUNT,
    DEFAULT_CHAIN_BLOCK_COUNT,
    DEFAULT_BLOCK_SIZE,
    DEFAULT_ITERATION_COUNT,
    DEFAULT_HASH_LENGTH,
>;

impl<
    const CHAIN_COUNT: usize,
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const BLOCK_SIZE: usize,
    const ITERATION_COUNT: usize,
    const HASH_LENGTH: usize,
> Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>
{
    const TOTAL_BLOCK_COUNT: usize = CHAIN_BLOCK_COUNT * CHAIN_COUNT;
    const _ENFORCE_CHAIN_BLOCK_COUNT_AT_LEAST_2: () = const {
        assert!(CHAIN_BLOCK_COUNT >= 2);
    };
    pub const fn chain_count() -> usize {
        CHAIN_COUNT
    }
}

pub(crate) mod chains;
pub(crate) mod hasher;

#[cfg(any(test, feature = "debug"))]
pub(crate) mod hex;

pub trait DebugPrinter: Copy {
    #[inline(always)]
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
    use std::mem::MaybeUninit;

    pub fn generate_proof(nonce: &Nonce, printer: impl DebugPrinter) -> Box<[u8]> {
        let chains = DefaultGenerator::generate_chains(nonce, printer);
        let chains: [&[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT]; DEFAULT_CHAIN_COUNT] =
            chains
                .iter()
                .map(|b| &**b)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
        DefaultGenerator::combine_chains(&chains, printer)
    }

    pub fn generate_chain(
        i: usize,
        nonce: &Nonce,
        printer: impl DebugPrinter,
    ) -> Box<[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT]> {
        assert!(i < DEFAULT_CHAIN_COUNT);
        DefaultGenerator::generate_chain(i, nonce, printer)
    }

    pub fn generate_allocated_chain(
        i: usize,
        nonce: &Nonce,
        blocks: &mut [Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT],
        printer: impl DebugPrinter,
    ) {
        assert!(i < DEFAULT_CHAIN_COUNT);
        // SAFETY: we just convert valid allocated memory into MaybeUninit
        let blocks = unsafe {
            &mut *(blocks as *mut _
                as *mut [MaybeUninit<Block<DEFAULT_BLOCK_SIZE>>; DEFAULT_CHAIN_BLOCK_COUNT])
        };
        DefaultGenerator::generate_allocated_chain(i, nonce, blocks, printer)
    }

    pub fn combine_chains(
        chains: &[&[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT]; DEFAULT_CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        DefaultGenerator::combine_chains(chains, printer)
    }

    pub fn hash_chain(
        chain: &[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT],
    ) -> Box<[[u8; DEFAULT_HASH_LENGTH]; DEFAULT_CHAIN_BLOCK_COUNT]> {
        DefaultGenerator::hash_chain(chain)
    }

    pub fn build_state(
        hash_chains: &[&[[u8; DEFAULT_HASH_LENGTH]; DEFAULT_CHAIN_BLOCK_COUNT];
             DEFAULT_CHAIN_COUNT],
    ) -> Box<State<DEFAULT_HASH_LENGTH>> {
        DefaultGenerator::build_state(hash_chains)
    }

    pub fn select_indices(state: &State<DEFAULT_HASH_LENGTH>) -> Box<[usize; DEFAULT_STEP_COUNT]> {
        DefaultGenerator::select_indices(state)
    }

    pub fn select_reference_indices(
        indices: &[usize; DEFAULT_STEP_COUNT],
        parent_blocks: &[&Block<DEFAULT_BLOCK_SIZE>; DEFAULT_STEP_COUNT],
    ) -> Box<[usize; DEFAULT_STEP_COUNT]> {
        DefaultGenerator::select_reference_indices(indices, parent_blocks)
    }

    pub fn combine(
        state: Box<State<DEFAULT_HASH_LENGTH>>,
        indices: &[usize; DEFAULT_STEP_COUNT],
        reference_indices: &[usize; DEFAULT_STEP_COUNT],
        parent_blocks: &[&Block<DEFAULT_BLOCK_SIZE>; DEFAULT_STEP_COUNT],
        reference_blocks: &[&Block<DEFAULT_BLOCK_SIZE>; DEFAULT_STEP_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        DefaultGenerator::combine(
            state,
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
    let hash: [u8; 16] = MerkleHasher::<16>::hash_with_custom_domain(
        merkle_root,
        (i as u64).to_le_bytes().as_slice(),
    );
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) as u128;
    let chain_seed = u64::from_le_bytes(hash[8..16].try_into().unwrap()) as u128;
    let chain = ((chain_seed * CHAIN_COUNT as u128) / U64_VALUE_COUNT) as usize;
    let offset = chain * CHAIN_BLOCK_COUNT;
    (((seed * (CHAIN_BLOCK_COUNT - 2) as u128) / U64_VALUE_COUNT) as usize) + 2 + offset
}

pub(crate) fn reference_block_index<const CHAIN_BLOCK_COUNT: usize, const BLOCK_SIZE: usize>(
    index: usize,
    parent_block: &Block<BLOCK_SIZE>,
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
    use std::thread;
    use std::time::UNIX_EPOCH;

    #[derive(Copy, Clone)]
    pub struct NoDebugPrinter;

    #[derive(Copy, Clone)]
    struct StdDebugPrinter;

    impl DebugPrinter for StdDebugPrinter {}
    impl DebugPrinter for NoDebugPrinter {
        #[inline(always)]
        fn debug_println(&self, _message: &str) {}
    }

    #[test]
    fn test_generate_chain_default() {
        let nonce = 0x8b7df143d91c716ecfa5fc1730022f6b_u128.to_be_bytes();
        let mut chain = vec![0u8; DEFAULT_BLOCK_SIZE * DEFAULT_CHAIN_BLOCK_COUNT];
        let ptr = chain.as_mut_ptr() as *mut [u8; DEFAULT_BLOCK_SIZE];
        let ptr: &mut [[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_CHAIN_BLOCK_COUNT] =
            unsafe { std::slice::from_raw_parts_mut(ptr, DEFAULT_CHAIN_BLOCK_COUNT) }
                .try_into()
                .unwrap();
        let blocks = unsafe {
            &mut *(ptr as *mut _
                as *mut [MaybeUninit<Block<DEFAULT_BLOCK_SIZE>>; DEFAULT_CHAIN_BLOCK_COUNT])
        };
        DefaultGenerator::generate_allocated_chain(0, &nonce, blocks, StdDebugPrinter);
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "e7e9e62c96ab862d1fd401d9e941ad244b0d9b7b75e05d813b3e45218a083dc7",
            hash
        );
        DefaultGenerator::generate_allocated_chain(1, &nonce, blocks, StdDebugPrinter);
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "3a527fd2a07faf360d1e3292e683e2c5f573533aa5facbf48519865070331202",
            hash
        );
        let chain1 = DefaultGenerator::generate_chain(0, &nonce, StdDebugPrinter);
        let chain2 = DefaultGenerator::generate_chain(1, &nonce, StdDebugPrinter);
        let proof = combine_chains(&[&chain1, &chain2], StdDebugPrinter);
        let chain = Box::into_raw(chain1) as *mut u8;
        let chain = unsafe {
            Box::from_raw(chain as *mut [u8; DEFAULT_BLOCK_SIZE * DEFAULT_CHAIN_BLOCK_COUNT])
        };
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "e7e9e62c96ab862d1fd401d9e941ad244b0d9b7b75e05d813b3e45218a083dc7",
            hash
        );
        let chain = Box::into_raw(chain2) as *mut u8;
        let chain = unsafe {
            Box::from_raw(chain as *mut [u8; DEFAULT_BLOCK_SIZE * DEFAULT_CHAIN_BLOCK_COUNT])
        };
        let hash = Sha256::default()
            .chain_update(chain.as_slice())
            .finalize()
            .to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "3a527fd2a07faf360d1e3292e683e2c5f573533aa5facbf48519865070331202",
            hash
        );
        let hash = Sha256::default().chain_update(proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "74fadde9b21ac7dc6b8978cbe425cc2eca6a78117ef426cf77d915e1192c08da",
            hash
        );
    }

    #[test]
    fn test_generate_serial_and_verify_proof_default() {
        let nonce = 0x0b206ed758abdcb0d43c9bb3e7808495_u128.to_be_bytes();
        let proof = generate_proof(&nonce, StdDebugPrinter);
        let hash = Sha256::default().chain_update(&proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "5d2ca36b69fc996a3c16f088dfc0762ce9609adef811a0dce09ab308a9dd6d8c",
            hash
        );
        let verified = verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_parallel_and_verify_proof_default() {
        type TestChallenge = Challenge;
        let nonce = 0x0b206ed758abdcb0d43c9bb3e7808495_u128.to_be_bytes();
        let t0 = UNIX_EPOCH.elapsed().unwrap();
        let proof = TestChallenge::generate_proof_in_parallel(&nonce, NoDebugPrinter);
        let elapsed = UNIX_EPOCH.elapsed().unwrap() - t0;
        println!("{}ms", elapsed.as_millis());
        let hash = Sha256::default().chain_update(&proof).finalize().to_vec();
        let hash = format!("{:x}", Hex(&hash));
        assert_eq!(
            "5d2ca36b69fc996a3c16f088dfc0762ce9609adef811a0dce09ab308a9dd6d8c",
            hash
        );
        let verified = verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_in_parallel_and_verify_proof() {
        type TestChallenge = Challenge<
            4,
            DEFAULT_STEP_COUNT,
            DEFAULT_CHAIN_BLOCK_COUNT,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_ITERATION_COUNT,
            DEFAULT_HASH_LENGTH,
        >;
        let nonce = 0xcc6b01afc72f00a711f2a41277e05c6a_u128.to_be_bytes();
        let proof = TestChallenge::generate_proof_in_parallel(&nonce, StdDebugPrinter);
        let verified = TestChallenge::verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_in_parallel_and_verify_proof_non_default() {
        type TestChallenge = Challenge<4, 5, 262_144, 1024, 6, 32>;
        let nonce = 0xdb7149f937648e7b5a5e3fe726d42b24_u128.to_be_bytes();
        let proof = TestChallenge::generate_proof_in_parallel(&nonce, StdDebugPrinter);
        let verified = TestChallenge::verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    impl<
        const CHAIN_COUNT: usize,
        const STEP_COUNT: usize,
        const CHAIN_BLOCK_COUNT: usize,
        const BLOCK_SIZE: usize,
        const ITERATION_COUNT: usize,
        const HASH_LENGTH: usize,
    >
        Challenge<
            CHAIN_COUNT,
            STEP_COUNT,
            CHAIN_BLOCK_COUNT,
            BLOCK_SIZE,
            ITERATION_COUNT,
            HASH_LENGTH,
        >
    where
        Challenge<
            CHAIN_COUNT,
            STEP_COUNT,
            CHAIN_BLOCK_COUNT,
            BLOCK_SIZE,
            ITERATION_COUNT,
            HASH_LENGTH,
        >: ValidChainCount<CHAIN_COUNT>,
    {
        fn generate_proof_in_parallel(
            nonce: &Nonce,
            printer: impl DebugPrinter + Send + Sync,
        ) -> Box<[u8]> {
            thread::scope(move |scope| {
                let joins = (0..CHAIN_COUNT)
                    .map(|i| scope.spawn(move || Self::generate_chain(i, &nonce, printer)))
                    .collect::<Vec<_>>();
                let chains = joins
                    .into_iter()
                    .map(|it| it.join().unwrap())
                    .collect::<Vec<_>>();
                let chains: [&[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]; CHAIN_COUNT] = chains
                    .iter()
                    .map(|b| &**b)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                Self::combine_chains(&chains, StdDebugPrinter)
            })
        }
    }
}
