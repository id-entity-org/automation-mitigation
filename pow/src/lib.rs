extern crate blake2;
pub(crate) extern crate core;
extern crate hkdf;
extern crate rs_merkle;

pub use core::Nonce;
pub use core::DEFAULT_BLOCK_SIZE;
pub use core::DEFAULT_CHAIN_BLOCK_COUNT;
pub use core::DEFAULT_CHAIN_COUNT;
pub use core::DEFAULT_HASH_LENGTH;
pub use core::DEFAULT_ITERATION_COUNT;
pub use core::DEFAULT_STEP_COUNT;

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

#[cfg(feature = "generate")]
mod generator;

#[cfg(feature = "generate")]
mod generate {
    use super::*;
    pub use crate::chains::*;
    pub use core::Block;

    pub fn generate_proof(nonce: &Nonce) -> Box<[u8]> {
        let chains = DefaultGenerator::generate_chains(nonce);
        DefaultGenerator::combine_chains(&chains)
    }

    pub fn generate_chain(
        i: usize,
        nonce: &Nonce,
    ) -> Box<[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT]> {
        assert!(i < DEFAULT_CHAIN_COUNT);
        let split_nonce = DefaultGenerator::split_nonce(nonce)[i];
        DefaultGenerator::generate_chain(i, &split_nonce)
    }

    pub fn combine_chains(
        chains: &[Box<[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT]>; 2],
    ) -> Box<[u8]> {
        DefaultGenerator::combine_chains(chains)
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

#[cfg(feature = "verify")]
pub use verify::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_generate_and_verify_proof_default() {
        let nonce = 0x0b206ed758abdcb0d43c9bb3e7808495_u128.to_le_bytes();
        let proof = generate_proof(&nonce);
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
        let nonce = 0xcc6b01afc72f00a711f2a41277e05c6a_u128.to_le_bytes();
        let proof = TestChallenge::generate_proof_in_parallel(&nonce);
        let verified = TestChallenge::verify_proof(&nonce, &proof);
        assert!(verified.is_some());
    }

    #[test]
    fn test_generate_in_parallel_and_verify_proof_non_default() {
        type TestChallenge = Challenge<4, 5, 262_144, 1024, 6, 32>;
        let nonce = 0xdb7149f937648e7b5a5e3fe726d42b24_u128.to_le_bytes();
        let proof = TestChallenge::generate_proof_in_parallel(&nonce);
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
        fn generate_proof_in_parallel(nonce: &Nonce) -> Box<[u8]> {
            thread::scope(move |scope| {
                let nonces = Self::split_nonce(&nonce);
                let joins = nonces
                    .iter()
                    .enumerate()
                    .map(|(i, &it)| scope.spawn(move || Self::generate_chain(i, &it)))
                    .collect::<Vec<_>>();
                let chains = joins
                    .into_iter()
                    .map(|it| it.join().unwrap())
                    .collect::<Vec<_>>();
                Self::combine_chains(&chains.try_into().unwrap())
            })
        }
    }
}
