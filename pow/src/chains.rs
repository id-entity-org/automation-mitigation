use crate::{Challenge, Nonce};
use blake2::{Blake2b, Blake2b512, Digest};

pub trait ValidChainCount<const CHAIN_COUNT: usize> {
    fn split_nonce(nonce: &Nonce) -> [Nonce; CHAIN_COUNT];
}

impl<
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const BLOCK_SIZE: usize,
    const ITERATION_COUNT: usize,
    const HASH_LENGTH: usize,
> ValidChainCount<1>
    for Challenge<1, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>
{
    fn split_nonce(nonce: &Nonce) -> [Nonce; 1] {
        [*nonce]
    }
}

impl<
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const BLOCK_SIZE: usize,
    const ITERATION_COUNT: usize,
    const HASH_LENGTH: usize,
> ValidChainCount<2>
    for Challenge<2, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>
{
    fn split_nonce(nonce: &Nonce) -> [Nonce; 2] {
        let hash: [u8; 32] = Blake2b::digest(nonce).into();
        let (nonce1, nonce2) = hash.split_at(16);
        let nonce1: Nonce = nonce1.try_into().unwrap();
        let nonce2: Nonce = nonce2.try_into().unwrap();
        [nonce1, nonce2]
    }
}

impl<
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const BLOCK_SIZE: usize,
    const ITERATION_COUNT: usize,
    const HASH_LENGTH: usize,
> ValidChainCount<3>
    for Challenge<3, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>
{
    fn split_nonce(nonce: &Nonce) -> [Nonce; 3] {
        let hash: [u8; 64] = Blake2b512::digest(nonce).into();
        let mut chunks = hash.chunks_exact(16);
        [
            chunks.next().unwrap().try_into().unwrap(),
            chunks.next().unwrap().try_into().unwrap(),
            chunks.next().unwrap().try_into().unwrap(),
        ]
    }
}

impl<
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const BLOCK_SIZE: usize,
    const ITERATION_COUNT: usize,
    const HASH_LENGTH: usize,
> ValidChainCount<4>
    for Challenge<4, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>
{
    fn split_nonce(nonce: &Nonce) -> [Nonce; 4] {
        let hash: [u8; 64] = Blake2b512::digest(nonce).into();
        let mut chunks = hash.chunks_exact(16);
        [
            chunks.next().unwrap().try_into().unwrap(),
            chunks.next().unwrap().try_into().unwrap(),
            chunks.next().unwrap().try_into().unwrap(),
            chunks.next().unwrap().try_into().unwrap(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_nonce_1() {
        let nonce = [0u8; 16];
        let nonces = Challenge::<1, 1, 2, 1>::split_nonce(&nonce);
        assert_eq!(nonces.len(), 1);
        assert_eq!(nonces[0], nonce);
    }

    #[test]
    fn test_split_nonce_2() {
        let nonce = [0u8; 16];
        let nonces = Challenge::<2, 1, 2, 1>::split_nonce(&nonce);
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonce);
        assert_ne!(nonces[1], nonce);
    }

    #[test]
    fn test_split_nonce_3() {
        let nonce = [0u8; 16];
        let nonces = Challenge::<3, 1, 2, 1>::split_nonce(&nonce);
        assert_eq!(nonces.len(), 3);
        assert_ne!(nonces[0], nonce);
        assert_ne!(nonces[1], nonce);
        assert_ne!(nonces[2], nonce);
    }

    #[test]
    fn test_split_nonce_4() {
        let nonce = [0u8; 16];
        let nonces = Challenge::<4, 1, 2, 1>::split_nonce(&nonce);
        assert_eq!(nonces.len(), 4);
        assert_ne!(nonces[0], nonce);
        assert_ne!(nonces[1], nonce);
        assert_ne!(nonces[2], nonce);
        assert_ne!(nonces[3], nonce);
    }
}
