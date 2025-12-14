pub(crate) extern crate blake2;
pub(crate) extern crate rs_merkle;

pub type Nonce = [u8; 16];
pub type Block<const BLOCK_SIZE: usize = DEFAULT_BLOCK_SIZE> = [u8; BLOCK_SIZE];

mod hasher;

use blake2::digest::FixedOutput;
use blake2::{Blake2b512, Digest};
pub use hasher::Blake2bHasher;
use std::convert::TryInto;

pub const DEFAULT_BLOCK_SIZE: usize = 256;
pub const DEFAULT_CHAIN_BLOCK_COUNT: usize = 524_288;
pub const DEFAULT_CHAIN_COUNT: usize = 2;
pub const DEFAULT_STEP_COUNT: usize = 10;
pub const DEFAULT_ITERATION_COUNT: usize = 4;
pub const DEFAULT_HASH_LENGTH: usize = 16;

pub fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
        .rotate_left(13)
        .wrapping_add(b)
        .rotate_left(32)
        ^ b
}

const U64_VALUE_COUNT: u128 = u64::MAX as u128 + 1;

pub fn challenge_index<const CHAIN_BLOCK_COUNT: usize, const CHAIN_COUNT: usize>(
    merkle_root: &[u8],
    i: usize,
) -> usize {
    let mut hasher = Blake2b512::new_with_prefix(merkle_root);
    hasher.update((i as u64).to_le_bytes());
    let hash = hasher.finalize_fixed();
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) as u128;
    let chain_seed = u64::from_le_bytes(hash[8..16].try_into().unwrap()) as u128;
    let chain = ((chain_seed * CHAIN_COUNT as u128) / U64_VALUE_COUNT) as usize;
    let offset = chain * CHAIN_BLOCK_COUNT;
    (((seed * (CHAIN_BLOCK_COUNT - 2) as u128) / U64_VALUE_COUNT) as usize) + 2 + offset
}

pub fn reference_block_index<const CHAIN_BLOCK_COUNT: usize, const BLOCK_SIZE: usize>(
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
