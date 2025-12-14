use crate::chains::ValidChainCount;
use crate::Challenge;
use blake2::digest::FixedOutput;
use blake2::{Blake2b512, Digest};
use core::{challenge_index, reference_block_index, Blake2bHasher, Block, Nonce};
use hkdf::SimpleHkdf;
use rs_merkle::{Hasher, MerkleTree};
use std::array::from_fn;
use std::convert::TryInto;

impl<
    const CHAIN_COUNT: usize,
    const STEP_COUNT: usize,
    const CHAIN_BLOCK_COUNT: usize,
    const BLOCK_SIZE: usize,
    const ITERATION_COUNT: usize,
    const HASH_LENGTH: usize,
> Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>
where
    Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, BLOCK_SIZE, ITERATION_COUNT, HASH_LENGTH>:
        ValidChainCount<CHAIN_COUNT>,
{
    const TREE_PROOF_BYTE_COUNT: usize = Self::TOTAL_BLOCK_COUNT.ilog2() as usize * HASH_LENGTH;
    const ESTIMATED_CHALLENGE_PROOF_BYTE_COUNT: usize =
        4 + 4 + BLOCK_SIZE + BLOCK_SIZE + HASH_LENGTH + 4 + (Self::TREE_PROOF_BYTE_COUNT / 2);
    const ESTIMATED_FULL_PROOF_BYTE_COUNT: usize =
        32 + Self::ESTIMATED_CHALLENGE_PROOF_BYTE_COUNT * STEP_COUNT;

    pub fn generate_chains(
        nonce: &Nonce,
    ) -> [Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]>; CHAIN_COUNT] {
        let nonces = Self::split_nonce(nonce);
        from_fn(|i| Self::generate_chain(i, &nonces[i]))
    }

    pub fn generate_chain(
        i: usize,
        split_nonce: &Nonce,
    ) -> Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]> {
        let offset = CHAIN_BLOCK_COUNT * i;
        let mut blocks = Vec::with_capacity(CHAIN_BLOCK_COUNT);
        blocks.push(Self::allocate_block(0u32, split_nonce));
        blocks.push(Self::allocate_block(1u32, split_nonce));
        for _ in 2..CHAIN_BLOCK_COUNT {
            blocks.push([0u8; BLOCK_SIZE]);
        }
        for index in 2..CHAIN_BLOCK_COUNT {
            let reference_index = reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(
                index + offset,
                &blocks[index - 1],
            );
            debug_assert!(reference_index >= offset, "{reference_index} - {offset}");
            Self::fill_block(split_nonce, &mut blocks, index, reference_index - offset);
        }
        blocks.into_boxed_slice().try_into().unwrap()
    }

    pub fn combine_chains(
        chains: &[Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]>; CHAIN_COUNT],
    ) -> Box<[u8]> {
        let mut output = Vec::with_capacity(Self::ESTIMATED_FULL_PROOF_BYTE_COUNT);
        let leaves = chains
            .iter()
            .flat_map(|it| it.iter().map(|it| Blake2bHasher::<HASH_LENGTH>::hash(it)))
            .collect::<Vec<_>>();
        let tree = MerkleTree::<Blake2bHasher<HASH_LENGTH>>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        output.extend_from_slice(&root);
        for i in 0..STEP_COUNT {
            let index = challenge_index::<CHAIN_BLOCK_COUNT, CHAIN_COUNT>(&root, i);
            let block = &chains[index / CHAIN_BLOCK_COUNT][index % CHAIN_BLOCK_COUNT];
            let parent_block =
                &chains[(index - 1) / CHAIN_BLOCK_COUNT][(index - 1) % CHAIN_BLOCK_COUNT];
            let reference_index =
                reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(index, parent_block);
            let reference_block =
                &chains[reference_index / CHAIN_BLOCK_COUNT][reference_index % CHAIN_BLOCK_COUNT];
            let block_hash = Blake2bHasher::<HASH_LENGTH>::hash(block);
            let mut indices = [index - 1, index, reference_index];
            indices.sort_unstable();
            let proof = tree.proof(&indices).to_bytes();
            output.extend_from_slice(&(index as u32).to_le_bytes());
            output.extend_from_slice(&(reference_index as u32).to_le_bytes());
            output.extend_from_slice(&block_hash);
            output.extend_from_slice(parent_block);
            output.extend_from_slice(reference_block);
            output.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            output.extend_from_slice(&proof);
        }
        output.into_boxed_slice()
    }

    fn allocate_block(i: u32, nonce: &Nonce) -> Block<BLOCK_SIZE> {
        let mut hasher = Blake2b512::new_with_prefix(i.to_le_bytes());
        hasher.update(nonce);
        let mut hash = hasher.finalize_fixed();
        for _ in 0..ITERATION_COUNT {
            hash = Blake2b512::digest(hash);
        }
        let mut allocated = [0u8; BLOCK_SIZE];
        SimpleHkdf::<Blake2b512>::new(Some(nonce), &hash)
            .expand(&[], &mut allocated)
            .expect("failed to expand hash");
        allocated
    }

    fn fill_block(
        nonce: &Nonce,
        blocks: &mut [Block<BLOCK_SIZE>],
        index: usize,
        reference_index: usize,
    ) {
        debug_assert!(index > 0, "{index}");
        let mut hasher = Blake2b512::new_with_prefix(blocks[index - 1]);
        hasher.update(blocks[reference_index]);
        let mut hash = hasher.finalize_fixed();
        for _ in 0..ITERATION_COUNT {
            hash = Blake2b512::digest(hash);
        }
        SimpleHkdf::<Blake2b512>::new(Some(nonce), &hash)
            .expand(&[], &mut blocks[index])
            .expect("failed to expand hash");
    }
}
