use crate::chains::ValidChainCount;
use crate::Challenge;
use blake2::digest::FixedOutput;
use blake2::{Blake2b512, Digest};
use core::{challenge_index, reference_block_index, Blake2bHasher, Block, Nonce};
use hkdf::SimpleHkdf;
use rs_merkle::{Hasher, MerkleProof};

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
    pub fn verify_proof(nonce: &Nonce, proof: &[u8]) -> Option<()> {
        let nonces = Self::split_nonce(nonce);
        let mut parser = Parser::new(proof);
        let root = *parser.read::<HASH_LENGTH>()?;
        for i in 0..STEP_COUNT {
            let index = parser.read_uint()?;
            if index != challenge_index::<CHAIN_BLOCK_COUNT, CHAIN_COUNT>(&root, i) {
                return None;
            }
            let reference_index = parser.read_uint()?;
            let block_hash = *parser.read::<HASH_LENGTH>()?;
            let blocks = parser.read_slice(BLOCK_SIZE * 2)?;
            let (parent_block, reference_block) = blocks.split_at_checked(BLOCK_SIZE)?;
            let parent_block: &Block<BLOCK_SIZE> = parent_block.try_into().unwrap();
            if reference_index
                != reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(index, parent_block)
            {
                return None;
            }
            let reference_block: &Block<BLOCK_SIZE> = reference_block.try_into().unwrap();
            let block = Self::compute_block(
                &nonces[index / CHAIN_BLOCK_COUNT],
                parent_block,
                reference_block,
            );
            if block_hash != Blake2bHasher::<HASH_LENGTH>::hash(&block) {
                return None;
            }
            let parent_block_hash = Blake2bHasher::<HASH_LENGTH>::hash(parent_block);
            let reference_block_hash = Blake2bHasher::<HASH_LENGTH>::hash(reference_block);
            let len = parser.read_uint()?;
            let proof = parser.read_slice(len)?;
            let proof = MerkleProof::<Blake2bHasher<HASH_LENGTH>>::from_bytes(proof).ok()?;
            let mut indexed_leaves = [
                (index - 1, parent_block_hash),
                (index, block_hash),
                (reference_index, reference_block_hash),
            ];
            indexed_leaves.sort_by_key(|&(i, _)| i);
            let mut indices = [0; 3];
            let mut leaves = [[0; HASH_LENGTH]; 3];
            for (i, (index, hash)) in indexed_leaves.into_iter().enumerate() {
                indices[i] = index;
                leaves[i] = hash;
            }
            if !proof.verify(root, &indices, &leaves, Self::TOTAL_BLOCK_COUNT) {
                return None;
            }
        }
        if !parser.unread().is_empty() {
            return None;
        }
        Some(())
    }

    fn compute_block(
        nonce: &Nonce,
        parent_block: &Block<BLOCK_SIZE>,
        reference_block: &Block<BLOCK_SIZE>,
    ) -> Block<BLOCK_SIZE> {
        let mut hasher = Blake2b512::new_with_prefix(parent_block);
        hasher.update(reference_block);
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
}

struct Parser<'a> {
    unread: &'a [u8],
}

impl<'a> Parser<'a> {
    pub(crate) fn new(slice: &'a [u8]) -> Self {
        Self { unread: slice }
    }
    pub(crate) fn read<const N: usize>(&mut self) -> Option<&[u8; N]> {
        let (value, remaining) = self.unread.split_at_checked(N)?;
        self.unread = remaining;
        Some(value.try_into().unwrap())
    }
    pub(crate) fn read_slice(&mut self, n: usize) -> Option<&[u8]> {
        let (value, remaining) = self.unread.split_at_checked(n)?;
        self.unread = remaining;
        Some(value)
    }
    pub(crate) fn read_uint(&mut self) -> Option<usize> {
        let (value, remaining) = self.unread.split_at_checked(4)?;
        self.unread = remaining;
        Some(u32::from_le_bytes(value.try_into().unwrap()) as usize)
    }
    pub(crate) fn unread(self) -> &'a [u8] {
        self.unread
    }
}
