use crate::chains::ValidChainCount;
use crate::hasher::MerkleHasher;
#[cfg(feature = "debug")]
use crate::hex::Hex;
use crate::{challenge_index, reference_block_index, Block, Nonce};
use crate::{Challenge, DebugPrinter};
use rs_merkle::{Hasher, MerkleTree};
use std::array::from_fn;

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
        printer: impl DebugPrinter,
    ) -> [Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]>; CHAIN_COUNT] {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!("nonce: {:x}", Hex(nonce)));
        let nonces = Self::split_nonce(nonce);
        from_fn(|i| Self::generate_chain_split_nonce(i, &nonces[i], printer))
    }

    pub fn generate_chain(
        i: usize,
        nonce: &Nonce,
        printer: impl DebugPrinter,
    ) -> Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]> {
        // SAFETY: The bytes are initialized in init_block and fill_block.
        let mut blocks: Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]> =
            unsafe { Box::<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]>::new_uninit().assume_init() };
        Self::generate_allocated_chain(i, nonce, &mut blocks, printer);
        blocks
    }

    fn generate_chain_split_nonce(
        i: usize,
        split_nonce: &Nonce,
        printer: impl DebugPrinter,
    ) -> Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]> {
        // SAFETY: The bytes are initialized in init_block and fill_block.
        let mut blocks: Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]> =
            unsafe { Box::<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]>::new_uninit().assume_init() };
        Self::generate_allocated_chain_split_nonce(i, split_nonce, &mut blocks, printer);
        blocks
    }

    pub fn generate_allocated_chain(
        i: usize,
        nonce: &Nonce,
        blocks: &mut [Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT],
        printer: impl DebugPrinter,
    ) {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!("nonce: {:x}", Hex(nonce)));
        let split_nonce = Self::split_nonce(nonce)[i];
        Self::generate_allocated_chain_split_nonce(i, &split_nonce, blocks, printer)
    }

    fn generate_allocated_chain_split_nonce(
        i: usize,
        split_nonce: &Nonce,
        blocks: &mut [Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT],
        printer: impl DebugPrinter,
    ) {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "generate chain {}/{CHAIN_COUNT} chains of {CHAIN_BLOCK_COUNT} blocks of {BLOCK_SIZE} bytes.",
            i + 1,
        ));
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "chain: split_nonce: {:x}, hash length: {HASH_LENGTH}, iteration count: {ITERATION_COUNT}.",
            Hex(split_nonce)
        ));
        let offset = CHAIN_BLOCK_COUNT * i;
        blocks[0].fill(0u8);
        blocks[1].fill(0u8);
        let mut allocated_hash = [0; 64];
        for index in 2..CHAIN_BLOCK_COUNT {
            let reference_index = reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(
                index + offset,
                &blocks[index - 1],
            );
            debug_assert!(reference_index >= offset, "{reference_index} - {offset}");
            Self::fill_block(
                split_nonce,
                blocks,
                index,
                reference_index - offset,
                &mut allocated_hash,
            );
        }
    }

    pub fn combine_chains(
        chains: &[&[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]; CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "combine {CHAIN_COUNT} chains of {CHAIN_BLOCK_COUNT} blocks of {BLOCK_SIZE} bytes."
        ));
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "proof: {STEP_COUNT} steps, hash length: {HASH_LENGTH}, iteration count: {ITERATION_COUNT}."
        ));
        let mut output = Vec::with_capacity(Self::ESTIMATED_FULL_PROOF_BYTE_COUNT);
        let leaves = chains
            .iter()
            .flat_map(|it| it.iter().map(|it| MerkleHasher::<HASH_LENGTH>::hash(it)))
            .collect::<Vec<_>>();
        let tree = MerkleTree::<MerkleHasher<HASH_LENGTH>>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        #[cfg(feature = "debug")]
        printer.debug_println(&format!("root: {:x}", Hex(&root)));
        output.extend_from_slice(&root);
        for i in 0..STEP_COUNT {
            #[cfg(feature = "debug")]
            printer.debug_println(&format!("step: {}/{STEP_COUNT}", i + 1));
            let index = challenge_index::<CHAIN_BLOCK_COUNT, CHAIN_COUNT>(&root, i);
            let block = &chains[index / CHAIN_BLOCK_COUNT][index % CHAIN_BLOCK_COUNT];
            let parent_block =
                &chains[(index - 1) / CHAIN_BLOCK_COUNT][(index - 1) % CHAIN_BLOCK_COUNT];
            let reference_index =
                reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(index, parent_block);
            let reference_block =
                &chains[reference_index / CHAIN_BLOCK_COUNT][reference_index % CHAIN_BLOCK_COUNT];
            let block_hash = MerkleHasher::<HASH_LENGTH>::hash(block);
            let mut indices = [index - 1, index, reference_index];
            indices.sort_unstable();
            let proof = tree.proof(&indices).to_bytes();
            #[cfg(feature = "debug")]
            printer.debug_println(&format!("index: {index}"));
            output.extend_from_slice(&(index as u32).to_le_bytes());
            #[cfg(feature = "debug")]
            printer.debug_println(&format!("reference index: {reference_index}"));
            output.extend_from_slice(&(reference_index as u32).to_le_bytes());
            #[cfg(feature = "debug")]
            printer.debug_println(&format!("bock hash: {:x}", Hex(&block_hash)));
            output.extend_from_slice(&block_hash);
            #[cfg(feature = "debug")]
            printer.debug_println(&format!(
                "parent block hash: {:x}",
                Hex(&MerkleHasher::<HASH_LENGTH>::hash(parent_block))
            ));
            output.extend_from_slice(parent_block);
            #[cfg(feature = "debug")]
            printer.debug_println(&format!(
                "reference block sha256 hash: {:x}",
                Hex(&MerkleHasher::<HASH_LENGTH>::hash(reference_block))
            ));
            output.extend_from_slice(reference_block);
            #[cfg(feature = "debug")]
            printer.debug_println(&format!("proof length: {} bytes", proof.len()));
            output.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            #[cfg(feature = "debug")]
            printer.debug_println(&format!(
                "proof hash: {:x}",
                Hex(&MerkleHasher::<HASH_LENGTH>::hash(&proof))
            ));
            output.extend_from_slice(&proof);
        }
        output.into_boxed_slice()
    }

    fn fill_block(
        nonce: &Nonce,
        blocks: &mut [Block<BLOCK_SIZE>],
        index: usize,
        reference_index: usize,
        hash: &mut [u8; 64],
    ) {
        MerkleHasher::hash_with_custom_domain_into(
            &blocks[index - 1],
            &blocks[reference_index],
            hash,
        );
        for _ in 0..ITERATION_COUNT {
            MerkleHasher::hash_self(hash);
        }
        MerkleHasher::hash_with_custom_domain_into(nonce, hash, &mut blocks[index]);
    }
}
