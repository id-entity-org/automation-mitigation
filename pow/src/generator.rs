use crate::chains::ValidChainCount;
use crate::hasher::MerkleHasher;
#[cfg(feature = "debug")]
use crate::hex::Hex;
use crate::{challenge_index, reference_block_index, Block, Nonce};
use crate::{Challenge, DebugPrinter};
use rs_merkle::{Hasher, MerkleTree};
use std::array::from_fn;
use std::mem::MaybeUninit;
use std::ptr;
use std::ptr::copy_nonoverlapping;
use std::slice::from_raw_parts;

pub struct State<const HASH_LENGTH: usize>(MerkleTree<MerkleHasher<HASH_LENGTH>>);

impl<const HASH_LENGTH: usize> State<HASH_LENGTH> {
    pub fn root(&self) -> Box<[u8; HASH_LENGTH]> {
        self.0
            .root()
            .unwrap()
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .unwrap()
    }
}

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
        let mut allocated = Box::<[Block<BLOCK_SIZE>]>::new_uninit_slice(CHAIN_BLOCK_COUNT);
        let blocks: &mut [MaybeUninit<Block<BLOCK_SIZE>>; CHAIN_BLOCK_COUNT] =
            allocated.as_mut().try_into().unwrap();
        Self::generate_allocated_chain(i, nonce, blocks, printer);
        // SAFETY: We just initialized all the blocks.
        unsafe { allocated.assume_init() }.try_into().unwrap()
    }

    fn generate_chain_split_nonce(
        i: usize,
        split_nonce: &Nonce,
        printer: impl DebugPrinter,
    ) -> Box<[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]> {
        let mut allocated = Box::<[Block<BLOCK_SIZE>]>::new_uninit_slice(CHAIN_BLOCK_COUNT);
        let blocks: &mut [MaybeUninit<Block<BLOCK_SIZE>>; CHAIN_BLOCK_COUNT] =
            allocated.as_mut().try_into().unwrap();
        Self::generate_allocated_chain_split_nonce(i, split_nonce, blocks, printer);
        // SAFETY: We just initialized all the blocks.
        unsafe { allocated.assume_init() }.try_into().unwrap()
    }

    pub fn generate_allocated_chain(
        i: usize,
        nonce: &Nonce,
        blocks: &mut [MaybeUninit<Block<BLOCK_SIZE>>; CHAIN_BLOCK_COUNT],
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
        blocks: &mut [MaybeUninit<Block<BLOCK_SIZE>>; CHAIN_BLOCK_COUNT],
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
        // SAFETY: Fill the first two blocks with zeros (they are just Box<[u8]>)
        unsafe {
            ptr::write_bytes(blocks[0].as_mut_ptr(), 0u8, BLOCK_SIZE);
            ptr::write_bytes(blocks[0].as_mut_ptr(), 0u8, BLOCK_SIZE);
        }
        let mut allocated_hash = [0; 64];
        for index in 2..CHAIN_BLOCK_COUNT {
            let reference_index = reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(
                index + offset,
                // SAFETY: We know blocks[index - 1] is initialized in a previous iteration.
                unsafe { blocks[index - 1].assume_init_ref() },
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

    pub fn hash_chain(
        chain: &[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT],
    ) -> Box<[[u8; HASH_LENGTH]; CHAIN_BLOCK_COUNT]> {
        let vec = chain
            .iter()
            .map(|it| {
                let hash: [u8; HASH_LENGTH] = MerkleHasher::<HASH_LENGTH>::hash(it);
                hash
            })
            .collect::<Vec<_>>();
        let raw = Box::into_raw(vec.into_boxed_slice());
        // SAFETY: we know the vec is the same size as the input chain.
        unsafe { Box::from_raw(raw as *mut [[u8; HASH_LENGTH]; CHAIN_BLOCK_COUNT]) }
    }

    pub fn build_state(
        hash_chains: &[&[[u8; HASH_LENGTH]; CHAIN_BLOCK_COUNT]; CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<State<HASH_LENGTH>> {
        let mut leaves = Vec::with_capacity(CHAIN_COUNT * CHAIN_BLOCK_COUNT);
        let mut cursor = leaves.as_mut_ptr();
        for (i, chain) in hash_chains.iter().enumerate() {
            #[cfg(feature = "debug")]
            printer.debug_println(&format!(
                "hash chain {}/{CHAIN_COUNT}: {:x}",
                i + 1,
                Hex(&MerkleHasher::<HASH_LENGTH>::hash(unsafe {
                    from_raw_parts(chain.as_ptr() as *const u8, CHAIN_BLOCK_COUNT * HASH_LENGTH)
                }))
            ));
            // SAFETY: direct memory copy and adjust size, we already reserved the correct capacity.
            unsafe {
                copy_nonoverlapping(chain.as_ptr(), cursor, CHAIN_BLOCK_COUNT);
                cursor = cursor.add(CHAIN_BLOCK_COUNT);
            }
        }
        // SAFETY: we've reserved the correct capacity and added the elements manually.
        unsafe {
            leaves.set_len(CHAIN_COUNT * CHAIN_BLOCK_COUNT);
        }
        Box::new(State(MerkleTree::from_leaves(&leaves)))
    }
    pub fn select_indices(root: &[u8; HASH_LENGTH]) -> Box<[usize; STEP_COUNT]> {
        Box::new(from_fn(|i| {
            challenge_index::<CHAIN_BLOCK_COUNT, CHAIN_COUNT>(root, i)
        }))
    }

    pub fn select_reference_indices(
        indices: &[usize; STEP_COUNT],
        parent_blocks: &[&Block<BLOCK_SIZE>; STEP_COUNT],
    ) -> Box<[usize; STEP_COUNT]> {
        let vec = indices
            .iter()
            .enumerate()
            .map(|(i, &index)| {
                reference_block_index::<CHAIN_BLOCK_COUNT, BLOCK_SIZE>(index, parent_blocks[i])
            })
            .collect::<Vec<_>>();
        let raw = Box::into_raw(vec.into_boxed_slice());
        // SAFETY: we know the vec is the same size as the slice of indices.
        unsafe { Box::from_raw(raw as *mut [usize; STEP_COUNT]) }
    }

    pub fn combine(
        state: Box<State<HASH_LENGTH>>,
        root: &[u8; HASH_LENGTH],
        indices: &[usize; STEP_COUNT],
        reference_indices: &[usize; STEP_COUNT],
        parent_blocks: &[&Block<BLOCK_SIZE>; STEP_COUNT],
        reference_blocks: &[&Block<BLOCK_SIZE>; STEP_COUNT],
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
        let tree = state.0;
        #[cfg(feature = "debug")]
        printer.debug_println(&format!("root: {:x}", Hex(root)));
        let mut output = Vec::with_capacity(Self::ESTIMATED_FULL_PROOF_BYTE_COUNT);
        output.extend_from_slice(root);
        for i in 0..STEP_COUNT {
            #[cfg(feature = "debug")]
            printer.debug_println(&format!("step: {}/{STEP_COUNT}", i + 1));
            let index = indices[i];
            let parent_block = parent_blocks[i];
            let reference_index = reference_indices[i];
            let reference_block = reference_blocks[i];
            let block_hash = tree.leaf(index).unwrap();
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
            printer.debug_println(&format!("block hash: {:x}", Hex(block_hash)));
            output.extend_from_slice(block_hash);
            #[cfg(feature = "debug")]
            printer.debug_println(&format!(
                "parent block hash: {:x}",
                Hex(&MerkleHasher::<HASH_LENGTH>::hash(parent_block))
            ));
            output.extend_from_slice(parent_block);
            #[cfg(feature = "debug")]
            printer.debug_println(&format!(
                "reference block hash: {:x}",
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
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "pow hash: {:x}",
            Hex(&MerkleHasher::<HASH_LENGTH>::hash(&output))
        ));
        output.into_boxed_slice()
    }

    pub fn combine_chains(
        chains: &[&[Block<BLOCK_SIZE>; CHAIN_BLOCK_COUNT]; CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        let hash_chains: [_; CHAIN_COUNT] = from_fn(|i| Self::hash_chain(chains[i]));
        let state = Self::build_state(&from_fn(|i| hash_chains[i].as_ref()), printer);
        let root = state.root();
        let indices = Self::select_indices(&root);
        let parent_blocks = Box::new(from_fn(|i| {
            let index = indices[i] - 1;
            &chains[index / CHAIN_BLOCK_COUNT][index % CHAIN_BLOCK_COUNT]
        }));
        let reference_indices = Self::select_reference_indices(&indices, &parent_blocks);
        let reference_blocks = Box::new(from_fn(|i| {
            let index = reference_indices[i];
            &chains[index / CHAIN_BLOCK_COUNT][index % CHAIN_BLOCK_COUNT]
        }));
        Self::combine(
            state,
            &root,
            &indices,
            &reference_indices,
            &parent_blocks,
            &reference_blocks,
            printer,
        )
    }

    fn fill_block(
        nonce: &Nonce,
        blocks: &mut [MaybeUninit<Block<BLOCK_SIZE>>],
        index: usize,
        reference_index: usize,
        hash: &mut [u8; 64],
    ) {
        // SAFETY: We know blocks[index - 1] and block[reference_index] are already initialized.
        MerkleHasher::hash_with_custom_domain_into(
            unsafe { blocks[index - 1].assume_init_ref() },
            unsafe { blocks[reference_index].assume_init_ref() },
            hash,
        );
        for _ in 0..ITERATION_COUNT {
            MerkleHasher::hash_self(hash);
        }
        // SAFETY: The hasher will fill the block without reading the bytes.
        let block = unsafe {
            core::slice::from_raw_parts_mut(blocks[index].as_mut_ptr() as *mut u8, BLOCK_SIZE)
        };
        MerkleHasher::<BLOCK_SIZE>::hash_with_custom_domain_into_slice(nonce, hash, block);
    }
}
