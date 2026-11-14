use crate::chains::ValidChainCount;
use crate::hasher::MerkleHasher;
#[cfg(feature = "debug")]
use crate::hex::Hex;
use crate::{BLOCK_SIZE, Block, Nonce, ProgressReporter, challenge_index, reference_block_index};
use crate::{Challenge, DebugPrinter};
use rs_merkle::{Hasher, MerkleTree};
use std::array::from_fn;
use std::mem::MaybeUninit;
use std::ptr;

pub struct State<const HASH_LENGTH: usize>(MerkleTree<MerkleHasher<HASH_LENGTH>, false>);

impl<const HASH_LENGTH: usize> State<HASH_LENGTH> {
    pub fn search_path(&self) -> Vec<[u8; HASH_LENGTH]> {
        self.0.proof(&[self.0.leaves_len()]).proof_hashes().to_vec()
    }

    pub fn commit_leaf(&mut self, leaf: [u8; HASH_LENGTH]) {
        self.0.insert(leaf).commit();
    }

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
    const HASH_LENGTH: usize,
> Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, HASH_LENGTH>
where
    Challenge<CHAIN_COUNT, STEP_COUNT, CHAIN_BLOCK_COUNT, HASH_LENGTH>:
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
        progress: impl ProgressReporter,
    ) -> [Box<[Block]>; CHAIN_COUNT] {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!("nonce: {:x}", Hex(nonce)));
        let nonces = Self::split_nonce(nonce);
        from_fn(|i| Self::generate_chain_split_nonce(i, &nonces[i], printer, progress))
    }

    pub fn generate_chain(
        i: usize,
        nonce: &Nonce,
        printer: impl DebugPrinter,
        progress: impl ProgressReporter,
    ) -> Box<[Block]> {
        let mut allocated = Box::<[Block]>::new_uninit_slice(Self::COMPUTED_BLOCK_COUNT);
        let blocks: &mut [MaybeUninit<Block>] = allocated.as_mut();
        Self::generate_allocated_chain(i, nonce, blocks, printer, progress);
        // SAFETY: We just initialized all the blocks.
        unsafe { allocated.assume_init() }
    }

    fn generate_chain_split_nonce(
        i: usize,
        split_nonce: &Nonce,
        printer: impl DebugPrinter,
        progress: impl ProgressReporter,
    ) -> Box<[Block]> {
        let mut allocated = Box::<[Block]>::new_uninit_slice(Self::COMPUTED_BLOCK_COUNT);
        let blocks: &mut [MaybeUninit<Block>] = allocated.as_mut();
        Self::generate_allocated_chain_split_nonce(i, split_nonce, blocks, printer, progress);
        // SAFETY: We just initialized all the blocks.
        unsafe { allocated.assume_init() }
    }

    pub fn generate_allocated_chain(
        i: usize,
        nonce: &Nonce,
        blocks: &mut [MaybeUninit<Block>],
        printer: impl DebugPrinter,
        progress: impl ProgressReporter,
    ) {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!("nonce: {:x}", Hex(nonce)));
        let split_nonce = Self::split_nonce(nonce)[i];
        Self::generate_allocated_chain_split_nonce(i, &split_nonce, blocks, printer, progress)
    }

    fn generate_allocated_chain_split_nonce(
        i: usize,
        split_nonce: &Nonce,
        blocks: &mut [MaybeUninit<Block>],
        #[allow(unused_variables)] printer: impl DebugPrinter,
        #[allow(unused_variables)] progress: impl ProgressReporter,
    ) {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "generate chain {}/{CHAIN_COUNT} chains of {CHAIN_BLOCK_COUNT} blocks of {BLOCK_SIZE} bytes.",
            i + 1,
        ));
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "chain: split_nonce: {:x}, hash length: {HASH_LENGTH}.",
            Hex(split_nonce)
        ));
        assert!(i < CHAIN_COUNT);
        assert_eq!(blocks.len(), Self::COMPUTED_BLOCK_COUNT);
        let offset = CHAIN_BLOCK_COUNT * i;
        // SAFETY: Fill the first two blocks with zeros.
        unsafe {
            ptr::write_bytes(blocks[0].as_mut_ptr(), 0u8, 1);
            ptr::write_bytes(blocks[1].as_mut_ptr(), 0u8, 1);
        }
        let mut allocated_hash = [0; BLOCK_SIZE];
        #[cfg(feature = "progress")]
        let mut p0 = 0;
        for index in 2..Self::COMPUTED_BLOCK_COUNT {
            let reference_index = reference_block_index::<CHAIN_BLOCK_COUNT>(
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
            #[cfg(feature = "progress")]
            {
                let p = 255 * index as u64 / (Self::COMPUTED_BLOCK_COUNT * CHAIN_COUNT) as u64;
                if p > p0 {
                    progress.increment((p - p0) as u8);
                    p0 = p;
                }
            }
        }
    }

    pub fn hash_chain(chain: &[Block]) -> Box<[[u8; HASH_LENGTH]]> {
        let vec = chain
            .iter()
            .map(|it| {
                let hash: [u8; HASH_LENGTH] = MerkleHasher::<HASH_LENGTH>::hash(it);
                hash
            })
            .collect::<Vec<_>>();
        vec.into_boxed_slice()
    }

    pub fn build_state(
        hash_chains: &[&[[u8; HASH_LENGTH]]; CHAIN_COUNT],
        #[allow(unused_variables)] printer: impl DebugPrinter,
    ) -> Box<State<HASH_LENGTH>> {
        // Leave the final, uncomputed leaf uncommitted. Root retries only need
        // its sibling path; commit the winning leaf once before making proofs.
        for chain in hash_chains {
            assert_eq!(chain.len(), Self::COMPUTED_BLOCK_COUNT);
        }
        let leaves = (0..Self::TOTAL_BLOCK_COUNT - 1).map(|index| {
            hash_chains[index / CHAIN_BLOCK_COUNT]
                .get(index % CHAIN_BLOCK_COUNT)
                .copied()
                .unwrap_or([0; HASH_LENGTH])
        });
        Box::new(State(MerkleTree::from_leaves_iter(leaves)))
    }

    /// Search a bounded batch. Disjoint starts and a common stride let workers
    /// share the search without sharing memory or repeating candidates.
    pub fn search_roots(
        path: &[[u8; HASH_LENGTH]],
        start: u64,
        stride: u64,
        count: u32,
    ) -> Option<u64> {
        assert_eq!(path.len(), Self::SEARCH_PATH_LENGTH);
        assert!(stride > 0);
        for attempt in 0..count {
            let trial = start.checked_add(u64::from(attempt).checked_mul(stride)?)?;
            let mut root = Self::trial_leaf(trial);
            let mut index = Self::TOTAL_BLOCK_COUNT - 1;
            for sibling in path {
                // An unpaired rightmost node is promoted unchanged.
                while index % 2 == 0 {
                    index /= 2;
                }
                root = MerkleHasher::custom_domain_hash_with_prefix(b"hash", sibling, &root);
                index /= 2;
            }
            if (0..STEP_COUNT).all(|i| {
                challenge_index::<CHAIN_BLOCK_COUNT, CHAIN_COUNT>(&root, i) % CHAIN_BLOCK_COUNT
                    < Self::COMPUTED_BLOCK_COUNT
            }) {
                return Some(trial);
            }
        }
        None
    }

    pub fn trial_leaf(trial: u64) -> [u8; HASH_LENGTH] {
        MerkleHasher::custom_domain_hash(b"trial", &trial.to_le_bytes())
    }

    pub fn select_indices(root: &[u8; HASH_LENGTH]) -> Box<[usize; STEP_COUNT]> {
        Box::new(from_fn(|i| {
            challenge_index::<CHAIN_BLOCK_COUNT, CHAIN_COUNT>(root, i)
        }))
    }

    pub fn select_reference_indices(
        indices: &[usize; STEP_COUNT],
        parent_blocks: &[&Block; STEP_COUNT],
    ) -> Box<[usize; STEP_COUNT]> {
        let vec = indices
            .iter()
            .enumerate()
            .map(|(i, &index)| reference_block_index::<CHAIN_BLOCK_COUNT>(index, parent_blocks[i]))
            .collect::<Vec<_>>();
        let raw = Box::into_raw(vec.into_boxed_slice());
        // SAFETY: we know the vec is the same size as the slice of indices.
        unsafe { Box::from_raw(raw as *mut [usize; STEP_COUNT]) }
    }

    pub fn combine(
        #[allow(clippy::boxed_local)] state: Box<State<HASH_LENGTH>>,
        root: &[u8; HASH_LENGTH],
        indices: &[usize; STEP_COUNT],
        reference_indices: &[usize; STEP_COUNT],
        parent_blocks: &[&Block; STEP_COUNT],
        reference_blocks: &[&Block; STEP_COUNT],
        #[allow(unused_variables)] printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "combine {CHAIN_COUNT} chains of {CHAIN_BLOCK_COUNT} blocks of {BLOCK_SIZE} bytes."
        ));
        #[cfg(feature = "debug")]
        printer.debug_println(&format!(
            "proof: {STEP_COUNT} steps, hash length: {HASH_LENGTH}."
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
        chains: &[&[Block]; CHAIN_COUNT],
        printer: impl DebugPrinter,
    ) -> Box<[u8]> {
        let hash_chains: [_; CHAIN_COUNT] = from_fn(|i| Self::hash_chain(chains[i]));
        let mut state = Self::build_state(&from_fn(|i| hash_chains[i].as_ref()), printer);
        let path = state.search_path();
        let mut start = 0;
        let trial = loop {
            if let Some(trial) = Self::search_roots(&path, start, 1, 1024) {
                break trial;
            }
            start = start.checked_add(1024).expect("root search exhausted");
        };
        state.commit_leaf(Self::trial_leaf(trial));
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
        blocks: &mut [MaybeUninit<Block>],
        index: usize,
        reference_index: usize,
        hash: &mut Block,
    ) {
        // SAFETY: We know blocks[index - 1] and block[reference_index] are already initialized.
        MerkleHasher::custom_domain_hash_with_prefix_into(
            b"initial",
            unsafe { blocks[index - 1].assume_init_ref() },
            unsafe { blocks[reference_index].assume_init_ref() },
            hash,
        );
        MerkleHasher::custom_domain_hash_self(&0u16.to_be_bytes(), hash);
        // SAFETY: The hasher will fill the block without reading the bytes.
        let block = unsafe {
            core::slice::from_raw_parts_mut(blocks[index].as_mut_ptr() as *mut u8, BLOCK_SIZE)
        };
        MerkleHasher::<BLOCK_SIZE>::custom_domain_hash_with_prefix_into_slice(
            b"final", nonce, hash, block,
        );
    }
}

#[cfg(all(test, feature = "verify"))]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct Quiet;
    impl DebugPrinter for Quiet {
        fn debug_println(&self, _: &str) {}
    }
    impl ProgressReporter for Quiet {
        fn increment(&self, _: u8) {}
    }

    fn check_prefix<const BLOCKS: usize>() {
        type Proof<const B: usize> = Challenge<3, 3, B, 16>;
        let nonce = [42; 16];
        let chains = Proof::<BLOCKS>::generate_chains(&nonce, Quiet, Quiet);
        assert!(
            chains
                .iter()
                .all(|chain| chain.len() == Proof::<BLOCKS>::COMPUTED_BLOCK_COUNT)
        );
        let hashes = chains
            .each_ref()
            .map(|chain| Proof::<BLOCKS>::hash_chain(chain));
        let mut state =
            Proof::<BLOCKS>::build_state(&hashes.each_ref().map(|hashes| &**hashes), Quiet);
        let path = state.search_path();
        assert_eq!(path.len(), Proof::<BLOCKS>::SEARCH_PATH_LENGTH);
        assert_eq!(Proof::<BLOCKS>::search_roots(&path, 0, 1, 0), None);
        let trial = Proof::<BLOCKS>::search_roots(&path, 0, 1, 100_000).unwrap();
        // Even/odd workers must find the same first successful candidate.
        let parallel = (0..2)
            .filter_map(|i| Proof::<BLOCKS>::search_roots(&path, i, 2, 50_000))
            .min();
        assert_eq!(parallel, Some(trial));
        state.commit_leaf(Proof::<BLOCKS>::trial_leaf(trial));
        let root = state.root();
        assert!(
            Proof::<BLOCKS>::select_indices(&root)
                .iter()
                .all(|i| i % BLOCKS < Proof::<BLOCKS>::COMPUTED_BLOCK_COUNT)
        );
        // Independently build the complete commitment, including the trial leaf.
        let mut leaves = vec![[0; 16]; 3 * BLOCKS];
        for (i, hashes) in hashes.iter().enumerate() {
            leaves[i * BLOCKS..i * BLOCKS + hashes.len()].copy_from_slice(hashes);
        }
        *leaves.last_mut().unwrap() = Proof::<BLOCKS>::trial_leaf(trial);
        assert_eq!(
            *root,
            MerkleTree::<MerkleHasher<16>>::from_leaves(&leaves)
                .root()
                .unwrap()
        );
        let proof =
            Proof::<BLOCKS>::combine_chains(&chains.each_ref().map(|chain| &**chain), Quiet);
        assert!(Proof::<BLOCKS>::verify_proof(&nonce, &proof).is_some());
        assert!(Proof::<BLOCKS>::verify_proof(&[43; 16], &proof).is_none());
        let mut tampered = proof.to_vec();
        tampered[0] ^= 1;
        assert!(Proof::<BLOCKS>::verify_proof(&nonce, &tampered).is_none());
    }

    #[test]
    fn prefix_search_and_commit_support_unbalanced_trees() {
        check_prefix::<4>();
        check_prefix::<5>();
        check_prefix::<15>();
        check_prefix::<16>();
        check_prefix::<17>();
        check_prefix::<64>();
    }
}
