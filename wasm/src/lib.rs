use pow::{
    Block, DebugPrinter, State, DEFAULT_BLOCK_SIZE, DEFAULT_CHAIN_BLOCK_COUNT,
    DEFAULT_CHAIN_COUNT, DEFAULT_HASH_LENGTH, DEFAULT_STEP_COUNT,
};
use std::array::from_fn;
use std::slice;

#[link(wasm_import_module = "js")]
unsafe extern "C" {
    fn println(ptr: usize, len: usize);
    fn eprintln(ptr: usize, len: usize);
}

#[derive(Copy, Clone)]
struct Printer;

impl DebugPrinter for Printer {
    #[inline(always)]
    fn debug_println(&self, message: &str) {
        unsafe { println(message.as_ptr() as usize, message.len()) }
    }
}

impl Printer {
    pub fn error_println(&self, message: &str) {
        unsafe { eprintln(message.as_ptr() as usize, message.len()) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hash(ptr: *const u8, len: usize) -> *mut u8 {
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    let hash = pow::hash(payload);
    Box::into_raw(Box::new(hash)) as *mut u8
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_hash(ptr: *mut u8) {
    Printer.debug_println("free blocks");
    let _ = unsafe { Box::from_raw(ptr as *mut [u8; DEFAULT_HASH_LENGTH]) };
}

/// Generates a chain of blocks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generate_chain(i: usize, nonce_ptr: *const u8) -> *mut u8 {
    Printer.debug_println("cast nonce to &[u8; 16]");
    let nonce: &[u8; 16] = unsafe {
        std::slice::from_raw_parts(nonce_ptr, 16)
            .try_into()
            .inspect_err(|err| Printer.error_println(&format!("{err}")))
            .unwrap()
    };
    Printer.debug_println("generate chain");
    let chain = pow::generate_chain(i, nonce, Printer);
    Box::into_raw(chain) as *mut u8
}

/// Returns the hashes of the blocks (converts a slice of blocks to an array of hashes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hash_chain(chain_ptr: *const u8) -> *mut u8 {
    let chain: &[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT] = unsafe {
        std::slice::from_raw_parts(
            chain_ptr as *const Block<DEFAULT_BLOCK_SIZE>,
            DEFAULT_CHAIN_BLOCK_COUNT,
        )
        .try_into()
        .inspect_err(|err| Printer.error_println(&format!("{err}")))
        .unwrap()
    };
    Printer.debug_println("hash chain");
    let hash_chain = pow::hash_chain(chain);
    Box::into_raw(hash_chain) as *mut u8
}

/// Converts the two arrays of hashes into the state (a merkle tree of the combination).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn build_state(
    hash_chain1_ptr: *const u8,
    hash_chain2_ptr: *const u8,
) -> *mut State<DEFAULT_HASH_LENGTH> {
    let chain1 = unsafe {
        &*(hash_chain1_ptr as *const [[u8; DEFAULT_HASH_LENGTH]; DEFAULT_CHAIN_BLOCK_COUNT])
    };
    let chain2 = unsafe {
        &*(hash_chain2_ptr as *const [[u8; DEFAULT_HASH_LENGTH]; DEFAULT_CHAIN_BLOCK_COUNT])
    };
    let state = pow::build_state(&[&chain1, &chain2]);
    Box::into_raw(state)
}

/// Returns the root of the merkle tree.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn root(state: *const State<DEFAULT_HASH_LENGTH>) -> *mut u8 {
    let root = pow::root(unsafe { &*state });
    Box::into_raw(root) as *mut u8
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn select_index(root: *const u8, i: usize) -> usize {
    let root = unsafe { &*(root as *const [u8; DEFAULT_HASH_LENGTH]) };
    let index =
        pow::index_log::<DEFAULT_CHAIN_BLOCK_COUNT, DEFAULT_CHAIN_COUNT>(root.as_ref(), i, Printer);
    index
}

/// Returns the proof of work indices from (a reference of) the state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select_indices(root: *const u8) -> *mut usize {
    let root = unsafe { &*(root as *const [u8; DEFAULT_HASH_LENGTH]) };
    let indices = pow::select_indices(&root);
    Printer.debug_println(&format!("select indices: {indices:?}"));
    Box::into_raw(indices) as *mut usize
}

/// Returns the proof of work reference indices from (a reference of) the indices
/// and (references of) the parent blocks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select_reference_indices(
    indices: *const usize,
    parent_blocks: *const u8,
) -> *mut usize {
    let parent_blocks: &[[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT] =
        unsafe { &*(parent_blocks as *const [[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT]) };
    let reference_indices = pow::select_reference_indices(
        unsafe { &*(indices as *const [usize; DEFAULT_STEP_COUNT]) },
        &from_fn(|i| &parent_blocks[i]),
    );
    Box::into_raw(reference_indices) as *mut usize
}

/// Returns the proof of work from the state (consumed), the indices (consumed),
/// the reference indices (consumed), the parent blocks (consumed) and the reference blocks (consumed)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn combine(
    state: *mut State<DEFAULT_HASH_LENGTH>,
    root: *mut u8,
    indices: *mut usize,
    reference_indices: *mut usize,
    parent_blocks: *mut u8,
    reference_blocks: *mut u8,
) -> Box<[u8; 8]> {
    let state = unsafe { Box::from_raw(state) };
    let root = unsafe { Box::from_raw(root as *mut [u8; DEFAULT_HASH_LENGTH]) };
    let indices = unsafe { Box::from_raw(indices as *mut [usize; DEFAULT_STEP_COUNT]) };
    let reference_indices =
        unsafe { Box::from_raw(reference_indices as *mut [usize; DEFAULT_STEP_COUNT]) };
    let parent_blocks: Box<[[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT]> = unsafe {
        Box::from_raw(parent_blocks as *mut [[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT])
    };
    let reference_blocks: Box<[[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT]> = unsafe {
        Box::from_raw(reference_blocks as *mut [[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT])
    };
    let proof = pow::combine(
        state,
        &root,
        &indices,
        &reference_indices,
        &from_fn(|i| &parent_blocks[i]),
        &from_fn(|i| &reference_blocks[i]),
        Printer,
    );
    let len = proof.len();
    let ptr = Box::into_raw(proof) as *mut u8;
    let mut ptr_and_len = Vec::with_capacity(8);
    ptr_and_len.extend_from_slice(&(ptr as u32).to_le_bytes());
    ptr_and_len.extend_from_slice(&(len as u32).to_le_bytes());
    unsafe { Box::from_raw(Box::into_raw(ptr_and_len.into_boxed_slice()) as *mut [u8; 8]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_hash_chain(ptr: *mut u8) {
    let _ = unsafe { Box::from_raw(ptr as *mut [[u8; DEFAULT_HASH_LENGTH]; DEFAULT_STEP_COUNT]) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_chain(ptr: *mut u8) {
    let _ = unsafe {
        Box::from_raw(ptr as *mut [Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT])
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_state(ptr: *mut State<DEFAULT_HASH_LENGTH>) {
    let _ = unsafe { Box::from_raw(ptr) };
}

// Combines the two chains to produce the proof of work.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn combine_chains(
    chain1_ptr: *const u8,
    chain2_ptr: *const u8,
) -> Box<[u8; 8]> {
    let chain1: &[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT] = unsafe {
        std::slice::from_raw_parts(
            chain1_ptr as *const Block<DEFAULT_BLOCK_SIZE>,
            DEFAULT_CHAIN_BLOCK_COUNT,
        )
        .try_into()
        .inspect_err(|err| Printer.error_println(&format!("{err}")))
        .unwrap()
    };
    let chain2: &[Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT] = unsafe {
        std::slice::from_raw_parts(
            chain2_ptr as *const Block<DEFAULT_BLOCK_SIZE>,
            DEFAULT_CHAIN_BLOCK_COUNT,
        )
        .try_into()
        .inspect_err(|err| Printer.error_println(&format!("{err}")))
        .unwrap()
    };
    let chains = [chain1, chain2];
    let proof = pow::combine_chains(&chains, Printer);
    let len = proof.len();
    let ptr = Box::into_raw(proof) as *mut u8;
    let mut ptr_and_len = Vec::with_capacity(8);
    ptr_and_len.extend_from_slice(&(ptr as u32).to_le_bytes());
    ptr_and_len.extend_from_slice(&(len as u32).to_le_bytes());
    unsafe { Box::from_raw(Box::into_raw(ptr_and_len.into_boxed_slice()) as *mut [u8; 8]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn alloc_nonce() -> *mut u8 {
    Printer.debug_println("alloc monce");
    let mut vec = Vec::<u8>::with_capacity(16);
    let ptr = vec.as_mut_ptr();
    core::mem::forget(vec);
    ptr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_nonce(ptr: *mut u8) {
    Printer.debug_println("free nonce");
    unsafe { Vec::from_raw_parts(ptr, 0, 16) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn alloc_blocks() -> *mut u8 {
    Printer.debug_println("alloc blocks");
    let blocks: Box<[[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT]> =
        Box::new([[0u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT]);
    Box::into_raw(blocks) as *mut u8
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_blocks(ptr: *mut u8) {
    Printer.debug_println("free blocks");
    let _ = unsafe { Box::from_raw(ptr as *mut [[u8; DEFAULT_BLOCK_SIZE]; DEFAULT_STEP_COUNT]) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ptr_and_len(ptr: *mut u8) {
    Printer.debug_println("free ptr and len");
    let ptr_and_len = unsafe { Box::from_raw(ptr as *mut [u8; 8]) };
    let ptr = u32::from_le_bytes(ptr_and_len[0..4].try_into().unwrap());
    let len = u32::from_le_bytes(ptr_and_len[4..8].try_into().unwrap());
    let _ = unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len as usize)) };
}
