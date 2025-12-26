use pow::{Block, DebugPrinter, DEFAULT_BLOCK_SIZE, DEFAULT_CHAIN_BLOCK_COUNT};

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
pub unsafe extern "C" fn generate_chain(i: usize, nonce_ptr: *const u8) -> *const u8 {
    let nonce: &[u8; 16] = unsafe {
        std::slice::from_raw_parts(nonce_ptr, 16)
            .try_into()
            .inspect_err(|err| Printer.error_println(&format!("{err}")))
            .unwrap()
    };
    let chain = pow::generate_chain(i, nonce, Printer);
    Box::into_raw(chain) as *const u8
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_chain(ptr: *mut u8) {
    let _ = unsafe {
        Box::from_raw(ptr as *mut [Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT])
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn generate_chain_prealloc(
    i: usize,
    nonce_ptr: *const u8,
    chain_ptr: *mut u8,
) {
    let nonce: &[u8; 16] = unsafe {
        std::slice::from_raw_parts(nonce_ptr, 16)
            .try_into()
            .inspect_err(|err| Printer.error_println(&format!("{err}")))
            .unwrap()
    };
    let chain: &mut [Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT] = unsafe {
        std::slice::from_raw_parts_mut(
            chain_ptr as *mut Block<DEFAULT_BLOCK_SIZE>,
            DEFAULT_CHAIN_BLOCK_COUNT,
        )
        .try_into()
        .inspect_err(|err| Printer.error_println(&format!("{err}")))
        .unwrap()
    };
    pow::generate_allocated_chain(i, nonce, chain, Printer);
}

#[repr(C)]
pub struct PtrAndLen {
    ptr: *const u8,
    len: usize,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn combine_chains(chain1_ptr: *const u8, chain2_ptr: *const u8) -> PtrAndLen {
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
    PtrAndLen {
        len: proof.len(),
        ptr: Box::into_raw(proof) as *const u8,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(len: usize) -> *mut u8 {
    let mut boxed = unsafe { Box::<[u8]>::new_uninit_slice(len).assume_init() };
    boxed.as_mut_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8, len: usize) {
    let _ = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr, len)) };
}
