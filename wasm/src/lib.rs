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
    Printer.debug_println("cast nonce to &[u8; 16]");
    let nonce: &[u8; 16] = unsafe {
        std::slice::from_raw_parts(nonce_ptr, 16)
            .try_into()
            .inspect_err(|err| Printer.error_println(&format!("{err}")))
            .unwrap()
    };
    Printer.debug_println("generate chain");
    let chain = pow::generate_chain(i, nonce, Printer);
    Box::into_raw(chain) as *const u8
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_chain(ptr: *mut u8) {
    let _ = unsafe {
        Box::from_raw(ptr as *mut [Block<DEFAULT_BLOCK_SIZE>; DEFAULT_CHAIN_BLOCK_COUNT])
    };
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
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    Printer.debug_println("malloc");
    let mut vec = Vec::<u8>::with_capacity(size);
    let ptr = vec.as_mut_ptr();
    core::mem::forget(vec);
    ptr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8, len: usize) {
    Printer.debug_println("free");
    let _ = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr, len)) };
}
