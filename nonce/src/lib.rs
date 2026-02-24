#[cfg(all(
    feature = "const-hash",
    not(any(feature = "tiny-keccak", feature = "rust-crypto"))
))]
use keccak_const::CShake256;
#[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
use sha3::{digest::*, CShake256Core};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::UNIX_EPOCH;
use std::{ptr, thread};
#[cfg(feature = "tiny-keccak")]
use tiny_keccak::{CShake, Hasher};

pub struct VerifiableNonce {
    pub generation: u16,
    pub counter: usize,
    pub nonce: [u8; 16],
}

pub struct NonceProducer<const MAX: usize = 512_000> {
    pub generation: u16,
    cursor: AtomicUsize,
    bitset: Box<[AtomicU64]>,
    iv: [u8; 32],
    mac_key: [u8; 32],
}

impl<const MAX: usize> NonceProducer<MAX> {
    pub fn for_generation(generation: u16, seed: &[u8; 32]) -> Self {
        const { assert!(MAX.is_multiple_of(64), "MAX must be a multiple of 64") };
        Self::generate(generation, seed)
    }
    pub(crate) fn for_generations(generation: u16, seed: &[u8; 32]) -> (Self, Self) {
        (
            Self::generate(generation, seed),
            Self::generate(generation.wrapping_add(1), seed),
        )
    }
    fn k_nonce(&self, k: usize) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        #[cfg(feature = "tiny-keccak")]
        {
            let mut hasher = CShake::v256(b"kdf", b"nonce");
            hasher.update(self.mac_key.as_slice());
            hasher.update(self.generation.to_le_bytes().as_slice());
            hasher.update((k as u64).to_le_bytes().as_slice());
            hasher.update(self.iv.as_slice());
            hasher.finalize(&mut nonce);
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        {
            let core = CShake256Core::new_with_function_name(b"kdf", b"nonce");
            let mut hasher = sha3::CShake256::from_core(core);
            hasher.update(self.mac_key.as_slice());
            hasher.update(self.generation.to_le_bytes().as_slice());
            hasher.update((k as u64).to_le_bytes().as_slice());
            hasher.update(self.iv.as_slice());
            let mut reader = hasher.finalize_xof();
            reader.read(&mut nonce);
        }
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        {
            CShake256::new(b"kdf", b"nonce")
                .update(self.mac_key.as_slice())
                .update(self.generation.to_le_bytes().as_slice())
                .update((k as u64).to_le_bytes().as_slice())
                .update(self.iv.as_slice())
                .finalize_into(&mut nonce);
        }
        nonce
    }
    pub fn nonce(&self) -> Option<(usize, [u8; 16])> {
        let k = self.next_index()?;
        Some((k, self.k_nonce(k)))
    }
    pub fn verify(&self, k: usize, nonce: &[u8; 16]) -> Option<()> {
        if &self.k_nonce(k) == nonce {
            if k < MAX {
                let i = k / 64;
                let j = k % 64;
                let mask = 1u64 << j;
                if self.bitset[i].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
                    Some(())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
    fn next_index(&self) -> Option<usize> {
        // we could probably optimize with a simple fetch_add as
        // it's unlikely to overflow and wrap around,
        // but fetch_update makes sure that doesn't happen.
        self.cursor
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |it| {
                if it == MAX { None } else { Some(it + 1) }
            })
            .ok()
    }
    fn generate(generation: u16, seed: &[u8; 32]) -> Self {
        #[cfg(feature = "tiny-keccak")]
        let (iv, mac_key) = {
            let mut hasher = CShake::v256(b"kdf", b"key");
            hasher.update(seed);
            hasher.update(generation.to_le_bytes().as_slice());
            let mut out = [0u8; 64];
            hasher.finalize(&mut out);
            let mut iv = [0u8; 32];
            iv.copy_from_slice(&out[..32]);
            let mut mac_key = [0u8; 32];
            mac_key.copy_from_slice(&out[32..]);
            (iv, mac_key)
        };
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        let (iv, mac_key) = {
            let core = CShake256Core::new_with_function_name(b"kdf", b"key");
            let mut hasher = sha3::CShake256::from_core(core);
            hasher.update(seed.as_slice());
            hasher.update(generation.to_le_bytes().as_slice());
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 64];
            reader.read(&mut out);
            let mut iv = [0u8; 32];
            iv.copy_from_slice(&out[..32]);
            let mut mac_key = [0u8; 32];
            mac_key.copy_from_slice(&out[32..]);
            (iv, mac_key)
        };
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        let (iv, mac_key) = {
            let mut out = [0u8; 64];
            CShake256::new(b"kdf", b"key")
                .update(seed.as_slice())
                .update(generation.to_le_bytes().as_slice())
                .finalize_into(&mut out);
            let mut iv = [0u8; 32];
            iv.copy_from_slice(&out[..32]);
            let mut mac_key = [0u8; 32];
            mac_key.copy_from_slice(&out[32..]);
            (iv, mac_key)
        };
        let len = MAX / 64;
        let mut bitset = Vec::<AtomicU64>::with_capacity(len);
        // SAFETY: we zero the memory to initialize,
        // which is safe because the pointer is correctly aligned by the vec.
        unsafe {
            ptr::write_bytes(bitset.as_mut_ptr(), 0, len);
            bitset.set_len(len);
        }
        let bitset = bitset.into_boxed_slice();
        Self {
            generation,
            cursor: AtomicUsize::default(),
            bitset,
            iv,
            mac_key,
        }
    }
}

struct Producers<const N: usize> {
    gen1: NonceProducer<N>,
    gen2: NonceProducer<N>,
}

impl<const N: usize> Producers<N> {
    pub(crate) fn rotate(&mut self) {
        std::mem::swap(&mut self.gen1, &mut self.gen2);
        self.gen2.generation = self.gen1.generation.wrapping_add(1);
        // Replace with AtomicU64::get_mut_slice when stabilize
        // Tracking issue: https://github.com/rust-lang/rust/issues/76314
        let slice: &mut [u64] =
            unsafe { &mut *(&mut *self.gen2.bitset as *mut [AtomicU64] as *mut [u64]) };
        slice.fill(0);
        self.gen2.cursor.store(0, Ordering::Relaxed);
    }
}

pub struct RollingWindow<const T: usize = 900, const N: usize = 512_000> {
    generations: Option<Arc<RwLock<Producers<N>>>>,
    rotator: Option<JoinHandle<()>>,
}

impl<const T: usize, const N: usize> RollingWindow<T, N> {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        const { assert!(T > 0, "T must be greater than 0") };
        const { assert!(N.is_multiple_of(64), "N must be a multiple of 64") };
        let generation = (UNIX_EPOCH.elapsed().unwrap().as_secs() / T as u64) as u16;
        let (gen1, gen2) = NonceProducer::<N>::for_generations(generation, seed);
        let generations = Arc::new(RwLock::new(Producers { gen1, gen2 }));
        let gens = Arc::downgrade(&generations);
        let rotator = Some(thread::spawn(move || {
            loop {
                let current_timestamp = UNIX_EPOCH.elapsed().unwrap().as_secs();
                let next_rotation_timestamp = (current_timestamp / T as u64 + 1) * T as u64;
                let sleep_duration = next_rotation_timestamp.saturating_sub(current_timestamp) + 1;
                thread::park_timeout(std::time::Duration::from_secs(sleep_duration));
                match gens.upgrade() {
                    Some(gens) => {
                        let mut generations = gens
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let generation =
                            (UNIX_EPOCH.elapsed().unwrap().as_secs() / T as u64) as u16;
                        while generation != generations.gen1.generation {
                            generations.rotate();
                        }
                    }
                    None => break,
                }
            }
        }));
        Self {
            generations: Some(generations),
            rotator,
        }
    }
    pub fn nonce(&self) -> Option<VerifiableNonce> {
        let gen2 = &self.generations.as_ref()?.read().ok()?.gen2;
        let (counter, nonce) = gen2.nonce()?;
        Some(VerifiableNonce {
            generation: gen2.generation,
            counter,
            nonce,
        })
    }
    pub fn verify(&self, nonce: &VerifiableNonce) -> Option<()> {
        let generations = &self.generations.as_ref()?.read().ok()?;
        let producer = if nonce.generation == generations.gen2.generation {
            &generations.gen2
        } else if nonce.generation == generations.gen1.generation {
            &generations.gen1
        } else {
            return None;
        };
        producer.verify(nonce.counter, &nonce.nonce)
    }
}

impl<const T: usize, const N: usize> Drop for RollingWindow<T, N> {
    fn drop(&mut self) {
        self.generations = None;
        if let Some(handle) = self.rotator.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}
