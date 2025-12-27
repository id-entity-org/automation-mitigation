extern crate rs_merkle;

use crate::DEFAULT_HASH_LENGTH;
#[cfg(all(
    feature = "const-hash",
    not(any(feature = "tiny-keccak", feature = "rust-crypto"))
))]
use keccak_const::{CShake256, Shake256};
use rs_merkle::Hasher;
#[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
use sha3::{digest::*, CShake256Core};
#[cfg(feature = "tiny-keccak")]
use tiny_keccak::{CShake, Hasher as _, Shake};

#[derive(Copy, Clone, Debug, Default)]
pub struct MerkleHasher<const HASH_LENGTH: usize = DEFAULT_HASH_LENGTH>;

#[cfg(all(
    feature = "const-hash",
    not(any(feature = "tiny-keccak", feature = "rust-crypto"))
))]
pub const SHAKE256: Shake256 = Shake256::new();

impl<const HASH_LENGTH: usize> Hasher for MerkleHasher<HASH_LENGTH> {
    type Hash = [u8; HASH_LENGTH];
    fn hash(data: &[u8]) -> Self::Hash {
        #[cfg(feature = "tiny-keccak")]
        {
            let mut hasher = Shake::v256();
            hasher.update(data);
            let mut hash = [0u8; HASH_LENGTH];
            hasher.finalize(&mut hash);
            hash
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        {
            let mut hasher = sha3::Shake256::default();
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            let mut hash = [0u8; HASH_LENGTH];
            reader.read(&mut hash);
            hash
        }
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        SHAKE256.update(data).finalize()
    }
}

impl<const HASH_LENGTH: usize> MerkleHasher<HASH_LENGTH> {
    pub fn hash_self(hash: &mut [u8; HASH_LENGTH]) {
        #[cfg(feature = "tiny-keccak")]
        {
            let mut hasher = Shake::v256();
            hasher.update(hash);
            hasher.finalize(hash);
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        {
            let mut hasher = sha3::Shake256::default();
            hasher.update(hash);
            let mut reader = hasher.finalize_xof();
            reader.read(hash);
        }
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        SHAKE256.update(hash).finalize_into(hash);
    }
    pub fn hash_with_custom_domain(prefix: &[u8], data: &[u8]) -> [u8; HASH_LENGTH] {
        #[cfg(feature = "tiny-keccak")]
        {
            let mut hasher = CShake::v256(b"pow", prefix);
            hasher.update(data);
            let mut hash = [0u8; HASH_LENGTH];
            hasher.finalize(&mut hash);
            hash
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        {
            let core = CShake256Core::new_with_function_name(b"pow", prefix);
            let mut hasher = sha3::CShake256::from_core(core);
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            let mut hash = [0u8; HASH_LENGTH];
            reader.read(&mut hash);
            hash
        }
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        CShake256::new(b"pow", prefix).update(data).finalize()
    }
    pub fn hash_with_custom_domain_into(prefix: &[u8], data: &[u8], hash: &mut [u8; HASH_LENGTH]) {
        #[cfg(feature = "tiny-keccak")]
        {
            let mut hasher = CShake::v256(b"pow", prefix);
            hasher.update(data);
            hasher.finalize(hash);
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        {
            let core = CShake256Core::new_with_function_name(b"pow", prefix);
            let mut hasher = sha3::CShake256::from_core(core);
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            reader.read(hash);
        }
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        CShake256::new(b"pow", prefix)
            .update(data)
            .finalize_into(hash);
    }
    pub fn hash_with_custom_domain_into_slice(prefix: &[u8], data: &[u8], hash: &mut [u8]) {
        #[cfg(feature = "tiny-keccak")]
        {
            let mut hasher = CShake::v256(b"pow", prefix);
            hasher.update(data);
            hasher.finalize(hash);
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "tiny-keccak")))]
        {
            let core = CShake256Core::new_with_function_name(b"pow", prefix);
            let mut hasher = sha3::CShake256::from_core(core);
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            reader.read(hash);
        }
        #[cfg(all(
            feature = "const-hash",
            not(any(feature = "tiny-keccak", feature = "rust-crypto"))
        ))]
        CShake256::new(b"pow", prefix)
            .update(data)
            .finalize_into_slice::<HASH_LENGTH>(hash);
    }
}
