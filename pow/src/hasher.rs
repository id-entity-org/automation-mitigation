extern crate rs_merkle;

use crate::DEFAULT_HASH_LENGTH;
use rs_merkle::Hasher;
use tiny_keccak::{CShake, Hasher as _};

#[derive(Copy, Clone, Debug, Default)]
pub struct MerkleHasher<const HASH_LENGTH: usize = DEFAULT_HASH_LENGTH>;

impl<const HASH_LENGTH: usize> Hasher for MerkleHasher<HASH_LENGTH> {
    type Hash = [u8; HASH_LENGTH];
    fn hash(data: &[u8]) -> Self::Hash {
        Self::custom_domain_hash(b"hash", data)
    }
}

impl<const HASH_LENGTH: usize> MerkleHasher<HASH_LENGTH> {
    pub fn custom_domain_hash_self(custom_domain: &[u8], hash: &mut [u8; HASH_LENGTH]) {
        let mut hasher = CShake::v256(b"pow", custom_domain);
        hasher.update(hash);
        hasher.finalize(hash);
    }
    pub fn custom_domain_hash(custom_domain: &[u8], data: &[u8]) -> [u8; HASH_LENGTH] {
        let mut hasher = CShake::v256(b"pow", custom_domain);
        hasher.update(data);
        let mut hash = [0u8; HASH_LENGTH];
        hasher.finalize(&mut hash);
        hash
    }
    pub fn custom_domain_hash_with_prefix(
        custom_domain: &[u8],
        prefix: &[u8],
        data: &[u8],
    ) -> [u8; HASH_LENGTH] {
        let mut hasher = CShake::v256(b"pow", custom_domain);
        hasher.update(prefix);
        hasher.update(data);
        let mut hash = [0u8; HASH_LENGTH];
        hasher.finalize(&mut hash);
        hash
    }
    pub fn custom_domain_hash_with_prefix_into(
        custom_domain: &[u8],
        prefix: &[u8],
        data: &[u8],
        hash: &mut [u8; HASH_LENGTH],
    ) {
        let mut hasher = CShake::v256(b"pow", custom_domain);
        hasher.update(prefix);
        hasher.update(data);
        hasher.finalize(hash);
    }
    pub fn custom_domain_hash_with_prefix_into_slice(
        custom_domain: &[u8],
        prefix: &[u8],
        data: &[u8],
        hash: &mut [u8],
    ) {
        let mut hasher = CShake::v256(b"pow", custom_domain);
        hasher.update(prefix);
        hasher.update(data);
        hasher.finalize(hash);
    }
}
