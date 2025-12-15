extern crate blake2;
extern crate rs_merkle;

use crate::DEFAULT_HASH_LENGTH;
use blake2::digest::VariableOutput;
use rs_merkle::Hasher;

#[derive(Copy, Clone, Debug, Default)]
pub struct Blake2bHasher<const HASH_LENGTH: usize = DEFAULT_HASH_LENGTH>;

impl<const HASH_LENGTH: usize> Hasher for Blake2bHasher<HASH_LENGTH> {
    type Hash = [u8; HASH_LENGTH];
    fn hash(data: &[u8]) -> Self::Hash {
        let mut output = [0u8; HASH_LENGTH];
        blake2::Blake2bVar::digest_variable(data, &mut output).unwrap();
        output
    }
}
