# Proof of work

## Implementation details

It starts with a 16-byte [Nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce).

We derive `CHAIN_COUNT` chains. `CHAIN_COUNT` is between 1 and 8 (2 by default).

Each chain has `CHAIN_BLOCK_COUNT` blocks (262_144 blocks by default).

Each block has `BLOCK_SIZE` hashes (256 by default) of `HASH_LEN` length (16 bytes by default).

---

### Steps to generate the proof
  - Split the original nonce into CHAIN_COUNT nonces.<br>
    [cShake256](https://kerkour.com/sha3#cshake) is used as [KDF](https://en.wikipedia.org/wiki/Key_derivation_function).<br>
    These nonces are used to seed each chain.<br><br>

  - Initialize the chains blocks.<br>
    The first two blocks are zero-filled.<br>
    For the next blocks:
    - Take the parent (previous) block
    - Take a reference block<br>
      The reference block is an index between 0 and parent index, 
      calculated deterministically from the parent block content.
    - For each hash (at index i) in the block, the value is the [cShake256](https://kerkour.com/sha3#cshake) hash
      with the parent block hash[i] as custom domain and reference block hash[i] as input, 
      followed by ITERATION_COUNT (1 by default) passes of cShake256 hashing.<br><br>

  - Create a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) from the blocks (from all the chains).<br>
    One leaf per block with the cShake256 hash of the full block (all hashes concatenated).<br><br>

  - Calculate STEP_COUNT (10 by default) indices.<br>
    They are calculated deterministically from the merkle tree root.<br><br>
    
  - Assemble the proof. 
    - The merkle tree root
    - For each step:
      - the step index `i`
      - the reference index `r`
      - the block hash `hash(block[i])`
      - the parent block `block[i-1]`
      - the reference block `block[r]`
      - the merkle tree proof for those 3 indices `tree.proof(&[i-1, i, r])`
    <br><br>

---

### Steps to verify the proof
  - Extract the merkle tree root<br><br>
  - For each step:
    - extract the index `i` and verify it
    - extract the reference index `r`
    - extract the block hash `hash(block[i])`
    - extract the parent block `block[i-1]`
    - extract the reference block `block[r]`
    - verify the reference index
    - compute the block and verify its hash
    - extract the proof for those 3 indices and verify it

<br>

## Crate features

You can choose between 3 different implementations of the cshake function:
  - [tiny-keccak](https://crates.io/crates/tiny-keccak)<br>
    CC0-1.0 licensed<br>
    The fastest of the 3 options and the one used by default.
  - [rust-crypto](https://rustcrypto.org) [sha3](https://crates.io/crates/sha3)<br>
    Dual licensed under Apache 2.0 and MIT.
  - const-hash<br>
    Dual licensed under Apache 2.0 and MIT.<br>
    Based on a fork of [keccak-const](https://crates.io/crates/keccak-const) that adds cShake and KMac variants.<br>
    Much slower but the hash functions are [const fn](https://doc.rust-lang.org/reference/const_eval.html#const-functions).

You can tweak the const parameters (mentioned in the implementation details above) with the features:
  - high-cpu<br>
    Modifies the hashing passes during block initialization from 1 to 16, which usually results in doubling the cpu time.
  - high-memory<br>
    Doubles the number of blocks to 524_288 per chain.<br><br>

The generation and verification are usually done in separate binaries.
You can enable only the part that is needed:
  - generate<br><br>
  - verify<br><br>

You can enable progress tracking with the feature:
  - progress<br><br>

You can add verbose logging with the feature:
  - debug<br><br>

---