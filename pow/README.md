# Proof of work

## Base algorithm

It starts with a 16-byte [Nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce).

We derive `CHAIN_COUNT` chains. `CHAIN_COUNT` is between 1 and 8 (2 by default).

Each chain has `CHAIN_BLOCK_COUNT` blocks (1_048_576 blocks by default).

Each block has `BLOCK_SIZE` bytes (fixed at 192, not a parameter). Its Merkle hash has `HASH_LENGTH` bytes (16 by default).

---

### Steps to generate the proof

  - Split the original nonce into CHAIN_COUNT nonces.<br>
    These nonces are used to seed each chain.<br><br>

  - Compute all blocks of each chain.<br>
    The first two blocks are zero-filled.<br>
    For the next blocks:
    - Take the parent (previous) block
    - Take a reference block<br>
      The reference block is an index between 0 and parent index, 
      calculated deterministically from the parent block content.
    - Hash the full parent and reference blocks into a 192-byte intermediate.
      Hash that intermediate once into 192 bytes, then hash it with the chain nonce into a 192-byte block.<br><br>

  - Create a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) from all the chains.<br>
    Each leaf is the hash of a full block.<br><br>

  - Calculate STEP_COUNT (7 by default) sample indices.<br>
    They are derived deterministically from the Merkle tree root.<br><br>

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

## Implemented shortcut

The implementation uses a shortcut to generate valid proofs faster and with less memory than
the base algorithm, at the cost of less predictable completion time. The proof format and
verification steps are the same: the verifier checks the sampled blocks, without requiring
every block in every chain to have been computed.

1. Compute only the first quarter of each chain (262_144 blocks per chain by default), using
   the same block computation as the base algorithm. Parent and reference blocks always
   precede the block being computed, so these prefixes can be computed independently of the rest.
2. Build the Merkle tree using the computed block hashes and zero placeholder hashes for the
   remaining positions. Leave the final placeholder leaf uncommitted.
3. Try different values for that final leaf until all seven sample indices land in the computed
   prefixes. Each candidate leaf is cShake256 with function name `pow`, domain `trial`, and a
   little-endian `u64` counter as input. Each retry recalculates only that leaf's path to the root
   and rejects the candidate at the first sample outside the prefixes.
4. Commit the winning leaf and assemble the proof once, as in the base algorithm.

The browser's two chain workers each compute their own prefix, then search disjoint counter
sequences in batches of 256 attempts. The coordinator chooses the lowest successful counter
in the completed batch, so worker scheduling does not change the proof.

The number of retries depends on luck: some proofs finish quickly, while others require many
more attempts. The shortcut reduces expected computation, but does not provide a fixed retry
count or completion time.

The computed prefixes occupy 96 MiB at the base settings, or 192 MiB with `high-memory`.
Merkle trees, transferred buffers, and other overhead are additional. Root-search duration varies;
progress reports phase estimates rather than a guaranteed remaining time.

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
  - high-memory<br>
    Doubles the committed positions to 2_097_152 per chain, with 524_288 computed blocks.<br><br>

The generation and verification are usually done in separate binaries.
You can enable only the part that is needed:
  - generate<br><br>
  - verify<br><br>

You can enable progress tracking with the feature:
  - progress<br><br>

You can add verbose logging with the feature:
  - debug<br><br>

---
