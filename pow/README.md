# Proof of work

## Implementation details

It starts with a 16-byte [Nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce).

We derive `CHAIN_COUNT` chains. `CHAIN_COUNT` is between 1 and 8 (2 by default).

Each chain has `CHAIN_BLOCK_COUNT` blocks (1_048_576 committed positions by default; the solver computes the first 262_144 blocks).

Each block has `BLOCK_SIZE` bytes (256 by default). Its Merkle hash has `HASH_LENGTH` bytes (16 by default).

---

### Steps to generate the proof
  - Split the original nonce into CHAIN_COUNT nonces.<br>
    [cShake256](https://kerkour.com/sha3#cshake) is used as [KDF](https://en.wikipedia.org/wiki/Key_derivation_function).<br>
    These nonces are used to seed each chain.<br><br>

  - Compute the first quarter of each chain.<br>
    The first two blocks are zero-filled.<br>
    For the next blocks:
    - Take the parent (previous) block
    - Take a reference block<br>
      The reference block is an index between 0 and parent index, 
      calculated deterministically from the parent block content.
    - Hash the full parent and reference blocks into a 64-byte intermediate with domain `initial`.
      Hash that intermediate once with domain `[0, 0]`, then expand it with the chain nonce
      and domain `final` into BLOCK_SIZE bytes. There is no iteration-count setting.<br><br>

  - Create a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) over all committed positions.<br>
    Use the computed block hashes for each prefix and zero placeholder hashes for the remaining positions.
    Leave the final placeholder leaf uncommitted.<br><br>

  - Search for a root whose STEP_COUNT (7 by default) indices all land in the computed prefixes.<br>
    Each candidate leaf is cShake256 with function name `pow`, domain `trial`, and a little-endian
    `u64` counter as input. Recalculate only the final leaf's path and reject a candidate at its
    first sample outside the prefixes. Commit the winning leaf once.<br>
    The browser's chain workers search disjoint counter sequences in batches of 256 attempts.
    The coordinator chooses the lowest successful counter in the completed batch, so worker
    scheduling does not change the proof. Existing channels still carry hashes and block requests.<br><br>

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

The computed prefixes occupy 128 MiB at the base settings, or 256 MiB with `high-memory`.
Merkle trees, transferred buffers, and other overhead are additional. Root-search duration varies;
progress reports phase estimates rather than a guaranteed remaining time.

The proof record format is unchanged, but the sample count and committed block count have changed.
Update generators and verifiers together; proofs for the previous settings are incompatible.
The `high-cpu` feature and its browser bundles have been removed. Use `lib-min.mjs` (base) or
`lib-high-mem-min.mjs` (high memory), with matching server features.

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