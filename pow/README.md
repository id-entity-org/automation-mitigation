It starts with a 16-byte Nonce.

We derive `CHAIN_COUNT` chains. `CHAIN_COUNT` is between 1 and 8 (2 by default).

Each chain has `CHAIN_BLOCK_COUNT` blocks (262_144 blocks by default).

Each block has `BLOCK_SIZE` hashes (256 by default) of `HASH_LEN` length (16 bytes by default).

---

### Steps to generate the proof
  - Split the original nonce into CHAIN_COUNT nonces.<br>
    [Shake256](https://kerkour.com/sha3#shake) is used as [KDF](https://en.wikipedia.org/wiki/Key_derivation_function).<br>
    These nonces are used to seed each chain.<br><br>

  - Initialize the chains blocks.<br>
    The first two blocks are all zeros.<br>
    For the next blocks:
    - take the parent (previous) block
    - take a reference block<br>
      The reference block is an index between 0 and parent index, 
      calculated deterministically from the parent block content.
    - For each hash (at index i) in the block, the value is the [cShake256](https://kerkour.com/sha3#cshake) hash
      with the parent block hash[i] as custom domain and reference block hash[i] as input, 
      followed by ITERATION_COUNT (1 by default) passes of Shake256 hashing.<br><br>

  - Create a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) from the blocks (from all the chains).<br>
    One leaf per block with the Shake256 hash of the full block (all hashes concatenated).<br><br>

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
  - Extract the merkle tree root
  - For each step:
    - extract the index `i` and verify it
    - extract the reference index `r`
    - extract the block hash `hash(block[i])`
    - extract the parent block `block[i-1]`
    - extract the reference block `block[r]`
    - verify the reference index
    - compute the block and verify its hash
    - extract the proof for those 3 indices and verify it
