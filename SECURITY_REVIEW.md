# Security and attacker-cost review

The goal is to make accepted automated submissions cost money. Measure the
cheapest solver's cost per accepted submission, including failed attempts,
rather than the supplied browser's running time or peak RAM. The changes below
improve implementation safety and enforce intended verification rules; they do
not establish a cryptographic lower bound on work or memory.

## Remaining priorities

### 1. Measure and price root grinding

The prover chooses the Merkle root, and all ten checks depend on that root.
A prover can compute a prefix, commit arbitrary hashes for the remaining leaves,
and change one uncomputed leaf repeatedly until every check lands in the prefix.
References for a prefix remain within it, so those checked transitions pass.
No hash collision or preimage attack is necessary.

`pow/examples/partial_chain.rs` reproduces this with ten samples: it generated
126 of 254 required transitions and obtained an accepted proof after 839 roots.
Run `cargo run -p automation-mitigation-pow --example partial_chain --release`.
It rebuilds a small tree each trial for clarity; this is not a production-cost
benchmark. An optimized solver can update the path of one changed leaf in
logarithmic work and reject a root as soon as a sample misses its prefix.

If fraction `f` of eligible indices is correctly computed, all `s` independent
samples land there with approximate probability `f^s` per root. At `f = 1/2`
and `s = 10`, expect about 1,024 roots; at `s = 32`, about 4.3 billion.
This does not mean 32 checks prevents all profitable partial computation:
larger prefixes need fewer retries, and issuance allows further nonce grinding.
Benchmark prefix fractions and native solvers before choosing `s`.

Increasing sample count is the simplest design adjustment (both ends and assets
must agree). A stronger alternative is an interactive protocol: commit the root,
then obtain unpredictable server-selected samples bound to that root and nonce.
Limit commitments/retries per nonce, or repeated server sampling recreates the
same attack. This needs a protocol change and was not silently implemented.

### 2. Treat memory as a time-memory trade-off

Each 256-byte block is an expansion of a 64-byte intermediate and the chain nonce.
A solver can retain that intermediate, regenerating blocks for reference reads
and disclosures. This reduces chain storage by four times at default block size,
at the price of extra final-expansion hashes. The `high-cpu` rounds need not be
repeated. Merkle storage remains additional, so total process RAM does not
necessarily fall four times.

Independent chains also allow serial processing or recomputation; two browser
workers do not enforce two simultaneous cores or two simultaneously stored chains.
Benchmark these native strategies. If memory cost is central, a future version
needs a compression function whose retained state scales with the block, plus
analysis of checkpoint/recomputation attacks. Increasing output size alone does
not achieve that. Related work includes
[Time-Memory Tradeoff Attacks on the MTP](https://eprint.iacr.org/2017/497.pdf);
its numerical results should not be assumed to apply to this construction.

### 3. Protect server resources and redemption scope

- Authenticate, check membership in the stored generation pair, and check consumed state before proof verification.
  Then verify the proof and atomically consume the nonce before accepting the
  action. The new `check` is only a precheck: concurrent requests may all pass it,
  but only one `verify` can consume the nonce locally.
- Cap request bodies before buffering them, using the raw proof bound plus
  separately bounded encoding/envelope overhead. Limit issuance, verification
  concurrency, and submissions. The finite issuance pool can be exhausted
  without any proof work. Valid unsolved tokens can still trigger verifier CPU.
- Choose difficulty on the server and bind nonces to the action/profile.
  Separate secret seeds/windows per action and difficulty are one simple option.
  Authenticate session/account binding where needed. Otherwise a proof can be
  transferred to another operation accepting the same nonce/profile.
- Local bitsets permit one redemption per backend. Fresh instances with the
  same seed/generation also issue the same counter sequence. Use issuer routing
  or shared consumption state when duplicate acceptance is too valuable.
  Restarting with the same seed resets consumed state and permits replay:
  persist that state or rotate the seed, invalidating outstanding tokens.
- Generate the secret seed with an OS CSPRNG. Nonce width does not replace seed
  entropy. The nominal window lasts between `T` and `2T` after issuance, not a fixed `T`.
  Only the background rotator advances the pair. Requests accept either stored
  generation even if rotation is delayed; strict wall-clock expiry is not required.

## Implemented changes and reasons

| Area | Change and reason |
| --- | --- |
| Chain initialization | Keep direct `write_bytes` initialization, fixing its element count to 1 and targeting blocks 0 and 1. Previously it wrote `BLOCK_SIZE` whole blocks and targeted block 0 twice. Tiny allocations could be overwritten; default allocations masked the error. |
| Block output | Initialize the destination in place before lending a mutable byte slice to the hasher. This avoids uninitialized references without introducing a block-sized stack temporary. |
| Parameter validation | Reject zero samples/hashes, blocks too short for reference-index reads, chains too short for sampling, and indices that exceed the wire format. Do not impose a hash-strength minimum or require extra hashing passes. |
| Verifier | Bound total/path sizes to limit attacker-controlled allocations. Initial blocks may be nonzero; disclosed transitions must still compute correctly and match the Merkle commitment. |
| Server features | Export `verify_proof` with `verify` alone; it was accidentally hidden without tests/debug. |
| WASM ABI | Require wasm32 for this adapter. Keep the original metadata and return descriptor; JavaScript reads the descriptor with DataView, which supports unaligned addresses. |
| WASM allocation | Allocate hash-chain arrays directly on the heap, avoiding multi-megabyte stack temporaries in less optimized builds. |
| JS memory access | Copy sample indices before further allocations; use little-endian reads and unsigned pointer offsets. Growth detaches old views; typed arrays otherwise use host byte order. |
| Worker protocol | Serve index zero, a valid reference that previously left generation waiting forever. |
| Worker lifecycle | Validate inputs early, cover startup cancellation, remove abort listeners, and propagate child/coordinator errors. This avoids needless work, retained listeners, and some pending requests that never settle. |
| Nonce rotation | Derive each generation's keys from the seed while reusing the existing bitsets. Reusing old keys made rotated servers disagree with freshly started servers. |
| Nonce epochs | Retain the explicitly requested `u32` generation choice. The background rotator jumps over missed windows instead of potentially iterating billions of times under the write lock after a clock change. Requests accept either stored generation without consulting the clock. |
| Nonce authentication | Separate non-consuming `check` from atomic `verify` consumption, allowing cheap rejection without burning a nonce before its proof passes. |
| Build | Move release settings to the workspace root, where Cargo applies them; fix minifier variant permissions. |
| Distribution | Rebuild four WASM variants, four minified JS variants, and nine Brotli assets so serving bundles/compressed files includes the fixes. |
| Documentation | Correct block units, iteration count, memory accounting, expiry, and server verification order. |

## Changes removed after scope review

- Removed the requirement that disclosed initial blocks be zero. Nonzero initial blocks are an accepted design choice; no material work-avoidance benefit from choosing them was demonstrated.
- Restored the original valid bulk zeroing of `AtomicU64` storage, bitset reuse during rotation, and the original nonce comparison.
- Removed the positive-capacity restriction and redundant counter comparison change; zero capacity is a valid exhausted producer.
- Replaced array-value initialization with direct in-place writes.
- Removed arbitrary minimum hash-length and iteration-count restrictions; retained only algorithm/format invariants.
- Removed exact Merkle-path canonicalization. Once allocation sizes are bounded, unused path hashes do not establish a work bypass or replay bypass, and the extra check duplicates tree traversal.
- Restored WASM metadata types and the byte-based return descriptor; the JavaScript DataView fix handles its alignment directly.
- Removed the extra client nonce copy and restored the existing Deno assertion import.
- Replaced the broad proof README rewrite with corrections to inaccurate algorithm/feature descriptions.
- Request-time clock refresh and `u64` generations had already been removed following the accepted design trade-offs.

The non-consuming nonce precheck remains because authenticating before proof verification
reduces unauthenticated verifier CPU abuse; consuming before proof verification would
instead let an invalid proof burn a valid token. Atomic consumption still happens last.

## WASM assumptions

Four-byte pointers are appropriate for `wasm32-unknown-unknown`, even in a 64-bit
browser. The native Rust verifier remains portable; wire indices explicitly use
`u32`. Memory64 needs a different adapter, including JavaScript BigInt handling.
The Rust reference documents [`usize` as pointer-sized](https://doc.rust-lang.org/stable/core/primitive.usize.html).

Growth triggered by Rust allocation can detach JavaScript ArrayBuffers. Copy or
recreate views after allocating calls; see
[MDN's memory.grow documentation](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory/grow).
Raw exported pointers still require trusted callers and correctly allocated
objects. Client pointer checks cannot enforce attacker work: bots can replace
the entire solver and submit proofs directly.

## Compatibility and validation

Nonce generation fields changed from `u16` to `u32`, changing nonce derivation.
Expire old tokens and upgrade issuers/verifiers together. Existing valid proof
bytes and published hashes remain unchanged. Difficulty/sample counts were not
changed; the demonstrated economic shortcuts remain open design trade-offs.

Completed validation:

- 14 existing Rust proof tests, 5 new proof-hardening/compatibility tests, and 5 nonce tests pass.
- A verifier-only build with default features disabled passes.
- Four release WASM variants compile.
- All 8 Deno proof hash vectors pass against rebuilt assets, as do 4 new JS tests
  for invalid inputs, startup abort, reference index zero, forced memory growth, and an unaligned descriptor.
- Nine regenerated Brotli assets decompress byte-for-byte to their source assets.
- The incomplete-chain example verifies its intentionally incomplete proof.

This was a source review with targeted tests, not fuzzing, a Miri run, a
cross-browser/mobile test matrix, or an optimized attacker-cost benchmark.
