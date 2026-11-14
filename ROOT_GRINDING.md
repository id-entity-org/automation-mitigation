# Partial-chain proofs and root retries

The proof uses ten samples to check a much larger computation. A prover can
exploit this sampling by computing only a chain prefix and trying different
Merkle roots until all samples fall inside the computed region. This is an
accepted cost trade-off: the project aims to impose meaningful work on bots,
while keeping proofs small enough for fast mobile uploads.

**How it works.** After receiving the server's nonce, the prover correctly
computes a prefix of each chain. It commits those block hashes in a Merkle tree,
using arbitrary hash values for the uncomputed remainder. The root determines
the sample indices. If a sample falls outside the prefixes, the prover changes
an unused leaf hash, calculates a new root, and tries again.

When every sample falls inside a prefix, its parent and reference are also
available: dependencies point backwards within the same chain. The disclosed
transitions are correct for the server's nonce, and their Merkle proofs are
valid. The verifier never checks the uncomputed transitions.

The nonce stays fixed throughout. All retries happen locally, and only the
successful proof needs submission. No hash collision, nonce forgery, or repeated
nonce redemption is required.

**What has been demonstrated.** The repository's `pow/examples/partial_chain.rs`
uses one 256-block chain, ten samples, and eight intermediate hashing rounds.
It computes the first 128 blocks, including the two initial blocks: 126 of the
254 required transitions. With its fixed example nonce, it produces an accepted
proof after 839 candidate roots. This demonstrates acceptance of incomplete
computation, not a measured production speedup.

**How much work it can save.** If fraction `f` of eligible sample positions is
computed, then, treating hash-derived samples as independent and uniform:

```text
Success probability per candidate root ≈ f^10
Expected candidate roots              ≈ 1 / f^10
```

| Computed fraction | Chain transitions skipped | Expected candidate roots |
| --- | --- | --- |
| 90% | About 10% | 2.9 |
| 75% | About 25% | 17.8 |
| 50% | About 50% | 1,024 |

For the base memory profile, storing half of both chains reduces block storage
from approximately 128 MiB to 64 MiB. Merkle storage and other overhead remain
additional. Half is an illustrative strategy, not an enforced minimum.

Retries are not free. An optimized solver retaining its tree can update only
the changed leaf's ancestors. The base profile has 524,288 leaves and 19 tree
levels, so roughly 1,024 candidates entail about 19,456 internal-node hashes,
plus sample-index calculations. A candidate can be rejected at its first sample
outside the prefixes. Initial tree construction and final proof construction
also cost work. The example rebuilds the entire small tree each time, which is
more expensive than updating one path.

Thus the half-prefix strategy avoids about half the chain transitions, but adds
root-search work. It does **not** establish a 50% reduction in total runtime,
energy, or monetary cost. Those net savings have not been benchmarked. The cost
to compare against full generation is:

```text
prefix computation + initial Merkle tree + root retries + final proof
```

**Why retain ten samples.** There is no obvious small fix that eliminates this
strategy while preserving the existing noninteractive protocol and proof-size
budget. Increasing the sample count is the straightforward mitigation: for a
half-prefix strategy, twenty samples increase expected candidates to 1,048,576.
However, they also roughly double proof size and verification work. Larger
prefixes still permit cheaper searches.

The sample count was chosen to keep mobile proof uploads fast. For this project,
the additional upload cost is not considered worth that mitigation; substantial
remaining computation is acceptable. This is a design decision, not a claim
that retry overhead has been measured to cancel all savings.

Forcing a check of the final block does not solve the problem: a prover can
construct a valid final transition from an arbitrary parent without computing
the intervening chain. Server-selected samples revealed after a root commitment
could prevent offline root selection, with enforced limits on commitments and
challenges, but would require an additional exchange and protocol coordination.
It is not a small adjustment to the current design.
