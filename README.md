# Automation Mitigation

Any website that allows visitors to submit content is a target for automation. 
Without bot mitigation, unprotected forms quickly become a vector for spam and malicious submissions.

Bot mitigation is typically handled by [CAPTCHAs](https://en.wikipedia.org/wiki/CAPTCHA),
but this approach has major downsides:
 - **Privacy risks:**<br>
  Because challenge-only CAPTCHAs are no longer effective, 
  modern CAPTCHAs rely on large‑scale cross‑site analysis of many signals:
  user location, behavior, browsing history, device fingerprints, etc...<br>
  However, these exact signals can be used (and often are) to identify and track users for other purposes. 
 - **False positives:**<br>
  Users of unconventional browsers, of privacy tools like VPNs, or using shared access points are often either blocked
  or always presented with a (sometimes long) series of challenges.
 - **User friction:**<br>
  Especially on their first interaction, users often have to solve puzzles to prove that they are human.<br>
  With the advance of AI, bots can now solve those challenges with greater accuracy than most humans.
  This makes them unreliable, yet they remain a significant barrier to real users.

Ultimately, no bot mitigation is bulletproof. The goal is simply to make automation no longer economically viable.<br>
A **cryptographic proof of work** is designed precisely for this purpose.
It requires the client to perform a verifiable and predictable amount of work on every submission,
making high-volume attacks prohibitively resource-intensive.<br>
<br>
This project implements a Proof of Work optimized for bot mitigation.
The CPU and memory requirements are tuned to ensure the cost is transparent to a legitimate user, but as demanding as possible
for the resource-constrained hardware typically used for mass automation.

See [the security review](./SECURITY_REVIEW.md) for demonstrated shortcuts and implementation fixes.

## Usage

The solution consists of two parts:
 - A client-side component
 - A server-side component

### Client-side

For each form submission, the client must:
  - Fetch a [nonce](https://en.wikipedia.org/wiki/Nonce) from the server.
  - Compute the proof of work using the nonce as the cryptographic seed.
  - Send the proof and the nonce to the server along with the form submission.

Since the proof takes a few seconds to compute, 
it is good practice to start the first two steps proactively in the background as soon as user intent is detected:

- On page load for dedicated form pages where the user's intent is clear from the start.
- On the interaction with the form.

Depending on the implementation of the server-side component, the nonce might be only valid for a limited time 
(nominally between 15 and 30 minutes for the default rolling-window implementation, plus any background rotation delay).
<br>
In that case, the client should restart the process when the expiration is imminent or has already passed.

**Client-side components**
 
- `lib.wasm`<br>
 
This is the WebAssembly code with the optimized implementation of the proof of work algorithm.
The implementation is split in multiple steps to allow parallel computation using multiple web workers.

You can generate the wasm file by compiling the [wasm](./wasm) crate.

The default parameters use **2 chains** with **128 MiB of block data** in total;
`high-memory` doubles that to **256 MiB**. Merkle trees, worker copies, and allocator overhead
increase peak RAM. The checked-in `lib.mjs` loads `lib-high.wasm`, which enables both high-memory
and high-cpu; the generated `lib-min.mjs` loads the base variant. Measure latency on your target devices.
However, both the cpu time and memory required can be adjusted.

**Reducing complexity** is generally only necessary for secondary forms where the computation is only started
upon interaction to save resources, but the submission is almost immediate (there are no required fields).

**Increasing complexity** can be desirable for forms involving content creation, such as writing a comment. 
Since the user will naturally spend more time on the form, the additional time required to compute the proof 
will not impact the user experience.

- `lib.mjs`<br>

This is a Javascript module that exports an async function to actually create the proof of work for a given nonce.
It makes use of the wasm module described above.<br>
The arguments are:
  - _nonce_<br>
    A 16-byte [`Uint8Array`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array) 
    provided by the server.
  - _signal_<br>
    An optional [`AbortSignal`](https://developer.mozilla.org/en-US/docs/Web/API/AbortSignal) 
    that can be used to abort the computation.
  - _onProgress_<br>
    An optional callback function triggered periodically to report the progress of the computation 
    as a number between 0 and 1.

### Server-side

For each form submission, the server must:
 - Issue a **16-byte nonce** used as the seed for the proof of work generation.
 - Verify the proof of work submitted by the client.

The [pow](./pow) crate (with the `verify` feature enabled) exports a `verify_proof` function:<br>
```rust
pub fn verify_proof(nonce: &[u8; 16], proof: &[u8]) -> Option<()>
```

If your server is not implemented in [Rust](https://rust-lang.org/),
the function can be compiled to WebAssembly and executed via a WASM runtime (see the [java](./examples/java) and [javascript](./examples/javascript) examples).

The nonce must be unpredictable and unique. Unpredictability prevents useful advance computation for a particular
nonce; it does not eliminate shortcuts in the proof algorithm. Atomic single-use consumption prevents replay.<br>
16 bytes provide enough entropy for the seed of the proof of work algorithm.

Authenticate the nonce and reject tokens outside the stored generation pair or already consumed before expensive proof verification.
With `RollingWindow`, call `check`, verify the proof, then call `verify` to atomically consume the nonce.
Accept the submission only if all three succeed. A successful `check` alone does not reserve a nonce.
Limit request sizes before buffering (`DefaultGenerator::MAX_PROOF_BYTES` bounds the raw proof),
and limit issuance and concurrent verification. Never trust difficulty parameters supplied by the client.

Keeping track of the nonces can be done in several ways, but doing it as cheaply as possible can be tricky.<br>
The [nonce](./nonce) crate provides an implementation that allows a large (over half a million)
but finite number of seeds per 15-minute generation.
It uses two small (64 kb) local and unsynchronized bit-vectors to track the consumed seeds.
It accepts either stored generation, giving issued nonces a nominal lifetime between 15 and 30 minutes.
Only the background thread advances the pair; requests tolerate delayed rotation without consulting the clock.
This design allows a challenge to be replayed on each backend with independent consumption state.
Restarting with the same seed also resets consumption and issuance state. These are deployment trade-offs:
use shared consumption storage or issuer routing if they are unacceptable, and persist consumption state
or rotate the secret seed on restart. Use a securely generated secret seed and scope it to the protected
action and difficulty profile so cheaper proofs cannot be spent on more valuable actions.

Nonce generations now use `u32`; upgrading changes nonce derivation. Expire old tokens and deploy
the nonce producer/verifier together. The proof byte format and existing valid proof vectors are unchanged.


## Examples
...
