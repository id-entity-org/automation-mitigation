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
(15 minutes for the example implementation).
<br>
In that case, the client should restart the process when the expiration is imminent or has already passed.

**Client-side components**
 
- `lib.wasm`<br>
 
This is the webassembly code with the optimized implementation of the proof of work algorithm.
The implementation is split in multiple steps to allow parallel computation using multiple web workers.

You can generate the wasm file by compiling the [wasm](./wasm) crate.

By default, the computation of the proof uses **2 CPU** cores and **256 MB** of RAM, 
and completes in about 10 seconds on a mid-range phone.
However, both the cpu time and memory required can be adjusted.

**Reducing complexity** is generally only necessary for secondary forms where the computation is only started
upon interaction to save resources, but the submission is almost immediate (there are no required fields).

**Increasing complexity** can be desirable for forms involving content creation, such as writing a comment. 
Since the user will naturally spend more time on the form, the proof can be more demanding without impacting
the user experience.

- `lib.mjs`<br>
...

### Server-side
...
