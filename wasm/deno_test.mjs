import {assertEquals} from "asserts";
import pow from "./lib.mjs";

Deno.test({
  name: "Generate POW proof",
  fn: async () => {
    // Use a concrete nonce from the Rust tests (pow/src/lib.rs)
    // 0x0b206ed758abdcb0d43c9bb3e7808495
    const nonce = new Uint8Array(16);
    nonce.setFromHex("0b206ed758abdcb0d43c9bb3e7808495");
    console.log(`Nonce: ${nonce.toHex()}`);

    const abortController = new AbortController();
    const onProgress = (progress) => {
      console.log(`Progress: ${Math.round(progress * 100)}%`);
    };

    const proof = await pow(nonce, abortController.signal, onProgress);
    console.log(`Proof generated: ${proof.length} bytes`);

    assertEquals(proof instanceof Uint8Array, true);
    assertEquals(proof.length > 0, true);

    const hashBuffer = await crypto.subtle.digest('SHA-256', proof);
    const hashArray = new Uint8Array(hashBuffer);
    const hashHex = hashArray.toHex();
    console.log(`Proof SHA-256: 0x${hashHex}`);

    // Expected hash from Rust tests: f8545c0973957c0b0ae86a6470d404a4359b753a3c9127c23b8fa1a6ba1abece
    assertEquals(hashHex, "f8545c0973957c0b0ae86a6470d404a4359b753a3c9127c23b8fa1a6ba1abece");
  },
  sanitizeResources: false,
  sanitizeOps: false,
});
