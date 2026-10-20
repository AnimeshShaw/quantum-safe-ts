/**
 * quantum-safe-ts Node.js entry: initialises synchronously from the embedded WASM, so every API is
 * usable immediately after `import`. The module is embedded rather than read from disk so that it
 * keeps working when a framework bundles server code (Next.js, Remix, Nitro, ...), where the
 * on-disk layout of node_modules is not preserved.
 */
export * from './core.js';

import { createCipheriv, createDecipheriv } from 'node:crypto';
import { setNativeAead } from './native-aead.js';
import { initSyncFromBytes, setDefaultSource } from './runtime.js';
import { inlineWasmBytes } from './wasm-inline.js';

setDefaultSource(inlineWasmBytes);
initSyncFromBytes(inlineWasmBytes());

// Large payloads are encrypted with Node's AES-256-GCM (about ten times faster than the WebAssembly cipher); see native-aead.ts.
setNativeAead({
  /** AES-256-GCM encryption through `node:crypto` with a 16-byte tag; returns `ciphertext || tag`. */
  encrypt(key, nonce, aad, plaintext) {
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const body = cipher.update(plaintext);
    const rest = cipher.final();
    const tag = cipher.getAuthTag();
    const out = new Uint8Array(body.length + rest.length + tag.length);
    out.set(body, 0);
    out.set(rest, body.length);
    out.set(tag, body.length + rest.length);
    return out;
  },
  /** AES-256-GCM decryption through `node:crypto`; returns `null` for input shorter than the tag or when authentication fails. */
  decrypt(key, nonce, aad, ciphertextWithTag) {
    if (ciphertextWithTag.length < 16) return null;
    const split = ciphertextWithTag.length - 16;
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      decipher.setAAD(aad);
      decipher.setAuthTag(ciphertextWithTag.subarray(split));
      const body = decipher.update(ciphertextWithTag.subarray(0, split));
      const rest = decipher.final();
      const out = new Uint8Array(body.length + rest.length);
      out.set(body, 0);
      out.set(rest, body.length);
      return out;
    } catch {
      return null;
    }
  },
});
