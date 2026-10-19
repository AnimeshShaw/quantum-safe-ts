/**
 * Optional native AES-256-GCM for large payloads.
 *
 * The WebAssembly core has no AES hardware instructions, so it encrypts at roughly 125 MiB/s. On Node.js the same
 * cipher runs about ten times faster in `node:crypto`. For payloads of {@link NATIVE_AEAD_MIN_BYTES} or more, `Envelope` and the
 * streaming API ask the core for the one-time key, nonce and associated data (the "plan"), run AES-256-GCM through the
 * implementation registered here and hand the result back. The bytes produced are identical to the core's own, and every check
 * (algorithm, version, lengths, counters) still happens in the core. Entry points that cannot offer such an implementation
 * (browsers, Workers, Deno without `node:crypto`) register nothing and keep the WebAssembly path.
 */

/** AES-256-GCM with a 12-byte nonce and a 16-byte tag. */
export interface NativeAead {
  /** Encrypts `plaintext`; returns `ciphertext || tag`. */
  encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  /** Decrypts `ciphertext || tag`; returns `null` when authentication fails (never throws for bad data). */
  decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertextWithTag: Uint8Array): Uint8Array | null;
}

/** Below this many bytes the WebAssembly path is used: the extra calls to fetch the key cost more than the faster cipher saves. */
export const NATIVE_AEAD_MIN_BYTES = 16 * 1024;

let registered: NativeAead | null = null;

/** @internal Registers (or, with `null`, removes) the native implementation. Called by the Node.js entry point. */
export function setNativeAead(impl: NativeAead | null): void {
  registered = impl;
}

/** @internal The registered implementation, if any. */
export function nativeAead(): NativeAead | null {
  return registered;
}
