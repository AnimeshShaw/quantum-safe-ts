/**
 * quantum-safe-ts: hybrid post-quantum cryptography for TypeScript and JavaScript.
 *
 * Generic entry point (browsers, Deno, Bun, edge runtimes, bundlers): the WASM module is embedded
 * as base64, so no bundler configuration is needed. Call `await init()` once before use.
 * On Node.js the `node` export condition resolves to an entry that initialises automatically.
 */
export * from './core.js';

import { setDefaultSource } from './runtime.js';
import { WASM_BASE64 } from './wasm-inline.generated.js';

function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

setDefaultSource(() => decodeBase64(WASM_BASE64));
