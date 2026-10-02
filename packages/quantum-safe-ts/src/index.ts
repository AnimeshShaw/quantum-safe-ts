/**
 * quantum-safe-ts: hybrid post-quantum cryptography for TypeScript and JavaScript.
 *
 * Generic entry point (browsers, Deno, Bun, edge runtimes, bundlers): the WASM module is embedded
 * as base64, so no bundler configuration is needed. Call `await init()` once before use.
 * On Node.js the `node` export condition resolves to an entry that initialises automatically.
 */
export * from './core.js';

import { setDefaultSource } from './runtime.js';
import { inlineWasmBytes } from './wasm-inline.js';

setDefaultSource(inlineWasmBytes);
