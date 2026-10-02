/**
 * quantum-safe-ts Node.js entry: initialises synchronously from the embedded WASM, so every API is
 * usable immediately after `import`. The module is embedded rather than read from disk so that it
 * keeps working when a framework bundles server code (Next.js, Remix, Nitro, ...), where the
 * on-disk layout of node_modules is not preserved.
 */
export * from './core.js';

import { initSyncFromBytes, setDefaultSource } from './runtime.js';
import { inlineWasmBytes } from './wasm-inline.js';

setDefaultSource(inlineWasmBytes);
initSyncFromBytes(inlineWasmBytes());
