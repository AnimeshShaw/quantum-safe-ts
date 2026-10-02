/**
 * quantum-safe-ts Node.js entry: reads the .wasm shipped next to this file and initialises
 * synchronously, so every API is usable immediately after `import`.
 */
export * from './core.js';

import { readFileSync } from 'node:fs';
import { initSyncFromBytes } from './runtime.js';

initSyncFromBytes(readFileSync(new URL('./quantum_safe_wasm_bg.wasm', import.meta.url)));
