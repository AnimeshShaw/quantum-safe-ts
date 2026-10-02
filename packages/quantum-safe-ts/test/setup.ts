import { readFileSync } from 'node:fs';
import { initSyncFromBytes } from '../src/runtime.js';

// Tests run against the freshly built WASM artifact (bindings/wasm via wasm-pack).
initSyncFromBytes(readFileSync(new URL('../wasm/quantum_safe_wasm_bg.wasm', import.meta.url)));
