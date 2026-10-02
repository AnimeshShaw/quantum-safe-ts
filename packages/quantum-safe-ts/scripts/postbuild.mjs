// Copies the raw .wasm next to the Node entry so Node can read it from disk instead of base64.
import { copyFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
copyFileSync(resolve(pkg, 'wasm', 'quantum_safe_wasm_bg.wasm'), resolve(pkg, 'dist', 'quantum_safe_wasm_bg.wasm'));
console.log('copied quantum_safe_wasm_bg.wasm to dist/');
