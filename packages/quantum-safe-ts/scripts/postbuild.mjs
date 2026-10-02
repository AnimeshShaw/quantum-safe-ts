// Post-build steps:
//  1. copy the raw .wasm into dist/ (used by the Workers subpath `quantum-safe-ts/quantum_safe_wasm_bg.wasm`);
//  2. write dist/wasm.d.ts so that `import wasm from 'quantum-safe-ts/quantum_safe_wasm_bg.wasm'` type-checks;
//  3. make every emitted declaration file reference the ESNext.Disposable lib, so consumers with lib: ["ES2022"] can compile `using` and
//     `Symbol.dispose` declarations without a TS2550 error (the bundler drops the triple-slash directive).
import { copyFileSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(pkg, 'dist');
copyFileSync(resolve(pkg, 'wasm', 'quantum_safe_wasm_bg.wasm'), resolve(dist, 'quantum_safe_wasm_bg.wasm'));
console.log('copied quantum_safe_wasm_bg.wasm to dist/');

writeFileSync(
  resolve(dist, 'wasm.d.ts'),
  '// The precompiled module for runtimes that import .wasm files as modules (for example Cloudflare Workers).\n' +
    'declare const wasmModule: object;\nexport default wasmModule;\n',
);

const REF = '/// <reference lib="esnext.disposable" />';
let patched = 0;
for (const f of readdirSync(dist)) {
  if (!/\.d\.c?ts$/.test(f) || f === 'wasm.d.ts') continue;
  const p = resolve(dist, f);
  const text = readFileSync(p, 'utf8');
  if (!text.includes(REF)) {
    writeFileSync(p, `${REF}\n${text}`);
    patched++;
  }
}
console.log(`added the esnext.disposable reference to ${patched} declaration files`);
