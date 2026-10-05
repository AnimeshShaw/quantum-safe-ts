// Writes tests/vectors/ts_raw_fips204_vectors.json: bare FIPS 204 ML-DSA signatures made by this library's
// standards-mode signer (the primitive behind StandardJwt) with a native context. quantum-safe-py >= 0.3.2
// verifies them with Sign.verify_raw (scripts/verify_ts_vectors.py).
// This uses the internal WASM module directly: the primitive is not part of the public TypeScript API.
// Run from the repository root after building the package:  node scripts/gen_ts_raw_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const wasmDir = path.join(root, 'packages/quantum-safe-ts/wasm');
const glue = await import(new URL(`file:///${path.join(wasmDir, 'quantum_safe_wasm.js').split(path.sep).join('/')}`).href);
glue.initSync({ module: fs.readFileSync(path.join(wasmDir, 'quantum_safe_wasm_bg.wasm')) });

const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const contexts = [new Uint8Array(0), enc('quantum-safe-ts interop'), Uint8Array.from({ length: 255 }, (_, i) => i)];
const out = { generated_by: 'quantum-safe-ts WASM core (standards mode, FIPS 204 ML-DSA.Sign with a native context)', vectors: [] };

for (const level of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const pair = glue.mldsaStandardKeyGen(level);
  const publicKey = pair.publicKey;
  const seed = pair.takeSeed();
  try {
    for (const ctx of contexts) {
      const message = enc(`standard FIPS 204 message from ts for ${level} ctx${ctx.length}`);
      const signature = glue.mldsaStandardSign(level, seed, message, ctx);
      out.vectors.push({ algorithm: level, public_key: hex(publicKey), message: hex(message), context: hex(ctx), signature: hex(signature) });
    }
  } finally {
    seed.free();
    pair.free();
  }
}

const file = path.join(root, 'tests/vectors/ts_raw_fips204_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} vectors`);
