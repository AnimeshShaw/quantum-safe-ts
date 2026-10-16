// Writes tests/vectors/ts_cose_vectors.json: COSE_Sign1 messages made by this library (ML-DSA-44/65/87; tagged, untagged, detached, with
// external AAD and a key id), for quantum-safe-py's protocols.cose to verify (tests/interop/vectors/ts_cose_vectors.json there).
// Run from the repository root after building the package:  node scripts/gen_cose_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const q = require(path.join(root, 'packages/quantum-safe-ts/dist/node.cjs'));
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);

const out = { generated_by: 'quantum-safe-ts cose.sign1 (RFC 9964 COSE half)', vectors: [] };
for (const algorithm of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const pair = new q.Sign(algorithm).generateStandardKeyPair();
  try {
    const cases = [
      { name: 'tagged with kid', opts: { kid: enc('ts-key-1') }, aad: '', payload: 'hello from typescript' },
      { name: 'untagged', opts: { tagged: false }, aad: '', payload: 'untagged message' },
      { name: 'external aad', opts: { externalAad: enc('app-context') }, aad: 'app-context', payload: 'bound to a context' },
      { name: 'detached', opts: { detached: true }, aad: '', payload: 'a detached document body' },
      { name: 'empty payload', opts: {}, aad: '', payload: '' },
    ];
    for (const c of cases) {
      const message = q.cose.sign1(enc(c.payload), pair, c.opts);
      out.vectors.push({
        algorithm, case: c.name, public_key: hex(pair.publicKey), external_aad: hex(enc(c.aad)), payload: hex(enc(c.payload)),
        detached: c.opts.detached === true, message: hex(message),
      });
    }
  } finally {
    pair.free();
  }
}
const file = path.join(root, 'tests/vectors/ts_cose_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} vectors`);
