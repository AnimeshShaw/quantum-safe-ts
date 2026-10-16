#!/usr/bin/env node
// Generates tests/vectors/ts_rewrap_vectors.json: envelopes sealed under an old key, and the same messages re-wrapped to a new key by
// quantum-safe-ts's Envelope.rewrap, with both secret keys, so quantum-safe-py can open the re-wrapped copy and re-wrap the original itself
// (tests/unit/test_ts_rewrap_interop.py in quantum-safe-py).
//
// Run from the repository root after `npm run build` in packages/quantum-safe-ts:
//   node scripts/gen_rewrap_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const q = require(path.join(root, 'packages/quantum-safe-ts/dist/node.cjs'));
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);

const pairs = [
  ['X25519+ML-KEM-768', 'X25519+ML-KEM-1024'],
  ['X25519+ML-KEM-512', 'X25519+ML-KEM-768'],
  ['P-256+ML-KEM-768', 'X25519+ML-KEM-1024'],
  ['P-256+ML-KEM-768', 'P-384+ML-KEM-1024'],
];
const out = { generated_by: 'quantum-safe-ts Envelope.rewrap', vectors: [] };
for (const [from, to] of pairs) {
  const oldPair = new q.HybridKEM(from).generateKeyPair();
  const newPair = new q.HybridKEM(to).generateKeyPair();
  for (const [label, plaintext, aad] of [
    ['with aad', enc('migrate me: ' + from), enc('record-42')],
    ['no aad', enc('no context'), new Uint8Array(0)],
  ]) {
    const original = q.Envelope.seal(plaintext, oldPair.publicKey, { aad });
    const moved = q.Envelope.rewrap(original, oldPair.secretKey, newPair.publicKey, { expectedAad: aad });
    out.vectors.push({
      label: `${from} -> ${to} (${label})`,
      from,
      to,
      plaintext: hex(plaintext),
      aad: hex(aad),
      old_secret_pem: oldPair.secretKey.toPem(),
      new_secret_pem: newPair.secretKey.toPem(),
      new_public_pem: newPair.publicKey.toPem(),
      original: hex(original.toBytes()),
      rewrapped: hex(moved.toBytes()),
    });
  }
  oldPair.free();
  newPair.free();
}
const file = path.join(root, 'tests/vectors/ts_rewrap_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} vectors`);
