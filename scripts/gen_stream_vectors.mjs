// Writes tests/vectors/stream_vectors.json: streaming envelopes (format v3) made by this library, for quantum-safe-py's StreamSealer / StreamOpener
// to open (tests/interop/vectors/stream_vectors.json there). Covers a hybrid suite, P-256, pure ML-KEM-1024 (HKDF-SHA-384), and X-Wing; empty, one-byte,
// exact-multiple and non-multiple lengths; with and without caller AAD.
// Run from the repository root after building the package:  node scripts/gen_stream_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const q = require(path.join(root, 'packages/quantum-safe-ts/dist/node.cjs'));

const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const CHUNK = 1024;
const out = { generated_by: 'quantum-safe-ts streaming envelope v3 (chunk size 1024)', chunk_size: CHUNK, vectors: [] };

const suites = ['X25519+ML-KEM-768', 'P-256+ML-KEM-512', 'P-384+ML-KEM-1024', 'ML-KEM-1024', 'X-Wing'];
for (const algorithm of suites) {
  const kem = algorithm.includes('+') || algorithm === 'X-Wing' ? new q.HybridKEM(algorithm) : new q.KEM(algorithm);
  const pair = kem.generateKeyPair();
  try {
    for (const [len, aad] of [[0, ''], [1, ''], [1024, ''], [1025, 'file-7'], [3000, ''], [2048, 'tenant-a']]) {
      const plaintext = Uint8Array.from({ length: len }, (_, i) => (i * 31 + len) & 0xff);
      const stream = await q.sealBytes(pair.publicKey, plaintext, { chunkSize: CHUNK, aad: enc(aad) });
      out.vectors.push({
        algorithm,
        secret_key: hex(pair.secretKey.exportBytes()),
        aad: hex(enc(aad)),
        plaintext: hex(plaintext),
        stream: hex(stream),
      });
    }
  } finally {
    pair.free();
  }
}
const file = path.join(root, 'tests/vectors/stream_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} vectors`);
