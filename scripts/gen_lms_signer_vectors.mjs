#!/usr/bin/env node
// Generates tests/vectors/ts_lms_signer_vectors.json: LMS public keys and signatures made by quantum-safe-ts's LmsSigner, for
// quantum-safe-py to verify with its independent implementation (pyhsslms) (tests/unit/test_ts_lms_signer_interop.py).
//
// Run from the repository root after `npm run build` in packages/quantum-safe-ts:
//   node scripts/gen_lms_signer_vectors.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { LmsSigner } = await import(pathToFileURL(path.join(root, 'packages/quantum-safe-ts/dist/lms-signer.js')).href);
const enc = new TextEncoder();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qs-lms-vec-'));
const out = { generated_by: 'quantum-safe-ts LmsSigner', vectors: [] };
try {
  for (const [height, winternitz, count] of [[5, 1, 2], [5, 2, 2], [5, 4, 2], [5, 8, 2], [10, 4, 2]]) {
    const signer = LmsSigner.create({ directory: path.join(tmp, `h${height}w${winternitz}`), height, winternitz });
    const cases = [];
    for (let i = 0; i < count; i++) {
      const message = enc.encode(`quantum-safe-ts LMS signer vector ${height}/${winternitz}/${i}`);
      cases.push({ message: Buffer.from(message).toString('hex'), signature: Buffer.from(signer.sign(message)).toString('hex') });
    }
    out.vectors.push({
      parameter_set: signer.parameterSet,
      height,
      winternitz,
      public_key: Buffer.from(signer.publicKey).toString('hex'),
      cases,
    });
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
const file = path.join(root, 'tests/vectors/ts_lms_signer_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} keys`);
