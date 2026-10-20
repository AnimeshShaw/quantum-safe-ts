// Writes tests/vectors/xwing_vectors.json: X-Wing (draft-connolly-cfrg-xwing-kem) key pairs, ciphertexts and shared secrets made by this
// library (the `x-wing` crate through the npm package). quantum-safe-py's X-Wing implementation consumes this file (tests/interop/vectors/)
// and must decapsulate every ciphertext to the same shared secret, and derive the same public key from each secret key.
// Run from the repository root after building the package:  node scripts/gen_xwing_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const q = require(path.join(root, 'packages/quantum-safe-ts/dist/node.cjs'));

const hex = (b) => Buffer.from(b).toString('hex');
const kem = new q.HybridKEM('X-Wing');
const out = {
  generated_by: 'quantum-safe-ts (x-wing crate); algorithm "X-Wing"; secret key = 32-byte seed, public key 1216 B, ciphertext 1120 B, shared secret 32 B',
  vectors: [],
  // The X25519 half of the ciphertext is a low-order point (all zero): RFC 7748 X25519 outputs all zeros and X-Wing does not reject it.
  low_order: [],
};
for (let i = 0; i < 6; i++) {
  const pair = kem.generateKeyPair();
  try {
    for (let j = 0; j < 2; j++) {
      const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
      const ss = sharedSecret.exportBytes();
      out.vectors.push({
        secret_key: hex(pair.secretKey.exportBytes()),
        public_key: hex(pair.publicKey.toBytes()),
        ciphertext: hex(ciphertext),
        shared_secret: hex(ss),
      });
      ss.fill(0);
      sharedSecret.free();
    }
    if (i < 3) {
      const { ciphertext } = kem.encapsulate(pair.publicKey);
      const bad = Uint8Array.from(ciphertext);
      bad.fill(0, 1088);
      const recovered = kem.decapsulate(pair.secretKey, bad);
      const rs = recovered.exportBytes();
      out.low_order.push({ secret_key: hex(pair.secretKey.exportBytes()), ciphertext: hex(bad), shared_secret: hex(rs) });
      rs.fill(0);
      recovered.free();
    }
  } finally {
    pair.free();
  }
}
const file = path.join(root, 'tests/vectors/xwing_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} vectors, ${out.low_order.length} low-order`);
