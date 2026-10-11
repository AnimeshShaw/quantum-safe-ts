// Writes tests/vectors/ts_private_vectors.json: private AKP JWKs and private COSE keys (the 32-byte seed) made by this library, with a token
// and a COSE_Sign1 each signed with them, for quantum-safe-py's seed-key support to consume (tests/interop/vectors/ts_private_vectors.json there).
// Run from the repository root after building the package:  node scripts/gen_private_key_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const q = require(path.join(root, 'packages/quantum-safe-ts/dist/node.cjs'));
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);

const out = { generated_by: 'quantum-safe-ts (StandardJwt private JWKs, cose private keys)', vectors: [] };
for (const algorithm of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const { publicJwk, privateJwk } = q.StandardJwt.generateKeyPair(algorithm, { kid: `ts-${algorithm}` });
  const token = q.StandardJwt.sign({ sub: 'from-typescript' }, privateJwk, { expiresIn: 0 });
  const pair = new q.Sign(algorithm).standardKeyPairFromSeed(Uint8Array.from(Buffer.from(privateJwk.priv, 'base64url')));
  try {
    out.vectors.push({
      algorithm,
      private_jwk: privateJwk,
      public_jwk: publicJwk,
      token,
      cose_private_key: hex(q.cose.encodePrivateKey(pair, { kid: enc(`ts-${algorithm}`) })),
      cose_sign1: hex(q.cose.sign1(enc('cose from typescript'), pair, { kid: enc(`ts-${algorithm}`) })),
      cose_payload: hex(enc('cose from typescript')),
    });
  } finally {
    pair.free();
  }
}
const file = path.join(root, 'tests/vectors/ts_private_vectors.json');
fs.writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${file}: ${out.vectors.length} vectors`);
