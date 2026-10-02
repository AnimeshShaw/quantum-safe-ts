// Writes tests/vectors/ts_js_vectors.json using the BUILT package (packages/quantum-safe-ts/dist):
// data produced by the TypeScript library that the real quantum-safe-py must accept
// (verified by scripts/verify_ts_vectors.py). Run: npm run build && node scripts/gen_ts_js_vectors.mjs
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const q = require('../packages/quantum-safe-ts/dist/node.cjs');

const out = { jwt: [], kem: [], envelope: [] };
for (const algorithm of ['ML-DSA-65', 'ML-DSA-44', 'ML-DSA-87', 'Ed25519+ML-DSA-65', 'Ed25519+ML-DSA-87', 'P-256+ML-DSA-65']) {
  const signer = algorithm.includes('+') ? new q.HybridSign(algorithm) : new q.Sign(algorithm);
  const pair = signer.generateKeyPair();
  const token = new q.JWTSigner(pair, { issuer: 'https://ts.example' }).sign({ sub: 'ts-user', n: 7 }, { expiresIn: 1_000_000_000 });
  out.jwt.push({ algorithm, public_key: q.toHex(pair.publicKey.toBytes()), token, issuer: 'https://ts.example' });
  pair.free();
}
// Facade-level (not just core) KEM + envelope vectors, so the published API surface is what is verified.
for (const algorithm of ['X25519+ML-KEM-768', 'X25519+ML-KEM-1024', 'P-256+ML-KEM-768']) {
  const kem = new q.HybridKEM(algorithm);
  const pair = kem.generateKeyPair();
  const sealed = q.Envelope.seal(q.utf8(`facade ${algorithm}`), pair.publicKey, { aad: q.utf8('facade') });
  out.envelope.push({
    algorithm,
    secret_key: q.toHex(pair.secretKey.exportBytes()),
    plaintext: q.toHex(q.utf8(`facade ${algorithm}`)),
    aad: q.toHex(q.utf8('facade')),
    sealed: sealed.toHex(),
  });
  pair.free();
}
writeFileSync(new URL('../tests/vectors/ts_js_vectors.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${out.jwt.length} JWT and ${out.envelope.length} facade envelope vectors`);
