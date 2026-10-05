// Writes tests/vectors/ts_v2_vectors.json: data produced by the quantum-safe-ts npm package for the formats
// quantum-safe-py 0.3.1 also reads: envelope v2, the -v2 signature format and RFC 9964 StandardJwt tokens.
// quantum-safe-py verifies it (scripts/verify_ts_vectors.py in this repo, and tests/interop in quantum-safe-py).
// Run from the repository root after building the package:  node scripts/gen_ts_v2_vectors.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { KEM, Envelope, Sign, HybridSign, StandardJwt } = await import(
  pathToFileURL(path.join(root, 'packages/quantum-safe-ts/dist/node.js')).href
);

const enc = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');
const V2_IDS = [
  'ML-DSA-44-v2', 'ML-DSA-65-v2', 'ML-DSA-87-v2',
  'Ed25519+ML-DSA-44-v2', 'Ed25519+ML-DSA-65-v2', 'Ed25519+ML-DSA-87-v2',
  'P-256+ML-DSA-44-v2', 'P-256+ML-DSA-65-v2',
];

const out = { generated_by: 'quantum-safe-ts npm package', envelope_v2: [], signatures_v2: [], standard_jwt: [] };

const kp = new KEM('ML-KEM-1024').generateKeyPair();
for (const aad of ['', 'ts-v2-vector']) {
  const pt = enc('ts envelope v2 ' + (aad ? 'with aad' : 'no aad'));
  const sealed = Envelope.seal(pt, kp.publicKey, aad ? { aad: enc(aad) } : {});
  if (sealed.version !== 2) throw new Error('expected an envelope v2');
  out.envelope_v2.push({ secret_key: hex(kp.secretKey.exportBytes()), plaintext: hex(pt), aad: hex(enc(aad)), sealed: hex(sealed.toBytes()) });
}

for (const id of V2_IDS) {
  const signer = id.includes('+') ? new HybridSign(id) : new Sign(id);
  const pair = signer.generateKeyPair();
  for (const ctx of ['', 'ts-v2-ctx']) {
    const sm = signer.sign(enc('ts signed message (v2)'), pair.secretKey, { context: enc(ctx) });
    out.signatures_v2.push({ algorithm: id, public_key: hex(pair.publicKey.toBytes()), context: hex(enc(ctx)), signed_message: hex(sm.toBytes()) });
  }
}

for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const { publicJwk, privateJwk } = StandardJwt.generateKeyPair(alg, { kid: `ts-${alg}` });
  // expiresIn: 0 omits exp, so the vector never expires.
  const token = StandardJwt.sign({ sub: 'ts-user', n: 7 }, privateJwk, { issuer: 'ts-iss', expiresIn: 0 });
  out.standard_jwt.push({ algorithm: alg, public_jwk: publicJwk, issuer: 'ts-iss', token });
}

const target = path.join(root, 'tests/vectors/ts_v2_vectors.json');
fs.writeFileSync(target, JSON.stringify(out, null, 1));
console.log(`wrote ${target}: ${out.envelope_v2.length} envelope, ${out.signatures_v2.length} signature, ${out.standard_jwt.length} jwt vectors`);
