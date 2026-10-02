// Writes tests/vectors/ts_js_vectors.json using the BUILT package (packages/quantum-safe-ts/dist):
// data produced by the TypeScript library that the real quantum-safe-py must accept
// (verified by scripts/verify_ts_vectors.py). Run: npm run build && node scripts/gen_ts_js_vectors.mjs
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { generateKeyPairSync } from 'node:crypto';
const require = createRequire(import.meta.url);
const q = require('../packages/quantum-safe-ts/dist/node.cjs');

const out = { jwt: [], kem: [], envelope: [], upgrade_kem: [], upgrade_sign: [], migrate_store: null };
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
// Migration: classical keys come from node:crypto (independent of both libraries); TS upgrades them; py must use the result.
const b64 = (s) => Buffer.from(s, 'base64url');
function classicalKeys(kind) {
  if (kind === 'X25519' || kind === 'Ed25519') {
    const { privateKey, publicKey } = generateKeyPairSync(kind.toLowerCase());
    return { secret: b64(privateKey.export({ format: 'jwk' }).d), pub: b64(publicKey.export({ format: 'jwk' }).x) };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const j = publicKey.export({ format: 'jwk' });
  return { secret: Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' })), x: b64(j.x), y: b64(j.y) };
}
for (const [classical, pqc] of [['X25519', 'ML-KEM-768'], ['P-256', 'ML-KEM-768'], ['X25519', 'ML-KEM-1024']]) {
  const k = classicalKeys(classical);
  const pub = classical === 'P-256' ? Buffer.concat([Buffer.from([4]), k.x, k.y]) : k.pub;
  const r = q.Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(k.secret), classicalPublic: new Uint8Array(pub), classicalAlgorithm: classical, targetPqc: pqc });
  const kem = new q.HybridKEM(r.newAlgorithm);
  const enc = kem.encapsulate(r.keyPair.publicKey);
  out.upgrade_kem.push({
    algorithm: r.newAlgorithm,
    classical_public: q.toHex(pub),
    public_key: q.toHex(r.keyPair.publicKey.toBytes()),
    secret_key: q.toHex(r.keyPair.secretKey.exportBytes()),
    ciphertext: q.toHex(enc.ciphertext),
    shared_secret: q.toHex(enc.sharedSecret.exportBytes()),
  });
  enc.sharedSecret.free();
  r.keyPair.free();
}
for (const [classical, pqc] of [['Ed25519', 'ML-DSA-65'], ['P-256', 'ML-DSA-65']]) {
  const k = classicalKeys(classical);
  const pub = classical === 'P-256' ? Buffer.concat([k.x, k.y]) : k.pub;
  const r = q.Upgrader.upgradeSigningKey({ classicalSecret: new Uint8Array(k.secret), classicalPublic: new Uint8Array(pub), classicalAlgorithm: classical, targetPqc: pqc });
  const signed = new q.HybridSign(r.newAlgorithm).sign(q.utf8('ts signs after upgrade'), r.keyPair.secretKey);
  out.upgrade_sign.push({ algorithm: r.newAlgorithm, public_key: q.toHex(r.keyPair.publicKey.toBytes()), signed_message: q.toHex(signed.toCbor()) });
  r.keyPair.free();
}
const mgr = new q.MigrationStateManager(new q.MemoryMigrationStore());
await mgr.transition({ keyId: 'ts-user-1', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'X25519+ML-KEM-768', actor: 'ts-job', metadata: { batch: 3 } });
await mgr.transition({ keyId: 'ts-user-1', fromState: 'hybrid_transition', toState: 'pqc_preferred', algorithm: 'X25519+ML-KEM-768' });
await mgr.transition({ keyId: 'ünï/slash', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'Ed25519+ML-DSA-65' });
const entries = await q.exportToPyStore(mgr);
out.migrate_store = { entries: Object.fromEntries([...entries].map(([k, v]) => [k, q.toHex(v)])) };
writeFileSync(new URL('../tests/vectors/ts_js_vectors.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${out.jwt.length} JWT, ${out.envelope.length} facade envelope, ${out.upgrade_kem.length + out.upgrade_sign.length} upgrade and ${Object.keys(out.migrate_store.entries).length} migration-store vectors`);
