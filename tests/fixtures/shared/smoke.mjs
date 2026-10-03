// The same end-to-end smoke test runs in every runtime/bundler fixture. It imports nothing: the
// fixture passes in the namespace it got from `quantum-safe-ts`, so this exercises the *packed
// tarball* exactly as a consumer would use it.
export async function smoke(q) {
  await q.init(); // no-op on Node.js
  const checks = {};
  const kem = new q.HybridKEM();
  const pair = kem.generateKeyPair();
  const sealed = q.Envelope.seal(q.utf8('fixture secret'), pair.publicKey, { aad: q.utf8('fx') });
  checks.envelope = new TextDecoder().decode(q.Envelope.open(sealed, pair.secretKey)) === 'fixture secret';
  const xw = new q.HybridKEM('X-Wing');
  const xp = xw.generateKeyPair();
  const enc = xw.encapsulate(xp.publicKey);
  const rec = xw.decapsulate(xp.secretKey, enc.ciphertext);
  checks.xwing = q.toHex(enc.sharedSecret.exportBytes()) === q.toHex(rec.exportBytes());
  const signer = new q.HybridSign();
  const sp = signer.generateKeyPair();
  const sm = signer.sign(q.utf8('m'), sp.secretKey, { context: q.utf8('c') });
  signer.verify(sm, sp.publicKey, { expectedContext: q.utf8('c') });
  checks.hybridSign = true;
  const { publicJwk, privateJwk } = q.StandardJwt.generateKeyPair('ML-DSA-44');
  checks.standardJwt = q.StandardJwt.verify(q.StandardJwt.sign({ sub: 'fx' }, privateJwk), publicJwk).sub === 'fx';
  const mk = await q.deriveMasterKey('pw', q.utf8('0123456789abcdef'));
  checks.argon2id = mk.length === 32;
  checks.cnsa2 = q.cnsa2.report({ kem: 'X25519+ML-KEM-768' }).compliant === false;
  checks.suites = q.kemSuites().length === 9 && q.sigSuites().length === 28;
  const v2 = new q.HybridSign('Ed25519+ML-DSA-44-v2');
  const vp = v2.generateKeyPair();
  v2.verify(v2.sign(q.utf8('m'), vp.secretKey, { context: q.utf8('c') }), vp.publicKey, { expectedContext: q.utf8('c') });
  checks.signatureV2 = true;
  vp.free();
  pair.free(); xp.free(); sp.free();
  const ok = Object.values(checks).every(Boolean);
  return { ok, checks, version: q.coreVersion() };
}
