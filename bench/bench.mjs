#!/usr/bin/env node
// Micro-benchmarks: quantum-safe-ts (WASM) vs @noble/post-quantum (pure JS) vs Node's native WebCrypto.
//
//   npm run build            (in packages/quantum-safe-ts)
//   node bench/bench.mjs [--json out.json]
//
// Methodology: each operation is warmed up, then timed in batches until >= 1.5 s elapsed; we report the MEDIAN
// of per-batch means (ops/s) and the spread. Single machine, single process, no CPU pinning: treat the numbers as
// order-of-magnitude, not as a benchmark of record. Environment details are printed so results can be compared.
import { createRequire } from 'node:module';
import { cpus, platform, release } from 'node:os';
import { writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

const require = createRequire(import.meta.url);
const q = require('../packages/quantum-safe-ts/dist/node.cjs');
const { ml_kem768 } = await import('../packages/quantum-safe-ts/node_modules/@noble/post-quantum/ml-kem.js');
const { ml_dsa65 } = await import('../packages/quantum-safe-ts/node_modules/@noble/post-quantum/ml-dsa.js');

// --list prints the benchmark names; --only <exact name> runs one benchmark (bench/run-matrix.mjs runs each in its own process so that heap
// and WASM-memory state left by earlier benchmarks cannot colour later ones).
const argv = process.argv;
const listing = argv.includes('--list');
const onlyIdx = argv.indexOf('--only');
const only = onlyIdx === -1 ? null : argv[onlyIdx + 1];
const names = [];
const want = (name) => {
  if (listing) {
    names.push(name);
    return false;
  }
  return only === null || only === name;
};

function measure(name, fn, { minMs = 1500, batch = 1 } = {}) {
  if (!want(name)) return null;
  for (let i = 0; i < 3; i++) fn(); // warm-up
  const means = [];
  const t0 = performance.now();
  while (performance.now() - t0 < minMs || means.length < 5) {
    const s = performance.now();
    for (let i = 0; i < batch; i++) fn();
    means.push((performance.now() - s) / batch);
    if (means.length > 2000) break;
  }
  means.sort((a, b) => a - b);
  const median = means[Math.floor(means.length / 2)];
  const p10 = means[Math.floor(means.length * 0.1)];
  const p90 = means[Math.floor(means.length * 0.9)];
  return { name, opsPerSec: 1000 / median, medianMs: median, p10Ms: p10, p90Ms: p90, samples: means.length };
}

const results = [];
const add = (r) => { if (!r) return; results.push(r); console.log(`${r.name.padEnd(46)} ${r.opsPerSec.toFixed(1).padStart(10)} ops/s   median ${r.medianMs.toFixed(3)} ms  (p10 ${r.p10Ms.toFixed(3)}, p90 ${r.p90Ms.toFixed(3)})`); };

console.log(`Node ${process.version} on ${platform()} ${release()}; ${cpus()[0].model} x${cpus().length}\n`);

// Every decapsulation benchmark below must measure the REAL path: the key and the ciphertext must belong together, or ML-KEM's implicit
// rejection returns a pseudo-random secret without any error and the benchmark would quietly time the wrong thing. `same` fails loudly.
const same = (a, b, what) => {
  if (a.length !== b.length || !a.every((x, i) => x === b[i])) throw new Error(`benchmark setup error: ${what} decapsulated to a different secret than was encapsulated`);
};

// ---- KEM ----
const hybrid = new q.HybridKEM();
add(measure('quantum-safe-ts HybridKEM X25519+ML-KEM-768 keygen', () => hybrid.generateKeyPair().free()));
const hp = hybrid.generateKeyPair();
add(measure('quantum-safe-ts HybridKEM encapsulate', () => hybrid.encapsulate(hp.publicKey).sharedSecret.free()));
const { ciphertext: hct, sharedSecret: hss } = hybrid.encapsulate(hp.publicKey);
same(hybrid.decapsulate(hp.secretKey, hct).exportBytes(), hss.exportBytes(), 'HybridKEM');
add(measure('quantum-safe-ts HybridKEM decapsulate', () => hybrid.decapsulate(hp.secretKey, hct).free()));

const pure = new q.KEM('ML-KEM-768');
const pp = pure.generateKeyPair();
add(measure('quantum-safe-ts ML-KEM-768 keygen', () => pure.generateKeyPair().free()));
add(measure('quantum-safe-ts ML-KEM-768 encapsulate', () => pure.encapsulate(pp.publicKey).sharedSecret.free()));
const { ciphertext: pct, sharedSecret: pss } = pure.encapsulate(pp.publicKey);
same(pure.decapsulate(pp.secretKey, pct).exportBytes(), pss.exportBytes(), 'ML-KEM-768');
add(measure('quantum-safe-ts ML-KEM-768 decapsulate', () => pure.decapsulate(pp.secretKey, pct).free()));

const nk = ml_kem768.keygen();
add(measure('noble ML-KEM-768 keygen', () => ml_kem768.keygen()));
add(measure('noble ML-KEM-768 encapsulate', () => ml_kem768.encapsulate(nk.publicKey)));
const nenc = ml_kem768.encapsulate(nk.publicKey);
same(ml_kem768.decapsulate(nenc.cipherText, nk.secretKey), nenc.sharedSecret, 'noble ML-KEM-768');
add(measure('noble ML-KEM-768 decapsulate', () => ml_kem768.decapsulate(nenc.cipherText, nk.secretKey)));

// Node native ML-KEM (OpenSSL) when available
if (globalThis.SubtleCrypto?.supports?.('encapsulateBits', 'ML-KEM-768')) {
  const subtle = webcrypto.subtle;
  const kp = await subtle.generateKey({ name: 'ML-KEM-768' }, false, ['encapsulateBits', 'decapsulateBits']);
  const asyncMeasure = async (name, fn) => {
    if (!want(name)) return;
    for (let i = 0; i < 20; i++) await fn();
    const times = [];
    const t0 = performance.now();
    while (performance.now() - t0 < 1500 || times.length < 5) { const s = performance.now(); await fn(); times.push(performance.now() - s); }
    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    add({ name, opsPerSec: 1000 / median, medianMs: median, p10Ms: times[Math.floor(times.length * 0.1)], p90Ms: times[Math.floor(times.length * 0.9)], samples: times.length });
  };
  await asyncMeasure('node WebCrypto ML-KEM-768 encapsulateBits (async)', () => subtle.encapsulateBits({ name: 'ML-KEM-768' }, kp.publicKey));
  const enc = await subtle.encapsulateBits({ name: 'ML-KEM-768' }, kp.publicKey);
  same(new Uint8Array(await subtle.decapsulateBits({ name: 'ML-KEM-768' }, kp.privateKey, enc.ciphertext)), new Uint8Array(enc.sharedKey), 'WebCrypto ML-KEM-768');
  await asyncMeasure('node WebCrypto ML-KEM-768 decapsulateBits (async)', () => subtle.decapsulateBits({ name: 'ML-KEM-768' }, kp.privateKey, enc.ciphertext));
}

// ---- Envelope ----
const kb = new Uint8Array(1024).fill(7);
const mb = new Uint8Array(1024 * 1024).fill(7);
add(measure('quantum-safe-ts Envelope.seal 1 KiB', () => q.Envelope.seal(kb, hp.publicKey)));
const sealed1k = q.Envelope.seal(kb, hp.publicKey);
add(measure('quantum-safe-ts Envelope.open 1 KiB', () => q.Envelope.open(sealed1k, hp.secretKey)));
add(measure('quantum-safe-ts Envelope.seal 1 MiB', () => q.Envelope.seal(mb, hp.publicKey), { minMs: 1500 }));

// ---- Signatures ----
const sg = new q.Sign('ML-DSA-65');
const sp = sg.generateKeyPair();
const msg = new Uint8Array(256).fill(1);
add(measure('quantum-safe-ts ML-DSA-65 keygen', () => sg.generateKeyPair().free()));
add(measure('quantum-safe-ts ML-DSA-65 sign (256 B, hedged)', () => sg.sign(msg, sp.secretKey)));
const signed = sg.sign(msg, sp.secretKey);
sg.verify(signed, sp.publicKey); // throws if the signature does not verify
add(measure('quantum-safe-ts ML-DSA-65 verify', () => sg.verify(signed, sp.publicKey)));
const hs = new q.HybridSign();
const hsp = hs.generateKeyPair();
add(measure('quantum-safe-ts Ed25519+ML-DSA-65 sign', () => hs.sign(msg, hsp.secretKey)));
const hsigned = hs.sign(msg, hsp.secretKey);
add(measure('quantum-safe-ts Ed25519+ML-DSA-65 verify', () => hs.verify(hsigned, hsp.publicKey)));
const dk = ml_dsa65.keygen();
add(measure('noble ML-DSA-65 keygen', () => ml_dsa65.keygen()));
add(measure('noble ML-DSA-65 sign (256 B)', () => ml_dsa65.sign(msg, dk.secretKey)));
const dsig = ml_dsa65.sign(msg, dk.secretKey);
if (ml_dsa65.verify(dsig, msg, dk.publicKey) !== true) throw new Error('benchmark setup error: noble ML-DSA-65 signature does not verify');
add(measure('noble ML-DSA-65 verify', () => ml_dsa65.verify(dsig, msg, dk.publicKey)));

// ---- X-Wing and JWT ----
const xw = new q.HybridKEM('X-Wing');
const xp = xw.generateKeyPair();
add(measure('quantum-safe-ts X-Wing encapsulate', () => xw.encapsulate(xp.publicKey).sharedSecret.free()));
const jwtSigner = new q.JWTSigner(sp, { issuer: 'https://bench.example' });
const jwtVerifier = new q.JWTVerifier(sp.publicKey, { issuer: 'https://bench.example' });
add(measure('quantum-safe-ts JWT ML-DSA-65 sign', () => jwtSigner.sign({ sub: 'u' }, { expiresIn: 3600 })));
const token = jwtSigner.sign({ sub: 'u' }, { expiresIn: 3600 });
add(measure('quantum-safe-ts JWT ML-DSA-65 verify', () => jwtVerifier.verify(token)));

// ---- KDF (async: awaited, so the time is real) ----
const salt = new Uint8Array(16).fill(3);
if (want('quantum-safe-ts Argon2id (default params)')) {
  for (let i = 0; i < 2; i++) await q.deriveMasterKey('password', salt);
  const times = [];
  const t0 = performance.now();
  while (performance.now() - t0 < 2500 || times.length < 5) { const s0 = performance.now(); await q.deriveMasterKey('password', salt); times.push(performance.now() - s0); }
  times.sort((x, y) => x - y);
  const median = times[Math.floor(times.length / 2)];
  add({ name: 'quantum-safe-ts Argon2id (default params)', opsPerSec: 1000 / median, medianMs: median, p10Ms: times[Math.floor(times.length * 0.1)], p90Ms: times[Math.floor(times.length * 0.9)], samples: times.length });
}

if (listing) {
  console.log(JSON.stringify(names));
  process.exit(0);
}
const out = { node: process.version, platform: `${platform()} ${release()}`, cpu: cpus()[0].model, cores: cpus().length, results };
const i = process.argv.indexOf('--json');
if (i !== -1) writeFileSync(process.argv[i + 1], JSON.stringify(out, null, 2));
