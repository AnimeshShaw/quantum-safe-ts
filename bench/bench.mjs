#!/usr/bin/env node
// Benchmarks for quantum-safe-ts, with the same measurement protocol and the same JSON schema as quantum-safe-py's tests/bench/bench_kem.py,
// so one aggregator and one set of table scripts read both.
//
//   npm run build            (in packages/quantum-safe-ts)
//   node bench/bench.mjs [--iterations 3000] [--warmup 100] [--raw-samples] [--save results/ts/run1.json]
//   node bench/bench.mjs --list          prints the benchmark names
//   node bench/bench.mjs --only "<name>" runs one benchmark
//
// One invocation is one RUN: every benchmark is warmed up (--warmup calls, discarded), then timed --iterations times with the monotonic
// clock, one call per sample; the fastest and slowest 1% of samples are removed; the row reports median, mean, p95, p99, standard deviation
// and coefficient of variation in microseconds, and with --raw-samples every kept sample. Garbage collection is forced before each
// benchmark and the benchmarks run in the order below. The protocol (run-protocol.mjs) repeats this in fresh processes: one warm-up run
// that is discarded, then the timed runs; aggregate-runs.mjs takes the median across runs of each run's median.
//
// Single machine, no isolation guarantees: the numbers describe the machine in the metadata, nothing else.
import { createRequire } from 'node:module';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import v8 from 'node:v8';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const q = require('../packages/quantum-safe-ts/dist/node.cjs');

const argv = process.argv;
const arg = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? dflt : argv[i + 1];
};
const listing = argv.includes('--list');
const only = arg('only', null);
const iterations = Number(arg('iterations', 3000));
const warmup = Number(arg('warmup', 100));
const rawSamples = argv.includes('--raw-samples');
const savePath = arg('save', null);
if (!Number.isInteger(iterations) || iterations < 10) throw new Error('--iterations must be an integer of at least 10');

v8.setFlagsFromString('--expose_gc');
const gc = vm.runInNewContext('gc');

const names = [];
const want = (name) => {
  if (listing) {
    names.push(name);
    return false;
  }
  return only === null || only === name;
};

const round = (x, d) => Math.round(x * 10 ** d) / 10 ** d;
const results = [];

/** Times `fn` `iterations` times, one call per sample; returns microseconds after trimming 1% from each tail. */
function bench(name, fn, { n = iterations } = {}) {
  if (!want(name)) return;
  gc();
  for (let i = 0; i < warmup; i++) fn();
  let samples = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    const t1 = process.hrtime.bigint();
    samples[i] = Number(t1 - t0) / 1000;
  }
  record(name, samples, n);
}

async function benchAsync(name, fn, { n = Math.min(iterations, 30) } = {}) {
  if (!want(name)) return;
  gc();
  for (let i = 0; i < Math.min(warmup, 3); i++) await fn();
  const samples = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    samples[i] = Number(process.hrtime.bigint() - t0) / 1000;
  }
  record(name, samples, n);
}

function record(name, raw, n) {
  const sorted = Float64Array.from(raw).sort();
  const clip = Math.max(1, Math.floor(sorted.length * 0.01));
  const s = sorted.subarray(clip, sorted.length - clip);
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  const stdev = s.length > 1 ? Math.sqrt(s.reduce((a, b) => a + (b - mean) ** 2, 0) / (s.length - 1)) : 0;
  const median = s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
  const at = (p) => s[Math.min(Math.floor(s.length * p), s.length - 1)];
  const row = {
    name,
    iterations: n,
    warmup,
    median_us: round(median, 2),
    mean_us: round(mean, 2),
    p95_us: round(at(0.95), 2),
    p99_us: round(at(0.99), 2),
    stdev_us: round(stdev, 2),
    cov_pct: round(mean === 0 ? 0 : (stdev / mean) * 100, 2),
  };
  if (rawSamples) row.samples_us = Array.from(s, (x) => round(x, 3));
  results.push(row);
  console.log(`  ${name.padEnd(46)} median=${row.median_us.toFixed(1).padStart(9)}µs  p95=${row.p95_us.toFixed(1).padStart(9)}µs  CoV=${row.cov_pct.toFixed(1)}%`);
}

// Every decapsulation benchmark must measure the REAL path: the key and the ciphertext must belong together, or ML-KEM's implicit rejection
// returns a pseudo-random secret without any error and the benchmark would quietly time the wrong thing. `same` fails loudly.
const same = (a, b, what) => {
  if (a.length !== b.length || !a.every((x, i) => x === b[i])) throw new Error(`benchmark setup error: ${what} decapsulated to a different secret than was encapsulated`);
};

if (!listing) console.log(`Node ${process.version} on ${platform()} ${release()}; ${cpus()[0].model} x${cpus().length}\nIterations: ${iterations}  Warmup: ${warmup}  Outlier trim: 1%\n`);

// ---- KEM ----
const hybrid = new q.HybridKEM();
bench('HybridKEM X25519+ML-KEM-768 keygen', () => hybrid.generateKeyPair().free());
const hp = hybrid.generateKeyPair();
bench('HybridKEM X25519+ML-KEM-768 encapsulate', () => hybrid.encapsulate(hp.publicKey).sharedSecret.free());
const { ciphertext: hct, sharedSecret: hss } = hybrid.encapsulate(hp.publicKey);
same(hybrid.decapsulate(hp.secretKey, hct).exportBytes(), hss.exportBytes(), 'HybridKEM');
bench('HybridKEM X25519+ML-KEM-768 decapsulate', () => hybrid.decapsulate(hp.secretKey, hct).free());

const pure = new q.KEM('ML-KEM-768');
const pp = pure.generateKeyPair();
bench('ML-KEM-768 keygen', () => pure.generateKeyPair().free());
bench('ML-KEM-768 encapsulate', () => pure.encapsulate(pp.publicKey).sharedSecret.free());
const { ciphertext: pct, sharedSecret: pss } = pure.encapsulate(pp.publicKey);
same(pure.decapsulate(pp.secretKey, pct).exportBytes(), pss.exportBytes(), 'ML-KEM-768');
bench('ML-KEM-768 decapsulate', () => pure.decapsulate(pp.secretKey, pct).free());

const pure1024 = new q.KEM('ML-KEM-1024');
const p1 = pure1024.generateKeyPair();
const { ciphertext: c1024, sharedSecret: s1024 } = pure1024.encapsulate(p1.publicKey);
same(pure1024.decapsulate(p1.secretKey, c1024).exportBytes(), s1024.exportBytes(), 'ML-KEM-1024');
bench('ML-KEM-1024 encapsulate', () => pure1024.encapsulate(p1.publicKey).sharedSecret.free());
bench('ML-KEM-1024 decapsulate', () => pure1024.decapsulate(p1.secretKey, c1024).free());

const xw = new q.HybridKEM('X-Wing');
const xp = xw.generateKeyPair();
bench('X-Wing keygen', () => xw.generateKeyPair().free());
bench('X-Wing encapsulate', () => xw.encapsulate(xp.publicKey).sharedSecret.free());
const { ciphertext: xct, sharedSecret: xss } = xw.encapsulate(xp.publicKey);
same(xw.decapsulate(xp.secretKey, xct).exportBytes(), xss.exportBytes(), 'X-Wing');
bench('X-Wing decapsulate', () => xw.decapsulate(xp.secretKey, xct).free());

// ---- Envelope ----
const kb = new Uint8Array(1024).fill(7);
const mb = new Uint8Array(1024 * 1024).fill(7);
bench('Envelope.seal 1 KiB', () => q.Envelope.seal(kb, hp.publicKey));
const sealed1k = q.Envelope.seal(kb, hp.publicKey);
bench('Envelope.open 1 KiB', () => q.Envelope.open(sealed1k, hp.secretKey, { expectedAad: new Uint8Array(0) }));
bench('Envelope.seal 1 MiB', () => q.Envelope.seal(mb, hp.publicKey), { n: Math.min(iterations, 300) });

// ---- Signatures ----
const msg = new Uint8Array(256).fill(1);
for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const sg = new q.Sign(alg);
  const sp = sg.generateKeyPair();
  bench(`${alg} keygen`, () => sg.generateKeyPair().free());
  bench(`${alg} sign (256 B, hedged)`, () => sg.sign(msg, sp.secretKey));
  const signed = sg.sign(msg, sp.secretKey);
  sg.verify(signed, sp.publicKey); // throws if the signature does not verify
  bench(`${alg} verify`, () => sg.verify(signed, sp.publicKey));
}
const hs = new q.HybridSign();
const hsp = hs.generateKeyPair();
bench('Ed25519+ML-DSA-65-v2 sign', () => hs.sign(msg, hsp.secretKey));
const hsigned = hs.sign(msg, hsp.secretKey);
hs.verify(hsigned, hsp.publicKey);
bench('Ed25519+ML-DSA-65-v2 verify', () => hs.verify(hsigned, hsp.publicKey));

const slh = new q.Sign('SLH-DSA-SHAKE-128f');
const slhp = slh.generateKeyPair();
bench('SLH-DSA-SHAKE-128f sign (256 B)', () => slh.sign(msg, slhp.secretKey), { n: Math.min(iterations, 300) });
const slhs = slh.sign(msg, slhp.secretKey);
slh.verify(slhs, slhp.publicKey);
bench('SLH-DSA-SHAKE-128f verify', () => slh.verify(slhs, slhp.publicKey));

// ---- JWT ----
const sg65 = new q.Sign('ML-DSA-65');
const jp = sg65.generateKeyPair();
const jwtSigner = new q.JWTSigner(jp, { issuer: 'https://bench.example' });
const jwtVerifier = new q.JWTVerifier(jp.publicKey, { issuer: 'https://bench.example' });
bench('JWT ML-DSA-65 sign', () => jwtSigner.sign({ sub: 'u' }, { expiresIn: 3600 }));
const token = jwtSigner.sign({ sub: 'u' }, { expiresIn: 3600 });
jwtVerifier.verify(token);
bench('JWT ML-DSA-65 verify', () => jwtVerifier.verify(token));

// ---- KDF (async: awaited, so the time is real) ----
const salt = new Uint8Array(16).fill(3);
await benchAsync('Argon2id deriveMasterKey (default parameters)', () => q.deriveMasterKey('password', salt));

if (listing) {
  console.log(JSON.stringify(names));
  process.exit(0);
}

function gitCommit() {
  if (process.env.QS_GIT_COMMIT) return process.env.QS_GIT_COMMIT;
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: here, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return 'unknown';
  }
}
function libraryVersion() {
  try {
    return JSON.parse(readFileSync(resolve(here, '../packages/quantum-safe-ts/package.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

const payload = {
  metadata: {
    recorded_at: new Date().toISOString(),
    node: process.version.slice(1),
    v8: process.versions.v8,
    platform: `${platform()}-${release()}`,
    machine: arch(),
    cpu_model: cpus()[0]?.model ?? 'unknown',
    logical_cpus: cpus().length,
    total_memory_mb: Math.round(totalmem() / 2 ** 20),
    cpu_affinity: null,
    library: 'quantum-safe-ts',
    library_version: libraryVersion(),
    git_commit: gitCommit(),
    in_container: existsSync('/.dockerenv'),
    default_iterations: iterations,
    warmup,
  },
  results,
};
if (savePath) {
  mkdirSync(dirname(resolve(savePath)), { recursive: true });
  writeFileSync(savePath, JSON.stringify(payload, null, 2));
  console.log(`\nSaved results to ${savePath}`);
}
