#!/usr/bin/env node
// Timing-leakage screen for the WASM build, using the two-class design of dudect (Reparaz, Balasch, Verbauwhede, 2017), as in
// quantum-safe-py's tests/bench/bench_leakage.py:
//
//   class FIXED  - the same secret key for every measurement
//   class RANDOM - a different secret key for every measurement
//
// Noise (GC, JIT, scheduler, frequency scaling) hits both classes, so a significant difference between them is attributable to the
// secret. Measurements are INTERLEAVED, inputs are pre-generated outside the timed region, and both classes use pools of the same size
// (the FIXED class is N distinct objects holding one secret, built exactly like the random keys) so cache locality and allocation
// patterns do not masquerade as leakage, and a random-vs-random control checks the setup for systematic bias. Every experiment has
// null controls (the same measurements, class labels shuffled) so the false-positive rate of THIS machine and runtime is visible, and a
// harness-validation experiment with a deliberately leaky comparison shows the screen can detect leakage at all.
//
//   node bench/leakage.mjs [--iterations 4000] [--rounds 3] [--json results/timing_leakage.json]
//
// What a pass means: no secret-dependent timing difference was detected at this resolution, on this machine, in this Node version.
// It is NOT a constant-time proof, says nothing about other runtimes (browsers coarsen timers), and ML-DSA signing has data-dependent
// timing by design (rejection sampling), so a difference there is expected to be a property of the algorithm, not a bug.
import { createRequire } from 'node:module';
import { cpus, platform, release } from 'node:os';
import { writeFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const q = require('../packages/quantum-safe-ts/dist/node.cjs');

const arg = (n, d) => {
  const i = process.argv.indexOf(`--${n}`);
  return i === -1 ? d : process.argv[i + 1];
};
const ITER = Number(arg('iterations', 4000));
const ROUNDS = Number(arg('rounds', 3));
const THRESH = 4.5; // dudect's conventional |t| threshold

// ---------- statistics ----------
function welch(a, b) {
  const stat = (x) => {
    let m = 0;
    for (const v of x) m += v;
    m /= x.length;
    let s = 0;
    for (const v of x) s += (v - m) ** 2;
    return { m, v: s / (x.length - 1), n: x.length };
  };
  const A = stat(a);
  const B = stat(b);
  const se = Math.sqrt(A.v / A.n + B.v / B.n);
  return { t: (A.m - B.m) / se, meanDiffNs: A.m - B.m, pooledSd: Math.sqrt((A.v + B.v) / 2) };
}
function cropTop(a, b, fraction) {
  const all = [...a, ...b].sort((x, y) => x - y);
  const cut = all[Math.floor(all.length * (1 - fraction))];
  return [a.filter((v) => v <= cut), b.filter((v) => v <= cut)];
}
function analyse(fixed, random) {
  const raw = welch(fixed, random);
  const [fc, rc] = cropTop(fixed, random, 0.005);
  const c1 = welch(fc, rc);
  const [fd, rd] = cropTop(fixed, random, 0.1);
  const c2 = welch(fd, rd);
  return { rawT: raw.t, croppedT: c1.t, strongCroppedT: c2.t, meanDiffNs: raw.meanDiffNs, effectSd: raw.meanDiffNs / raw.pooledSd };
}
// null control: re-split the pooled measurements of one class pair at random
function nullControl(fixed, random) {
  const pool = [...fixed, ...random];
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return analyse(pool.slice(0, fixed.length), pool.slice(fixed.length));
}

// ---------- measurement ----------
const now = () => Number(process.hrtime.bigint());
function interleaved(n, runFixed, runRandom) {
  const f = new Array(n);
  const r = new Array(n);
  const order = new Uint8Array(n * 2);
  for (let i = n; i < 2 * n; i++) order[i] = 1;
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  let fi = 0;
  let ri = 0;
  for (let k = 0; k < order.length; k++) {
    if (order[k] === 0) {
      const s = now();
      runFixed(fi);
      f[fi++] = now() - s;
    } else {
      const s = now();
      runRandom(ri);
      r[ri++] = now() - s;
    }
  }
  return [f, r];
}

// ---------- experiments ----------
function pool(n, make) {
  return Array.from({ length: n }, make);
}
// Both classes are built the same way (SecretKey.fromBytes from raw bytes, allocated in the same pattern), so the only difference
// between them is the VALUE of the key. `control: true` makes the "fixed" class random too: it must show no difference.
function kemFixedVsRandom(name, algorithm, makeKem, { control = false } = {}) {
  return {
    name,
    n: ITER,
    control,
    setup(n) {
      const kem = makeKem();
      const fresh = () => kem.generateKeyPair();
      const classAKeys = [];
      const classACts = [];
      const classASecrets = [];
      const fixedPair = control ? null : fresh();
      const fixedRaw = control ? null : fixedPair.secretKey.exportBytes();
      for (let i = 0; i < n; i++) {
        const pair = control ? fresh() : fixedPair;
        const raw = control ? pair.secretKey.exportBytes() : fixedRaw;
        classAKeys.push(q.SecretKey.fromBytes(algorithm, raw));
        const e = kem.encapsulate(pair.publicKey);
        if (i === 0) classASecrets.push(e.sharedSecret.exportBytes());
        e.sharedSecret.free();
        classACts.push(e.ciphertext);
        if (control) pair.free();
      }
      const classBKeys = [];
      const classBCts = [];
      const classBSecrets = [];
      for (let i = 0; i < n; i++) {
        const pair = fresh();
        classBKeys.push(q.SecretKey.fromBytes(algorithm, pair.secretKey.exportBytes()));
        const e = kem.encapsulate(pair.publicKey);
        if (i === 0) classBSecrets.push(e.sharedSecret.exportBytes());
        e.sharedSecret.free();
        classBCts.push(e.ciphertext);
        pair.free();
      }
      // Setup check: each key must decapsulate ITS ciphertext to the secret that was encapsulated (otherwise the screen would time the
      // implicit-rejection path for one class and the real path for the other).
      for (const [keys, cts, secrets, label] of [[classAKeys, classACts, classASecrets, 'A'], [classBKeys, classBCts, classBSecrets, 'B']]) {
        const got = kem.decapsulate(keys[0], cts[0]);
        const gotBytes = got.exportBytes();
        got.free();
        if (gotBytes.length !== secrets[0].length || !gotBytes.every((x, j) => x === secrets[0][j])) throw new Error(`leakage setup error: class ${label} key and ciphertext do not match in '${name}'`);
      }
      return [
        (i) => kem.decapsulate(classAKeys[i], classACts[i]).free(),
        (i) => kem.decapsulate(classBKeys[i], classBCts[i]).free(),
        () => {
          classAKeys.forEach((k) => k.free());
          classBKeys.forEach((k) => k.free());
          fixedPair?.free();
        },
      ];
    },
  };
}

const experiments = [];
experiments.push(kemFixedVsRandom('ML-KEM-768 decapsulate: fixed vs random secret key', 'ML-KEM-768', () => new q.KEM('ML-KEM-768')));
experiments.push(kemFixedVsRandom('X25519+ML-KEM-768 decapsulate: fixed vs random secret key', 'X25519+ML-KEM-768', () => new q.HybridKEM()));
experiments.push(kemFixedVsRandom('CONTROL: ML-KEM-768 decapsulate, random vs random (must show no difference)', 'ML-KEM-768', () => new q.KEM('ML-KEM-768'), { control: true }));

// Calibration: encapsulation uses only PUBLIC data, so any fixed-vs-random difference here cannot be a secret leak. ML-KEM expands the public
// matrix from the public seed rho with rejection sampling, which takes data-dependent time and which a CPU's branch predictor learns when the
// same key repeats. If decapsulation's fixed-vs-random effect is about the size of this one, it is explained by public-value dependence.
experiments.push({
  name: 'CALIBRATION: ML-KEM-768 encapsulate, fixed vs random PUBLIC key (no secret involved)',
  n: ITER,
  calibration: true,
  setup(n) {
    const kem = new q.KEM('ML-KEM-768');
    const fixedPair = kem.generateKeyPair();
    const fixedRaw = fixedPair.publicKey.toBytes();
    const fixedKeys = pool(n, () => q.PublicKey.fromBytes('ML-KEM-768', fixedRaw));
    const randKeys = pool(n, () => {
      const p = kem.generateKeyPair();
      const k = q.PublicKey.fromBytes('ML-KEM-768', p.publicKey.toBytes());
      p.free();
      return k;
    });
    return [
      (i) => kem.encapsulate(fixedKeys[i]).sharedSecret.free(),
      (i) => kem.encapsulate(randKeys[i]).sharedSecret.free(),
      () => {
        fixedKeys.forEach((k) => k.free());
        randKeys.forEach((k) => k.free());
        fixedPair.free();
      },
    ];
  },
});

experiments.push({
  name: 'ML-KEM-768 decapsulate: valid vs invalid ciphertext (implicit rejection path), same key',
  n: ITER,
  setup(n) {
    const kem = new q.KEM('ML-KEM-768');
    const pair = kem.generateKeyPair();
    const valid = pool(n, () => {
      const e = kem.encapsulate(pair.publicKey);
      e.sharedSecret.free();
      return e.ciphertext;
    });
    const invalid = valid.map((ct) => {
      const c = ct.slice();
      c[Math.floor(Math.random() * c.length)] ^= 1 << Math.floor(Math.random() * 8);
      return c;
    });
    return [(i) => kem.decapsulate(pair.secretKey, valid[i]).free(), (i) => kem.decapsulate(pair.secretKey, invalid[i]).free(), () => pair.free()];
  },
});

experiments.push({
  name: 'Envelope.open (1 KiB) failure path: tampered first ciphertext byte vs tampered last tag byte, same key',
  n: ITER,
  setup(n) {
    const kem = new q.HybridKEM();
    const pair = kem.generateKeyPair();
    const pt = new Uint8Array(1024).fill(9);
    const sealed = pool(n, () => q.Envelope.seal(pt, pair.publicKey));
    const tamper = (m, where) => {
      const ct = m.ciphertext.slice();
      ct[where === 'first' ? 0 : ct.length - 1] ^= 1;
      return q.SealedMessage.fromParts({ version: m.version, algorithm: m.algorithm, kemCiphertext: m.kemCiphertext, nonce: m.nonce, ciphertext: ct, aad: m.aad });
    };
    const early = sealed.map((m) => tamper(m, 'first'));
    const late = sealed.map((m) => tamper(m, 'last'));
    const tryOpen = (m) => {
      try {
        q.Envelope.open(m, pair.secretKey);
      } catch {
        /* both classes fail; the failure path is what is timed */
      }
    };
    return [(i) => tryOpen(early[i]), (i) => tryOpen(late[i]), () => pair.free()];
  },
});

experiments.push({
  name: 'ML-DSA-65 sign: fixed vs random secret key (rejection sampling makes timing vary by design)',
  n: Math.max(500, Math.floor(ITER / 4)),
  setup(n) {
    const sg = new q.Sign('ML-DSA-65');
    const fixed = sg.generateKeyPair();
    const fixedRaw = fixed.secretKey.exportBytes();
    const fixedKeys = pool(n, () => q.SecretKey.fromBytes('ML-DSA-65', fixedRaw));
    const randKeys = pool(n, () => {
      const p = sg.generateKeyPair();
      const k = q.SecretKey.fromBytes('ML-DSA-65', p.secretKey.exportBytes());
      p.free();
      return k;
    });
    const msg = new Uint8Array(64).fill(5);
    return [
      (i) => sg.sign(msg, fixedKeys[i]),
      (i) => sg.sign(msg, randKeys[i]),
      () => {
        randKeys.forEach((k) => k.free());
        fixedKeys.forEach((k) => k.free());
        fixed.free();
      },
    ];
  },
});

// Harness validation: a deliberately leaky early-exit comparison. The screen MUST flag this one.
experiments.push({
  name: 'HARNESS CHECK: deliberately leaky early-exit comparison (must be flagged)',
  n: ITER,
  mustLeak: true,
  setup() {
    const secret = new Uint8Array(2048).fill(7);
    const early = new Uint8Array(2048).fill(7);
    early[0] = 1; // mismatch at the first byte: returns immediately
    const late = new Uint8Array(2048).fill(7);
    late[2047] = 1; // mismatch at the last byte: scans everything
    let sink = 0;
    const leakyEqual = (a, b) => {
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
      return true;
    };
    return [() => (sink += leakyEqual(secret, early) ? 1 : 0), () => (sink += leakyEqual(secret, late) ? 1 : 0), () => void sink];
  },
});

// ---------- run ----------
const out = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: `${platform()} ${release()}`,
  cpu: cpus()[0].model,
  iterationsPerClass: ITER,
  rounds: ROUNDS,
  threshold: THRESH,
  note: 'Screen at the resolution of this setup. Not a constant-time proof. See the header of bench/leakage.mjs.',
  experiments: [],
};
console.log(`Node ${process.version}; ${out.cpu}; ${ITER} measurements per class, ${ROUNDS} rounds, |t| threshold ${THRESH}\n`);
const levels = ['rawT', 'croppedT', 'strongCroppedT'];
const only = arg('only', '');
for (const ex of experiments.filter((e) => !only || e.name.toLowerCase().includes(only.toLowerCase()) || e.mustLeak)) {
  const rounds = [];
  for (let r = 0; r < ROUNDS; r++) {
    const [runA, runB, cleanup] = ex.setup(ex.n);
    for (let i = 0; i < 50; i++) {
      runA(i % ex.n);
      runB(i % ex.n);
    }
    const [a, b] = interleaved(ex.n, runA, runB);
    cleanup();
    const real = analyse(a, b);
    const nulls = [nullControl(a, b), nullControl(a, b), nullControl(a, b)];
    rounds.push({ real, nullMaxAbsT: Math.max(...nulls.flatMap((x) => levels.map((k) => Math.abs(x[k])))) });
  }
  // DETECTED only if, at some crop level, every round exceeds the threshold with the same sign.
  const consistentAt = levels.filter((k) => rounds.every((r) => Math.abs(r.real[k]) > THRESH && Math.sign(r.real[k]) === Math.sign(rounds[0].real[k])));
  const anyFlag = rounds.some((r) => levels.some((k) => Math.abs(r.real[k]) > THRESH));
  const verdict = consistentAt.length
    ? `DIFFERENCE DETECTED (consistent across rounds at: ${consistentAt.join(', ')})`
    : anyFlag
      ? 'inconclusive (flagged in some rounds or levels only)'
      : 'no difference detected';
  out.experiments.push({ name: ex.name, measurementsPerClass: ex.n, mustLeak: !!ex.mustLeak, control: !!ex.control, calibration: !!ex.calibration, verdict, rounds });
  console.log(ex.name);
  for (const r of rounds) {
    console.log(
      `   t raw=${r.real.rawT.toFixed(2).padStart(7)} crop0.5%=${r.real.croppedT.toFixed(2).padStart(7)} crop10%=${r.real.strongCroppedT.toFixed(2).padStart(7)}  diff=${r.real.meanDiffNs.toFixed(0).padStart(7)} ns (${r.real.effectSd.toFixed(3)} sd)   null-control max|t|=${r.nullMaxAbsT.toFixed(2)}`,
    );
  }
  console.log(`   => ${verdict}\n`);
}
const check = out.experiments.find((e) => e.mustLeak);
out.controlsClean = out.experiments.filter((e) => e.control).every((e) => !e.verdict.startsWith('DIFFERENCE DETECTED'));
out.harnessValid = check?.verdict.startsWith('DIFFERENCE DETECTED') ?? false;
console.log(
  out.harnessValid
    ? 'Harness check passed: the screen detects a deliberate early-exit leak.'
    : 'HARNESS CHECK FAILED: the screen did not detect the deliberate leak; results above are not meaningful.',
);
const i = process.argv.indexOf('--json');
if (i !== -1) writeFileSync(process.argv[i + 1], JSON.stringify(out, null, 2) + '\n');
console.log(out.controlsClean ? 'Random-vs-random control: no difference, as required.' : 'WARNING: the random-vs-random control showed a difference, so this setup has a systematic bias; read the other results with that in mind.');
process.exit(out.harnessValid ? 0 : 1);
