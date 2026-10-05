# Benchmarks and timing-leakage screen

Scripts that produce the numbers and the timing screen mentioned in the main README. The raw
results of the last run are in [`../results/`](../results/).

```bash
npm ci --prefix packages/quantum-safe-ts && npm run build --prefix packages/quantum-safe-ts
node bench/bench.mjs                         # operations per second, several rounds
node bench/leakage.mjs --iterations 4000 --rounds 3 --json results/timing_leakage.json
node bench/run-matrix.mjs                    # repeats bench.mjs in fresh processes, aggregates the rounds into results/bench_matrix.json
```

`py_baseline.py` measures liboqs (through liboqs-python) and quantum-safe-py on the same machine as a
reference; it needs `pip install quantum-safe-py[liboqs]`. `bench.mjs` also times noble and Node's
WebCrypto ML-KEM for comparison.

## What the numbers are, and are not

- One machine, one Node version, Windows, pinned to one performance-core thread by `run-matrix.mjs`. The header of each results
  file records the CPU, Node version and date. Treat the figures as relative, not as a guarantee for
  your hardware. Browsers coarsen timers, so none of this says anything about them.
- Every decapsulation benchmark first checks that the key and ciphertext belong together and that
  decapsulation returns the secret that was encapsulated. (quantum-safe-py's old harness lacked this
  check and timed ML-KEM's implicit-rejection path; this one cannot.)

## The timing-leakage screen

`leakage.mjs` is a two-class test in the style of dudect (fixed secret key against random keys),
with controls that show what it can and cannot tell you:

| Experiment | Result in `results/timing_leakage.json` (2026-10-05) |
|---|---|
| ML-KEM-768 and X25519+ML-KEM-768 decapsulate, fixed vs random key | difference detected |
| **Calibration:** ML-KEM-768 *encapsulate*, fixed vs random **public** key (no secret involved) | difference detected |
| Random vs random control | no difference |
| Deliberately leaky comparison (harness check) | detected |
| Valid vs invalid ciphertext (implicit rejection), same key | no difference |
| `Envelope.open` failure paths; ML-DSA-65 sign | no difference |

The calibration row matters: an operation with no secret reproduces the same kind of difference as
decapsulation, so the decapsulation difference is **not evidence of a secret-dependent timing leak**.
The cause is not established here. quantum-safe-py's harness found the same pattern. The screen can miss a real leak
and a clean result is not a constant-time proof; JavaScript and WebAssembly runtimes give no
constant-time guarantee at all (see the security guide).
