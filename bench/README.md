# Benchmarks and timing-leakage screen

Scripts that produce the numbers and the timing screen mentioned in the main README. The summaries
of the last run (`results/ts/2026-10-19/`: the aggregate, the environment and the leakage screen) are in [`../results/`](../results/); the per-run sample files are attached to the [1.0.0 release](https://github.com/AnimeshShaw/quantum-safe-ts/releases/tag/v1.0.0) as `quantum-safe-ts-benchmarks-node22-2026-10-19.tar.gz`, with checksums and the steps to recompute the published figures.

```bash
npm ci --prefix packages/quantum-safe-ts && npm run build --prefix packages/quantum-safe-ts
node bench/bench.mjs --save results/ts/run1.json --raw-samples    # one run: 3,000 timed calls per benchmark
node bench/leakage.mjs --iterations 20000 --json results/ts/leakage.json
node bench/run-protocol.mjs                  # the whole protocol: 1 discarded warm-up run + 15 timed runs, leakage screen, aggregate
node bench/aggregate-runs.mjs results/ts/<date>/run*.json --discard-first --out results/ts/<date>/aggregate.json
```

## Protocol

The harness measures quantum-safe-ts only, with the same protocol and the same JSON files as quantum-safe-py's `tests/bench`, so one
aggregator and one set of table scripts read both (`aggregate_runs.py` in quantum-safe-py reads these run files unchanged).

- **A run** (`bench.mjs`): each benchmark is warmed up (100 calls, discarded), then timed 3,000 times with the monotonic clock, one call per
  sample; the fastest and slowest 1% of samples are removed. A row has `median_us`, `mean_us`, `p95_us`, `p99_us`, `stdev_us`, `cov_pct` and,
  with `--raw-samples`, every kept sample, so any statistic can be recomputed from the file.
- **The protocol** (`run-protocol.mjs`): one warm-up run that is discarded, then 15 timed runs, each in a fresh process (optionally pinned to
  one core), then the leakage screen with its controls, then the aggregate.
- **The aggregate** (`aggregate-runs.mjs`): the median across runs of each run's median, the fastest and slowest run, the run-to-run CoV and
  a 95% bootstrap interval over the runs.
- **The metadata** in every file: date, Node and V8 versions, platform, CPU model, logical CPUs, memory, commit, library version, whether it
  ran in a container.
- The commit recorded is the commit that ran: the protocol refuses a working tree with uncommitted changes.

## What the numbers are, and are not

- One machine, one Node version, Windows, pinned to one performance-core thread by `run-protocol.mjs`. The header of each results
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
