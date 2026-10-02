# Security model

::: warning Status
Pre-1.0 and experimental. Not independently audited and not FIPS 140-3 validated. The RustCrypto crates it builds on (`ml-kem`, `ml-dsa`,
`slh-dsa`, `x-wing`) also state that they have not been independently audited. Do not protect real secrets with it until an independent
review is published.
:::

The authoritative policy, including how to report a vulnerability privately, is
[SECURITY.md](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/SECURITY.md). A summary:

## What it defends against

| Adversary | Defence |
|---|---|
| Harvest-now-decrypt-later (records ciphertext today, breaks classical crypto later) | Hybrid and pure ML-KEM envelopes; the audit tool finds classical crypto to migrate. |
| A network attacker or malicious input supplier | Every parser fails closed with a typed error. Mutation tests, property tests and cargo-fuzz targets cover them. Keys, signed messages and sealed messages are capped at 10 MB and are shape-checked (flat, definite-length, no duplicate keys, no trailing bytes) before decoding. Type-confusion and version-rollback rejection. The AEAD authenticates version, algorithm and AAD. JWT algorithm is pinned to the key; no `alg: none`. |
| Curious code in the same page or process | Secrets are held in WebAssembly memory behind opaque objects (the owned buffers are zeroized on `.free()`; copies made by argument passing and by parsing may remain in WebAssembly memory). `toString`, `toJSON` and `util.inspect` never reveal them. Errors and hints never contain key material. |
| A hostile repository scanned by the audit tool | Reports contain only short identifier-like details. The MCP server is read-only, offline and path-confined. |
| A supply-chain attacker | Pinned `Cargo.lock`, `cargo-deny`, `npm audit` in CI, no install scripts in the shipped packages, a provenance-capable release workflow, and a reproducible WebAssembly build check. |

## What it does not defend against

- **Side channels.** JavaScript and WebAssembly give no constant-time guarantee. ML-DSA signing time varies with the number of rejection-sampling iterations (by design not secret-dependent, which still makes timing screens noisy). We publish a
  timing-leakage *screen* (see below); a pass is not a proof.
- **Memory disclosure** of the JS heap, swap, core dumps, browser extensions with page access, or a compromised runtime.
- **Fault attacks.** Hedged signing mitigates some lattice fault attacks; it is not a general defence.
- **Weak passwords.** Argon2id slows guessing; it cannot rescue a guessable password.
- **Key management.** Storage, rotation, backup and access control are your responsibility.
- **Compliance.** Nothing here makes a system CNSA 2.0 or FIPS 140-3 compliant.

## Evidence in the repository

| Evidence | Where |
|---|---|
| 1,317 NIST ACVP cases (ML-KEM, ML-DSA, SLH-DSA) | `crates/quantum-safe-core/tests/acvp.rs`; CI job "NIST ACVP" |
| Byte parity with the real quantum-safe-py, both directions | `scripts/generate_suite_vectors.py`, `scripts/verify_ts_vectors.py`; CI job "Parity" |
| Differential tests against `@noble/post-quantum` and Node WebCrypto | `packages/quantum-safe-ts/test/differential.test.ts` |
| cargo-fuzz targets for the main binary parsers (envelope, keys, signed message, ciphertexts, secret keys, LMS); property and mutation tests for the rest | `fuzz/`, `test/`; CI job "cargo-fuzz" |
| Packed-tarball fixtures in 12 real toolchains | `tests/fixtures/` |
| Timing-leakage screen with null controls and a harness check | `bench/leakage.mjs` |
| Reproducible-build check | `scripts/repro-check.mjs` |

## The timing screen, honestly

`bench/leakage.mjs` runs the two-class fixed-versus-random test of dudect (Reparaz et al., 2017) on the WebAssembly artifact in Node. It
interleaves measurements, builds both classes from equally many distinct objects, reports null controls so the false-positive rate of the
machine is visible, includes a random-versus-random control, and includes a deliberately leaky comparison that the screen must flag.

Latest run (Node 24.18, Intel i9-14900HX, the process pinned to one performance core by the operating system (the script does not pin), `node bench/leakage.mjs --iterations 6000 --rounds 4`; ML-DSA signing used a quarter of that, 1,500 measurements per class; raw data in
`results/timing_leakage.json` and `results/timing_leakage_calibration.json`):

| Experiment | Result |
|---|---|
| ML-KEM-768 decapsulation, valid versus invalid ciphertext (the implicit-rejection path) | No difference detected |
| Envelope open, failure path: tampered first byte versus tampered last tag byte | No difference detected |
| ML-DSA-65 signing, fixed versus random key | No difference detected (signing time varies by design) |
| Random-versus-random control | No difference, as required |
| Deliberately leaky comparison (harness check) | Detected, as required |
| ML-KEM-768 decapsulation, fixed versus random key | A small difference: the fixed key was about 2% faster in three rounds and about 9% in the fourth (4 to 17 microseconds of roughly 200, over four rounds), consistent across rounds only after trimming the slowest 10% of samples |
| X25519+ML-KEM-768 (the default hybrid) decapsulation, fixed versus random key | Inconclusive: flagged in some rounds and trim levels only, with the fixed key faster by about 5 to 8 microseconds in every round; same suspected cause, not demonstrated |

The last row needs care. A calibration run using **encapsulation, which touches only public data**, shows a difference of the same sign and
similar size. We therefore attribute it to behaviour that depends on the *public* key (ML-KEM expands a public matrix from a public seed by
rejection sampling, which takes value-dependent time and which a processor's branch predictor learns when the same key repeats), not to the
secret. We cannot prove that nothing secret-dependent hides inside that 2%, and we do not claim to.

A "no difference detected" result bounds leakage at the resolution of that setup, on that machine, in that Node version. It says nothing
about browsers, whose timers are coarsened, and it is **not a constant-time proof**.
