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
| Reproducible-build check | `scripts/repro-check.mjs` |

## Timing

JavaScript and WebAssembly runtimes give **no constant-time guarantee**, and this library does not claim one. The maintainer runs a timing-leakage screen (a dudect-style fixed-versus-random test with null controls) before releases; a screen can fail to detect a leak and is **not a proof**. Browsers coarsen timers and add their own noise. If your threat model includes a local timing attacker, use a native implementation in a hardened environment.
