# Roadmap

What is planned for quantum-safe-ts, in priority order. These are intentions, not promises: there are no dates, the order can change, and
anything here can be dropped. Shipped changes are in [CHANGELOG.md](CHANGELOG.md). Progress is tracked in the
[milestones](https://github.com/AnimeshShaw/quantum-safe-ts/milestones). The Python counterpart has its own
[roadmap](https://github.com/AnimeshShaw/quantum-safe-py/blob/master/ROADMAP.md); the two libraries change defaults together.

While the version starts with `0.`, a **minor** release (0.1 to 0.2) is where breaking changes happen, and each one is announced a release
earlier in the documentation and the changelog. A patch release (0.1.0 to 0.1.1) does not break correct code. The wire formats of released
identifiers never change: new capability arrives under a new, explicit identifier.

## Now: 0.2.0 (the minor release, in step with quantum-safe-py 0.4.0)

The theme is "make the safe thing the only thing", the same as in Python.

- **Defaults.** The default hybrid signature suite is `Ed25519+ML-DSA-65-v2`; the original format keeps
  working when named. An omitted `expectedContext` means "expect an empty context" and an omitted
  `expectedAad` accepts any AAD, each with a once-per-call-site warning. `hedged: false` with a `-v2`
  suite is accepted and warns (`QS_HEDGED_IGNORED`).
- **Same bytes as Python.** `signRaw` / `verifyRaw` with seed keys, X-Wing, streaming envelopes,
  COSE_Sign1 and private JWKs for ML-DSA (RFC 9964), all twelve SLH-DSA parameter sets, checked against
  quantum-safe-py 0.4.0 in both directions.
- **`LmsSigner`** for Node.js: LMS signing with write-ahead durable state and the seed encrypted at rest.
- **P-384 hybrids** (`P-384+ML-KEM-1024`, `P-384+ML-DSA-87`, and the `-v2` form) for estates that hold CNSA 1.0 keys, shared with Python.
- **Envelope re-wrap** (`Envelope.rewrap`, `rewrapDirectory` from `quantum-safe-ts/rewrap`): move stored envelopes to a new key, resumable and
  verified, with a JSON and CycloneDX report, shared with Python.
- **A benchmark protocol** with the same JSON files as Python (one warm-up run and fifteen timed runs,
  raw samples, bootstrap interval over runs).

## Next

- **Benchmarks and timing-leakage figures re-measured**, with raw samples published, on more than one
  machine ([#12](https://github.com/AnimeshShaw/quantum-safe-ts/issues/12)).
- Listings for coding agents (the MCP Registry and Context7) once the packages have settled.

## Later (no release assigned)

- **API shape before 1.0**: argument order (`sign(message, key)` against `decapsulate(key, ciphertext)`), subpath exports for migration, JWT and
  LMS, `Jwt*` casing, typed algorithm parameters. Deprecated aliases would keep old calls working for a release.
- **ESM only, or a shared registry**: the dual ESM and CommonJS builds create two copies of each class when both are loaded in one process.
- **A native-accelerated provider for Node**: Node's WebCrypto ML-KEM is faster than the WebAssembly for the bare primitive but asynchronous
  and ML-KEM only. It needs a second implementation kept byte-identical and an async story.
- **XMSS** and **multi-level HSS signing**, if a maintained library provides them. CNSA 2.0 asks for LMS or XMSS, and LMS is covered.
- **FN-DSA** after FIPS 206 is final and **HQC** after its standard is final, never presented as standard earlier.
- **Standards-based X.509** for ML-DSA and ML-KEM.
- **Per-feature WebAssembly builds** (KEM only, signatures only) to cut the size.
- **Per-framework example repositories**, and an **independent measurement of the scanner's accuracy** on third-party code (the committed corpus
  was written by the authors; it is a regression guard, not an accuracy claim).

## What would make it 1.0

1.0 means the API and formats are stable and will not break without a major version. It will not be called 1.0 before:

1. the 0.2.0 changes have shipped and settled for at least one release cycle;
2. the benchmarks and timing figures are re-measured and reproducible from published data;
3. the documentation and quantum-safe-py are in step, with the interop vectors passing in both directions on every release.

## What this library will not become

- **A TLS stack.** It helps build hybrid protocols; it does not implement TLS.
- **An application, a vault or a key-management service.** It is a library.

## Suggest or vote

Open an [issue](https://github.com/AnimeshShaw/quantum-safe-ts/issues). Security reports go through the private channel in
[SECURITY.md](SECURITY.md), not a public issue.
