# Roadmap

What is planned for quantum-safe-ts, in priority order. These are intentions, not promises: there are no dates, the order can change, and
anything here can be dropped. Shipped changes are in [CHANGELOG.md](CHANGELOG.md). Progress is tracked in the
[milestones](https://github.com/AnimeshShaw/quantum-safe-ts/milestones). The Python counterpart has its own
[roadmap](https://github.com/AnimeshShaw/quantum-safe-py/blob/master/ROADMAP.md); the two libraries change defaults together.

From 1.0 the API and the wire formats follow semantic versioning: a breaking change happens only in a **major** release and is announced a release
earlier in the documentation and the changelog. A minor release adds capability and a patch release fixes defects; neither breaks correct code. The
wire formats of released identifiers never change: new capability arrives under a new, explicit identifier.

## Now: 1.0.0 (in step with quantum-safe-py 1.0.0)

The theme is "make the safe thing the only thing", the same as in Python.

- **Defaults.** The default hybrid signature suite is `Ed25519+ML-DSA-65-v2`; the original format keeps
  working when named. An omitted `expectedContext` means "expect an empty context" and an omitted
  `expectedAad` accepts any AAD, each with a once-per-call-site warning. `hedged: false` with a `-v2`
  suite is accepted and warns (`QS_HEDGED_IGNORED`).
- **Same bytes as Python.** `signRaw` / `verifyRaw` with seed keys, X-Wing, streaming envelopes,
  COSE_Sign1 and private JWKs for ML-DSA (RFC 9964), all twelve SLH-DSA parameter sets, checked against
  quantum-safe-py 1.0.0 in both directions.
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

- **API shape.** The argument order (`sign(message, key)` against `decapsulate(key, ciphertext)`) mirrors quantum-safe-py and is part of the 1.0 contract, as are the
  subpath exports and the `Jwt*` names. A change would come in a major release, with deprecated aliases kept for one release.
- **ESM only, or a shared registry**: the dual ESM and CommonJS builds create two copies of each class when both are loaded in one process.
- **A native provider for ML-KEM and ML-DSA on Node.** Large payloads already use Node's native AES-256-GCM. Node's WebCrypto ML-KEM is faster than the WebAssembly for the
  bare primitive but asynchronous and ML-KEM only; using it needs a second implementation kept byte-identical and an async story.
- **XMSS** and **multi-level HSS signing**, if a maintained library provides them. CNSA 2.0 asks for LMS or XMSS, and LMS is covered.
- **FN-DSA** after FIPS 206 is final and **HQC** after its standard is final, never presented as standard earlier.
- **Standards-based X.509** for ML-DSA and ML-KEM.
- **Per-feature WebAssembly builds** (KEM only, signatures only) to cut the size.
- **Per-framework example repositories**, and an **independent measurement of the scanner's accuracy** on third-party code (the committed corpus
  was written by the authors; it is a regression guard, not an accuracy claim).

## What this library will not become

- **A TLS stack.** It helps build hybrid protocols; it does not implement TLS.
- **An application, a vault or a key-management service.** It is a library.

## Suggest or vote

Open an [issue](https://github.com/AnimeshShaw/quantum-safe-ts/issues). Security reports go through the private channel in
[SECURITY.md](SECURITY.md), not a public issue.
