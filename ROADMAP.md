# Roadmap

What is planned for quantum-safe-ts, in priority order. These are intentions, not promises: there are no dates, the order can change, and
anything here can be dropped. Shipped changes are in [CHANGELOG.md](CHANGELOG.md). Progress is tracked in the
[milestones](https://github.com/AnimeshShaw/quantum-safe-ts/milestones). The Python counterpart has its own
[roadmap](https://github.com/AnimeshShaw/quantum-safe-py/blob/master/ROADMAP.md); the two libraries change defaults together.

While the version starts with `0.`, a **minor** release (0.1 to 0.2) is where breaking changes happen, and each one is announced a release
earlier in the documentation and the changelog. A patch release (0.1.0 to 0.1.1) does not break correct code. The wire formats of released
identifiers never change: new capability arrives under a new, explicit identifier.

## Now: 0.1.x (patch releases after the first release)

0.1.0 is the first release of `quantum-safe-audit`, `quantum-safe-ts`, `quantum-safe-mcp` and the short aliases `pqc-audit` and `pqc-mcp`, each
published with npm provenance from a manually started workflow that waits for approval. The GitHub Action can be pinned as
`AnimeshShaw/quantum-safe-ts@v0.1.1`.

- Patch releases: documentation, bug fixes and dependency updates. A patch release never changes a wire format.
- Switch npm publishing to trusted publishing (no stored token).
- Listings for coding agents (the MCP Registry and Context7) once the packages have settled.

## Next: 0.2.0 (the breaking release, in step with quantum-safe-py 0.4.0)

The theme is "make the safe thing the only thing", the same as in Python.

- **The default hybrid signature suite becomes `Ed25519+ML-DSA-65-v2`** (no prefix, native FIPS 204 context), in `HybridSign()` and the `easy`
  layer, at the same time as quantum-safe-py 0.4.0 flips its default. Signatures made with the new default will not verify on quantum-safe-py
  0.3.0 or earlier, so this is announced in 0.1.0; existing signatures and the old identifiers keep working when named explicitly.
- **Decide whether `expectedContext` and `expectedAad` become required arguments**, as `context=` and `expected_aad=` become in Python 0.4.0.
  Today they default to empty, which is safe but easy to leave out.
- **A public bare FIPS 204 sign and verify** (a `signRaw` / `verifyRaw` equivalent): a standard ML-DSA signature over your own bytes with a
  native context, for other ecosystems. The primitive already exists in the core (it is what `StandardJwt` uses) and is tested against
  quantum-safe-py 0.3.2's `Sign.sign_raw()` and `Sign.verify_raw()` for ML-DSA-44, 65 and 87 with empty, short and 255-byte contexts, in both
  directions. What is missing is a public API and a decision on keys (the TypeScript core signs from a 32-byte seed; liboqs uses an expanded secret key).
- **Benchmarks and timing-leakage figures re-measured with raw samples published**, on more than one machine.

## Later (no release assigned)

- **API shape before 1.0**: argument order (`sign(message, key)` against `decapsulate(key, ciphertext)`), subpath exports for migration, JWT and
  LMS, `Jwt*` casing, typed algorithm parameters. Deprecated aliases would keep old calls working for a release.
- **ESM only, or a shared registry**: the dual ESM and CommonJS builds create two copies of each class when both are loaded in one process.
- **A native-accelerated provider for Node**: Node's WebCrypto ML-KEM is faster than the WebAssembly for the bare primitive but asynchronous
  and ML-KEM only. It needs a second implementation kept byte-identical and an async story.
- **P-384 hybrids** (`P-384+ML-KEM-1024`, `P-384+ML-DSA-87`). Only worth building for someone who needs the TLS `SecP384r1MLKEM1024` group;
  NSA's CNSA 2.0 FAQ does not make any hybrid compliant, so they would still report `partial`.
- **XMSS** next to LMS verification. LMS or XMSS signing only behind a documented durable-state interface (it may never ship: stateful signing is
  easy to misuse).
- **FN-DSA** after FIPS 206 is final and **HQC** after its standard is final, never presented as standard earlier.
- **COSE serialization** for RFC 9964 and standards-based X.509 for ML-DSA and ML-KEM.
- **React Native** (Hermes WebAssembly) with a device or simulator fixture; **per-feature WebAssembly builds** (KEM only, signatures only) to cut
  the size.
- **`StandardJwt` private keys that Python can sign with.** RFC 9964 stores a seed; liboqs cannot turn a seed back into a key pair yet.
- **Per-framework example repositories**, and an **independent measurement of the scanner's accuracy** on third-party code (the committed corpus
  was written by the authors; it is a regression guard, not an accuracy claim).

## What would make it 1.0

1.0 means the API and formats are stable and will not break without a major version. It will not be called 1.0 before:

1. the 0.2.0 breaking changes have shipped and settled for at least one release cycle;
2. the benchmarks and timing figures are re-measured and reproducible from published data;
3. the documentation and quantum-safe-py are in step, with the interop vectors passing in both directions on every release.

## What this library will not become

- **A TLS stack.** It helps build hybrid protocols; it does not implement TLS.
- **An application, a vault or a key-management service.** It is a library.

## Suggest or vote

Open an [issue](https://github.com/AnimeshShaw/quantum-safe-ts/issues). Security reports go through the private channel in
[SECURITY.md](SECURITY.md), not a public issue.
