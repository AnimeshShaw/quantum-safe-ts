# Security Policy

## Status

`quantum-safe-ts` is **pre-1.0 and experimental**. It has **not** been independently audited, and it is **not** FIPS 140-3 / CMVP / CAVP validated.
Conformance tests against NIST ACVP vectors are evidence of correctness, not a validation. Do not use it to protect real secrets until a
third-party review is published and this notice is removed. The upstream RustCrypto crates it builds on (`ml-kem`, `ml-dsa`, `slh-dsa`,
`x-wing`) also state that they have not been independently audited.

JavaScript and WebAssembly runtimes give **no constant-time guarantee**. Secret-bearing objects are wiped on the WASM side with `.free()`, but any
copy extracted into the JavaScript heap is outside this library's control.

## Reporting a vulnerability

Please report privately, not in a public issue:

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on <https://github.com/AnimeshShaw/quantum-safe-ts>.
- Include the affected version, a minimal reproduction (no real secrets), and the impact.

You can expect an acknowledgement within 7 days. We aim to ship a fix or mitigation within 90 days of a confirmed report and will credit
reporters who want credit.

## Scope

In scope: the Rust core (`crates/`), the WASM bindings, the TypeScript package, the audit tool and MCP server, and the build/release
workflows. Out of scope: vulnerabilities in third-party dependencies that are not reachable through this library (report those upstream).

## Supported versions

Only the latest released minor version receives fixes while the project is pre-1.0.

## Threat model (summary)

**Assets:** secret keys and shared secrets; plaintext; signing keys; the integrity of verification verdicts; the integrity of published packages.

**Adversaries considered**

| Adversary | Capability | What the library does about it |
|---|---|---|
| Harvest-now-decrypt-later quantum adversary | Records ciphertext today, breaks classical public-key crypto later | Hybrid (classical + ML-KEM) and pure ML-KEM-1024 envelopes; the audit tool finds classical crypto to migrate |
| Network attacker / malicious input supplier | Controls ciphertexts, sealed messages, keys, signatures, JWTs, CBOR/PEM/JWK, PEM files | Every parser fails closed with a typed error (never panics; mutation tests + cargo-fuzz); 10 MB payload cap; type-confusion and version-rollback rejection; AEAD authenticates version, algorithm and AAD; JWT algorithm is pinned to the key; no `alg: none` |
| Curious JS code in the same page/process | Reads JS-heap memory, logs objects | Secrets stay in WASM memory behind opaque objects; `toString`/`toJSON`/`util.inspect` never reveal them; errors and hints never contain key material |
| Hostile repository scanned by the audit tool/MCP server | Embeds prompt-injection text or malformed files | Reports contain only short identifier-like details (other literals are redacted); MCP server is read-only, offline, and path-confined (symlink-safe) |
| Supply-chain attacker | Compromises a dependency or build | Pinned `Cargo.lock`, `cargo-deny`, `npm audit` in CI, provenance-capable release workflow, no install scripts in the shipped packages |

**Explicitly not defended against**

- Side channels: no constant-time guarantee in JS/WASM; ML-DSA rejection sampling leaks by design; browsers and JITs add noise and leakage.
- Memory disclosure of the JS heap, swap, core dumps, browser extensions with page access, or a compromised runtime.
- Fault attacks (hedged signing mitigates some lattice fault attacks; it is not a general defence).
- Weak passwords: Argon2id slows guessing; it cannot rescue a guessable password. No Unicode normalisation is applied (documented).
- Key management: storage, rotation, backup and access control of keys are the application's responsibility.
- Compliance: nothing here makes a system CNSA 2.0, FIPS 140-3, or any other certification compliant.

**Residual risks to weigh before any production use:** no independent audit; unaudited upstream crates; novel combination of constructions
(compatible with quantum-safe-py, but neither library's custom hybrid combiner has been reviewed against NIST SP 800-227 §5.5.2).

## Defences verified by tests in this repository

- Malformed or hostile bytes never panic any parser (mutation fuzzing in `crates/quantum-safe-core/tests/robustness.rs`, six cargo-fuzz targets,
  property tests in the TypeScript suite). A guard validates packed ML-DSA secret keys before decoding because the upstream decoder can panic.
- Use-after-free, double-free, and secret redaction behaviour (`behavior.test.ts`).
- X25519 low-order points are rejected; ML-KEM implicit rejection is documented and tested.
- Version relabelling between envelope profiles fails; every authenticated field is tamper-tested.
