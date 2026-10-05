# Security Policy

## Memory

The owned buffers of secret-bearing objects are zeroized on the WASM side by `.free()`, but that is not a promise that no copy remains: the
buffers wasm-bindgen uses to pass arguments in, and intermediate values created while parsing or serialising a key (CBOR, PEM), are not all wiped, and a
review found residual copies in WASM linear memory after `.free()`. Any copy extracted into the JavaScript heap is outside this library's control. Treat memory
as not reliably scrubbed.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Preferred: use GitHub's private reporting. On <https://github.com/AnimeshShaw/quantum-safe-ts> choose **Security, then Report a vulnerability**
(Security → Advisories). Or email:

> **animesh15b [at] iimk.edu.in**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept (no real secrets)
- The version of `quantum-safe-ts` (and the package: library, audit tool, MCP server) you tested against
- Your runtime (Node.js, Deno, Bun, browser, edge) and operating system

You will receive an acknowledgement within **48 hours** and a full response within **7 days**. If the vulnerability is confirmed, a patch will be
prepared and released before public disclosure, and a GitHub Security Advisory (with a CVE where one applies) will be published with the fixed
release. We follow [coordinated disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html): we ask that you
give us 90 days to patch before publishing details, and we credit reporters who want credit.

## Scope

In scope: the Rust core (`crates/`), the WASM bindings, the TypeScript package, the audit tool and MCP server, and the build/release
workflows. Out of scope: vulnerabilities in third-party dependencies that are not reachable through this library (report those upstream).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (the latest release) | Yes |
| Anything older than the latest release | **No. Upgrade.** |

Only the latest release receives security fixes. The same applies to `quantum-safe-audit`, `quantum-safe-mcp` and the `pqc-audit` and `pqc-mcp` aliases.

## Published advisories

None for quantum-safe-ts. The signature prefix forgery in quantum-safe-py 0.1.0 to 0.3.0
([GHSA-wqv6-gm9x-69x8](https://github.com/AnimeshShaw/quantum-safe-py/security/advisories/GHSA-wqv6-gm9x-69x8), fixed in quantum-safe-py 0.3.1) does not affect
this library: every public TypeScript verification path for the default signature format (`verify`, `verifyBytes`, and the JWT verifier that calls it)
pins the prefix length to the verifier's hedging mode before it checks the signature, and that check was in the code before any release. Details are in the
threat model below. If you use quantum-safe-py alongside this library, use quantum-safe-py 0.3.2 or later.

## Threat model (summary)

**Assets:** secret keys and shared secrets; plaintext; signing keys; the integrity of verification verdicts; the integrity of published packages.

**Adversaries considered**

| Adversary | Capability | What the library does about it |
|---|---|---|
| Harvest-now-decrypt-later quantum adversary | Records ciphertext today, breaks classical public-key crypto later | Hybrid (classical + ML-KEM) and pure ML-KEM-1024 envelopes; the audit tool finds classical crypto to migrate |
| Network attacker / malicious input supplier | Controls ciphertexts, sealed messages, keys, signatures, JWTs, CBOR/PEM/JWK, PEM files | Every parser fails closed with a typed error (never panics; mutation tests + cargo-fuzz); keys, signed messages and sealed messages are capped at 10 MB and shape-checked before decoding (flat, definite-length, no duplicate keys, no trailing bytes, bounded entry counts); type-confusion and version-rollback rejection; AEAD authenticates version, algorithm and AAD; JWT algorithm is pinned to the key; no `alg: none`; JWT signatures have one accepted spelling |
| Curious JS code in the same page/process | Reads JS-heap memory, logs objects | Secrets are held in WASM memory behind opaque objects (see the zeroization caveat above); `toString`/`toJSON`/`util.inspect` never reveal them; errors and hints never contain key material |
| Hostile repository scanned by the audit tool/MCP server | Embeds prompt-injection text or malformed files | Reports contain only short identifier-like details (other literals are redacted); the MCP server is read-only, offline and path-confined (symlink-safe), and limits the character set and length of file names and errors it echoes (it cannot make arbitrary words safe: file names are untrusted data) |
| Supply-chain attacker | Compromises a dependency or build | Pinned `Cargo.lock`, `cargo-deny`, `npm audit` in CI, provenance-capable release workflow, no install scripts in the shipped packages |

**Constructions inherited from quantum-safe-py, and what this library does about their weaknesses**

- *Signature prefix/message boundary.* The signed bytes are `len(ctx) || ctx || prefix || message`, and the prefix length is stored in the **unsigned** signature blob. A verifier that
  accepted any prefix length would let anyone move bytes between the prefix and the message of a valid signature and obtain a valid signature on a suffix or a prefixed version of the
  signed message, from public data alone. (A review demonstrated this against the permissive verifier.) The TypeScript verifiers
  therefore **pin the prefix length to the verifier's hedging mode**: exactly 32 bytes when `hedged` is true (the default), exactly 0 when it is false. To verify signatures made with hedging disabled,
  construct the verifier with `{ hedged: false }`. The bytes on the wire are unchanged. The Rust core's own `verify` is still permissive; use it only through the TypeScript layer or enforce the same rule.
  The `-v2` signature formats (see the signatures guide; quantum-safe-py 0.3.2 or later reads and writes them too) remove the ambiguity for good: no prefix, algorithm and context inside the signed bytes of both halves, one fixed-length encoding, keys tagged `-v2` (advisory: never reuse one key's bytes in both formats). Prefer v2 unless a quantum-safe-py older than 0.3.2 must verify the signature.
- *Do not use one signing key in both hedged and unhedged mode.* The prefix pin removes the forgery for a key used in one mode. A key whose owner signs both hedged and unhedged messages
  has two prefix lengths in circulation, and a verifier for either mode accepts the other's signatures on shifted message splits; the complete fix is the `-v2` format (below). With the quantum-safe-py-compatible format, pick one mode per key (hedged, the default) and never verify with both.
- *Hybrid signature halves are unbound.* In `Ed25519+ML-DSA-*`, each half is an ordinary signature over the same input and neither commits to the other half. A verifier requires both, so forging one half does not help, but
  a classical half and a post-quantum half taken from two different signatures on the same message by the same key pair can be recombined; this changes the signature bytes, not the signed message (see malleability). In the `-v2` formats both halves sign the same bytes, which include the algorithm identifier and context, so a recombination can only reproduce a signature the key already made on that message.
- *Key parsing is stricter than quantum-safe-py.* `ktype` must be present, a public key must have the exact length for its algorithm, a JWK must have `kty: "AKP"`, a hybrid signature has exactly four entries, CBOR integers are in shortest form. Anything py writes still loads.
- *Context.* A verifier must be told which context it expects (`expectedContext`, default empty); reading it from the message would let an attacker choose it. The `easy` layer does this.
- *Envelopes are anonymous.* Anyone holding the recipient's public key can seal a message with any AAD. The AAD detects tampering; it binds a message to a context only when the opener passes
  `expectedAad`. Sign separately for sender authentication.
- *Malleability.* Valid signatures and tokens can have more than one encoding in places (extra entries in a hybrid signature payload, the high-S twin of a P-256 signature). JWT signature text has one spelling.
  Do not use signature bytes or token text as a unique identifier or replay key; use an identifier inside the signed data.

**Explicitly not defended against**

- Side channels: ML-DSA signing time varies with the number of rejection-sampling iterations (by design not secret-dependent); browsers and JITs add noise. See the security guide.
- Memory disclosure of the JS heap, swap, core dumps, browser extensions with page access, or a compromised runtime.
- Fault attacks (hedged signing mitigates some lattice fault attacks; it is not a general defence).
- Weak passwords: Argon2id slows guessing; it cannot rescue a guessable password. No Unicode normalisation is applied (documented).
- Key management: storage, rotation, backup and access control of keys are the application's responsibility.

## Defences verified by tests in this repository

- Malformed or hostile bytes never panic any parser (mutation fuzzing in `crates/quantum-safe-core/tests/robustness.rs`, eight cargo-fuzz targets (including LMS),
  property tests in the TypeScript suite). A guard validates packed ML-DSA secret keys before decoding because the upstream decoder can panic.
- Use-after-free, double-free, and secret redaction behaviour (`behavior.test.ts`).
- X25519 low-order points are rejected; ML-KEM implicit rejection is documented and tested.
- Version relabelling between envelope profiles fails; every authenticated field is tamper-tested.
- A reproducible-build check for the WebAssembly artifact (`scripts/repro-check.mjs`), a pinned Rust toolchain, and a CycloneDX SBOM and CBOM of the library (`scripts/generate-sboms.mjs`).
- The migration state manager's cross-process behaviour is tested with real concurrent child processes (exactly one writer wins a race). `FileMigrationStore` locks carry an owner token, are kept fresh by a heartbeat, and are re-checked before each write; a process frozen for longer than `staleLockMs` can still lose its lock, in which case it fails instead of writing.
