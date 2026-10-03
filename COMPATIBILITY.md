# Compatibility with quantum-safe-py

`quantum-safe-ts` is the TypeScript/WASM sibling of
[quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py). The goal is **byte-for-byte wire compatibility** for every persisted or
transmitted format, proven by shared fixtures, not assumed. This page is the source of truth for what is compatible, what is not, and why.
Status reflects **quantum-safe-ts 0.1.0** and **quantum-safe-py 0.3.0**, as of 2026-10-03.

> Pre-1.0, experimental, not independently audited. Conformance evidence is not a CAVP/CMVP validation.

## Legend

| Tag | Meaning |
|---|---|
| **DONE** | Implemented; a committed fixture proves it in CI against the real quantum-safe-py, through the WASM artifact |
| **N/A** | Cannot or should not be ported; reason given |
| **NEW** | Exists only in quantum-safe-ts (additive; never alters a py-compatible byte) |
| **PARTIAL** | Some of the feature exists; the gap is stated |

## 1. Parity matrix

### Key exchange and encryption
| # | quantum-safe-py feature | Status | Evidence |
|---|---|---|---|
| 1 | Hybrid KEM `X25519+ML-KEM-512/768/1024` | **DONE** | py→ts decapsulation and ts→py decapsulation, all three levels |
| 2 | Hybrid KEM `P-256+ML-KEM-512/768` | **DONE** | Includes py's quirk: the P-256 secret key is **PKCS#8 PEM text bytes** inside the packed key |
| 3 | Pure `KEM("ML-KEM-512/768/1024")` | **DONE** | both directions |
| 4 | `Envelope.seal/open`, AES-256-GCM, `SealedMessage` CBOR, AAD | **DONE** | All 5 hybrid suites, both directions, plus the published-package (facade) path |
| 5 | `SealedMessage.to_hex/from_hex/inspect` | **DONE** | |
| 6 | `SharedSecret.derive_key` (HKDF-SHA256, no salt) | **DONE** | |

### Signatures
| # | Feature | Status | Evidence |
|---|---|---|---|
| 7 | ML-DSA-44/65/87 (`Sign`) | **DONE** | py→ts verify and ts→py verify; py secret keys sign here and vice versa |
| 8 | `HybridSign` Ed25519 + ML-DSA-{44,65,87} | **DONE** | both directions, hedged and un-hedged |
| 9 | `HybridSign` P-256 + ML-DSA-{44,65} | **DONE** | ECDSA-SHA256 DER; public key is raw `x‖y` |
| 10 | SLH-DSA-SHAKE-128s/128f/256s (the three py exposes) | **DONE** | both directions |
| 11 | `SignedMessage` CBOR, signature blob, `HybridSignature` CBOR, hedged prefix | **DONE** | |
| 12 | LMS stateful signatures (RFC 8554) | **PARTIAL** | **Verification only** (`Lms.verify`): RFC 8554 Appendix F (2/2) and 13 pyhsslms-made signatures. No signing (stateful; unsafe without a durable state store), no XMSS, no SHAKE/192-bit variants. |

### Keys and formats
| # | Feature | Status | Evidence |
|---|---|---|---|
| 13 | Hybrid key packing | **DONE** | |
| 14 | Key CBOR `{v,algo,ms,ktype,key}` incl. version rollback/ceiling and the 10 MB cap | **DONE** | Re-serialisation is **byte-identical** to py for all 8 key types |
| 15 | Key PEM (`QUANTUM SAFE PUBLIC/SECRET KEY`, `qs-*` headers) | **DONE** | byte-identical |
| 16 | Public-key JWK (`kty:"AKP"`, `qs-*`) | **DONE** | equal JSON; secret keys are never emitted as JWK |
| 17 | Fingerprint `sha256(algo‖0x00‖raw)` (+ colon form) | **DONE** | BLAKE3 variant not provided (py falls back to SHA-256 without the optional package) |
| 18 | `KeyPair` CBOR bundle, `MigrationState` | **DONE** | byte-identical |
| 19 | Exception taxonomy | **DONE** | Same names where equivalent; adds stable `code` and `hint` (NEW) |
| 20 | JSON+base64 fallback when `cbor2` is absent | **N/A** | A hazard in py (a silent JSON+base64 fallback when `cbor2` is missing); TS always emits CBOR and rejects the fallback |

### Protocols
| # | Feature | Status | Evidence |
|---|---|---|---|
| 21 | PQC JWT (py format) | **DONE** | `JWTSigner/JWTVerifier`: py-issued tokens verify here (4 algorithms) and TS-issued tokens verify in py (6 algorithms). **Only py/ts can verify them.** |
| 22 | Hybrid X.509 builder + co-signature bundle | **Not implemented** | py's design is custom (classical cert + cosig). Standards-based X.509 for ML-DSA/ML-KEM (IETF LAMPS) is the better target; deferred. |
| 23 | TLS `ssl.SSLContext` configuration | **N/A** | Python-specific. Node ≥ 24 and current browsers negotiate hybrid TLS natively (RFC 10024). |
| 24 | `FernetShim` / `JWTShim` | **N/A** | Tied to Python `cryptography`/PyJWT. Replaced by `quantum-safe-audit` fix-hints and migration guides. |

### Migration, audit, evidence
| # | Feature | Status | Evidence |
|---|---|---|---|
| 25 | Scanner | **NEW (JS/TS)** | `quantum-safe-audit`: AST scanner for JS/TS (py's scanner is Python-only; py itself says TypeScript scanning is "planned") |
| 26 | CycloneDX 1.6 CBOM | **DONE** | validated against the official CycloneDX 1.6 JSON schema in CI |
| 27 | SARIF output, CI exit codes | **DONE** | validated against the official SARIF 2.1.0 schema |
| 28 | CNSA 2.0 report/enforce | **DONE, with deliberate differences** | See §3. TS reports hybrid X25519+ML-KEM-1024 as `partial` and adds a key-derivation-hash row. |
| 29 | `Upgrader`, `MigrationStateManager` | **DONE** | **Upgrader:** same `u16_be(len)‖classical‖pqc` packing and `hybrid_transition` state; fixtures (`tests/vectors/migrate_vectors.json`) built from independently generated X25519, Ed25519 and P-256 keys prove both directions: py-upgraded keys work in TS, TS-upgraded keys work in py, and `stripClassicalComponent` output is byte-identical to py's. **State manager:** same transition rules (forward chain; backward only with `allowBackward` and a reason; `pqc_only` terminal; stale-state check). **Store:** records are JSON in TS and CBOR in py, so they differ as stored; `exportToPyStore` / `importFromPyStore` convert to and from py's exact `<id>_current` / `<id>_history` layout (exports are byte-identical to py's; py loads and continues a TS-written store). **Locking:** py documents an external distributed lock; TS instead writes each key's whole history with one compare-and-set, safe across processes and machines when the store's `compareAndSet` is atomic (`FileMigrationStore` is a tested single-host one). **Known py quirk:** py's docstring claims old classical senders can still use an upgraded key (`backward_compat=True`); its code packs the key, so they cannot. TS says so in `UpgradeResult.notes`. |
| 25a | `qs-audit sbom` (enrich a CycloneDX SBOM with PQC readiness) | **DONE (npm)** | `quantum-safe-audit sbom <bom.json>` adds `quantum-safe:pqc-readiness` / `reason` / `action` properties to npm components from a small, dated, name-based knowledge base; unknown components are `UNKNOWN`, never `READY`. Not interchangeable with py's Python-package knowledge base. |
| 25b | `qs-audit requirements` (quick dependency check) | **DONE (different input)** | `quantum-safe-audit scan` reads `package.json` dependency sections (QSJ050 classical libraries, QSJ900 post-quantum libraries); `sbom` covers lockfile-derived SBOMs. |
| 25c | `qs-audit compliance` (SP 800-208 / FIPS control report with COMPLIANT/PARTIAL/NON_COMPLIANT levels) | **Declined** | A static scan cannot establish compliance, and emitting a compliance verdict from it would contradict this project's no-overclaiming rule. The scanner reports findings, CNSA 2.0 hash gaps (`--cnsa2`) and migration hints; `cnsa2.report()` in the library reports parameter-set gaps. |
| 25d | `qs-audit cnsa2` (CLI report) | **Library only** | `cnsa2.report()` / `cnsa2.enforce()`; no CLI (the audit package does not depend on the library). |
| 25e | `qs-migrate scan` / `upgrade-key` / `status` CLI | **Partly** | `scan` is `quantum-safe-audit scan`. `upgrade-key` and `status` are library calls (`Upgrader`, `MigrationStateManager`); no key-file CLI is provided (it would put secret keys on a command line or in files by default). |
| 30 | ACVP known-answer harness | **DONE (more)** | **1,317** NIST ACVP cases (py: 225): ML-KEM, ML-DSA, SLH-DSA keyGen/sigGen/sigVer/encap/decap. |
| 31 | Timing-leakage harness | **DONE (screen, not a proof)** | `bench/leakage.mjs`: dudect-style fixed-vs-random with interleaving, equal-footprint pools, null controls, a random-vs-random control and a deliberately leaky harness check. JS/WASM still gives no constant-time guarantee. |
| 32 | `ctypes.memset` zeroization | **N/A → replaced** | Rust `zeroize` + explicit `.free()` / `using`. JS-heap copies cannot be wiped; documented. |
| 33 | Pluggable backends | **N/A → reframed** | One WASM backend, verified by tests; native WebCrypto is used only as a test oracle (a native provider was evaluated and not built: with the speed-optimised build the WebAssembly code is within about 2x of Node's native ML-KEM). |
| 34 | CMVP / FIPS 140-3 validation | **N/A** | Neither library can claim it. |
| 35 | Signature format `-v2` (`<suite>-v2`) | **TS-only, additive** | New identifiers; quantum-safe-py cannot read them and fails closed on the unknown name. No prefix, ML-DSA half = FIPS 204 with context `quantum-safe-sig-v2` over `M2`, keys tagged `-v2`. See `website/guide/signatures.md`; tests in `signature-v2.test.ts` and `sig/v2.rs`. |

### Known quirks reproduced for parity (not endorsements)

- Public-key JWKs carry `key_ops: ["encapsulate", "verify"]` for every key type, as quantum-safe-py writes them; a strict JOSE consumer may object for a KEM or a signature key.
- **Stricter than py on input (every key py writes still loads):** a key CBOR must carry `ktype` (`pub` or `sec`; py accepts an absent one as either type, and both libraries always write it); a public key must have the exact length for its algorithm; a JWK must have `kty: "AKP"` (py ignores `kty`); a hybrid signature payload must have exactly its four entries; CBOR integers and lengths must be in shortest form. These checks refuse inputs py would accept, never the reverse.
- The signature prefix-length ambiguity and its mitigation (see SECURITY.md): TypeScript verifiers pin the prefix length per hedging mode, so signatures made with hedging disabled need a verifier created with `hedged: false`.

## 2. TypeScript-only additions (never alter a py-compatible byte)

| Addition | Why |
|---|---|
| `X-Wing` KEM suite | py's combiner is bespoke (§3). X-Wing (an individual Internet-Draft, not an RFC) is tested against `@noble/post-quantum`'s `ml_kem768_x25519`, is built on the RustCrypto `x-wing` crate, has not been tested against hpke-js, and is mentioned as an example in NIST SP 800-227. |
| `StandardJwt` (RFC 9964: ML-DSA JOSE, `AKP` JWK) | Verifiable by any compliant JOSE implementation (checked against noble and Node WebCrypto). |
| Envelope **v2** (pure ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM) | The CNSA 2.0 profile; py's HKDF-SHA-256 combiner cannot meet CNSA's SHA-384/512 requirement. |
| 9 additional SLH-DSA parameter sets | FIPS 205 completeness (py's high-level API accepts three). |
| Argon2id `deriveMasterKey` | py has no master-password concept. Matches Node WebCrypto Argon2id. |
| `Lms.verify` | CNSA 2.0 code-signing verification. |
| `easy` layer (`generateEncryptionKeys`, `encrypt`, `decrypt`, `generateSigningKeys`, `sign`, `verify`) | Strings and bytes in and out, nothing to free. Context is enforced on verify. |
| `FileMigrationStore`, `exportToPyStore` / `importFromPyStore`, `KeyPair.fromKeys` | Cross-process-safe migration state and py store conversion. |
| Typed errors with stable `code`/`hint`, `llms.txt`, MCP server, `quantum-safe-audit`, GitHub Action | Built for coding agents to pick, use, and self-correct. |
| Zero-config inline-WASM build and a tested runtime/framework matrix | See README. |

## 3. Compatibility is not interoperability, and one CNSA difference

A quantum-safe-py envelope opens in quantum-safe-ts because both implement the *same custom construction*. That construction is **not**
X-Wing, **not** RFC 10024's `X25519MLKEM768`, and **not** FIPS 204's native context for signatures. Consequences:

- Envelopes and hybrid signatures are readable **only** by quantum-safe-py / quantum-safe-ts.
- py's ML-DSA signatures verify under plain FIPS 204 **only with an empty context and the prefixed message** (`len(ctx) ‖ ctx ‖ prefix ‖
  message`), which a generic verifier must be told to reconstruct (verified with noble in `differential.test.ts`).
- Where other ecosystems must read your data, use the **NEW** standards options (`X-Wing`, `StandardJwt`).
- **CNSA 2.0:** py reports `X25519+ML-KEM-1024` compliant. Per the NSA CNSA 2.0 FAQ, hybrid is optional and the classical half of a hybrid
  must be CNSA 1.0 (ECDH P-384). TypeScript therefore reports that hybrid `partial` and treats pure `ML-KEM-1024` as the compliant choice.
  Details and sources: the "CNSA 2.0 and standards alignment" page of the documentation site (`website/guide/standards.md`).

## 4. How parity is proven

`scripts/generate_suite_vectors.py` (real quantum-safe-py + liboqs) writes `tests/vectors/suite_vectors.json`: 8 KEM, 5 envelope, 8 key-format,
22 signature and 4 JWT vectors. These are consumed by (a) Rust integration tests (`py_parity_*.rs`) and (b) the Vitest suite running the **WASM
artifact** (`parity.test.ts`, 70 tests). In the other direction `gen_ts_vectors` (Rust) and `gen_ts_js_vectors.mjs` (the built npm package)
produce data that `verify_ts_vectors.py` feeds to the real quantum-safe-py (**58 checks**, including migration). CI runs both directions on every push.

A row is **DONE** only when a committed fixture proves it in CI.
