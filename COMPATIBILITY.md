# Compatibility with quantum-safe-py

`quantum-safe-ts` is the TypeScript/WASM sibling of
[quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py). The goal is
**byte-for-byte wire compatibility** for every persisted or transmitted format, proven by
shared fixtures, not assumed. This page is the source of truth for what is compatible
today, what will be, and what never can be. Status reflects **quantum-safe-core 0.1.0**
and **quantum-safe-py 0.3.0**, as of 2026-10-02.

> Pre-1.0, experimental, not independently audited. Conformance evidence is not a
> CAVP/CMVP validation.

## Legend

| Tag | Meaning |
|---|---|
| **DONE** | Implemented and verified against quantum-safe-py vectors |
| **NOW** | Not built yet; a suitable pure-Rust crate exists, so it can be built and verified today |
| **SCRATCH** | No suitable crate; must be written from scratch (feasible, more effort and review) |
| **N/A** | Cannot or should not be ported; reason given |
| **NEW** | Exists only in quantum-safe-ts (additive; never alters a py-compatible format) |

## 1. Parity matrix

### Key exchange and encryption
| # | quantum-safe-py feature | TS status | Phase | Notes |
|---|---|---|---|---|
| 1 | Hybrid KEM X25519+ML-KEM-768 (default) | **DONE** | 1 | HKDF combiner matches vectors |
| 2 | Envelope seal/open, AES-256-GCM, `SealedMessage` CBOR, AAD | **DONE** | 1 | One round-trip vector; py→ts direction only so far |
| 3 | Hybrid X25519+ML-KEM-1024 (CNSA 2.0 KEM) | **NOW** | 2 | `ml-kem` supports 1024; combiner `info` already includes algo name. py verified: ct = 1602 B |
| 4 | Hybrid X25519+ML-KEM-512 | **NOW** | 2 | |
| 5 | Hybrid P-256+ML-KEM-512/768 | **NOW** | 2 | `p256` crate; 65-byte uncompressed point. Low priority; exact ECDH/ct layout to be verified against py before building |
| 6 | Pure `KEM("ML-KEM-xxx")`, `CipherText`, `SharedSecret.derive_key` | **NOW** | 2 | |
| 7 | `SealedMessage.to_hex/from_hex/inspect()` | **NOW** | 2 | Trivial |
| 8 | Non-standard KEMs (BIKE, HQC placeholders in registry) | **N/A** | — | py marks them non-standard/not hybrid-suitable. HQC revisited only after NIST finalises (Phase 7) |

### Signatures
| # | Feature | TS status | Phase | Notes |
|---|---|---|---|---|
| 9 | ML-DSA-44/65/87 (`Sign`) | **NOW** | 3 | `ml-dsa` 0.1.1. py construction: pure FIPS 204, empty ctx, message = `len(ctx)‖ctx‖rand‖msg`. Verified by probe |
| 10 | `HybridSign` Ed25519 + ML-DSA-{44,65,87} | **NOW** | 3 | `ed25519-dalek` 3.0. Both sub-sigs verified unconditionally |
| 11 | `HybridSign` P-256 + ML-DSA | **NOW** | 3 | Quirk: py stores the P-256 secret as PKCS#8 **PEM bytes** inside the packed secret key; ECDSA-SHA256 DER signature |
| 12 | SLH-DSA (FIPS 205: SHAKE/SHA2 × 128/192/256 × s/f) | **NOW** | 3 | `slh-dsa` 0.1.0. py ≥0.3.0 uses FIPS 205 (not SPHINCS+ round 3); legacy `SPHINCS+-*` names will be rejected, not silently mapped |
| 13 | `SignedMessage` CBOR, signature blob, `HybridSignature` CBOR | **NOW** | 3 | Formats fully specified in the research doc |
| 14 | Hedged signing (32-byte random prefix) | **NOW** | 3 | Must be reproduced for verify-compat even though FIPS 204 is already hedged by default |
| 15 | LMS stateful signatures (RFC 8554) | **SCRATCH** | 7 | `lms-signature` is 0.0.1. Plan: **verify-only first**, then signing behind a write-ahead state-store interface mirroring py. SP 800-208 also wants key generation in a validated module, which neither library can claim |
| 16 | XMSS | **SCRATCH** | 7+ | py doesn't have it either; Bouncy Castle is the only library in py's audit with both |

### Keys and formats
| # | Feature | TS status | Phase | Notes |
|---|---|---|---|---|
| 17 | Hybrid key packing (`u16_be ‖ classical ‖ pqc`) | **DONE** | 1 | |
| 18 | Key CBOR `{v,algo,ms,ktype,key}` + version-floor/ceiling + 10 MB cap | **NOW** | 2 | |
| 19 | Key PEM (`QUANTUM SAFE PUBLIC/SECRET KEY`, `qs-*` headers) | **NOW** | 2 | |
| 20 | Public-key JWK (`kty:"AKP"`, `qs-*` extras) | **NOW** | 2 | Secret keys never JWK, same as py |
| 21 | Fingerprint `sha256(algo‖0x00‖raw)`; BLAKE3 optional | **NOW** | 2 | |
| 22 | `KeyPair` CBOR bundle, `MigrationState` enum | **NOW** | 2 | |
| 23 | Exception taxonomy (`QuantumSafeError` → `CryptoError`, `KeyParseError`, …) | **NOW** | 1–2 | Same names; add stable `code` and `hint` (NEW) |
| 24 | JSON+base64 fallback when `cbor2` is absent in py | **N/A (read-only)** | 2 | TS will *detect and reject* it with a clear error rather than emit it |

### Protocols
| # | Feature | TS status | Phase | Notes |
|---|---|---|---|---|
| 25 | PQC JWT (py format, hedged, py-verifiable only) | **NOW** | 3 | Provided as explicit `compat: "quantum-safe-py"` mode |
| 26 | Standards-based JOSE ML-DSA JWT (RFC 9964) | **NEW** | 3 | Verifiable by other libraries; the interoperable choice |
| 27 | Hybrid X.509 builder + co-signature bundle | **SCRATCH** | 7+ | py's design is custom (classical cert + cosig). Better target: standards-based ML-DSA certs (IETF LAMPS RFCs) — decide after Phase 6 |
| 28 | TLS `ssl.SSLContext` hybrid configuration | **N/A** | — | Python-specific. Node ≥24 and browsers negotiate hybrid TLS natively. TS offers capability *detection* only (Phase 4) |
| 29 | `FernetShim` / `JWTShim` drop-in shims | **N/A** | — | Tied to Python `cryptography`/PyJWT APIs. Replaced by migration guides + audit fix-hints for `jose`, `jsonwebtoken`, `node:crypto` |

### Migration, audit, evidence
| # | Feature | TS status | Phase | Notes |
|---|---|---|---|---|
| 30 | Scanner (Python AST) | **N/A** as ported; **NEW** as a JS/TS scanner | 4 | py itself notes "TypeScript scanning planned". JS/TS AST scanner is the natural counterpart |
| 31 | CycloneDX 1.6 CBOM | **NOW** | 4 | Pure data transform. Note `cdxgen` already inventories JS/TS crypto; our value is PQC verdicts + policy |
| 32 | CNSA 2.0 report/enforce, `cnsa2.hybridKem()/hybridSign()` | **NOW** | 2–3 | Pure logic over the registry; default stays 768 for wire compat, same disclosed gap as py |
| 33 | SARIF output, CI gate exit codes, SBOM enrichment, NIST mapping | **NOW** | 4 | |
| 34 | `Upgrader`, `MigrationStateManager` | **NOW** | 4 | Async store interface (JS has no thread locks; distributed-lock caveat is the same as py's) |
| 35 | ACVP known-answer harness (225/225 in py) | **NOW** | 2–3 | Same NIST vectors against the **WASM artifact**; publish JSON results |
| 36 | Timing-leakage harness (two-class fixed-vs-random) | **NOW (limited)** | 6 | Can be run on the WASM artifact. Result must be reported honestly: JS engines/WASM runtimes give no constant-time guarantee |
| 37 | `ctypes.memset` zeroization | **N/A → replaced** | 1 | Rust `zeroize` + explicit `.free()` + `Symbol.dispose`. JS-heap copies the caller extracts cannot be wiped; documented |
| 38 | Pluggable backends (liboqs / rustcrypto / noble) | **N/A → reframed** | 6 | One audited WASM backend by default; optional native-WebCrypto *accelerated* provider with differential tests |
| 39 | CMVP / FIPS 140-3 validation | **N/A** | — | Neither library can claim it. Stated plainly everywhere |

## 2. TypeScript-only additions (never alter a py-compatible byte)

| Addition | Why | Phase |
|---|---|---|
| **X-Wing suite** and RFC 10024-style hybrids as extra, explicitly-named algorithm suites | py's combiner is bespoke (see §3). Standards-based suites make envelopes interoperable with noble/HPKE/TLS ecosystems | 2 |
| Argon2id master-key derivation | py has no master-password concept | **DONE** (1) |
| Standards-mode JWT (RFC 9964 + AKP JWK) | Verifiable outside our libraries | 3 |
| Zero-config inline-WASM entry + framework fixture matrix | "Works in Vite/Next/SvelteKit/Workers/MV3" is tested, not claimed | 1 |
| Stable error `code` + `hint`, JSON-schema'd CLI output, `llms.txt`, MCP server | Built for coding agents to pick, use, and self-correct | 1, 5 |
| Streaming/chunked envelope (v2) | Large files; v1 stays single-shot and compatible | 7 |
| JS/TS crypto audit CLI + GitHub Action | Fills the gap py documents but does not fill | 4 |

## 3. Compatibility ≠ interoperability (read this)

A quantum-safe-py envelope opens in quantum-safe-ts because both implement the *same
custom construction*. That construction is **not** X-Wing, **not** RFC 10024's
`X25519MLKEM768`, and **not** FIPS 204's native context for signatures. Consequences:

- Envelopes and hybrid signatures from either library are readable **only** by
  quantum-safe-py / quantum-safe-ts. No third-party library will open them.
- py's ML-DSA signatures verify under plain FIPS 204 **only with an empty context and the
  prefixed message**, so a generic verifier needs to be told to reconstruct it.
- Where interoperability with the wider ecosystem matters, use the **NEW** standards
  suites; where you must read existing py data, use the compat suite. Both live behind an
  explicit algorithm identifier, so crypto-agility is by data, not by flag day.

## 4. Findings to feed back to quantum-safe-py (do not change py from this repo)

1. `backends/liboqs.py` docstring claims the context prefix is "consistent with
   HashML-DSA (FIPS 204 §5.4)"; the observed construction is a plain message prefix with
   an empty FIPS 204 context. Documentation fix, or adopt the native `ctx` parameter in a
   future versioned suite.
2. Consider adding an X-Wing / RFC 10024 hybrid suite so py envelopes can be interoperable.
3. JWT hedged-prefix design cannot be verified by any other JOSE library; consider an
   RFC 9964-compliant mode.
4. Add the **reverse-direction parity test** (py opens a ts-sealed envelope and verifies a
   ts-made signature) to the quantum-safe-py repo. Until then parity is one-directional.
5. The silent JSON fallback when `cbor2` is missing can emit a different wire format.

## 5. How parity is proven

1. `scripts/generate_vectors.py` generates fixtures from quantum-safe-py (envelope, key
   CBOR/PEM/JWK, SignedMessage, hybrid signatures, JWT) into `tests/vectors/`.
2. Rust unit tests and the Node/Vitest suite consume the same files.
3. CI runs the WASM artifact (not just native Rust) against them, plus ACVP KATs.
4. Reverse direction (ts → py) is run in a Python job that installs quantum-safe-py,
   until the equivalent test lands in that repo.

A row moves to **DONE** only when a committed fixture proves it in CI.
