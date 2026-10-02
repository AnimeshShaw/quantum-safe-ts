# quantum-safe-ts — Ecosystem, Parity and Delta Research

**Date:** 2026-10-02 (all external facts are as of this date; re-verify before quoting)
**Scope:** the standalone `quantum-safe-ts` library only. Nothing here concerns QSafe Vault.
**Method:** (1) read `quantum-safe-py` 0.3.0 source, tests, changelog and its own
production-readiness rubric; (2) ran the real Python library against liboqs to confirm
wire-format claims empirically; (3) queried the npm and crates.io registries and primary
sources for the JS/TS and Rust PQC ecosystem; (4) compared against the current Rust core.

Evidence labels used throughout: **[verified]** = I ran it or read it in source today;
**[sourced]** = from a cited external page; **[inferred]** = my reasoning, not confirmed.

---

## 1. Where quantum-safe-ts stands today

| Item | State |
|---|---|
| Rust crate `quantum-safe-core` 0.1.0 | Done. **[verified]** `cargo test`: 29 passed. `cargo check --target wasm32-unknown-unknown`: clean. |
| What it implements | Hybrid X25519+ML-KEM-768 KEM, HKDF-SHA256 combiner, AES-256-GCM, envelope AAD, CBOR `SealedMessage`, Argon2id master-key derivation |
| Parity evidence | Vectors generated from quantum-safe-py 0.3.0 for combiner, enc-key derivation, AAD, AES-GCM, and one full envelope round-trip (`tests/vectors/glue_vectors.json`) |
| WASM bindings, TS facade, npm package, fuzzing, CI | **Not started.** Designed and approved (`docs/superpowers/specs/2026-09-30-wasm-bindings-npm-package-design.md`). No `bindings/`, `packages/`, `fuzz/`, `.github/` exist. |
| npm name | `quantum-safe-ts`, `quantum-safe`, `quantum-safe-js` all return 404 on the registry, i.e. **unclaimed**. **[verified]** |
| Local toolchain | rustc/cargo 1.98.1, wasm-pack 0.15.0, node 24.18.0 (has native WebCrypto ML-KEM/ML-DSA, usable as a test oracle). `clippy` is **not installed**; CI plan requires it. |

Measured against the *current* crate, quantum-safe-ts implements roughly the envelope slice
of quantum-safe-py: **1 of ~10 functional areas** (see the matrix in `COMPATIBILITY.md`).

---

## 2. What quantum-safe-py actually is (the thing we must match)

Source: `D:\quantum_safe` @ 0.3.0, ~10.9k lines of Python across these areas:

| Area | Modules | Size |
|---|---|---|
| KEM (pure + hybrid) | `kem/{core,hybrid,algorithms}.py` | ML-KEM-512/768/1024; hybrid with X25519 or P-256 |
| Signatures | `signatures/{core,hybrid,stateful,algorithms}.py` | ML-DSA-44/65/87, SLH-DSA (FIPS 205), hybrid Ed25519/P-256 + ML-DSA, LMS (optional) |
| Key/value types | `types/{keys,kem,signatures}.py` | `PublicKey`/`SecretKey`/`KeyPair`, PEM + CBOR + JWK, fingerprints, `MigrationState`, `SignedMessage`, `HybridSignature` |
| Protocols | `protocols/{envelope,jwt,x509,tls}.py` | Envelope, PQC JWT, hybrid X.509 cert + co-signature bundle, TLS context helper |
| Migration | `migrate/{scanner,upgrader,state,shims}.py` | Python-AST scanner, key upgrader, state manager, Fernet/JWT shims |
| Audit/compliance | `audit/*`, `compliance/cnsa2.py` | CI gate, SARIF, SBOM enrichment, CycloneDX 1.6 CBOM, NIST mapping, CNSA 2.0 report/enforce |
| Evidence | `tests/conformance/acvp_kat.py`, `tests/bench/*` | 225/225 ACVP KAT cases, two-class timing-leakage harness |

### 2.1 Wire formats we must reproduce byte-for-byte **[verified in source + probe]**

| Format | Exact definition |
|---|---|
| Hybrid key packing | `uint16_be(len(classical)) ‖ classical ‖ pqc` (public and secret) |
| Hybrid KEM ciphertext | `uint16_be(len(classical_ct)) ‖ classical_ct ‖ pqc_ct` |
| Hybrid KEM combiner | `HKDF-SHA256(ikm = ss_c ‖ ss_pqc, salt = ct_c ‖ ct_pqc, info = "quantum-safe hybrid KEM v1" ‖ 0x00 ‖ algo, L=32)` — **done** for X25519+ML-KEM-768 |
| Envelope | AES-256-GCM, 12-byte nonce, `enc_key = HKDF(ss, salt=None, info="qs-envelope-enc-v1")`, AAD = `0x01 ‖ len(algo) ‖ algo ‖ extra`; CBOR map `{v, algo, kct, n, ct, aad}` — **done** |
| Key CBOR | `{v:1, algo, ms, ktype:"pub"/"sec", key}`; reader rejects `v<1` and `v>1`; 10 MB payload cap |
| Key PEM | label `QUANTUM SAFE PUBLIC KEY` / `QUANTUM SAFE SECRET KEY`; headers `qs-version`, `qs-algo`, `qs-migration`; body = base64(key CBOR), 64-col wrap |
| Key JWK | `{kty:"AKP", alg:<algo string>, pub:<b64url raw>, qs-version, qs-migration, key_ops}`; **public keys only** |
| Fingerprint | `sha256(algo_ascii ‖ 0x00 ‖ raw_key)` hex (optional BLAKE3) |
| `SignedMessage` CBOR | `{v:1, msg, sig, algo, ctx, fp, ts(float), hybrid(bool)}` |
| Signature blob | `prefix_len(1B) ‖ rand_prefix(0 or 32B) ‖ payload` |
| Hybrid signature payload | CBOR `{classical_sig, pqc_sig, classical_algo, pqc_algo}` |
| ML-DSA sub-signature | **Probe result:** the signature verifies as *plain FIPS 204 ML-DSA-65 with empty context* over `len(ctx) ‖ ctx ‖ rand_prefix ‖ message`. Not FIPS 204's native context parameter. Reproducible with any ML-DSA library. |
| Ed25519 sub-signature | Plain Ed25519 over `len(ctx) ‖ ctx ‖ rand_prefix ‖ message` |
| Sizes **[verified]** | Hybrid sign pub 1986 B / sec 4066 B; Ed25519+ML-DSA-65 signature blob 3476 B (64 B + 3309 B + CBOR + 33 B prefix); X25519+ML-KEM-1024 ciphertext 1602 B |

### 2.2 Things in quantum-safe-py that are quirks, bugs-in-docs, or non-standard
These matter because "100% compatible" means reproducing them, and because they are worth
reporting upstream. None is a break in the Python library's own correctness.

1. **Bespoke hybrid combiner.** Salt-from-ciphertexts HKDF is neither X-Wing nor the
   TLS `X25519MLKEM768` construction. A py-sealed envelope can therefore never be opened
   by noble's `XWing`, Node's `MLKEM768-X25519`, or any TLS stack. Compatibility with
   py ≠ interoperability with the standards ecosystem. **[verified in source]**
2. **ML-DSA "context" is not FIPS 204 context.** `backends/liboqs.py` docstring claims the
   construction is "consistent with HashML-DSA FIPS 204 §5.4". The probe shows it is a
   plain message prefix with an empty FIPS 204 context. A FIPS 204 verifier given
   `ctx=<app context>` will reject these signatures. **[verified by probe]**
3. **py JWTs are verifiable only by quantum-safe-py** (hedged random prefix hidden in the
   signature blob; the module docstring says so). Not RFC 9964 JOSE. **[verified in source]**
4. **Hybrid P-256 secret key** stores a PKCS#8 *PEM string's bytes* inside the packed
   secret key, not raw scalar bytes. **[verified in source]**
5. **CBOR fallback.** If `cbor2` is missing, `_internal/serialization.py` silently emits a
   JSON+base64url envelope (`{"_qs_fmt":"json-b64-v1",...}`) instead of CBOR. `cbor2` is a
   hard dependency in `pyproject.toml`, so normal installs emit CBOR, but a reader should
   recognise or explicitly reject the fallback. **[verified in source]**
6. **Env note:** this machine has liboqs 0.15.0 under liboqs-python 0.16.0 (version-mismatch
   warning). Probe outputs above are internally consistent; the committed vectors were
   generated under the same pairing.

### 2.3 Honest scoring by py's *own* rubric
`docs/production_readiness_rubric.md` (9 externally anchored dimensions, D1–D9) scores
quantum-safe-py: Full on D1, D2, D5, D7, D8, D9; Partial on D3 (LMS only), D4 (225/225
ACVP, no CMVP), D6 (defaults below CNSA 2.0). The same rubric scores `noble-post-quantum`
Full on D1/D2/D5, Partial on D4, None on D3/D7/D8/D9. This is the yardstick I use below.

---

## 3. The JS/TS and adjacent ecosystem (as of 2026-10-02)

### 3.1 JS/TS libraries **[verified via npm registry + sourced pages]**

| Library | Version | Weekly downloads | What it is | Notes |
|---|---|---|---|---|
| `@noble/post-quantum` | 0.7.1 | **~495,000** | Pure-JS ML-KEM, ML-DSA, SLH-DSA, Falcon, hybrids (X-Wing, ML-KEM-768+X25519/P-256, ML-KEM-1024+P-384) | MIT. Self-audit spring 2026 (sources say March and April); README: "not independently audited"; explicitly **does not claim constant-time**. No CBOR, envelope, serialization, protocol or tooling layer. Strongest incumbent on primitives. |
| `mlkem` / `crystals-kyber-js` | 2.7.0 | ~20,000 | ML-KEM only, pure TS | MIT |
| `@oqs/liboqs-js` | 0.15.1 | ~2,400 | WASM bindings to liboqs, 103 algorithms | MIT. README: "meant for research, prototyping, and experimentation"; not an official OQS product; no audit. |
| `@hpke/core` + `@hpke/hybridkem-x-wing` | 1.9.0 / 0.7.0 | ~950,000 (core) | HPKE + X-Wing | MIT. Narrow, standards-focused. |
| `pqc-kyber` | 0.7.0 | n/a | Rust→WASM Kyber | Stale since 2023 |
| OpenPGP.js | v6 | n/a | ML-KEM + ECC hybrid, opt-in since May 2026 | [sourced] Application-level, not a general library |
| **quantum-safe-ts** | — | — | Rust→WASM hybrid envelope + (planned) signatures, audit, migration | Not published |

### 3.2 Native platform support (changes the strategy) **[sourced: Node.js docs]**
Node.js **v24.7.0+** ships WebCrypto **ML-KEM-512/768/1024** and **ML-DSA-44/65/87**,
ChaCha20-Poly1305, AES-OCB, SHA-3/SHAKE, KMAC; **v24.8.0** adds **Argon2d/i/id**;
**v26.10.0** adds hybrid KEMs **MLKEM768-X25519, MLKEM768-P256, MLKEM1024-P384**. All are
"Stability 1.1 – active development" under the WICG *Modern Algorithms in the Web
Cryptography API* proposal; `SubtleCrypto.supports()` feature-detects. Cloudflare Workers
exposes ML-KEM/ML-DSA in WebCrypto. Chromium has cleared intent-to-ship for these
algorithms (details of per-browser shipping state **unverified**; verify before claiming).
**Implication:** raw ML-KEM/ML-DSA primitives are becoming platform commodities. A new
library cannot win on primitives and should not try. The durable value is the layer above:
formats, constructions, compatibility, migration, audit, and developer ergonomics. Native
engines are also a candidate *accelerated backend* and a *test oracle* (Phase 6).

### 3.3 Standards state **[sourced]**
- **RFC 10024** (Aug 2026): TLS 1.3 hybrids `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`.
- **RFC 9964** (May 2026): ML-DSA for JOSE/COSE; defines the `AKP` JWK key type.
  `draft-ietf-jose-pqc-kem-06` (KEMs for JOSE/COSE) and `draft-ietf-jose-pq-composite-sigs`
  still drafts. SLH-DSA for JOSE/COSE still a draft.
- **X-Wing**: `draft-connolly-cfrg-xwing-kem-10`, Informational, expired Sept 2026, but
  implemented widely (noble, `@hpke/hybridkem-x-wing`, RustCrypto `x-wing` 0.1.1).
- **RFC 9980**: post-quantum OpenPGP (ML-KEM-768+X25519 mandatory).
- **FIPS 206 (FN-DSA/Falcon)**: still draft; finalisation expected late 2026/early 2027.
  **HQC**: selected March 2025; standard still in progress. Neither is safe to ship as a
  "standard" algorithm yet.

### 3.4 Rust building blocks (crates.io, **[verified]**)

| Need | Crate | Version | Maturity signal |
|---|---|---|---|
| ML-KEM (have) | `ml-kem` | 0.3.2 | 9.3M dl |
| ML-DSA | `ml-dsa` | 0.1.1 | 3.3M dl, RustCrypto |
| SLH-DSA | `slh-dsa` | 0.1.0 | 1.1M dl, RustCrypto |
| X-Wing | `x-wing` | 0.1.1 (updated 2026-10-01) | 0.7M dl |
| Ed25519 | `ed25519-dalek` | 3.0.0 | 225M dl |
| P-256 | `p256` | 0.14.0 | 195M dl |
| Formally-verified alt. | `libcrux-ml-kem` / `libcrux-ml-dsa` | 0.0.10 | Cryspen; verification has known gaps (IACR 2026/192) |
| FN-DSA | `fn-dsa` | 0.4.0 | Pre-standard |
| LMS | `lms-signature` | **0.0.1** | 8k dl, too immature |
| XMSS | `xmss` | 0.1.0-pre.0 | Pre-release |
| HQC | none on crates.io | — | Would be from scratch |

All "pure Rust, no C" — the property that makes `npm install` work with no native build.

### 3.5 Crypto-inventory tooling (competitor to the audit idea) **[sourced]**
`cdxgen` already produces CycloneDX CBOM including JavaScript/TypeScript source-level
algorithm inventory; other small scanners (`cbom-scan`, package.json CBOM generators)
exist. So *raw inventory for JS is not a gap*. What none of the sourced tools were shown to
do (**[inferred]**, to be re-verified in Phase 4): PQC-readiness verdicts, CNSA 2.0 policy
gating, concrete fix hints that point at working replacement code, and CI exit codes tied
to a policy. That is the defensible differentiator, not inventory itself.

### 3.6 Agent discoverability practices **[sourced]**
Ship `llms.txt` (short, <~2k tokens) and `llms-full.txt` inside the npm tarball; add
`AGENTS.md`/`CLAUDE.md` templates; a README section "Using with AI coding agents"; register
with Context7; an MCP server for docs/tooling; test every snippet in CI; **no hidden
instructions aimed at agents** (visible, factual content only).

---

## 4. Answering "will it cater to Node, React, Vite, Svelte…?"

**Short answer: yes in principle, but only because we will test it, not because WASM is magic.**
Frameworks (React, Vue, Svelte, Angular, Next, Nuxt, SvelteKit, Astro) are not runtimes;
they are consumers that sit on a **runtime** (Node, browser, edge worker, Deno, Bun,
extension, React Native) and a **bundler** (Vite/Rollup, webpack, esbuild, Turbopack). WASM
runs on all the runtimes, but the real friction is in loading the `.wasm`:

| Concern | Reality | Mitigation |
|---|---|---|
| `.wasm` asset loading differs per bundler | Vite needs a plugin or `?url`; webpack 5 needs `asyncWebAssembly`; Next.js differs server vs edge; Workers require a module import | Ship a **zero-config inline-base64 entry** (`quantum-safe-ts` default) plus a separate-asset entry for size-sensitive apps |
| Async init vs sync API | WASM instantiation is async | `await init()` hidden behind async-first API; top-level-await-free |
| Browser CSP | Strict CSP and MV3 extensions need `'wasm-unsafe-eval'` | Document; test in an MV3 fixture |
| Hermes / React Native | Hermes gained WASM support (RN **0.84**, **[sourced]**) but older RN has none | RN is a *later-phase, explicitly-scoped* target with a fallback strategy; do not claim it until tested |
| Dual module formats | Consumers mix ESM/CJS | tsup ESM + CJS + `.d.ts`, conditional `exports` |
| Bundle size | Unknown | Measure in Phase 1 and set a budget; do not publish a number before measuring |

**Guarantee mechanism:** a CI fixture matrix (Node 20/22/24, Deno, Bun, Cloudflare Workers
via miniflare, Vite, webpack, Next.js, SvelteKit, esbuild, Chromium+Firefox+WebKit via
Playwright, MV3 extension) that installs the *packed tarball* and runs a seal/open smoke
test. A runtime appears in the README support table only when its fixture is green.

---

## 5. Can it become "the go-to library"? Honest assessment

- **Not by competing on primitives.** noble has ~495k weekly downloads and is the default
  that humans and agents already reach for; Node and browsers are absorbing primitives.
- **Yes as the production layer** noble explicitly does not provide: versioned wire formats,
  typed errors, key lifecycle/migration state, envelope + signatures + JWT, CNSA 2.0
  profiles, conformance evidence, and a JS/TS PQC audit/CBOM tool. This mirrors the
  positioning that holds up in quantum-safe-py's own rubric ("production layer", not "PQC
  exists").
- **Agents recommend what is findable, current, and unambiguous.** Levers we control:
  `llms.txt`/`llms-full.txt` in the tarball, `AGENTS.md`, tested snippets, a "which library
  should I use" page that is honest (including "use WebCrypto/noble if you only need a raw
  primitive"), stable error codes with a `hint` field for self-repair, JSON-schema'd CLI
  output, an MCP server exposing audit/recommend/migrate tools, and Context7/registry
  listings. Levers we do not control: model training cut-offs. Expect lag; plan for
  retrieval-based discovery first.
- **Credibility is the moat:** publish ACVP results, cross-implementation differential
  tests (WASM vs noble vs Node WebCrypto vs liboqs), reproducible builds with npm
  provenance, and a plain-language threat model. No audit claim until one exists.

---

## 6. Rubric self-score (quantum-safe-py's D1–D9), today vs. target

| Dim | Today | After Phase 3 | After Phase 6 | Note |
|---|---|---|---|---|
| D1 ML-KEM-1024 | None | Full | Full | |
| D2 ML-DSA-87 | None | Full | Full | |
| D3 Stateful (LMS/XMSS) | None | None | None → Partial (Phase 7: LMS verify first) | Signing needs state discipline; SP 800-208 wants validated keygen |
| D4 Conformance evidence | Partial (parity vectors only) | Partial (ACVP KEM+sig) | Partial+ (ACVP + differential + Wycheproof) | Never "validated"; no CMVP |
| D5 Hybrid combiner | Full | Full | Full | + X-Wing suite |
| D6 Defaults vs CNSA 2.0 | Partial | Partial | Partial | Compat default stays 768; `cnsa2` profile gives 1024/87; honest like py |
| D7 Discovery/inventory | None | None | Full (Phase 4) | |
| D8 Migration | None | Partial | Full (Phase 4) | |
| D9 Protocol integration | Partial (envelope) | Full (envelope + JWT) | Full | |

---

## 7. Sources

- Node.js WebCrypto docs — https://nodejs.org/api/webcrypto.html
- @noble/post-quantum — https://github.com/paulmillr/noble-post-quantum · https://www.npmjs.com/package/@noble/post-quantum
- liboqs-js — https://github.com/open-quantum-safe/liboqs-js
- mlkem / crystals-kyber-js — https://github.com/dajiaji/crystals-kyber-js
- RFC 10024 — https://www.rfc-editor.org/info/rfc10024/
- RFC 9964 — https://datatracker.ietf.org/doc/rfc9964/
- draft-ietf-jose-pqc-kem — https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/
- X-Wing draft — https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- RFC 9980 (PQ OpenPGP) — https://postquantum.com/security-pqc/post-quantum-openpgp-rfc-9980/
- FN-DSA / FIPS 206 status — https://www.encryptionconsulting.com/education-center/fn-dsa-fips-206/
- Hermes WebAssembly — https://www.callstack.com/events/react-native-0-84-and-other-news
- cdxgen — https://github.com/cdxgen/cdxgen
- llms.txt practice — https://dev.to/alfredz0x/how-to-make-your-api-ai-discoverable-with-llmstxt-and-openapi-2026-guide-469l
- libcrux verification caveats — https://eprint.iacr.org/2026/192.pdf
- PQC library survey — https://arxiv.org/abs/2508.16078
- npm registry and crates.io APIs — queried 2026-10-02
- quantum-safe-py — `D:\quantum_safe` @ 0.3.0 (source, CHANGELOG, `docs/production_readiness_rubric.md`)
