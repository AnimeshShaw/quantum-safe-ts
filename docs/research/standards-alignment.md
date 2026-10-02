# Standards alignment and gap analysis

**Scope:** `quantum-safe-ts` (the library only). **Date:** 2026-10-03. **Evidence labels:** **[verified]** = reproduced by a test in this
repository; **[sourced]** = from a cited external page; **[inferred]** = my reasoning, not confirmed by a primary source.

Nothing in this library is, or should be described as, audited, FIPS 140-3 validated, CAVP/CMVP certified, or constant-time. The
purpose of this document is the reverse: to state precisely what the library does and does not satisfy, so claims stay honest.

## 1. Summary

| Area | Verdict |
|---|---|
| NIST FIPS 203 / 204 / 205 algorithms | **Implemented, with conformance evidence** (1,317 NIST ACVP known-answer cases pass). Not CAVP/CMVP validated. |
| FIPS 206 (FN-DSA), HQC | **Not implemented.** Standards are not final (see §2). |
| NIST SP 800-208 / RFC 8554 (LMS) | **Partial.** LMS/HSS *verification* (SHA-256, n=32) only. No signing (by design), no XMSS, no SHAKE/192-bit variants. |
| NSA CNSA 2.0 parameter sets | **Met in the pure-KEM profile** (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM; ML-DSA-87). Hybrid with X25519 is **not** CNSA-conformant. LMS signing/XMSS and FIPS 140-3 validation are **gaps**. |
| NIST SP 800-227 (KEMs) | **X-Wing provided** (the example SP 800-227 itself uses). The quantum-safe-py-compatible combiner has **not** been reviewed against SP 800-227 §5.5.2. |
| IETF | RFC 9964 (JOSE ML-DSA) **implemented**; X-Wing draft **implemented**; TLS hybrids (RFC 10024) **delegated to the platform**; HPKE-PQ, JOSE KEM, composite signatures, LAMPS X.509 **not implemented**. |
| FIPS 140-3 / CMVP | **No.** Not pursued by this project. |

## 2. NIST standards

| Standard | Requirement | Status | Evidence / note |
|---|---|---|---|
| **FIPS 203** (ML-KEM) | ML-KEM-512/768/1024 keygen, encaps, decaps incl. implicit rejection | **Met (algorithms)** | ACVP keyGen 75/75, encap 75/75, decap 30/30 **[verified]**; cross-checked against `@noble/post-quantum` both directions **[verified]**; Node WebCrypto not yet a KEM oracle (Node ≥ 24.7 has one; planned). |
| | Encapsulation/decapsulation **key checks** (§7.2/7.3) | **Partial** | Keys are length-checked and parsed (`EncapsulationKey::new`), but the ACVP `…KeyCheck` groups (60 cases) are **not run** (reported as skipped). |
| **FIPS 204** (ML-DSA) | ML-DSA-44/65/87 | **Met (algorithms)** | ACVP keyGen 75/75, sigGen 180/180, sigVer 90/90 (18 accept, 72 reject) **[verified]**. |
| | HashML-DSA (pre-hash), externalMu | **Not provided** | ACVP groups skipped and counted (270 cases). The quantum-safe-py-compatible signature scheme does not use FIPS 204's native context at all (see COMPATIBILITY.md). |
| **FIPS 205** (SLH-DSA) | All 12 SHA2/SHAKE parameter sets | **Met (algorithms)** | ACVP keyGen 120/120, sigGen 336/336, sigVer 336/336 (48 accept, 288 reject) **[verified]**. HashSLH-DSA groups (456 cases) skipped. |
| **FIPS 206** (FN-DSA/Falcon) | n/a | **Not implemented** | Draft; final expected late 2026–early 2027 **[sourced]**. `fn-dsa` crate is 0.4.0 (pre-standard). Will not ship as "standard" before finalisation. |
| **HQC** (planned FIPS) | n/a | **Not implemented** | Selected March 2025; no Rust crate; standard in progress **[sourced]**. |
| **SP 800-208** (LMS/HSS, XMSS) | Stateful hash-based signatures | **Partial** | `Lms.verify` implements RFC 8554 verification (SHA-256 M32; LM-OTS N32 W1/2/4/8; HSS 1–8 levels). **Verified** against RFC 8554 Appendix F (2/2) and 13 signatures from pyhsslms **[verified]**. No signing: stateful signing is unsafe without a durable atomic state store, and SP 800-208 requires keygen in a validated module. No XMSS. N24/SHAKE variants rejected explicitly. |
| **SP 800-227** (KEM recommendations) | Hybrid ("PQ/T") KEMs must use an approved key combiner; hybrids allowed, not required | **Partial / unreviewed** | X-Wing (SP 800-227's own example) is provided and tested against noble **[verified]**. The compat combiner (HKDF-SHA-256 over `ss_c‖ss_pqc`, salt `ct_c‖ct_pqc`, domain-separated `info`) follows an extract-then-expand shape consistent with SP 800-56C-style two-step derivation, but I have **not** confirmed it against §5.5.2 **[inferred]**. |
| **SP 800-38D** (GCM) | ≤ 2³² invocations per key with random 96-bit IVs | **Met by construction** | Each `seal` derives a fresh AES key from a fresh KEM secret, so a key is used once. |
| **IR 8547** (transition; *draft*) | RSA/ECC deprecated after 2030, disallowed after 2035 | **Informs tooling** | `quantum-safe-audit` flags every RSA/ECDSA/ECDH/EdDSA/DH/DSA use as quantum-vulnerable **[sourced: draft, not final as of mid-2026]**. |
| **SP 800-132 / Argon2** | Password hashing | **Informational** | Argon2id is not NIST-approved (PBKDF2 is). Parameters are the OWASP interactive profile (19 MiB, t=2, p=1), below RFC 9106's first recommended option (2 GiB, t=1, p=4). Chosen for browser feasibility; documented, not claimed as NIST-compliant. |
| **FIPS 140-3 / CMVP / CAVP** | Validated module / algorithm validation | **Not met** | Requires an accredited laboratory. No JavaScript library has CMVP validation **[inferred]**; Bouncy Castle (Java) holds certificate #4943 **[sourced via quantum-safe-py's rubric]**. |

## 3. NSA CNSA 2.0 (algorithm specification, May 2025; FAQ)

| Requirement | Library status | Evidence / note |
|---|---|---|
| Key establishment: **ML-KEM-1024** | **Met** with pure `ML-KEM-1024` | NSA FAQ: hybrid is *allowed, not required*; standalone ML-KEM-1024 satisfies the requirement **[sourced]**. |
| Classical component of a hybrid must be **CNSA 1.0 (ECDH P-384)** | **Gap for hybrids** | `X25519+ML-KEM-1024` is therefore reported as `partial`. P-384 hybrids are **not implemented** (quantum-safe-py names P-384 in its CNSA helper but does not implement it either). |
| Signatures: **ML-DSA-87** | **Met** (`ML-DSA-87`, `Ed25519+ML-DSA-87`) | ACVP ML-DSA-87 included in the 1,317 cases. |
| Symmetric: **AES-256** | **Met** | AES-256-GCM only. |
| Hashing / KDF: **SHA-384 or SHA-512** | **Met for envelope v2; not for the compat suites** | v2 uses HKDF-SHA-384 **[verified]** against Node's `hkdfSync('sha384')` and AES-GCM implemented independently. The quantum-safe-py-compatible combiner and envelope v1 use HKDF-SHA-256 and **cannot** meet this; `cnsa2.report()` says so. |
| Software/firmware signing: **LMS or XMSS** | **Partial** | Verification only (see §2). |
| Compliance for National Security Systems | **Not met** | Requires FIPS 140-3 validated modules / NIAP. Out of reach for this project. |
| Timelines (new NSS acquisitions CNSA 2.0 compliant from 2027-01-01; exclusive use 2030/2033; complete 2035) | Informational | **[sourced]** |

**Honest CNSA statement for the README:** "provides the CNSA 2.0 parameter sets (pure ML-KEM-1024, ML-DSA-87, AES-256-GCM,
HKDF-SHA-384) and reports exactly where a configuration falls short. It is not a validated module and does not make a system
CNSA 2.0 compliant."

## 4. IETF and other specifications

| Specification | Status in this library |
|---|---|
| **RFC 9964** (ML-DSA for JOSE/COSE, May 2026) | **Implemented** as `StandardJwt` (AKP JWK, native-context-free pure ML-DSA). Verified against `@noble/post-quantum` and Node WebCrypto (OpenSSL) **[verified]**. COSE serialization is **not** implemented. |
| **RFC 10024** (hybrid ML-KEM for TLS 1.3, Aug 2026) | **Delegated to the platform** (Node ≥ 24, current browsers negotiate `X25519MLKEM768`). This library does not implement TLS. |
| **X-Wing** (`draft-connolly-cfrg-xwing-kem`, expired draft, widely implemented) | **Implemented**, interoperable with noble's `ml_kem768_x25519` **[verified]**. |
| `draft-ietf-jose-pqc-kem` (ML-KEM for JOSE/COSE) | Not implemented (draft). |
| `draft-ietf-jose-pq-composite-sigs`, composite ML-DSA | Not implemented (draft). |
| IETF LAMPS (ML-DSA/ML-KEM in X.509/CMS), HPKE-PQ | Not implemented. |
| **RFC 9980** (PQ OpenPGP) | Out of scope. |
| **RFC 8554** (LMS) | Verification only (above). |
| **CycloneDX 1.6 CBOM** | Emitted by `quantum-safe-audit`; validated against the official schema **[verified]**. |
| **SARIF 2.1.0** | Emitted by `quantum-safe-audit`; validated against the official schema **[verified]**. |

## 5. National guidance (secondary sources; verify before quoting)

- **BSI (Germany):** recommends hybrid key establishment for data with long confidentiality horizons; AES-256-GCM and SHA-384/512
  accepted **[sourced, secondary]**. The default hybrid here aligns; the CNSA pure-KEM profile is a deliberate NSA-style choice.
- **ANSSI (France):** hybrid in the current phase, possible pure PQC from 2030 **[sourced, secondary]**.
- **NCSC (UK):** discovery and plan by 2028, highest-priority migrations by 2031, complete by 2035 **[sourced, secondary]**. This is
  the case for shipping `quantum-safe-audit`.
- **ASD (Australia):** ML-KEM-1024-class parameters after 2030 **[sourced, secondary]**.

## 6. Findings that need action (ordered)

| # | Finding | Severity | Action |
|---|---|---|---|
| F1 | quantum-safe-py's `cnsa2.hybrid_kem()` returns `X25519+ML-KEM-1024` and reports it CNSA-compliant; per the NSA FAQ the classical half must be P-384 and hybrid is optional | High (misleading compliance claim in a sibling project) | Reported upstream; this library reports it `partial` and offers pure `ML-KEM-1024`. |
| F2 | Compat hybrid combiner and envelope v1 use HKDF-SHA-256: below CNSA 2.0's SHA-384/512 | Medium | Envelope v2 (HKDF-SHA-384) shipped for pure ML-KEM-1024. A SHA-384 *hybrid* suite is possible but needs a P-384 classical half first. |
| F3 | quantum-safe-py's ML-DSA "context" is a message prefix, and its docstring claims FIPS 204 §5.4 consistency | Medium (documentation accuracy; interoperability) | Documented in COMPATIBILITY.md; `StandardJwt` provides the standards-conformant construction. |
| F4 | ML-DSA-87 secret-key size in quantum-safe-py's registry is 4864; actual (liboqs/FIPS 204) is 4896 | Low | Report upstream. |
| F5 | The compat combiner is not X-Wing, not RFC 10024, and has not been reviewed against SP 800-227 §5.5.2 | Medium | Offer X-Wing (done). Seek review before any claim of SP 800-227 alignment. |
| F6 | LMS signing and XMSS absent | Medium (CNSA 2.0 code-signing) | Verification shipped. Signing only with a documented durable-state interface, if ever. |
| F7 | ACVP pre-hash, externalMu, and key-check groups not run (786 cases: 270 ML-DSA, 456 SLH-DSA, 60 ML-KEM) | Low | Implement HashML-DSA/HashSLH-DSA and key-check APIs, or keep them documented as out of scope. |
| F8 | JS/WASM provides no constant-time guarantee; ML-DSA rejection sampling leaks by design (noble documents the same) | Medium | Documented in SECURITY.md. A dudect-style harness on the WASM artifact is planned (Phase 6). |
| F9 | No independent audit; RustCrypto `ml-dsa`/`slh-dsa` state "never independently audited" | High (for any production use) | The mandatory gate before 1.0. |
| F10 | Upstream `ml-dsa` `from_expanded` can panic on malformed keys (observed with random keys) | Medium (fixed here) | Guard validates the packed secret-key regions before decoding; mutation tests and cargo-fuzz cover it. Report upstream. |

## 7. What can be claimed today

- "Implements FIPS 203, 204 and 205 and passes 1,317 NIST ACVP known-answer cases (not a CAVP/CMVP validation)."
- "Byte-compatible with quantum-safe-py in both directions, verified in CI against the real library."
- "Verifies LMS/HSS signatures per RFC 8554, checked against the RFC's vectors and an independent implementation."
- "Provides the CNSA 2.0 parameter sets and reports its own gaps."

What must **not** be claimed: audited; FIPS 140-3/CMVP/CAVP validated; CNSA 2.0 compliant; constant-time; "quantum-proof";
SP 800-227 compliant.

## 8. Sources

- NIST FIPS 203/204/205 (Aug 2024). NIST SP 800-208. NIST SP 800-227 (<https://postquantum.com/quantum-policy/nist-sp-800-227/>).
- NIST IR 8547 ipd (<https://www.encryptionconsulting.com/education-center/nist-ir-8547-sp-800-131a-algorithm-transitions/>).
- NSA CNSA 2.0 algorithms (<https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF>); FAQ summary
  (<https://postquantum.com/security-pqc/nsa-cnsa-2-0-faq-v2-1-update/>, <https://pqaudit.org/timelines/cnsa-2-0/>).
- IETF: RFC 10024 (<https://www.rfc-editor.org/info/rfc10024/>), RFC 9964 (<https://datatracker.ietf.org/doc/rfc9964/>),
  X-Wing draft (<https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>), RFC 8554 (<https://www.rfc-editor.org/rfc/rfc8554>).
- National guidance summaries: <https://blog.quickztna.com/blog/bsi-post-quantum-transition-2026/>,
  <https://www.softwareseni.com/post-quantum-cryptography-compliance-deadlines-and-what-the-global-regulatory-mandates-require/>.
- ACVP-Server vectors, commit `975de31eb83d` (<https://github.com/usnistgov/ACVP-Server>).
