# CNSA 2.0 and standards alignment

**Nothing here makes a system CNSA 2.0, FIPS 140-3 or SP 800-227 compliant.** This page states what the library implements, what it
tests, and where it falls short, so you can make an informed decision. Evidence labels: **verified** means reproduced by a test in this
repository; **sourced** means from a cited external document.

## Summary

| Area | Status |
|---|---|
| NIST FIPS 203 / 204 / 205 algorithms | Implemented, with conformance evidence: 1,317 NIST ACVP known-answer cases pass. Not CAVP/CMVP validated. |
| FIPS 206 (FN-DSA), HQC | Not implemented. The standards are not final. |
| NIST SP 800-208 / RFC 8554 (LMS) | Partial: HSS/LMS **verification** only (SHA-256). No signing, no XMSS. |
| NSA CNSA 2.0 parameter sets | The pure-KEM profile meets them (ML-KEM-1024, HKDF-SHA-384, AES-256-GCM; ML-DSA-87). Hybrids with X25519 are **not** CNSA-conformant. |
| NIST SP 800-227 | X-Wing provided (SP 800-227 mentions it as an example of a hybrid KEM; that is not an endorsement). The quantum-safe-py-compatible combiner has not been reviewed against its key-combiner guidance. |
| IETF | RFC 9964 (ML-DSA for JOSE) implemented. X-Wing implemented. TLS hybrids (RFC 10024) are left to the platform. |
| FIPS 140-3 / CMVP | Not met and not pursued. |

## Using the CNSA 2.0 profile

```ts test
import { cnsa2 } from 'quantum-safe-ts';

const report = cnsa2.report({ kem: 'X25519+ML-KEM-768', signature: 'Ed25519+ML-DSA-65' });
if (report.compliant) throw new Error('the defaults are below CNSA 2.0');

const kem = cnsa2.kem();              // pure ML-KEM-1024: Envelope.seal then produces envelope v2 (HKDF-SHA-384)
cnsa2.enforce({ kem: kem.algorithm, signature: 'ML-DSA-87' }, { strict: true }); // throws PolicyViolationError below the parameter sets; strict also rejects 'partial' hybrids (the default only checks the post-quantum half)
```

CNSA 2.0 requires ML-KEM-1024, ML-DSA-87, AES-256, SHA-384 or SHA-512, and LMS or XMSS for software and firmware signing. Picking the
parameter sets is necessary and **not sufficient**. Known gaps, reported by `cnsa2.report()`:

1. A hybrid is outside what CNSA 2.0 prescribes, so `X25519+ML-KEM-1024` reports `partial`. NSA's CNSA 2.0 FAQ (Dec 2024, Ver. 2.1) says hybrid products are not required and a hybrid should not be used on NSS mission systems except for exceptions NSA specifically recommends (it names IKEv2). Pure ML-KEM-1024 satisfies the
   key-establishment requirement. quantum-safe-py (0.3.1+) reports hybrids the same way.
2. The quantum-safe-py-compatible combiner and envelope v1 use HKDF-SHA-256, below the SHA-384/512 requirement. Envelope v2 uses HKDF-SHA-384
   (verified against independent HKDF and AES-GCM implementations, and against quantum-safe-py 0.3.1+ in both directions).
3. LMS is verification-only and XMSS is absent.
4. Compliance for National Security Systems runs through FIPS 140-3 validated modules. This library is not one.

## NIST

| Standard | Status | Evidence |
|---|---|---|
| FIPS 203 (ML-KEM) | Algorithms met | ACVP keyGen 75/75, encap 75/75, decap 30/30; cross-checked against `@noble/post-quantum` in both directions. Encapsulation/decapsulation key-check groups (60 cases) are not run. |
| FIPS 204 (ML-DSA) | Algorithms met | ACVP keyGen 75/75, sigGen 180/180, sigVer 90/90. HashML-DSA and externalMu are not provided. |
| FIPS 205 (SLH-DSA) | Algorithms met, all 12 parameter sets | ACVP keyGen 120/120, sigGen 336/336, sigVer 336/336. HashSLH-DSA is not provided. |
| SP 800-208 | Partial | LMS/HSS verification checked against RFC 8554 Appendix F and 13 signatures from an independent implementation. |
| SP 800-227 | Partial | SP 800-227 mentions X-Wing as an example hybrid KEM (not an endorsement). The compatible combiner is unreviewed. |
| SP 800-38D (GCM) | Designed to stay within its limits | Every `seal` derives a fresh AES key from a fresh KEM secret, so a key encrypts once. |
| FIPS 140-3 / CMVP / CAVP | Not met | Needs an accredited laboratory. |

## IETF and others

| Specification | Status |
|---|---|
| RFC 9964, ML-DSA for JOSE | Implemented as `StandardJwt`, verified against `@noble/post-quantum` and Node WebCrypto. COSE serialisation is not implemented. |
| RFC 10024, TLS 1.3 hybrids | Delegated to the platform. This library does not implement TLS. |
| X-Wing (`draft-connolly-cfrg-xwing-kem`) | Implemented, interoperable with noble's `ml_kem768_x25519`. |
| JOSE KEM drafts, composite signatures, LAMPS X.509/CMS, HPKE-PQ | Not implemented. |
| CycloneDX 1.6 CBOM, SARIF 2.1.0 | Emitted by `quantum-safe-audit`, validated against the official schemas. |

## What you can and cannot say

You can say: implements the pure (non-pre-hash) algorithms of FIPS 203, 204 and 205 and passes 1,317 NIST ACVP cases for them (not a CAVP/CMVP validation; HashML-DSA, HashSLH-DSA, external-mu and the ML-KEM key-check groups are not provided); byte-compatible with
quantum-safe-py in both directions; provides the CNSA 2.0 parameter sets and reports its own gaps.

Do not say: audited; FIPS 140-3 validated; CNSA 2.0 compliant; constant-time; quantum-proof; SP 800-227 compliant.
