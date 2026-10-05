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

## Reading a report

`cnsa2.report()` returns one check per requirement, each with a `finding` of `compliant`, `partial`, `non-compliant` or `not-covered`, the value
it expected and the value it saw. `report.compliant` is true only when every checked requirement is `compliant`. `report.failures` lists the
rest, and `report.render()` prints a table for humans.

```ts test
import { cnsa2 } from 'quantum-safe-ts';

const good = cnsa2.report({ kem: 'ML-KEM-1024', signature: 'ML-DSA-87', hashAlgorithm: 'sha384', includeCodeSigning: false });
if (!good.compliant || good.failures.length !== 0) throw new Error('the pure CNSA 2.0 parameter sets must pass');
console.log(good.render());

// A hybrid is `partial` (the parameter set is right, but a hybrid is outside what CNSA 2.0 prescribes); SHA-256 is below the hash requirement.
const mixed = cnsa2.report({ kem: 'X25519+ML-KEM-1024', signature: 'ML-DSA-87', hashAlgorithm: 'sha256' });
const byName = Object.fromEntries(mixed.checks.map((c) => [c.requirement, c.finding]));
if (byName['Key establishment'] !== 'partial' || byName['Hashing'] !== 'non-compliant' || mixed.compliant) throw new Error('unexpected findings');
```

`includeCodeSigning: false` leaves out the software and firmware signing row (CNSA 2.0 asks for LMS or XMSS there, and this library only
verifies LMS). Without it that row is reported `partial`, so the report is never `compliant` for a system that signs firmware.

## Why a hybrid is `partial`

NSA's CNSA 2.0 FAQ (December 2024, Ver. 2.1) says NSA does not require hybrid products for security purposes, and that a hybrid should not be used
on National Security System mission systems except for exceptions NSA specifically recommends (the one it names is IKEv2). So `X25519+ML-KEM-1024` has
the right ML-KEM parameter set but is not what CNSA 2.0 prescribes, and the library says so instead of calling it compliant. Pure `ML-KEM-1024`
and `ML-DSA-87` are the compliant selections. quantum-safe-py (0.3.1+) reports hybrids the same way.

## Configuring a service for the CNSA 2.0 parameter sets

```ts test
import { cnsa2, Envelope, Sign, utf8 } from 'quantum-safe-ts';

const kem = cnsa2.kem();                              // pure ML-KEM-1024
const signer = new Sign('ML-DSA-87');                 // pure ML-DSA-87
cnsa2.enforce({ kem: kem.algorithm, signature: signer.algorithm }, { strict: true });

using enc = kem.generateKeyPair();
const sealed = Envelope.seal(utf8('classified-style payload'), enc.publicKey);
if (sealed.version !== 2) throw new Error('pure ML-KEM-1024 produces envelope v2 (HKDF-SHA-384)');

using sig = signer.generateKeyPair();
const signed = signer.sign(utf8('payload'), sig.secretKey, { context: utf8('svc-v1') });
signer.verify(signed, sig.publicKey, { expectedContext: utf8('svc-v1') });
```

## Guarding a service at start-up or in CI

`cnsa2.enforce` throws `PolicyViolationError` when a configuration is below the parameter sets, so a mis-set environment variable cannot
quietly weaken a deployment. By default it checks the post-quantum half; `strict: true` also rejects `partial` hybrids.

```ts test
import { cnsa2, PolicyViolationError } from 'quantum-safe-ts';

function assertPolicy(config: { kem: string; signature: string }): void {
  cnsa2.enforce(config, { strict: true });
}

assertPolicy({ kem: 'ML-KEM-1024', signature: 'ML-DSA-87' });                   // passes
let refused = 0;
for (const bad of [
  { kem: 'ML-KEM-768', signature: 'ML-DSA-87' },                                // below ML-KEM-1024
  { kem: 'ML-KEM-1024', signature: 'Ed25519+ML-DSA-65' },                      // below ML-DSA-87
  { kem: 'X25519+ML-KEM-1024', signature: 'ML-DSA-87' },                        // a hybrid is partial under strict
  { kem: 'RSA-1024+ML-KEM-1024', signature: 'ML-DSA-87' },                      // not a name this library implements
]) {
  try { assertPolicy(bad); } catch (e) { if (e instanceof PolicyViolationError) refused++; else throw e; }
}
if (refused !== 4) throw new Error(`expected 4 refusals, got ${refused}`);
```

Pair it with the [audit tool](/tools/audit) (`--cnsa2` reports SHA-256 where CNSA 2.0 applies) and the [GitHub Action](/tools/github-action).

## What the profile does not cover

Selecting parameters is necessary and **not sufficient**: no software library makes a system CNSA 2.0 compliant. Missing here: LMS or XMSS
signing for software and firmware, a FIPS 140-3 validated module, SHA-384/512 key derivation for the hybrid and v1 envelope formats (they use
HKDF-SHA-256 for byte-compatibility), and everything outside this library (protocols, key management, platform).

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
