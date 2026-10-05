# Choosing what to use

The library offers several ways to do each job. This page says which to pick for a given situation and, just as important, when **not** to
use something. It is the answer the maintainers would give you in person.

## The decision in one table

| You want to... | Use | Do not use |
|---|---|---|
| Encrypt data to someone's public key | `Envelope.seal` with a hybrid key (`HybridKEM`, default `X25519+ML-KEM-768`) | `HybridKEM.encapsulate` plus your own AES code |
| Encrypt under the CNSA 2.0 parameter sets | `Envelope.seal` with a pure `ML-KEM-1024` key (envelope v2) via `cnsa2.kem()` | A hybrid key (reported `partial`); `ML-KEM-768` |
| Encrypt data that other ecosystems (not Python) must decrypt | `X-Wing` | The default hybrid (it is its own construction: only Python and this library read it) |
| Encrypt a large file or an upload | `sealStream` / `openStream` (experimental) | `Envelope.seal` on a multi-gigabyte buffer |
| Sign data that only quantum-safe libraries verify | `HybridSign` with a `context` | A signature without a context |
| Sign data that other ecosystems must verify | `Sign('ML-DSA-65-v2')` or `HybridSign('Ed25519+ML-DSA-65-v2')` | The default format (a generic ML-DSA library cannot verify it) |
| Issue tokens your own services verify | `JWTSigner` / `JWTVerifier` | Hand-built tokens |
| Issue tokens that other JOSE libraries must verify | `StandardJwt` (RFC 9964) | `JWTSigner` (only quantum-safe libraries verify it) |
| Move existing keys to post-quantum safely | `Upgrader` plus `MigrationStateManager` | Swapping every key atomically in one deploy |
| Find classical cryptography in a codebase | `quantum-safe-audit scan` in CI | Grep |
| Check a configuration against the CNSA 2.0 parameter sets | `cnsa2.report` and `cnsa2.enforce` | A hybrid suite offered as a compliance claim |

The same decision as code:

```ts test
import { HybridKEM, HybridSign, cnsa2, Envelope, utf8 } from 'quantum-safe-ts';

function encryptionKeys(cnsa2Profile: boolean) {
  // Pure ML-KEM-1024 (envelope v2) for the CNSA 2.0 profile; otherwise the hybrid default.
  return cnsa2Profile ? cnsa2.kem().generateKeyPair() : new HybridKEM().generateKeyPair();
}

function signer(everyVerifierIsPy031OrTs: boolean) {
  // -v2 when every verifier can read it; the default format when an older Python verifier is involved.
  return everyVerifierIsPy031OrTs ? new HybridSign('Ed25519+ML-DSA-65-v2') : new HybridSign();
}

for (const profile of [false, true]) {
  using keys = encryptionKeys(profile);
  const sealed = Envelope.seal(utf8('data'), keys.publicKey);
  if (sealed.version !== (profile ? 2 : 1)) throw new Error('the version is chosen by the key, not by you');
}
for (const modern of [false, true]) {
  const s = signer(modern);
  using kp = s.generateKeyPair();
  const sm = s.sign(utf8('data'), kp.secretKey, { context: utf8('example-v1') });
  s.verify(sm, kp.publicKey, { expectedContext: utf8('example-v1') });
}
```

## Key exchange and encryption

### Hybrid or pure?

**Use hybrid (the default)** for new deployments during the transition. A hybrid such as `X25519+ML-KEM-768` stays secure if *either* of its
two components holds, which is the position NIST, CISA, BSI and NCSC take for the transition period. The price is a few tens of microseconds
and 34 extra bytes of ciphertext and of public key (X25519's 32 bytes plus a 2-byte length).

**Use pure ML-KEM** when a standard or a contract requires it. CNSA 2.0 is the main case: NSA accepts standalone `ML-KEM-1024` and does not
require hybrids (see [CNSA 2.0](/guide/standards)).

**Do not use** pure ML-KEM merely to save bytes. If bandwidth is tight, measure first; the hybrid overhead is small next to a network round
trip.

### Which security level?

| Parameter set | NIST category | Pick it when |
|---|---|---|
| `ML-KEM-512` | 1 | Almost never. Only to interoperate with something that fixes it. |
| `ML-KEM-768` | 3 | The default. Right for most applications. |
| `ML-KEM-1024` | 5 | CNSA 2.0, or long-lived secrets where you want margin. |

### Hybrid, X-Wing, or the Python-compatible hybrid?

| | `X25519+ML-KEM-768` (default) | `X-Wing` |
|---|---|---|
| Readable by | quantum-safe-py and quantum-safe-ts | Other X-Wing implementations (for example `@noble/post-quantum`) and quantum-safe-ts; **not** quantum-safe-py |
| Specified by | quantum-safe-py's own HKDF combiner | `draft-connolly-cfrg-xwing-kem` (an individual Internet-Draft, not an RFC) |
| Reviewed against NIST SP 800-227's combiner guidance | No | Mentioned in SP 800-227 as an example; that is not an endorsement |

If Python is on the other end, take the default. If anyone else is, take `X-Wing`.

### Envelope v1 or v2?

You do not choose a version: `Envelope.seal` picks it from the key. A hybrid key gives **v1** (HKDF-SHA-256). A pure `ML-KEM-1024` key gives
**v2** (HKDF-SHA-384, which is what CNSA 2.0 asks of key derivation). quantum-safe-py 0.3.2 or later reads and writes both.

## Signatures

### Hybrid or pure?

**Use hybrid** (`HybridSign`, `Ed25519+ML-DSA-65`) while classical signatures still carry trust in your ecosystem. Both signatures must
verify.

**Use pure ML-DSA** (`Sign`) for CNSA 2.0 (`ML-DSA-87`) or when size matters more than belt-and-braces. Sizes are fixed by the algorithm:

```ts test
import { Sign, HybridSign, utf8 } from 'quantum-safe-ts';

const message = utf8('size check');
const sizes: Record<string, number> = {};
for (const name of ['ML-DSA-65', 'ML-DSA-65-v2'] as const) {
  const s = new Sign(name);
  using kp = s.generateKeyPair();
  sizes[name] = s.sign(message, kp.secretKey).signature.length;
}
const h = new HybridSign('Ed25519+ML-DSA-65-v2');
using hk = h.generateKeyPair();
sizes['Ed25519+ML-DSA-65-v2'] = h.sign(message, hk.secretKey).signature.length;
console.log(sizes);
// -v2: the ML-DSA-65 signature is 3309 bytes; the hybrid adds a 64-byte Ed25519 signature.
if (sizes['ML-DSA-65-v2'] !== 3309 || sizes['Ed25519+ML-DSA-65-v2'] !== 3309 + 64) throw new Error('unexpected sizes');
// The default format adds a 33-byte hedging prefix (1 length byte + 32 random bytes).
if (sizes['ML-DSA-65'] !== 3309 + 33) throw new Error('unexpected default-format size');
```

### Default format or `-v2`?

| | Default (v1) | `-v2` |
|---|---|---|
| Who can verify | quantum-safe-py (all versions) and quantum-safe-ts | quantum-safe-py **0.3.2 or later** and quantum-safe-ts. A standard FIPS 204 library can verify it only by rebuilding the wrapped message `M2` and passing the context `quantum-safe-sig-v2`. |
| Structure | Hedging prefix and an unsigned length byte, wrapped in CBOR | No prefix; one fixed-length blob |
| Hedging | Your choice (`hedged`); the verifier must match | Always hedged inside ML-DSA; nothing to match |
| What is signed | Context yes; the algorithm no | Algorithm and context, for both halves |
| Available for | Every ML-DSA suite, the hybrids, SLH-DSA | ML-DSA-44/65/87 and the Ed25519 / P-256 hybrids (no SLH-DSA) |

**Recommendation.** For new signatures where every verifier you control is quantum-safe-py 0.3.2+ or quantum-safe-ts, use `-v2`. Keep the
default while an older Python verifier is in the loop. **The default of `easy.generateSigningKeys` and `HybridSign()` stays
`Ed25519+ML-DSA-65` for now, so that existing Python deployments keep verifying; it is planned to flip to `-v2` in the next minor release.**
Choosing `-v2` explicitly today is safe and is the clean choice.

::: warning
Never use the same key material in both formats. The ML-DSA halves are separated by FIPS 204's context, but the classical halves are not.
Generate separate keys for `-v2`.
:::

### Always give signatures a context

A context such as `myapp-release-v1` ties a signature to one purpose. Sign with it and verify with the same value (`expectedContext`), and
a signature made for one purpose cannot be replayed for another.

## Tokens (JWT)

- **`JWTSigner` / `JWTVerifier`**: tokens that only quantum-safe-py and quantum-safe-ts can verify. Supports hybrid keys. Pick it when every
  verifier is yours.
- **`StandardJwt`** (RFC 9964): tokens any compliant JOSE library can verify; pure ML-DSA only. Pick it when other ecosystems, gateways or
  third parties verify your tokens.

**Do not** put a `JWTSigner` token in front of a generic JWT gateway: it will be rejected.

## Migration

`Upgrader` produces a hybrid key that *contains* your classical key, and `MigrationStateManager` tracks each key through
`classical_only → hybrid_transition → pqc_preferred → pqc_only`. An upgraded hybrid key is **not** backward compatible: classical-only
software cannot parse it, so keep publishing the original classical key to such clients during the transition. Give the manager a store
with `compareAndSet` whenever more than one process shares it ([Migration](/guide/migration)).

## When this library is not the right tool

Being straightforward about limits is part of being safe to adopt.

- **You need a validated module.** It is not FIPS 140-3 validated and is not a CAVP or CMVP result. The ACVP known-answer tests it passes are
  evidence, not validation. If a procurement rule needs a certificate, use a validated module.
- **You need stateful hash-based signing** (LMS or XMSS, for firmware signing under CNSA 2.0). Only LMS *verification* is provided. Signing
  needs durable state and is deliberately left out.
- **You need constant-time guarantees.** JavaScript and WebAssembly runtimes give none ([security model](/guide/security)). Use a native
  implementation in a hardened environment if a local timing attacker is in your threat model.
- **You need to run on constrained or embedded devices.** The WebAssembly is about 410 KiB gzipped. Use liboqs, mlkem-native or a vendor SDK
  there.
- **You need a formally verified implementation.** It builds on RustCrypto crates that state they are not independently audited, and nobody
  has audited this layer yet.
- **You only need a primitive** and the platform already has it (recent Node.js and some browsers expose ML-KEM and ML-DSA in WebCrypto). A
  smaller dependency is better; see [Which library should I use?](/compare).
