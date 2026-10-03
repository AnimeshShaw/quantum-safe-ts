# Signatures

```ts test
import { HybridSign, Sign, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign('Ed25519+ML-DSA-65');
using pair = signer.generateKeyPair();
const signed = signer.signWithFingerprint(utf8('contract v3'), pair, { context: utf8('myapp-v1-docs') });
signer.verify(signed, pair.publicKey, { expectedContext: utf8('myapp-v1-docs') }); // throws VerificationError unless BOTH signatures verify AND the context matches

const tampered = Uint8Array.from(signed.message, (b, i) => (i === 0 ? b ^ 1 : b));
try {
  signer.verifyBytes(tampered, signed.signature, pair.publicKey, { context: utf8('myapp-v1-docs') });
  throw new Error('should not verify');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}

const pure = new Sign('ML-DSA-87', { hedged: true });
using p2 = pure.generateKeyPair();
if (!pure.isValid(pure.sign(utf8('x'), p2.secretKey), p2.publicKey)) throw new Error('unexpected');
```

## What to know

- A **hybrid** signature carries a classical and a post-quantum signature, and **both** must verify.
- **Context** is a domain-separation label (at most 255 bytes) that is part of what is signed. Use a different one per purpose
  (`myapp-v1-docs`, `myapp-v1-login`) so a signature made for one purpose cannot be replayed for another.
- `verify` throws `VerificationError` with a fixed message and no detail about why it failed.
- **Pass the context you expect** (`{ expectedContext }`, default empty). The message carries its own context, but an attacker can choose that, so the verifier never trusts it.
- **The verifier's `hedged` setting must match the signer's** (default `true`: a 32-byte random prefix; `{ hedged: false }` for signatures made without hedging). The signed bytes are
  `len(ctx) ‖ ctx ‖ prefix ‖ message` and the prefix length sits in the *unsigned* signature blob, so a verifier that accepted any length would let anyone move bytes between the prefix and the
  message and forge a signature on a suffix of a signed message. Pinning the length per mode closes that; it does not change any bytes on the wire.
- Hedged signing (extra randomness) is the default, as in quantum-safe-py. Pass `{ hedged: false }` for deterministic signatures.
- `SignedMessage` is self-contained (`message`, `signature`, `algorithm`, `context`, `signerFingerprint`, `signedAt`). The fingerprint and
  timestamp are metadata and are **not** covered by the signature.

## Algorithms

| Name | Notes |
|---|---|
| `Ed25519+ML-DSA-44/65/87`, `P-256+ML-DSA-44/65` | Hybrid. Default `Ed25519+ML-DSA-65`. Byte-compatible with quantum-safe-py. |
| `ML-DSA-44/65/87` | FIPS 204. `ML-DSA-87` is the CNSA 2.0 level. |
| `SLH-DSA-*` (12 parameter sets) | FIPS 205, hash-based. Large signatures, conservative assumptions. |
| LMS / HSS | **Verification only** (`Lms`), per RFC 8554. Signing needs durable state and is intentionally not provided. |

## Format v2 (`-v2`): the cleaner format, TypeScript only

Every ML-DSA and hybrid suite also exists as `<name>-v2` (`ML-DSA-65-v2`, `Ed25519+ML-DSA-65-v2`, ...). It removes the structure that makes the quantum-safe-py construction delicate:

- **No prefix, no unsigned length byte.** There is no boundary between "prefix" and "message" to move, and no `hedged` setting to get wrong. The blob is the signature itself, in one fixed-length encoding.
- **Plain FIPS 204 for the ML-DSA half.** It signs `M2` with the native context `quantum-safe-sig-v2`, so any FIPS 204 library (noble, Node WebCrypto) verifies it given `M2`. Signing is always hedged inside ML-DSA.
- **Algorithm and context are signed.** `M2 = len(algo) ‖ algo ‖ len(ctx) ‖ ctx ‖ message`, and both halves of a hybrid sign the same bytes (the classical half signs `label ‖ 0x00 ‖ M2`).
- **One encoding.** Hybrid blob = classical signature (64 bytes) ‖ ML-DSA signature; P-256 signatures are raw `r ‖ s` and the high-S twin is refused.
- **Keys are tagged `-v2`**, and the library refuses a v1 key in a v2 signer and the reverse. The tag is metadata, though: v1 and v2 keys have identical bytes, so **never use the same key material in both formats** (the ML-DSA halves are separated by FIPS 204's context; the classical halves are not). Generate new keys for v2.
- The `SignedMessage` container is the same CBOR as in v1 and is not canonical; the signature blob and the verified message are not malleable, but do not use a hash of the container as an identity.

```ts test
import { HybridSign, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using pair = signer.generateKeyPair();
const signed = signer.sign(utf8('release 1.2.3'), pair.secretKey, { context: utf8('myapp-v1-release') });
signer.verify(signed, pair.publicKey, { expectedContext: utf8('myapp-v1-release') });
let rejected = false;
try { signer.verify(signed, pair.publicKey); } catch (e) { rejected = e instanceof VerificationError; } // wrong (empty) context
if (!rejected) throw new Error('context must be enforced');
```

quantum-safe-py cannot read v2. It has no SLH-DSA v2. Use v1 when Python must verify; use v2 otherwise. `JWTSigner`/`JWTVerifier` accept v2 keys too.

## Compatibility note

quantum-safe-py's "context" is a message prefix (`len(ctx) ‖ ctx ‖ random ‖ message`) signed with an *empty* FIPS 204 context. A generic
ML-DSA verifier will not accept these signatures unless it rebuilds that input. For signatures other implementations must verify, use
[`StandardJwt`](/guide/jwt) (RFC 9964) or pure ML-DSA through your own framing.
