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

## Compatibility note

quantum-safe-py's "context" is a message prefix (`len(ctx) ‖ ctx ‖ random ‖ message`) signed with an *empty* FIPS 204 context. A generic
ML-DSA verifier will not accept these signatures unless it rebuilds that input. For signatures other implementations must verify, use
[`StandardJwt`](/guide/jwt) (RFC 9964) or pure ML-DSA through your own framing.
