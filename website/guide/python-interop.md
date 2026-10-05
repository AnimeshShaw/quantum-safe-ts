# Interop with quantum-safe-py

quantum-safe-ts is byte-compatible with [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py) 0.3.0, and with 0.3.1 and later for
the additional formats marked below. Data written by one opens in the other, in both directions, and that is checked in CI against the real Python
library (liboqs backend), not a re-implementation.

| Data | Compatible |
|---|---|
| Hybrid KEM keys, ciphertexts, shared secrets (`X25519+ML-KEM-*`, `P-256+ML-KEM-*`) | Yes |
| Envelopes (`Envelope.seal` / `open`, `SealedMessage` CBOR) | Yes |
| Keys: CBOR, PEM, JWK, fingerprints, key-pair bundles | Yes |
| Signatures and `SignedMessage` (`ML-DSA`, SLH-DSA shared sets, hybrids) | Yes |
| JWTs in quantum-safe-py mode | Yes |
| Migration `Upgrader` output and migration store layout | Yes (through converters for the store) |
| Envelope v2 (CNSA profile: pure `ML-KEM-1024`, HKDF-SHA-384) | Yes, with quantum-safe-py 0.3.1+ |
| Signature format `-v2` (all eight identifiers) | Yes, with quantum-safe-py 0.3.1+ |
| `StandardJwt` (RFC 9964) tokens and public `AKP` JWKs | Yes, with quantum-safe-py 0.3.1+. Private JWKs (`priv` is a seed) are TypeScript only: liboqs cannot derive a Python key from a seed |
| `X-Wing`, streaming encryption, LMS signing, nine SLH-DSA sets | TypeScript only |

The full table, the wire formats and the known quirks are in
[COMPATIBILITY.md](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/COMPATIBILITY.md).

## Compatible is not the same as standard

Matching quantum-safe-py means matching its own constructions: an HKDF-SHA-256 hybrid key combiner, and an ML-DSA "context" that is a message
prefix signed with an empty FIPS 204 context. They are sound engineering choices but **not** X-Wing, **not** TLS `X25519MLKEM768`, and **not**
FIPS 204's native context, and they have not been reviewed against NIST SP 800-227's key-combiner guidance.

Use the defaults when both ends are quantum-safe-py or quantum-safe-ts. Use `X-Wing`, `StandardJwt` and the `-v2` signatures when other ecosystems must read your data (`-v2` needs an ML-DSA verifier that supplies the native context `quantum-safe-sig-v2`).

## Settings that must match across the two libraries

The verifiers state what they expect, in both libraries:

| What | quantum-safe-ts | quantum-safe-py |
|---|---|---|
| Signature context | `verify(signed, pub, { expectedContext })` | `verify(sm, pub, context=...)` |
| Hedging mode of v1 signatures | `new Sign(algo, { hedged })` (default `true`) | `Sign(algo, hedged=...)`, `JWTVerifier(..., hedged=)`, `verify_cosig(..., hedged=)` |
| Envelope AAD | `Envelope.open(sealed, sk, { expectedAad })` | `Envelope.open(sealed, sk, expected_aad=...)` |

A signature made with `hedged: false` verifies only on a verifier built with `hedged: false`; the prefix length is not covered by the signature, so a verifier
requires the one its own mode produces. `-v2` signatures have no hedging mode.

## Example

Python:

```python
from quantum_safe import HybridKEM
from quantum_safe.protocols.envelope import Envelope

kem = HybridKEM()                       # X25519+ML-KEM-768
kp = kem.generate_keypair()
sealed = Envelope.seal(b"hello from python", kp.public, aad=b"demo")
open("sealed.bin", "wb").write(sealed.to_bytes())
open("secret.cbor", "wb").write(kp.secret.to_cbor())
```

TypeScript:

```ts
import { readFileSync } from 'node:fs';
import { Envelope, SealedMessage, SecretKey } from 'quantum-safe-ts';

const secret = SecretKey.fromCbor(readFileSync('secret.cbor'));
const plain = Envelope.open(SealedMessage.fromBytes(readFileSync('sealed.bin')), secret);
console.log(new TextDecoder().decode(plain)); // hello from python
```
