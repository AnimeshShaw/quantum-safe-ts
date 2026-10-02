# Interop with quantum-safe-py

quantum-safe-ts is byte-compatible with [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py) 0.3.0. Data written by one opens in
the other, in both directions, and that is checked in CI against the real Python library (liboqs backend), not a re-implementation.

| Data | Compatible |
|---|---|
| Hybrid KEM keys, ciphertexts, shared secrets (`X25519+ML-KEM-*`, `P-256+ML-KEM-*`) | Yes |
| Envelopes (`Envelope.seal` / `open`, `SealedMessage` CBOR) | Yes |
| Keys: CBOR, PEM, JWK, fingerprints, key-pair bundles | Yes |
| Signatures and `SignedMessage` (`ML-DSA`, SLH-DSA shared sets, hybrids) | Yes |
| JWTs in quantum-safe-py mode | Yes |
| Migration `Upgrader` output and migration store layout | Yes (through converters for the store) |
| `X-Wing`, envelope v2 (CNSA profile), `StandardJwt`, LMS, nine SLH-DSA sets | TypeScript only |

The full table, the wire formats and the known quirks are in
[COMPATIBILITY.md](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/COMPATIBILITY.md).

## Compatible is not the same as standard

Matching quantum-safe-py means matching its own constructions: an HKDF-SHA-256 hybrid key combiner, and an ML-DSA "context" that is a message
prefix signed with an empty FIPS 204 context. They are sound engineering choices but **not** X-Wing, **not** TLS `X25519MLKEM768`, and **not**
FIPS 204's native context, and they have not been reviewed against NIST SP 800-227's key-combiner guidance.

Use the defaults when both ends are quantum-safe-py or quantum-safe-ts. Use `X-Wing` and `StandardJwt` when other ecosystems must read your data.

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
