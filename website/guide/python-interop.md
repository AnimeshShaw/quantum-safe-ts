# Interop with quantum-safe-py

quantum-safe-ts is byte-compatible with [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py) 0.3.0, and with 0.3.2 or later for
the additional formats marked below (they first appeared in 0.3.1). Data written by one opens in the other, in both directions. That is checked in CI against the **real
Python library** (liboqs backend), not a re-implementation: the fixtures are produced by Python and verified here, and produced here and
verified by Python.

:::tip Which Python version
Use quantum-safe-py **0.3.2 or later** (`pip install "quantum-safe-py>=0.3.2"`). Version 0.3.1 fixed a signature-verification flaw in Python
0.1.0 to 0.3.0 (see [Security](/guide/security)) and added the formats marked "0.3.2+" below; 0.3.2 added `Sign.sign_raw()` and a standard
`Sign.verify_raw()`. The vectors in this repository's tests were checked against the released 0.3.2.
:::

## What crosses

| Data | Compatible |
|---|---|
| Hybrid KEM ciphertexts (`X25519+ML-KEM-*`, `P-256+ML-KEM-*`) and pure ML-KEM | Yes |
| `SealedMessage` envelopes (v1, hybrid) | Yes |
| Keys: CBOR, PEM, public-key JWK, fingerprints, `KeyPair` bundles | Yes, byte for byte |
| Signatures and `SignedMessage` (`ML-DSA`, SLH-DSA shared sets, hybrids), default format | Yes |
| JWTs in quantum-safe-py mode | Yes |
| Migration `Upgrader` output and migration store layout | Yes (through converters for the store) |
| Envelope v2 (CNSA profile: pure `ML-KEM-1024`, HKDF-SHA-384) | Yes, with quantum-safe-py 0.3.2+ |
| Signature format `-v2` (all eight identifiers) | Yes, with quantum-safe-py 0.3.2+ |
| `StandardJwt` (RFC 9964) tokens and public `AKP` JWKs | Yes, with quantum-safe-py 0.3.2+. Private JWKs (`priv` is a seed) are TypeScript only: liboqs cannot derive a Python key from a seed |
| `X-Wing`, streaming encryption, LMS signing, nine SLH-DSA sets | TypeScript only |

Python 0.3.0 fails closed on the identifiers it does not know (it never mis-verifies). The full table, the wire formats and the known quirks
are in [COMPATIBILITY.md](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/COMPATIBILITY.md).

## Compatible is not the same as standard

Matching quantum-safe-py means matching its own constructions: an HKDF-SHA-256 hybrid key combiner, and an ML-DSA "context" that is a message
prefix signed under an empty FIPS 204 context. They are sound engineering choices, but they are **not** X-Wing, **not** the TLS
`X25519MLKEM768` group and **not** FIPS 204's native context, and they have not been reviewed against NIST SP 800-227's key-combiner guidance.

| Your situation | Use |
|---|---|
| Both ends are quantum-safe-py or quantum-safe-ts | The defaults, or `-v2` for new signatures |
| The other side is a standard FIPS 204 ML-DSA implementation, and you need a signature over your own bytes | Python: `Sign.sign_raw()` / `Sign.verify_raw()` (0.3.2). TypeScript: not in the public API yet (see below) |
| A JOSE or JWT library must read the token | `StandardJwt` (RFC 9964), in both libraries |
| The other side is a third-party X-Wing or TLS-hybrid implementation | Use `X-Wing` for KEMs. quantum-safe-py envelopes (HKDF-SHA-256 combiner) cannot be read by them |

What each signature format is, exactly:

- **Default (v1):** signs `len(ctx) ‖ ctx ‖ prefix ‖ message` under an empty FIPS 204 context, in a library-specific blob. A standard library cannot verify it.
- **`-v2`:** signs `M2 = len(algo) ‖ algo ‖ len(ctx) ‖ ctx ‖ message` under the FIPS 204 context `quantum-safe-sig-v2`. A standard library could verify it
  only by rebuilding `M2` and passing that context. `-v2` is for quantum-safe-py and quantum-safe-ts.
- **Standard ML-DSA:** `ML-DSA.Sign(sk, message, ctx)` with the native context and the bare signature. Python 0.3.2 makes and checks it with
  `sign_raw` / `verify_raw`; before 0.3.2, `verify_raw` rejected every standard signature.

In TypeScript the bare FIPS 204 primitive exists in the core (it is what `StandardJwt` uses) but is not a public function. It is tested against
Python's `sign_raw` and `verify_raw` for ML-DSA-44, 65 and 87 with empty, short and 255-byte contexts, in both directions, and a public
`signRaw` / `verifyRaw` is a [roadmap](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/ROADMAP.md) item. Until then use `StandardJwt` or `-v2`.

## Settings that must match across the two libraries

The verifiers state what they expect, in both libraries. A mismatch fails closed, with no detail about why.

| What | quantum-safe-ts | quantum-safe-py (0.3.2+) |
|---|---|---|
| Signature context | `verify(signed, pub, { expectedContext })` | `verify(sm, pub, context=...)` |
| Hedging mode of v1 signatures | `new Sign(algo, { hedged })` (default `true`) | `Sign(algo, hedged=...)`, `JWTVerifier(..., hedged=)`, `verify_cosig(..., hedged=)` |
| Envelope AAD | `Envelope.open(sealed, sk, { expectedAad })` | `Envelope.open(sealed, sk, expected_aad=...)` |

A signature made with `hedged: false` verifies only on a verifier built with `hedged: false`; the prefix length is not covered by the
signature, so a verifier requires the one its own mode produces. `-v2` signatures have no hedging mode.

## Worked round trip, TypeScript to Python

TypeScript signs with the clean format, encrypts to a key the Python side published, and writes the bytes. (The key PEMs in this example are
generated on the spot to show the shape; in reality the Python side generates its key and publishes only the public PEM.)

```ts test
import { Envelope, HybridKEM, HybridSign, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using signing = signer.generateKeyPair();
const signed = signer.sign(utf8('hello from TypeScript'), signing.secretKey, { context: utf8('interop-v1') });

using pythonKey = new HybridKEM().generateKeyPair();
const sealed = Envelope.seal(utf8('secret for Python'), pythonKey.publicKey, { aad: utf8('interop-v1') });

const files = {
  'ts-signing-public.pem': signing.publicKey.toPem(),        // text
  'ts-signed.bin': signed.toBytes(),                          // CBOR SignedMessage
  'ts-sealed.bin': sealed.toBytes(),                          // CBOR SealedMessage
};
console.log(Object.fromEntries(Object.entries(files).map(([name, v]) => [name, typeof v === 'string' ? `${v.length} chars` : `${v.length} bytes`])));
if (typeof files['ts-signing-public.pem'] !== 'string' || files['ts-signed.bin'].length < 3000 || files['ts-sealed.bin'].length < 1100) throw new Error('unexpected sizes');
```

Python then reads them, stating the context and AAD it expects (verified with quantum-safe-py 0.3.2; the files are the ones the block above
writes, plus the secret PEM of the key it encrypted to):

```python
from quantum_safe import HybridSign
from quantum_safe.types import PublicKey, SecretKey
from quantum_safe.types.signatures import SignedMessage
from quantum_safe.protocols.envelope import Envelope, SealedMessage

pub = PublicKey.from_pem(open("ts-signing-public.pem").read())
sm = SignedMessage.from_cbor(open("ts-signed.bin", "rb").read())
HybridSign("Ed25519", "ML-DSA-65-v2").verify(sm, pub, context=b"interop-v1")   # raises unless valid
print(sm.message)                                                               # b'hello from TypeScript'

sk = SecretKey.from_pem(open("py-encryption-secret.pem").read())
print(Envelope.open(SealedMessage.from_bytes(open("ts-sealed.bin", "rb").read()), sk, expected_aad=b"interop-v1"))
```

## Worked round trip, Python to TypeScript

Python signs and encrypts to a public key the TypeScript side published:

```python
from quantum_safe import HybridSign
from quantum_safe.types import PublicKey
from quantum_safe.protocols.envelope import Envelope

signer = HybridSign("Ed25519", "ML-DSA-65-v2")
kp = signer.generate_keypair()
sm = signer.sign(b"hello from Python", kp.secret, context=b"interop-v1")
open("py-signing-public.pem", "w").write(kp.public.to_pem())
open("py-signed.bin", "wb").write(sm.to_cbor())

ts_pub = PublicKey.from_pem(open("ts-encryption-public.pem").read())      # published by the TypeScript side
open("py-sealed.bin", "wb").write(Envelope.seal(b"secret for TypeScript", ts_pub, aad=b"interop-v1").to_bytes())
```

TypeScript reads them (a Node.js example, verified against the files the Python above writes; it is marked `no-run` only because it needs
those files):

```ts no-run
import { readFileSync } from 'node:fs';
import { Envelope, HybridSign, PublicKey, SecretKey, SignedMessage, utf8 } from 'quantum-safe-ts';

const pub = PublicKey.fromPem(readFileSync('py-signing-public.pem', 'utf8'));
const signed = SignedMessage.fromBytes(readFileSync('py-signed.bin'));
new HybridSign('Ed25519+ML-DSA-65-v2').verify(signed, pub, { expectedContext: utf8('interop-v1') });
console.log(new TextDecoder().decode(signed.message));                                   // hello from Python

using sk = SecretKey.fromPem(readFileSync('ts-encryption-secret.pem', 'utf8'));
const plain = Envelope.open(readFileSync('py-sealed.bin'), sk, { expectedAad: utf8('interop-v1') });
console.log(new TextDecoder().decode(plain));                                            // secret for TypeScript
```

Real bytes from the Python library, kept in the repository and checked in CI: `tests/vectors/py_v2_vectors.json` (Python-made: envelope v2, all
eight `-v2` identifiers, `StandardJwt` tokens) and `tests/vectors/ts_v2_vectors.json` (TypeScript-made, verified by Python through
`scripts/verify_ts_vectors.py` and by quantum-safe-py's own `tests/interop`).

## Choosing formats when both libraries are in play

| Situation | Use |
|---|---|
| Both ends are quantum-safe-py 0.3.2+ or quantum-safe-ts, new signatures | `-v2` |
| A Python 0.3.0 verifier is in the loop | The default format, with matching `hedged` |
| Encrypting between the two | Hybrid envelopes (v1). For the CNSA 2.0 profile, pure `ML-KEM-1024` (v2) |
| Tokens that only your own services verify | `JWTSigner` / `JWTVerifier` on both sides |
| Tokens other parties verify | `StandardJwt` (Python 0.3.2+ and TypeScript) |
| Moving migration state | `exportToPyStore` / `importFromPyStore` ([Migration](/guide/migration#moving-state-to-or-from-quantum-safe-py)) |

## When interop fails

| Symptom | Cause | Fix |
|---|---|---|
| `VerificationError` on a signature the other side made | Different context, or a different hedging mode (default format) | Same context on both ends; same `hedged`; or use `-v2` |
| `UnsupportedAlgorithmError` / Python `UnsupportedAlgorithm` for `...-v2` | The Python side is 0.3.0 | Upgrade Python to 0.3.2+, or use the default format |
| `DecryptionAuthenticationError` on an envelope | Different AAD, wrong key, or modified bytes | Same AAD on both ends |
| Envelope v2 cannot be opened by Python | Python is 0.3.0 | Upgrade, or use a hybrid key |
| `KeyParseError` on a key from Python | A secret key presented as public, or a damaged PEM | Export the right half; copy the PEM whole |
| A private JWK from Python | Not supported across languages | Use PEM/CBOR keys, or `StandardJwt` public JWKs and tokens |
