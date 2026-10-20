# COSE_Sign1 (RFC 9964, the COSE half)

`cose.sign1` and `cose.verify1` sign and verify **COSE_Sign1** messages with ML-DSA: the CBOR counterpart of a compact JWS, used by CBOR Web
Tokens, WebAuthn and many IoT and attestation formats. [`StandardJwt`](/guide/jwt) is the JOSE half of the same RFC.

**Use it** when a CBOR/COSE system must verify your signature (or you must verify theirs). **Do not use it** between two quantum-safe
services that only need to exchange signed data: [`Sign` with a context](/guide/signatures) is simpler.

## A complete example

```ts test
import { Sign, VerificationError, cose, utf8 } from 'quantum-safe-ts';

const signer = new Sign('ML-DSA-65');                 // ML-DSA-44, -65 or -87 (COSE algorithms -48, -49, -50)
using pair = signer.generateStandardKeyPair();        // a 32-byte seed and the FIPS 204 public key

const message = cose.sign1(utf8('hello'), pair, { kid: utf8('key-1'), externalAad: utf8('myapp-v1') });
const payload = cose.verify1(message, pair.publicKey, { externalAad: utf8('myapp-v1') });
if (new TextDecoder().decode(payload) !== 'hello') throw new Error('payload changed');

try {
  cose.verify1(message, pair.publicKey);              // the external AAD is part of what was signed
  throw new Error('should have been refused');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}

const info = cose.inspectSign1(message);              // facts without a key
if (info.algorithm !== 'ML-DSA-65' || info.coseAlg !== -49) throw new Error('unexpected header');
```

## What it signs

`Sig_structure = ["Signature1", protected, external_aad, payload]` (RFC 9052), signed with plain FIPS 204 `ML-DSA.Sign` and the **empty**
context, the same operation as [`Sign.signRaw`](/guide/signatures#standard-fips-204-signatures). Any compliant COSE library verifies the result.
RFC 9964's own Appendix A examples (all three levels) are in this library's tests: its signatures verify, its signed bytes are reproduced
byte for byte, and its all-zero seed derives its public key.

## Options

| Option | Effect |
|---|---|
| `kid` | Key identifier, placed in the protected header |
| `externalAad` | Application data that is signed but not carried; the verifier must pass the same value |
| `tagged: false` | Omit CBOR tag 18 (the default is tagged) |
| `detached: true` | Leave the payload out; the verifier passes `detachedPayload` |

## Keys

`cose.encodeKey(algorithm, publicKey, { kid })` writes an AKP `COSE_Key`; `cose.encodePrivateKey(pair)` also writes the 32-byte seed
(label `-2`), which you must store as a secret; `cose.decodeKey(bytes)` and `cose.keyPairFromCoseKey(bytes)` read them back.

## Strictness

Verification refuses: an algorithm that is not in the protected header or not ML-DSA; a `crit` header; non-minimal CBOR, indefinite
lengths, duplicate map labels and trailing bytes; a COSE_Sign (tag 98) where a COSE_Sign1 is expected.

::: danger Seed keys sign; expanded keys from quantum-safe-py only verify
quantum-safe-py's liboqs-generated secret keys are expanded keys with no recoverable seed, so TypeScript cannot sign with them (see
[Signatures](/guide/signatures#standard-fips-204-signatures)). It verifies everything they sign.
:::
