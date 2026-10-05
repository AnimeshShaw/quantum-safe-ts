# Signatures

A digital signature proves that a message was produced by the holder of a signing key and has not been changed. `Sign` is for a single
algorithm (ML-DSA or SLH-DSA); `HybridSign` pairs a classical signature (Ed25519 or P-256) with ML-DSA so that **both** must verify.

**Use it for** release artifacts, signed documents, audit-log entries, webhooks, anything a recipient must be able to attribute to you.
**Do not use it** to hide content (a signature does not encrypt), or without a context (see below).

## A complete example

```ts test
import { HybridSign, SignedMessage, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign();                       // Ed25519 + ML-DSA-65, hedged
using keys = signer.generateKeyPair();

const signed = signer.sign(utf8('release 1.2.3'), keys.secretKey, { context: utf8('myapp-release-v1') });

// Verify with the context YOU expect. Returns nothing; throws VerificationError unless valid.
signer.verify(signed, keys.publicKey, { expectedContext: utf8('myapp-release-v1') });

// Transport: the signed message is self-contained.
const wire = signed.toBytes();
const received = SignedMessage.fromBytes(wire);
if (new TextDecoder().decode(received.message) !== 'release 1.2.3') throw new Error('message changed');

// Any change to the message, the signature, the context or the key is refused.
const tampered = SignedMessage.fromParts({ ...received, message: utf8('release 9.9.9') });
try {
  signer.verify(tampered, keys.publicKey, { expectedContext: utf8('myapp-release-v1') });
  throw new Error('should have failed');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}
```

`verify` returns nothing and throws `VerificationError` with a fixed message and no detail about *why*: telling an attacker which part failed
helps them. Use `isValid` for a boolean, or `verifyBytes(message, signature, publicKey, { context })` to check a detached signature.

## What to know

- **Pass the context you expect** (`expectedContext`, default empty). A message carries its own context, but an attacker can choose it, so the
  verifier never trusts it. A context (at most 255 bytes) ties a signature to one purpose: `myapp-release-v1` and `myapp-login-v1` cannot be
  swapped. See [Concepts](/guide/concepts#context-and-aad-the-verifier-says-what-it-expects).
- A **hybrid** signature carries a classical and a post-quantum signature, and **both** must verify. Both halves are always evaluated before
  the result is combined, so a failure does not reveal which half failed.
- **Hedged signing** (extra randomness) is the default, as in quantum-safe-py. With the default format (v1), a verifier must be in the same
  hedging mode as the signer (`new Sign(algo, { hedged: false })`). The [`-v2` format](#format-v2--v2) has no such setting.
- `SignedMessage` is self-contained: `message`, `signature`, `algorithm`, `context`, `signerFingerprint`, `signedAt`. The fingerprint and
  timestamp are metadata and are **not** covered by the signature. Do not use them for security decisions.
- Sign a **digest** of large artifacts, not the whole file.
- Keep `signerFingerprint` useful: `signer.signWithFingerprint(message, keyPair, { context })` records `keyPair.publicKey.fingerprint()` so a
  verifier can find the right key quickly.

## Algorithms

| Name | Notes |
|---|---|
| `Ed25519+ML-DSA-44/65/87`, `P-256+ML-DSA-44/65` | Hybrid. Default `Ed25519+ML-DSA-65` (NIST category 3). Byte-compatible with quantum-safe-py. |
| `ML-DSA-44/65/87` | FIPS 204. `ML-DSA-87` is the CNSA 2.0 level. |
| `SLH-DSA-SHAKE-*` and `SLH-DSA-SHA2-*` (`128/192/256`, `s`/`f`; 12 sets) | FIPS 205, hash-based. Large signatures, conservative assumptions, slower signing. `f` is faster to sign, `s` smaller. |
| `<any ML-DSA or hybrid>-v2` | The cleaner format described below. |
| LMS / HSS | **Verification only** (`Lms`), per RFC 8554. Signing needs durable state and is intentionally not provided. |

```ts test
import { Sign, sigSuites, utf8 } from 'quantum-safe-ts';

const fast = new Sign('SLH-DSA-SHAKE-128f');    // hash-based: no lattice assumption
using keys = fast.generateKeyPair();
const signed = fast.sign(utf8('long-term archive record'), keys.secretKey, { context: utf8('archive-v1') });
fast.verify(signed, keys.publicKey, { expectedContext: utf8('archive-v1') });
console.log('SLH-DSA-SHAKE-128f signature bytes:', signed.signature.length);
if (sigSuites().filter((s) => s.name.startsWith('SLH-DSA')).length !== 12) throw new Error('expected 12 SLH-DSA sets');
```

## Format v2 (`-v2`)

Every ML-DSA and hybrid suite also exists as `<name>-v2` (`ML-DSA-65-v2`, `Ed25519+ML-DSA-65-v2`, ...). It removes the structure that makes the
quantum-safe-py construction delicate:

- **No prefix, no unsigned length byte.** There is no boundary between "prefix" and "message" to move, and no `hedged` setting to get wrong.
  The blob is the signature itself, in one fixed-length encoding.
- **Plain FIPS 204 for the ML-DSA half.** It signs `M2` with the native context `quantum-safe-sig-v2`, so any FIPS 204 library (noble, Node
  WebCrypto) verifies it given `M2`. Signing is always hedged inside ML-DSA.
- **Algorithm and context are signed.** `M2 = len(algo) ‖ algo ‖ len(ctx) ‖ ctx ‖ message`, and both halves of a hybrid sign the same bytes
  (the classical half signs `label ‖ 0x00 ‖ M2`).
- **One encoding.** Hybrid blob = classical signature (64 bytes) ‖ ML-DSA signature; P-256 signatures are raw `r ‖ s` and the high-S twin is refused.
- **Keys are tagged `-v2`**, and the library refuses a v1 key in a v2 signer and the reverse. The tag is metadata, though: v1 and v2 keys have
  identical bytes, so **never use the same key material in both formats**. Generate new keys for v2.
- The `SignedMessage` container is the same CBOR as in v1 and is not canonical; the signature blob and the verified message are not
  malleable, but do not use a hash of the container as an identity.

```ts test
import { HybridSign, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using pair = signer.generateKeyPair();
const signed = signer.sign(utf8('release 1.2.3'), pair.secretKey, { context: utf8('myapp-release-v1') });
signer.verify(signed, pair.publicKey, { expectedContext: utf8('myapp-release-v1') });
let rejected = false;
try { signer.verify(signed, pair.publicKey); } catch (e) { rejected = e instanceof VerificationError; } // wrong (empty) context
if (!rejected) throw new Error('context must be enforced');
if (signed.signature.length !== 64 + 3309) throw new Error('hybrid v2 blob is 64 + the ML-DSA-65 signature');
```

quantum-safe-py 0.3.1 and later reads and writes v2 (all eight identifiers are verified in both directions); 0.3.0 cannot read it and fails
closed on the identifier. There is no SLH-DSA v2. `JWTSigner` / `JWTVerifier` accept v2 keys too.

**Which to use:** the default stays `Ed25519+ML-DSA-65` for now so existing Python deployments keep verifying, and is planned to flip to
`-v2` in the next minor release. Choose `-v2` explicitly when every verifier you control is quantum-safe-py 0.3.1+ or quantum-safe-ts
([Choosing what to use](/guide/choosing#default-format-or-v2)).

## Verifying bytes from elsewhere

`verifyBytes` checks a detached message and signature blob, which is how you verify something another tool produced.

```ts test
import { Sign, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new Sign('ML-DSA-65-v2');
using keys = signer.generateKeyPair();
const signed = signer.sign(utf8('detached'), keys.secretKey, { context: utf8('ctx-v1') });

signer.verifyBytes(utf8('detached'), signed.signature, keys.publicKey, { context: utf8('ctx-v1') });
try {
  signer.verifyBytes(utf8('detached!'), signed.signature, keys.publicKey, { context: utf8('ctx-v1') });
  throw new Error('should have failed');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}
```

## The easy layer

```ts test
import { easy } from 'quantum-safe-ts';

const keys = easy.generateSigningKeys('Ed25519+ML-DSA-65-v2');          // PEM strings; default is Ed25519+ML-DSA-65
const signed = easy.sign(keys.secretKey, 'hello', { context: 'docs-v1' }); // Uint8Array (CBOR SignedMessage)
if (easy.verifyText(keys.publicKey, signed, { context: 'docs-v1' }) !== 'hello') throw new Error('verify');
if (easy.isValid(keys.publicKey, signed, { context: 'other' })) throw new Error('a different context must not verify');
```

`easy.verify` returns the message bytes and throws unless the signature is valid **and** its context equals `options.context` (default empty).

## Stateful hash-based signatures (LMS / HSS)

`Lms.verify(publicKey, message, signature)` verifies RFC 8554 signatures (SHA-256 parameter sets), checked against the RFC's own vectors and
against signatures made by an independent implementation. `Lms.isValid` returns a boolean and `Lms.inspectPublicKey` reports the parameter
set. **Signing is not provided**: a stateful scheme that reuses a one-time key is broken, and a library cannot guarantee durable state.
Use the signer your HSM or tooling provides.

## Common mistakes

| Mistake | What happens | Fix |
|---|---|---|
| Signing without a context | A signature made for one purpose is valid for any other use of the key | Always pass `context` and verify with `expectedContext` |
| Reading the context out of the message | An attacker chooses it | Pass the value you expect |
| Verifying a `hedged: false` signature with the default verifier | `VerificationError` | Construct the verifier with the signer's mode, or use `-v2` |
| Using one key for both formats (v1 and v2) | The classical halves are not domain-separated | Separate keys per format |
| Treating `signerFingerprint` / `signedAt` as authenticated | They are not signed | Put anything that matters inside the signed message |
| Using the hash of a `SignedMessage` as an identity | The container is not canonical | Use an identifier inside the signed data |
| Signing a huge buffer | Memory and time | Sign a digest |
