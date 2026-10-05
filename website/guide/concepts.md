# Concepts

The ideas behind the API, and why some calls insist on arguments that look redundant. Skim this once; it explains most of the "why does it
throw?" questions.

## Why hybrid

A hybrid algorithm pairs a classical one (X25519, Ed25519, P-256) with a post-quantum one (ML-KEM, ML-DSA). The data is protected as long as
**either** half holds. That matters because the post-quantum algorithms are young, while the classical ones are well studied but fall to a
large quantum computer. Hybrid is the position NIST, CISA, BSI and NCSC take for the transition. The cost is size and a little time:

```ts test
import { HybridKEM, KEM } from 'quantum-safe-ts';

const hybrid = new HybridKEM('X25519+ML-KEM-768');
const pure = new KEM('ML-KEM-768');
using h = hybrid.generateKeyPair();
using p = pure.generateKeyPair();
const diff = h.publicKey.toBytes().length - p.publicKey.toBytes().length;
console.log('hybrid public key is', diff, 'bytes larger'); // 34: a 2-byte length field plus X25519's 32 bytes
if (diff !== 34) throw new Error('unexpected overhead');
```

Pure suites exist for the cases that require them (the CNSA 2.0 profile). See [Choosing what to use](/guide/choosing).

## Keys, formats and what they are

| Thing | What it is | Where it lives |
|---|---|---|
| `PublicKey` | An algorithm name plus raw public-key bytes. Safe to share and log. | JavaScript object |
| `SecretKey` | The same for the secret half. | **WebAssembly memory**, wiped on `.free()` |
| `KeyPair` | Both. | Public in JS, secret in WebAssembly memory |
| `SecretBytes` (also `SharedSecret`) | A secret byte string, such as a KEM shared secret or an Argon2id master key. | WebAssembly memory |
| `SealedMessage` | A KEM ciphertext plus AES-GCM ciphertext and metadata. | Bytes (CBOR) |
| `SignedMessage` | Message, signature, algorithm, context and metadata. | Bytes (CBOR) |

Every key carries its algorithm name, and every API checks it. Serialization is CBOR, PEM (`QUANTUM SAFE PUBLIC KEY`) or, for public keys,
JWK; all byte-identical to quantum-safe-py. See [Keys](/guide/keys).

## Context and AAD: the verifier says what it expects

A signature or ciphertext that is valid is not necessarily valid **for this purpose**. A context (signatures) and an AAD, "associated data"
(encryption), bind the result to a purpose such as `myapp-release-v1` or `order-4711`.

The rule that makes them work: **the verifier supplies the value it expects. It never reads it from the message.** The message is attacker
input; if the verifier trusted the context stored inside it, an attacker could simply write the context they like.

```ts test
import { HybridSign, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign();
using keys = signer.generateKeyPair();
const signed = signer.sign(utf8('transfer 10 EUR'), keys.secretKey, { context: utf8('payments-v1') });

signer.verify(signed, keys.publicKey, { expectedContext: utf8('payments-v1') }); // ok

let refused = 0;
for (const expected of [utf8('login-v1'), new Uint8Array(0)]) {
  try {
    signer.verify(signed, keys.publicKey, { expectedContext: expected });
  } catch (e) {
    if (e instanceof VerificationError) refused++;
    else throw e;
  }
}
if (refused !== 2) throw new Error('wrong or missing context must be refused');
```

The same holds for encryption: `Envelope.open(sealed, secretKey, { expectedAad })`. Without `expectedAad`, a message sealed with *any* AAD
opens, because anyone with your public key can seal one. Always pass it when the AAD means something.

Use a distinct context per purpose (`myapp-v1-login`, `myapp-v1-release`), include a version, and keep each at most 255 bytes.

## Hedged signing, and why a verifier must match the signer

ML-DSA signing can be deterministic or can mix in fresh randomness ("hedged"), which blunts some fault attacks. In the original
quantum-safe-py signature format (v1) hedging works by prepending 32 random bytes to the message, and the length of that prefix is stored in
the signature blob **outside the signed bytes**. A verifier that accepted any prefix length would let an attacker move bytes between the
prefix and the message and obtain a valid signature on a suffix of what was signed. So a v1 verifier pins the prefix length to its own mode:
32 when `hedged` is true (the default), 0 when it is false.

```ts test
import { Sign, VerificationError, utf8 } from 'quantum-safe-ts';

const unhedgedSigner = new Sign('ML-DSA-44', { hedged: false });
using keys = unhedgedSigner.generateKeyPair();
const signed = unhedgedSigner.sign(utf8('hello'), keys.secretKey);

new Sign('ML-DSA-44', { hedged: false }).verify(signed, keys.publicKey); // a verifier in the same mode accepts it

try {
  new Sign('ML-DSA-44').verify(signed, keys.publicKey);                  // the default (hedged) verifier refuses it
  throw new Error('should have been refused');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}
```

Practical rules: keep the default (hedged) unless you have a reason; if you sign unhedged, say so on every verifier; never mix both modes
for one key. The [`-v2` format](#the-two-signature-formats) has no hedging mode to get wrong.

## The two signature formats

| | v1 (default) | v2 (`-v2` suffix) |
|---|---|---|
| Identifier | `ML-DSA-65`, `Ed25519+ML-DSA-65`, ... | `ML-DSA-65-v2`, `Ed25519+ML-DSA-65-v2`, ... |
| Bytes signed | `len(ctx) ‖ ctx ‖ prefix ‖ message`, ML-DSA with an **empty** FIPS 204 context | `M2 = len(algo) ‖ algo ‖ len(ctx) ‖ ctx ‖ message`; ML-DSA with the **native** FIPS 204 context `quantum-safe-sig-v2` |
| Prefix | 32 random bytes (hedged) or none, length stored unsigned | none |
| Hybrid blob | CBOR map holding both signatures | `classical (64 bytes) ‖ ML-DSA signature` |
| Algorithm covered by the signature | no | yes (for both halves) |
| Python | all versions | quantum-safe-py 0.3.1 and later |

v2 removes the structure that makes v1 delicate. Its ML-DSA half is plain FIPS 204, so any FIPS 204 library can verify it once told the
bytes (`M2`) and the context (`quantum-safe-sig-v2`). Keys are tagged with the format in their algorithm name (`...-v2`); the library refuses a
v1 key in a v2 signer and the reverse. The tag is metadata, though: v1 and v2 keys have identical bytes, so **never use the same key
material in both formats**.

## Hybrid combiners

A hybrid KEM produces two shared secrets, one from the classical half and one from ML-KEM, and combines them into one. The combiner decides
how safe the combination is.

- The default suites use quantum-safe-py's construction: `HKDF-SHA-256(ss_classical ‖ ss_pqc, salt = ct_classical ‖ ct_pqc, info = "quantum-safe hybrid KEM v1" ‖ 0x00 ‖ algorithm)`.
  It is sound engineering and byte-compatible with Python, but it is its own construction: **not** X-Wing, **not** TLS `X25519MLKEM768`,
  and not reviewed against NIST SP 800-227's key-combiner guidance.
- `X-Wing` is a published combiner (an individual Internet-Draft) that other libraries implement. Use it when other ecosystems must read
  your data.

The envelope then derives its AES-256-GCM key from the combined secret with HKDF. Each `seal` uses a fresh KEM secret, so each AES key
encrypts exactly one message.

## Versions and algorithm binding

Everything that is written down names its algorithm and version, and the readers check both.

| Where | What is bound |
|---|---|
| Key CBOR | `v`, `algo`, `ktype` (`pub` or `sec`). A secret key never loads as a public key, a newer version is refused, and a public key must have the exact length of its algorithm. |
| `SealedMessage` | The version, the algorithm and your AAD are inside the AES-GCM authenticated data. A message cannot be relabelled as another profile. |
| `SignedMessage` | The algorithm name is checked against the key; in `-v2` it is also signed. |
| JWT | The `alg` header must equal the key's algorithm; `alg: "none"` is rejected. |

```ts test
import { HybridKEM, AlgorithmMismatchError } from 'quantum-safe-ts';

using a = new HybridKEM('X25519+ML-KEM-512').generateKeyPair();
using b = new HybridKEM('X25519+ML-KEM-768').generateKeyPair();
const kem512 = new HybridKEM('X25519+ML-KEM-512');
const { ciphertext, sharedSecret } = kem512.encapsulate(a.publicKey);
sharedSecret.free();
try {
  kem512.decapsulate(b.secretKey, ciphertext); // a key of another algorithm is refused up front
  throw new Error('should have been refused');
} catch (e) {
  if (!(e instanceof AlgorithmMismatchError)) throw e;
}
```

## Memory and secrets

WebAssembly memory holds secret keys and shared secrets; `.free()` (or leaving a `using` scope) wipes the owned buffers. What you copy out
of WebAssembly (`exportBytes()`, `toPem()` of a secret, plaintext from `Envelope.open`) lives in the JavaScript heap, which this library
cannot wipe: call `wipe()` on those copies. `toString`, `toJSON` and `util.inspect` never show key material, and errors and hints never
contain it. [Security model](/guide/security) has the full list of what this does and does not protect against.
