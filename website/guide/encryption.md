# Encryption (envelopes)

An **envelope** is a self-describing, authenticated, public-key encrypted message. `Envelope.seal` encrypts to a public key; `Envelope.open`
decrypts with the matching secret key. Under the hood it runs a key encapsulation (hybrid by default), derives a one-time AES-256-GCM key
from the result with HKDF, and encrypts. The output, a `SealedMessage`, carries everything the recipient needs except the secret key.

**Use it for** messages between services, fields you store, anything one party encrypts and another decrypts. **Do not use it** for large
files (use [streaming](/guide/streaming)), for proving who sent something (envelopes are anonymous; [sign](/guide/signatures) as well), or for
password-based encryption (derive a key with [`deriveMasterKey`](/guide/keys#passwords) and use it with a symmetric cipher of your own).

## A complete example

```ts test
import { Envelope, HybridKEM, SealedMessage, DecryptionAuthenticationError, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
const sealed = Envelope.seal(utf8('secret'), pair.publicKey, { aad: utf8('item-42') });

// The recipient states the context it expects.
const plain = Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('item-42') });
if (new TextDecoder().decode(plain) !== 'secret') throw new Error('round trip failed');

// Store or send the bytes; read them back later.
const wire = sealed.toBytes();                  // CBOR, identical to quantum-safe-py's SealedMessage.to_bytes()
const again = SealedMessage.fromBytes(wire);
if (again.algorithm !== 'X25519+ML-KEM-768' || again.version !== 1) throw new Error('unexpected metadata');

// A different expected AAD is refused: nothing about *why*.
try {
  Envelope.open(wire, pair.secretKey, { expectedAad: utf8('item-43') });
  throw new Error('should not open');
} catch (e) {
  if (!(e instanceof DecryptionAuthenticationError)) throw e;
}
```

`Envelope.open` accepts a `SealedMessage` or its bytes. `wipe()` the returned plaintext when you are done with it: it lives in the JavaScript
heap.

## What is protected, and what is not

| Property | Status |
|---|---|
| Confidentiality of the plaintext | Yes: AES-256-GCM under a key that only the secret-key holder can derive |
| Integrity of the ciphertext, the version, the algorithm and the AAD | Yes: all are in the GCM authentication |
| Authentication of the **sender** | **No.** Anyone holding the public key can seal. Sign separately. |
| Binding to a context | Only if the opener passes `expectedAad` |
| Hiding the length of the plaintext | No |
| Hiding the algorithm or the AAD | No: both are stored in the clear inside the message |
| Forward secrecy against a later theft of the secret key | No: it is encryption to a long-term key |

## Associated data (AAD): bind a message to a record

The AAD is data that is authenticated but not encrypted. Use it to tie a ciphertext to the thing it belongs to, such as a record id, a
user id or a protocol label, so a ciphertext cannot be copied to another record unnoticed.

```ts test
import { Envelope, HybridKEM, SealedMessage, DecryptionAuthenticationError, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
const sealed = Envelope.seal(utf8('4111 1111 1111 1111'), pair.publicKey, { aad: utf8('table=cards;id=17') });

// An attacker copies the ciphertext of record 17 onto record 18. The application opens it as record 18:
try {
  Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('table=cards;id=18') });
  throw new Error('a message must not open under another record id');
} catch (e) {
  if (!(e instanceof DecryptionAuthenticationError)) throw e;
}

// The AAD stored in the message can be read (it is not secret), and changing it breaks authentication.
const forged = SealedMessage.fromParts({ ...sealed, aad: utf8('table=cards;id=18') });
try {
  Envelope.open(forged, pair.secretKey, { expectedAad: utf8('table=cards;id=18') });
  throw new Error('rewriting the stored AAD must not help the attacker');
} catch (e) {
  if (!(e instanceof DecryptionAuthenticationError)) throw e;
}
```

**Always pass `expectedAad` when the AAD means something.** The AAD is stored inside the message, so without `expectedAad` a message sealed
with *any* AAD opens: anyone holding your public key can seal one.

## Inspecting a message without a key

```ts test
import { Envelope, HybridKEM, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
const sealed = Envelope.seal(utf8('hello'), pair.publicKey, { aad: utf8('x') });
const info = sealed.inspect();   // non-secret metadata only
console.log(info);
if (info.version !== 1 || info.algorithm !== 'X25519+ML-KEM-768' || info.nonceLength !== 12 || info.aadLength !== 1) throw new Error('unexpected');
// KEM ciphertext (1,122 bytes for this suite) + nonce (12) + the encrypted message plus a 16-byte tag.
if (info.ciphertextLength !== 5 + 16) throw new Error('ciphertext is plaintext length plus the tag');
```

## Which algorithms

| Key | Envelope version | Key derivation | Notes |
|---|---|---|---|
| `X25519+ML-KEM-512`, `-768` (default), `-1024` | 1 | HKDF-SHA-256 | Byte-compatible with quantum-safe-py |
| `P-256+ML-KEM-512`, `-768` | 1 | HKDF-SHA-256 | Hybrid with NIST P-256 |
| `X-Wing` | 1 | HKDF-SHA-256 | For data other X-Wing implementations must read |
| `ML-KEM-1024` (pure) | 2 | HKDF-SHA-384 | The CNSA 2.0 profile; quantum-safe-py 0.3.1 and later reads and writes it too |
| `ML-KEM-512`, `ML-KEM-768` (pure) | not supported | | `Envelope.seal` throws `UnsupportedAlgorithmError` |

The version is chosen by the key; you never pass it. See [Choosing what to use](/guide/choosing) for which to pick.

```ts test
import { Envelope, KEM, UnsupportedAlgorithmError, utf8 } from 'quantum-safe-ts';

using pure1024 = new KEM('ML-KEM-1024').generateKeyPair();
if (Envelope.seal(utf8('x'), pure1024.publicKey).version !== 2) throw new Error('pure ML-KEM-1024 gives envelope v2');

using pure768 = new KEM('ML-KEM-768').generateKeyPair();
try {
  Envelope.seal(utf8('x'), pure768.publicKey);
  throw new Error('pure ML-KEM-768 envelopes are not produced');
} catch (e) {
  if (!(e instanceof UnsupportedAlgorithmError)) throw e;
}
```

## The easy layer

`easy.encrypt` and `easy.decrypt` wrap the same envelope with PEM-string keys, so there is nothing to free.

```ts test
import { easy } from 'quantum-safe-ts';

const keys = easy.generateEncryptionKeys('X-Wing');             // any KEM name; default X25519+ML-KEM-768
const sealed = easy.encrypt(keys.publicKey, 'hello', { aad: 'greeting' });
const text = easy.decryptText(keys.secretKey, sealed, { aad: 'greeting' });
if (text !== 'hello') throw new Error('round trip failed');
```

The trade-off: your secret key is a string in the JavaScript heap, where it cannot be wiped. Use the class API if that matters.

## The quantum-safe-py construction: compatible, not standard

The default hybrid suites match quantum-safe-py byte for byte, including its own HKDF combiner. That is *compatible*, not *standard*: it is not
X-Wing, not TLS `X25519MLKEM768`, and it has not been reviewed against NIST SP 800-227's key-combiner guidance. If you do not need Python
interop, prefer `X-Wing`.

## Common mistakes

| Mistake | What happens | Fix |
|---|---|---|
| `Envelope.open` without `expectedAad` where the AAD matters | Any AAD opens | Pass `expectedAad` |
| Treating a sealed message as proof of the sender | Anyone with the public key can seal | Sign it too |
| Putting a secret in the AAD | It is stored in the clear | Put secrets in the plaintext |
| Using pure `ML-KEM-768` for envelopes | `UnsupportedAlgorithmError` | Use a hybrid key, or `ML-KEM-1024` |
| Expecting a wrong key to fail at decapsulation | ML-KEM never fails there (implicit rejection) | The failure is `DecryptionAuthenticationError` from `open` |
| Re-using one `SealedMessage` object after mutating its parts | Parts are read-only | Build a new one with `SealedMessage.fromParts` |
