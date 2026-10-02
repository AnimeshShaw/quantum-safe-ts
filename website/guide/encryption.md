# Encryption

## Envelopes

`Envelope.seal` encrypts a message to a public key. It runs a key encapsulation (hybrid by default), derives a one-time AES-256-GCM key
from the result with HKDF, and returns a self-describing `SealedMessage`.

```ts test
import { Envelope, HybridKEM, SealedMessage, DecryptionAuthenticationError, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
const sealed = Envelope.seal(utf8('secret'), pair.publicKey, { aad: utf8('item-42') });
const plain = Envelope.open(sealed, pair.secretKey);

const wire = sealed.toBytes();                  // CBOR; identical to quantum-safe-py's SealedMessage.to_bytes()
const again = SealedMessage.fromBytes(wire);
if (again.algorithm !== 'X25519+ML-KEM-768' || plain.length !== 6) throw new Error('unexpected');

try {
  // The AAD is authenticated: changing it makes decryption fail.
  Envelope.open(SealedMessage.fromParts({ ...again, aad: utf8('other') }), pair.secretKey);
  throw new Error('should not open');
} catch (e) {
  if (!(e instanceof DecryptionAuthenticationError)) throw e;
}
```

- The AAD (associated data) is authenticated against tampering and stored in clear inside the message. **It binds a message to a context only if you say which context you expect:** pass `{ expectedAad }` to `Envelope.open` (or `{ aad }` to `easy.decrypt`). Without it, a message sealed with any AAD opens, because anyone holding your public key can seal one.
- Envelopes are **anonymous**: they do not say who sent the message. Sign separately when that matters.
- `open` throws `DecryptionAuthenticationError` for a wrong key, a tampered message, or an AAD that differs from `expectedAad`. It reveals nothing about why.
- ML-KEM decapsulation never reports a wrong ciphertext (FIPS 203 implicit rejection): the failure surfaces at authentication.

## Key encapsulation directly

Use this when you want a shared secret rather than an encrypted message, for example to derive session keys.

```ts test
import { HybridKEM, utf8, equalBytes } from 'quantum-safe-ts';

const kem = new HybridKEM('X25519+ML-KEM-768');
using pair = kem.generateKeyPair();
const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);   // sender
using recovered = kem.decapsulate(pair.secretKey, ciphertext);          // key holder
if (!equalBytes(recovered.exportBytes(), sharedSecret.exportBytes())) throw new Error('mismatch');
const sessionKey = sharedSecret.deriveKey(32, utf8('myapp-session-v1')); // HKDF-SHA-256
sharedSecret.free();
if (sessionKey.length !== 32) throw new Error('unexpected');
```

## Algorithms

| Name | Notes |
|---|---|
| `X25519+ML-KEM-512`, `-768` (default), `-1024` | Hybrid. Byte-compatible with quantum-safe-py. |
| `P-256+ML-KEM-512`, `-768` | Hybrid with NIST P-256. |
| `X-Wing` | A widely implemented hybrid KEM specified in an individual Internet-Draft (`draft-connolly-cfrg-xwing-kem`; not an RFC). Use it for data other ecosystems must read; pass `'X-Wing'` to `easy.generateEncryptionKeys` or `new HybridKEM('X-Wing')`. |
| `ML-KEM-512/768/1024` (pure) | Not recommended for new deployments except `ML-KEM-1024` in the [CNSA 2.0 profile](/guide/standards). |

Envelopes need a hybrid key, except pure `ML-KEM-1024`, which produces an envelope v2 (HKDF-SHA-384; TypeScript only, not readable by
quantum-safe-py).

## Be aware

The quantum-safe-py-compatible hybrid construction is *compatible*, not *standard*: its key combiner is its own HKDF construction. It is
not X-Wing and not TLS `X25519MLKEM768`, and it has not been reviewed against NIST SP 800-227's key-combiner guidance. If you do not need quantum-safe-py
interop, prefer `X-Wing`.
