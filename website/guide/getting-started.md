# Getting started

```bash
npm install quantum-safe-ts
```

The package is ESM and CommonJS, ships its own types, and has no install scripts or native build step.

## The shortest path

The `easy` layer takes strings and bytes and returns strings and bytes. There is nothing to free.

```ts test
import { easy } from 'quantum-safe-ts';

const { publicKey, secretKey } = easy.generateEncryptionKeys(); // PEM strings, X25519 + ML-KEM-768
const sealed = easy.encrypt(publicKey, 'attack at dawn', { aad: 'msg-1' });
const plain = easy.decrypt(secretKey, sealed);
if (new TextDecoder().decode(plain) !== 'attack at dawn') throw new Error('round trip failed');
```

On Node.js this works immediately. In browsers, Deno, Bun and edge runtimes call `await init()` once first
([details](/guide/runtimes)).

::: tip What the easy layer trades away
Your secret key is a plain string in the JavaScript heap, where this library cannot wipe it and where a logger or heap dump can see it.
That is fine for many uses; when it is not, use the class API below.
:::

## The class API

Secret keys stay inside WebAssembly memory; the owned secret buffers are zeroized on `.free()` (copies made while passing arguments or parsing may remain in WebAssembly memory; see SECURITY.md) when you call `.free()` or leave a `using` scope.

```ts test
import { init, HybridKEM, Envelope, utf8 } from 'quantum-safe-ts';

await init(); // required outside Node.js; a no-op on Node.js

const kem = new HybridKEM();          // X25519 + ML-KEM-768
using pair = kem.generateKeyPair();   // freed (and the owned buffers zeroized) at the end of the scope

const sealed = Envelope.seal(utf8('attack at dawn'), pair.publicKey, { aad: utf8('msg-1') });
const plain = Envelope.open(sealed, pair.secretKey);
if (plain.length !== 14) throw new Error('unexpected length');
```

## Choosing algorithms

| You want | Use |
|---|---|
| The sensible default | `X25519+ML-KEM-768` for encryption, `Ed25519+ML-DSA-65` for signatures |
| Compatibility with quantum-safe-py | The defaults. Formats are byte-compatible both ways. |
| Data that other ecosystems must read | `X-Wing` for encryption and [`StandardJwt`](/guide/jwt) (RFC 9964) for tokens |
| The CNSA 2.0 parameter sets | pure `ML-KEM-1024` and `ML-DSA-87` ([details](/guide/standards)) |

Hybrid means a classical algorithm and a post-quantum one both protect the data: an attacker has to break both. Hybrid encryption
is the recommended posture while the post-quantum algorithms are young.

## Next

[Encryption](/guide/encryption), [Signatures](/guide/signatures), [JWT](/guide/jwt), [Keys and passwords](/guide/keys),
[Migrating an existing system](/guide/migration).
