# Quick start recipes

Short, complete solutions to the five things most people come to this library for. Each recipe says what it is for, when to use it, and
what usually goes wrong. Every block runs in the test suite. Longer, end-to-end scenarios are in the [Cookbook](/guide/cookbook).

All recipes use the class API, which keeps secret keys inside WebAssembly memory. Outside Node.js, call `await init()` once first.

## 1. Encrypt a message to a public key

**For:** sending something only the holder of a secret key can read: a message between services, a field you store, a backup note.
**Not for:** proving who sent it (an envelope is anonymous; sign it too if that matters) or large files (use [streaming](#5-encrypt-a-large-file-in-chunks)).

```ts test
import { HybridKEM, Envelope, PublicKey, utf8 } from 'quantum-safe-ts';

// Recipient, once: make a key pair and publish the public key.
using recipient = new HybridKEM().generateKeyPair();
const publicKeyPem = recipient.publicKey.toPem();

// Sender: needs only the public key.
const toRecipient = PublicKey.fromPem(publicKeyPem);
const sealed = Envelope.seal(utf8('order 4711 shipped'), toRecipient, { aad: utf8('order-4711') });
const wire: Uint8Array = sealed.toBytes(); // send or store this

// Recipient: opens it, stating the context it expects.
const plain = Envelope.open(wire, recipient.secretKey, { expectedAad: utf8('order-4711') });
if (new TextDecoder().decode(plain) !== 'order 4711 shipped') throw new Error('round trip failed');
toRecipient.free();
```

**Common mistakes:** forgetting `expectedAad` on `open` (then any label opens, see [concepts](/guide/concepts#context-and-aad-the-verifier-says-what-it-expects)); logging the
secret key; treating `plain` as safe to keep forever (it lives in the JavaScript heap: `wipe(plain)` when done).

## 2. Sign a release

**For:** proving that a file, message or build came from the holder of a signing key, and was not altered.
**Not for:** hiding the content (a signature does not encrypt).

```ts test
import { HybridSign, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign();                    // Ed25519 + ML-DSA-65
using keys = signer.generateKeyPair();

const artifactDigest = utf8('sha256:9f86d081884c7d659a2feaa0c55ad015'); // sign a digest of the artifact, not the whole file
const signed = signer.sign(artifactDigest, keys.secretKey, { context: utf8('myapp-release-v1') });

const wire = signed.toBytes();                      // publish next to the artifact
if (wire.length < 2000) throw new Error('hybrid signatures are a few kilobytes');
```

**Common mistakes:** signing without a `context` (then a signature made for one purpose is valid for any other use of the same key);
signing a huge buffer instead of its digest.

## 3. Verify with the context you expect

**For:** the receiving side of the previous recipe.

```ts test
import { HybridSign, SignedMessage, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign();
using keys = signer.generateKeyPair();
const wire = signer.sign(utf8('payload'), keys.secretKey, { context: utf8('myapp-release-v1') }).toBytes();

const received = SignedMessage.fromBytes(wire);
signer.verify(received, keys.publicKey, { expectedContext: utf8('myapp-release-v1') }); // returns nothing; throws unless valid

try {
  signer.verify(received, keys.publicKey); // the default expected context is empty, so this is refused
  throw new Error('should have failed');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}
const ok: boolean = signer.isValid(received, keys.publicKey, { expectedContext: utf8('myapp-release-v1') }); // boolean variant
if (!ok) throw new Error('should be valid');
```

**Common mistakes:** passing no `expectedContext` when the signer used one (you get `VerificationError`, with no reason, by design);
catching `Error` broadly and continuing as if the signature were fine.

## 4. Issue and verify a JWT

**For:** access tokens between your own services, with post-quantum signatures.
Use `StandardJwt` instead when *other* JOSE libraries must verify the token ([JWT page](/guide/jwt)).

```ts test
import { HybridSign, JWTSigner, JWTVerifier } from 'quantum-safe-ts';

using keys = new HybridSign().generateKeyPair();
const token = new JWTSigner(keys, { issuer: 'https://auth.example' }).sign({ sub: 'user-1', scope: 'read' }, { expiresIn: 600 });

const claims = new JWTVerifier(keys.publicKey, { issuer: 'https://auth.example' }).verify(token, { requireExp: true });
if (claims.sub !== 'user-1') throw new Error('unexpected claims');
```

**Common mistakes:** issuing tokens without `expiresIn`; verifying without `requireExp` when you rely on expiry; accepting a token whose
issuer you did not check.

## 5. Encrypt a large file in chunks

**For:** data that does not fit in memory or arrives in pieces: uploads, backups, exports. Experimental, TypeScript-only.

```ts test
import { HybridKEM, openStream, sealStream, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();

async function* chunks() {                      // any async or sync iterable of Uint8Array: a file stream, a fetch body, a generator
  for (let i = 0; i < 5; i++) yield new Uint8Array(40_000).fill(i);
}

const encrypted: Uint8Array[] = [];
for await (const part of sealStream(pair.publicKey, chunks(), { aad: utf8('backup-2026-10') })) encrypted.push(part);

let total = 0;
for await (const part of openStream(pair.secretKey, encrypted, { expectedAad: utf8('backup-2026-10') })) total += part.length;
if (total !== 200_000) throw new Error('lost bytes');
```

**Common mistakes:** using the output before the whole stream has verified (chunks are released as they verify; a cut-off stream fails at
the end, after earlier chunks were already yielded: collect first if you need all-or-nothing); not passing the same `aad` on both ends.

## Next

[Choosing what to use](/guide/choosing) · [Cookbook](/guide/cookbook) · [Concepts](/guide/concepts)
