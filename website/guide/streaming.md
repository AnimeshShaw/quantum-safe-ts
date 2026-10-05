# Streaming encryption

`sealStream` and `openStream` encrypt data that does not fit in memory, or arrives in pieces: files, uploads, backups, exports. They are
**TypeScript-only** (quantum-safe-py has no streaming format).

**Use them for** large or unbounded data. **Do not use them** for small messages (use [`Envelope`](/guide/encryption): simpler, and its output is
also readable by Python), or if you need sender authentication (a stream, like an envelope, is anonymous: sign it separately).

## A complete example

```ts test
import { HybridKEM, openStream, sealStream, QuantumSafeError, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();

async function* source() {            // any AsyncIterable<Uint8Array> or Iterable<Uint8Array>
  yield utf8('first part, ');
  yield utf8('second part');
}

const pieces: Uint8Array[] = [];
for await (const piece of sealStream(pair.publicKey, source(), { aad: utf8('backup-2026-10') })) pieces.push(piece);
const encrypted = new Uint8Array(pieces.reduce((n, p) => n + p.length, 0));
let at = 0;
for (const p of pieces) { encrypted.set(p, at); at += p.length; }

let plain = '';
for await (const part of openStream(pair.secretKey, [encrypted], { expectedAad: utf8('backup-2026-10') })) plain += new TextDecoder().decode(part);
if (plain !== 'first part, second part') throw new Error('round trip');

let rejected = false;
try {
  for await (const _ of openStream(pair.secretKey, [encrypted.slice(0, encrypted.length - 3)], { expectedAad: utf8('backup-2026-10') })) { /* consume */ }
} catch (e) { rejected = QuantumSafeError.is(e); }
if (!rejected) throw new Error('a truncated stream must not open');
```

`sealStream` yields the encrypted stream as pieces: first the prelude (magic and header), then one frame per chunk. Concatenate or forward them
in order. The input can be split any way you like and can be empty. `openStream` accepts the encrypted bytes split any way too.

## With Node.js streams, web streams and files

An `AsyncIterable<Uint8Array>` is all that is needed, and the common stream types are already that.

```ts test
import { Readable } from 'node:stream';
import { HybridKEM, openStream, sealStream } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
const original = new Uint8Array(300_000).map((_, i) => i % 251);

// Node.js readable -> encrypted pieces. (A file: Readable.from(fs.createReadStream(path)) or just fs.createReadStream(path).)
const nodeSource = Readable.from([original.slice(0, 100_000), original.slice(100_000)]);
const encrypted: Uint8Array[] = [];
for await (const piece of sealStream(pair.publicKey, nodeSource)) encrypted.push(piece);

// A web ReadableStream (browsers, Deno, Bun, Node 18+) is async-iterable too.
const web = new ReadableStream<Uint8Array>({
  start(controller) {
    for (const piece of encrypted) controller.enqueue(piece);
    controller.close();
  },
});
let total = 0;
let firstByte = -1;
for await (const part of openStream(pair.secretKey, web as unknown as AsyncIterable<Uint8Array>)) {
  if (firstByte < 0) firstByte = part[0]!;
  total += part.length;
}
if (total !== original.length || firstByte !== original[0]) throw new Error('lost or changed bytes');
```

In a browser, `response.body` from `fetch` can be passed to `openStream` the same way (cast it to `AsyncIterable<Uint8Array>` where the DOM
typings do not declare it iterable).

## What it guarantees

- One key encapsulation per stream. The data is cut into fixed-size chunks (default 64 KiB; 1 KiB to 16 MiB with `chunkSize`), each sealed
  with AES-256-GCM. A counter and a "last chunk" flag are in the nonce (the STREAM construction), so chunks **cannot be reordered,
  duplicated or removed from the middle, and a truncated or extended stream fails** because the final chunk present was not sealed as the last.
- The header (KEM ciphertext, nonce prefix, chunk size) and your `aad` are bound into every chunk. The opener must pass the same `expectedAad`.
- The first chunk that fails ends the stream: `openStream` throws `DecryptionAuthenticationError` (or `MalformedCiphertextError` for a malformed
  prelude or frame) and yields nothing further. Frame lengths are checked **before** anything is allocated, so a hostile length cannot make
  you allocate gigabytes.
- **Output is released chunk by chunk as it verifies.** A stream cut off later still yielded its earlier chunks. If you need
  all-or-nothing, collect the output and use it only after the generator completes.
- Keys: a hybrid KEM key (such as `X25519+ML-KEM-768`, or `X-Wing`) or pure `ML-KEM-1024` (the CNSA 2.0 profile; key derivation uses SHA-384).
- Layout: `"QSS3" | u32 header length | header (CBOR) | { u32 ciphertext length | ciphertext }*`, big endian.

```ts test
import { HybridKEM, openBytes, sealBytes, MalformedCiphertextError, DecryptionAuthenticationError, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
const data = new Uint8Array(5000).fill(7);
const encrypted = await sealBytes(pair.publicKey, data, { chunkSize: 1024, aad: utf8('x') });  // helpers for small inputs
if ((await openBytes(pair.secretKey, encrypted, { expectedAad: utf8('x') })).length !== 5000) throw new Error('round trip');

const attempts: [string, Uint8Array][] = [
  ['wrong magic', Uint8Array.from([...utf8('NOPE'), ...encrypted.slice(4)])],
  ['cut inside a frame', encrypted.slice(0, encrypted.length - 5)],
  ['flipped byte', Uint8Array.from(encrypted, (b, i) => (i === encrypted.length - 20 ? b ^ 1 : b))],
  ['empty input', new Uint8Array(0)],
];
for (const [label, bytes] of attempts) {
  try {
    await openBytes(pair.secretKey, bytes, { expectedAad: utf8('x') });
    throw new Error(`${label}: should have failed`);
  } catch (e) {
    if (!(e instanceof MalformedCiphertextError || e instanceof DecryptionAuthenticationError)) throw e;
  }
}
```

## Low-level control

`StreamSealer` and `StreamOpener` give you the header and the chunks directly, for your own framing or transport. They own the key and the
chunk counter, so a nonce can never be reused or skipped. Every chunk except the last must be exactly `chunkSize` bytes; the last may be
shorter or empty; nothing is accepted after it.

```ts test
import { HybridKEM, StreamOpener, StreamSealer, inspectStreamHeader, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();
using sealer = StreamSealer.start(pair.publicKey, { chunkSize: 1024, aad: utf8('ctx') });
console.log(inspectStreamHeader(sealer.header));          // { algorithm, kemCiphertextLength, chunkSize }

const c1 = sealer.seal(new Uint8Array(1024).fill(1), false); // full, not last
const c2 = sealer.seal(new Uint8Array(10).fill(2), true);    // short and last

using opener = StreamOpener.start(pair.secretKey, sealer.header, { expectedAad: utf8('ctx') });
const p1 = opener.open(c1, false);
const p2 = opener.open(c2, true);
if (p1.length !== 1024 || p2.length !== 10 || p2[0] !== 2) throw new Error('round trip');
```

## Limits

A stream may have at most 2^32 chunks
(256 TiB at the default size). Memory use is about one chunk plus the input you hand over. Keys must be hybrid (including `X-Wing`) or pure
`ML-KEM-1024`; other pure KEM keys throw `UnsupportedAlgorithmError`.

## Common mistakes

| Mistake | Fix |
|---|---|
| Using the output before the generator completes when you need all-or-nothing | Collect, and use it only after the loop ends |
| Different `aad` on the two ends | Pass the same `aad` / `expectedAad` |
| Hand-slicing chunks with `StreamSealer` and getting the sizes wrong | Use `sealStream`, or make every non-final chunk exactly `chunkSize` |
| Assuming the stream proves who sent it | Sign the stream's header and digest separately |
| Reading a whole large file into memory first | Pass a file stream |
