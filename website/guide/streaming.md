# Streaming encryption

`sealStream` and `openStream` encrypt data that does not fit in memory, or arrives in pieces: files, uploads, backups, exports. They are **TypeScript-only** (quantum-safe-py cannot read them) and **experimental until the construction has been reviewed**.

```ts test
import { HybridKEM, openStream, sealStream, DecryptionAuthenticationError, utf8 } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();

async function* source() {            // any AsyncIterable<Uint8Array> or Iterable<Uint8Array>: a Node stream, a web ReadableStream, a generator
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
try { for await (const _ of openStream(pair.secretKey, [encrypted.slice(0, encrypted.length - 3)])) { /* consume */ } } catch (e) { rejected = e instanceof Error; }
if (!rejected) throw new Error('a truncated stream must not open');
```

## What it guarantees

- One key encapsulation per stream. The data is cut into fixed-size chunks (default 64 KiB, 1 KiB to 16 MiB), each sealed with AES-256-GCM. A counter and a "last chunk" flag are in the nonce (the STREAM construction), so chunks **cannot be reordered, duplicated or removed from the middle, and a truncated stream fails** because the final chunk present was not sealed as the last one.
- The header (KEM ciphertext, nonce prefix, chunk size) and your `aad` are bound into every chunk. The opener must pass the same `expectedAad`.
- The first chunk that fails ends the stream: `openStream` throws `DecryptionAuthenticationError` (or `MalformedCiphertextError` for a malformed prelude or frame) and yields nothing further. **Output is released chunk by chunk as it verifies**; a stream cut off later still yielded its earlier chunks. If you need all-or-nothing, collect the output and use it only after the generator completes.
- Keys: a hybrid KEM key (such as `X25519+ML-KEM-768`, or `X-Wing`) or pure `ML-KEM-1024` (the CNSA 2.0 profile uses SHA-384). Like `Envelope`, a stream is **anonymous**: anyone with your public key can make one. Sign separately for sender authentication.
- Layout: `"QSS3" | u32 header length | header (CBOR) | { u32 ciphertext length | ciphertext }*`, big endian. Frames are length-checked before anything is allocated.

## Limits

Not audited. No constant-time guarantee. A stream may have at most 2^32 chunks (256 TiB at the default size). Memory use is about one chunk plus the input you hand over. The low-level `StreamSealer` and `StreamOpener` classes give you the chunks and the header directly if you need your own framing.
