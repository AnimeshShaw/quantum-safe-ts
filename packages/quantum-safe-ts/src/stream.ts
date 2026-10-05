/**
 * Streaming envelope (format v3): authenticated public-key encryption for data that does not fit in memory or arrives in pieces.
 * TypeScript-only (quantum-safe-py cannot read it) and experimental until reviewed.
 *
 * One KEM encapsulation per stream; the data is cut into fixed-size chunks, each sealed with AES-256-GCM under a key derived from the KEM shared
 * secret and the stream header, with a counter and a "last chunk" flag in the nonce (the STREAM construction). Chunks cannot be reordered,
 * duplicated or dropped from the middle, and a truncated stream fails because its final chunk was not sealed as the last one.
 *
 * Wire layout: `"QSS3"` | `u32 header length` | header (CBOR) | then per chunk: `u32 ciphertext length` | ciphertext. All integers big endian.
 *
 * The recipient key must be a hybrid KEM key (for example `X25519+ML-KEM-768`) or `ML-KEM-1024`. Like {@link Envelope}, a stream is anonymous: it does
 * not authenticate the sender (sign separately).
 *
 * @example
 * ```ts
 * import { sealStream, openStream, HybridKEM } from 'quantum-safe-ts';
 * using pair = new HybridKEM().generateKeyPair();
 * const encrypted = sealStream(pair.publicKey, readable);          // readable: AsyncIterable<Uint8Array> (Node stream, web ReadableStream, generator)
 * const plain = openStream(pair.secretKey, encrypted);             // AsyncGenerator<Uint8Array>
 * ```
 */
import { InvalidArgumentError, MalformedCiphertextError } from './errors.js';
import { PublicKey, SecretKey } from './keys.js';
import { call } from './runtime.js';
import { bytes } from './utils.js';

const MAGIC = new Uint8Array([0x51, 0x53, 0x53, 0x33]); // "QSS3"
const TAG_LEN = 16;
/** Largest header accepted (a KEM ciphertext plus a few fixed fields). */
const MAX_HEADER_LEN = 64 * 1024;
/** Default chunk size: 64 KiB. */
export const DEFAULT_STREAM_CHUNK_SIZE = 64 * 1024;

/** Options for {@link sealStream} and {@link StreamSealer}. */
export interface SealStreamOptions {
  /** Additional authenticated data bound to every chunk. Not stored in the stream: the opener must pass the same value. */
  aad?: Uint8Array;
  /** Plaintext chunk size in bytes, 1,024 to 16,777,216 (default 65,536). */
  chunkSize?: number;
}

/** Options for {@link openStream} and {@link StreamOpener}. */
export interface OpenStreamOptions {
  /** The associated data the sender used (default: none). A mismatch fails authentication. */
  expectedAad?: Uint8Array;
}

/** Non-secret fields of a stream header. */
export interface StreamHeaderInfo {
  readonly algorithm: string;
  readonly kemCiphertextLength: number;
  readonly chunkSize: number;
}

const u32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
const readU32 = (b: Uint8Array, at: number): number => ((b[at]! << 24) | (b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!) >>> 0;

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Inspects a stream header (the CBOR bytes, not the whole prelude) without any key. */
export function inspectStreamHeader(header: Uint8Array): StreamHeaderInfo {
  return JSON.parse(call((w) => w.streamHeaderInspect(bytes(header, 'header')))) as StreamHeaderInfo;
}

/**
 * Low-level sealer: one object per stream. It owns the key and the chunk counter, so a nonce cannot be reused or skipped. Every chunk except
 * the last must be exactly `chunkSize` bytes; the last may be shorter or empty. Free it (or use `using`) when done.
 */
export class StreamSealer implements Disposable {
  readonly #h: ReturnType<typeof makeSealer>;
  /** The header bytes to send first (the recipient needs them to open the stream). */
  readonly header: Uint8Array;
  readonly chunkSize: number;

  private constructor(h: ReturnType<typeof makeSealer>) {
    this.#h = h;
    this.header = h.header;
    this.chunkSize = h.chunkSize;
  }

  static start(publicKey: PublicKey, options: SealStreamOptions = {}): StreamSealer {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    const chunkSize = options.chunkSize ?? DEFAULT_STREAM_CHUNK_SIZE;
    if (!Number.isInteger(chunkSize)) throw new InvalidArgumentError('chunkSize must be an integer.');
    return new StreamSealer(makeSealer(publicKey, bytes(options.aad ?? new Uint8Array(), 'aad'), chunkSize));
  }

  /** Seals the next chunk; pass `last = true` for the final one (exactly once). Returns the ciphertext (plaintext length + 16 bytes). */
  seal(plaintext: Uint8Array, last = false): Uint8Array {
    return call(() => this.#h.cipher.sealChunk(bytes(plaintext, 'plaintext'), last));
  }

  free(): void {
    this.#h.cipher.free();
  }
  [Symbol.dispose](): void {
    this.free();
  }
}

function makeSealer(publicKey: PublicKey, aad: Uint8Array, chunkSize: number) {
  const cipher = call((w) => w.StreamCipher.startSealing(publicKey._wasm, aad, chunkSize));
  return { cipher, header: cipher.header, chunkSize: cipher.chunkSize };
}

/** Low-level opener: feed the ciphertext of each chunk in order, saying whether it is the last one. A failure ends the stream. */
export class StreamOpener implements Disposable {
  readonly #cipher: WasmStreamCipher;
  readonly chunkSize: number;

  private constructor(cipher: WasmStreamCipher) {
    this.#cipher = cipher;
    this.chunkSize = cipher.chunkSize;
  }

  static start(secretKey: SecretKey, header: Uint8Array, options: OpenStreamOptions = {}): StreamOpener {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    const h = bytes(header, 'header').slice();
    if (h.length > MAX_HEADER_LEN) throw new MalformedCiphertextError('Stream header is too large.');
    return new StreamOpener(
      call((w) => w.StreamCipher.startOpening(secretKey._wasm, h, bytes(options.expectedAad ?? new Uint8Array(), 'expectedAad'))),
    );
  }

  /** Opens the next chunk. @throws {DecryptionAuthenticationError} if it was modified, reordered, dropped, truncated, or the key or AAD is wrong. */
  open(ciphertext: Uint8Array, last: boolean): Uint8Array {
    return call(() => this.#cipher.openChunk(bytes(ciphertext, 'ciphertext'), last));
  }

  free(): void {
    this.#cipher.free();
  }
  [Symbol.dispose](): void {
    this.free();
  }
}

/** The slice of the WebAssembly `StreamCipher` class used here. */
type WasmStreamCipher = ReturnType<typeof makeSealer>['cipher'];

/** What `sealStream` and `openStream` read from: any async or sync iterable of byte arrays (Node.js streams, web `ReadableStream`s, generators, arrays). */
export type ByteSource = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

/** Accumulates byte pieces and hands out exact-length slices without repeatedly copying the whole buffer. */
class ByteQueue {
  #pieces: Uint8Array[] = [];
  #offset = 0; // bytes already consumed from the first piece
  length = 0;

  push(piece: Uint8Array): void {
    if (piece.length === 0) return;
    this.#pieces.push(piece);
    this.length += piece.length;
  }

  /** Removes and returns exactly `n` bytes (the caller checks `length >= n`). */
  take(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let at = 0;
    while (at < n) {
      const head = this.#pieces[0]!;
      const avail = head.length - this.#offset;
      const use = Math.min(avail, n - at);
      out.set(head.subarray(this.#offset, this.#offset + use), at);
      at += use;
      this.#offset += use;
      if (this.#offset === head.length) {
        this.#pieces.shift();
        this.#offset = 0;
      }
    }
    this.length -= n;
    return out;
  }

  /** Reads a big-endian u32 at the head without consuming it (the caller checks `length >= 4`). */
  peekU32(): number {
    const b = new Uint8Array(4);
    let at = 0;
    let piece = 0;
    let off = this.#offset;
    while (at < 4) {
      const head = this.#pieces[piece]!;
      const use = Math.min(head.length - off, 4 - at);
      b.set(head.subarray(off, off + use), at);
      at += use;
      piece++;
      off = 0;
    }
    return readU32(b, 0);
  }
}

/**
 * Encrypts a stream of byte chunks (any sizes) to `publicKey`. Yields the encrypted stream as an async sequence of byte pieces: the prelude
 * (magic, header), then one frame per chunk. Concatenate the pieces to store or send them. Input of any length, including none, is accepted.
 *
 * @throws {UnsupportedAlgorithmError} for a key that is not a hybrid KEM key or `ML-KEM-1024`.
 */
export async function* sealStream(publicKey: PublicKey, source: ByteSource, options: SealStreamOptions = {}): AsyncGenerator<Uint8Array> {
  using sealer = StreamSealer.start(publicKey, options);
  yield concat([MAGIC, u32(sealer.header.length), sealer.header]);
  const cs = sealer.chunkSize;
  const pending = new ByteQueue();
  for await (const piece of source) {
    pending.push(bytes(piece, 'chunk'));
    // Only emit a full chunk when MORE data exists beyond it, so that the final chunk is always known to be the last.
    while (pending.length > cs) yield frame(sealer.seal(pending.take(cs), false));
  }
  yield frame(sealer.seal(pending.take(pending.length), true));
}

function frame(ciphertext: Uint8Array): Uint8Array {
  return concat([u32(ciphertext.length), ciphertext]);
}

/**
 * Decrypts a stream produced by {@link sealStream}. The source may deliver the bytes in pieces of any size. Yields the plaintext chunk by chunk.
 * It throws on the first chunk that fails; a truncated, extended, reordered or modified stream never completes silently.
 *
 * @throws {DecryptionAuthenticationError} on authentication failure; {@link MalformedCiphertextError} for a malformed prelude or frame.
 */
export async function* openStream(secretKey: SecretKey, source: ByteSource, options: OpenStreamOptions = {}): AsyncGenerator<Uint8Array> {
  const queue = new ByteQueue();
  const iterator = (Symbol.asyncIterator in source ? (source as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]() : (source as Iterable<Uint8Array>)[Symbol.iterator]()) as
    | AsyncIterator<Uint8Array>
    | Iterator<Uint8Array>;
  let ended = false;
  /** Pulls from the source until at least `n` bytes are queued or the source ends. */
  const fill = async (n: number): Promise<void> => {
    while (!ended && queue.length < n) {
      const r = await iterator.next();
      if (r.done) ended = true;
      else queue.push(bytes(r.value, 'chunk'));
    }
  };

  await fill(8);
  if (queue.length < 8) throw new MalformedCiphertextError('Stream is too short to contain a header.');
  const magic = queue.take(4);
  if (!magic.every((b, i) => b === MAGIC[i])) throw new MalformedCiphertextError('Not a quantum-safe-ts stream (bad magic).');
  const headerLen = queue.peekU32();
  queue.take(4);
  if (headerLen === 0 || headerLen > MAX_HEADER_LEN) throw new MalformedCiphertextError('Stream header length is out of range.');
  await fill(headerLen);
  if (queue.length < headerLen) throw new MalformedCiphertextError('Stream ended inside the header.');
  const header = queue.take(headerLen);

  using opener = StreamOpener.start(secretKey, header, options);
  const maxFrame = opener.chunkSize + TAG_LEN;
  for (;;) {
    await fill(4);
    if (queue.length === 0) throw new MalformedCiphertextError('Stream ended without a final chunk (truncated).');
    if (queue.length < 4) throw new MalformedCiphertextError('Stream ended inside a frame length (truncated).');
    const len = queue.peekU32();
    if (len < TAG_LEN || len > maxFrame) throw new MalformedCiphertextError('Stream frame length is out of range.');
    // Need the whole frame AND to know whether any byte follows it (that tells whether it is the last).
    await fill(4 + len + 1);
    if (queue.length < 4 + len) throw new MalformedCiphertextError('Stream ended inside a frame (truncated).');
    queue.take(4);
    const ciphertext = queue.take(len);
    const last = queue.length === 0; // `fill` tried to read past the frame; nothing there means the source ended
    yield opener.open(ciphertext, last);
    if (last) return;
  }
}

/** Convenience: encrypts a whole buffer. Returns the complete encrypted stream as one array. */
export async function sealBytes(publicKey: PublicKey, data: Uint8Array, options: SealStreamOptions = {}): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const piece of sealStream(publicKey, [bytes(data, 'data')], options)) parts.push(piece);
  return concat(parts);
}

/** Convenience: decrypts a whole buffer produced by {@link sealBytes}. */
export async function openBytes(secretKey: SecretKey, data: Uint8Array, options: OpenStreamOptions = {}): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const piece of openStream(secretKey, [bytes(data, 'data')], options)) parts.push(piece);
  return concat(parts);
}
