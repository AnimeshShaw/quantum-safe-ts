/**
 * Streaming envelope (format v3): authenticated public-key encryption for data that does not fit in memory or arrives in pieces.
 * Byte-compatible with quantum-safe-py 1.0.0 (`quantum_safe.protocols.stream`); 0.3.x cannot read it.
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
import { NATIVE_AEAD_MIN_BYTES, nativeAead } from './native-aead.js';
import type { NativeAead } from './native-aead.js';
import { call } from './runtime.js';
import { bytes, wipe } from './utils.js';

/** The four bytes that begin every stream. */
const MAGIC = new Uint8Array([0x51, 0x53, 0x53, 0x33]); // "QSS3"
/** Length of the AES-256-GCM authentication tag appended to every chunk, in bytes. */
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
  /** The KEM algorithm of the recipient key, for example `X25519+ML-KEM-768`. */
  readonly algorithm: string;
  /** Length in bytes of the KEM ciphertext carried in the header. */
  readonly kemCiphertextLength: number;
  /** Plaintext chunk size in bytes. */
  readonly chunkSize: number;
}

/** Encodes `n` as four big-endian bytes. */
const u32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
/** Reads the four big-endian bytes of `b` starting at `at` as an unsigned integer. */
const readU32 = (b: Uint8Array, at: number): number => ((b[at]! << 24) | (b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!) >>> 0;

/** Joins `parts` into one new array, in order. */
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

/** What a stream needs to run its chunks through the native AES-256-GCM: the implementation, the stream's one-time key and its AAD. */
interface NativeChunks {
  readonly aead: NativeAead;
  readonly key: Uint8Array;
  readonly aad: Uint8Array;
}

/** Fetches the key and AAD for the native cipher, or `null` when the WebAssembly cipher should be used (no native cipher, or small chunks). */
function nativeChunks(cipher: WasmStreamCipher, chunkSize: number): NativeChunks | null {
  const aead = nativeAead();
  if (aead === null || chunkSize < NATIVE_AEAD_MIN_BYTES) return null;
  const secret = cipher.takeKey();
  try {
    return { aead, key: secret.exportBytes(), aad: cipher.aad };
  } finally {
    secret.free();
  }
}

/**
 * Inspects a stream header (the CBOR bytes, not the whole prelude) without any key.
 * @param header - The header bytes: the CBOR that follows the magic and the length field.
 * @returns The algorithm, the KEM ciphertext length and the chunk size.
 * @throws {MalformedCiphertextError} if the header is not a valid stream header.
 * @throws {UnsupportedAlgorithmError} if the header names an algorithm that streams do not support.
 * @throws {InvalidArgumentError} if `header` is not bytes.
 */
export function inspectStreamHeader(header: Uint8Array): StreamHeaderInfo {
  return JSON.parse(call((w) => w.streamHeaderInspect(bytes(header, 'header')))) as StreamHeaderInfo;
}

/**
 * Low-level sealer: one object per stream. It owns the key and the chunk counter, so a nonce cannot be reused or skipped. Every chunk except
 * the last must be exactly `chunkSize` bytes; the last may be shorter or empty. Free it (or use `using`) when done.
 *
 * Chunk cipher: when the chunk size is 16 KiB or more ({@link NATIVE_AEAD_MIN_BYTES}) and the runtime has registered a native AES-256-GCM
 * (Node.js), the chunks are encrypted with it; otherwise the WebAssembly cipher is used. The choice is made once, in {@link StreamSealer.start}.
 * Either way the output bytes are the same, and the WebAssembly core stays in charge of the stream: for each chunk it checks that the stream is
 * open and that the length is allowed, issues the nonce from its own counter, and advances the counter only after the chunk is encrypted.
 * The native path holds a copy of the stream key, which {@link StreamSealer.free} wipes.
 *
 * @example
 * ```ts
 * using sealer = StreamSealer.start(pair.publicKey, { chunkSize: 4096 });
 * const first = sealer.seal(chunk, false); // `chunk` is exactly 4096 bytes
 * const final = sealer.seal(rest, true); // `rest` is 0 to 4096 bytes
 * // `sealer.header` is what StreamOpener.start needs; `sealStream` adds the magic and the length framing around it.
 * ```
 */
export class StreamSealer implements Disposable {
  readonly #h: ReturnType<typeof makeSealer>;
  readonly #native: NativeChunks | null;
  /** The header bytes to send first (the recipient needs them to open the stream). */
  readonly header: Uint8Array;
  /** Plaintext chunk size in bytes. */
  readonly chunkSize: number;

  /** Wraps a started core cipher and selects the native or WebAssembly chunk cipher for it. */
  private constructor(h: ReturnType<typeof makeSealer>) {
    this.#h = h;
    this.#native = nativeChunks(h.cipher, h.chunkSize);
    this.header = h.header;
    this.chunkSize = h.chunkSize;
  }

  /**
   * Starts a stream to `publicKey`: encapsulates once, derives the stream key and builds the header.
   * @param publicKey - The recipient's hybrid KEM key or `ML-KEM-1024` key.
   * @param options - `aad` bound to every chunk (default none) and `chunkSize` (default 65,536 bytes; 1,024 to 16,777,216).
   * @returns A sealer; send {@link StreamSealer.header} first.
   * @throws {InvalidArgumentError} if `publicKey` is not a {@link PublicKey}, `chunkSize` is not an integer in range, or `aad` is not bytes.
   * @throws {UnsupportedAlgorithmError} if the key is not a hybrid KEM key or `ML-KEM-1024`.
   */
  static start(publicKey: PublicKey, options: SealStreamOptions = {}): StreamSealer {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    const chunkSize = options.chunkSize ?? DEFAULT_STREAM_CHUNK_SIZE;
    if (!Number.isInteger(chunkSize)) throw new InvalidArgumentError('chunkSize must be an integer.');
    return new StreamSealer(makeSealer(publicKey, bytes(options.aad ?? new Uint8Array(), 'aad'), chunkSize));
  }

  /**
   * Seals the next chunk; pass `last = true` for the final one (exactly once). Returns the ciphertext (plaintext length + 16 bytes).
   *
   * The core checks the length (exactly `chunkSize` bytes unless `last`, then 0 to `chunkSize`) and that the stream is still open. After the
   * last chunk the sealer refuses further calls.
   * @param plaintext - The chunk to seal.
   * @param last - True for the final chunk of the stream.
   * @returns The ciphertext followed by the 16-byte tag.
   * @throws {InvalidArgumentError} if `plaintext` is not bytes, its length is not allowed, the stream is already finished, or the chunk counter
   * is exhausted.
   */
  seal(plaintext: Uint8Array, last = false): Uint8Array {
    const data = bytes(plaintext, 'plaintext');
    const native = this.#native;
    const cipher = this.#h.cipher;
    if (native === null) return call(() => cipher.sealChunk(data, last));
    // The core checks the length and the state and issues the nonce; the native cipher encrypts; the core then advances its counter.
    const nonce = call(() => cipher.prepareSeal(data.length, last));
    const out = native.aead.encrypt(native.key, nonce, native.aad, data);
    call(() => cipher.commit(last));
    return out;
  }

  /** Wipes the native key copy, if any, and releases the core cipher and its key. */
  free(): void {
    if (this.#native !== null) wipe(this.#native.key);
    this.#h.cipher.free();
  }
  /** Calls {@link StreamSealer.free}, so the sealer can be declared with `using`. */
  [Symbol.dispose](): void {
    this.free();
  }
}

/** Starts a sealing cipher in the core and returns it with its header and chunk size. */
function makeSealer(publicKey: PublicKey, aad: Uint8Array, chunkSize: number) {
  const cipher = call((w) => w.StreamCipher.startSealing(publicKey._wasm, aad, chunkSize));
  return { cipher, header: cipher.header, chunkSize: cipher.chunkSize };
}

/**
 * Low-level opener: feed the ciphertext of each chunk in order, saying whether it is the last one. A failure ends the stream.
 *
 * Chunk cipher: as for {@link StreamSealer}, a chunk size of 16 KiB or more on a runtime with a registered native AES-256-GCM (Node.js) uses
 * it, and otherwise the WebAssembly cipher is used; the choice is made once, in {@link StreamOpener.start}. In both cases the core checks the
 * ciphertext length and the stream state, owns the counter and issues the nonce. When the native cipher reports an authentication failure, the
 * core opens the same chunk itself, so the error comes from the core and the stream ends exactly as it does on the WebAssembly path. The
 * native path holds a copy of the stream key, which {@link StreamOpener.free} wipes.
 *
 * @example
 * ```ts
 * using opener = StreamOpener.start(pair.secretKey, header);
 * const plain = opener.open(ciphertext, true); // a single-chunk stream
 * ```
 */
export class StreamOpener implements Disposable {
  readonly #cipher: WasmStreamCipher;
  readonly #native: NativeChunks | null;
  /** Plaintext chunk size in bytes, read from the stream header. */
  readonly chunkSize: number;

  /** Wraps a started core cipher and selects the native or WebAssembly chunk cipher for it. */
  private constructor(cipher: WasmStreamCipher) {
    this.#cipher = cipher;
    this.chunkSize = cipher.chunkSize;
    this.#native = nativeChunks(cipher, cipher.chunkSize);
  }

  /**
   * Starts opening a stream: parses and validates the header, decapsulates, and derives the stream key.
   * @param secretKey - The recipient's KEM secret key.
   * @param header - The header bytes (the CBOR after the magic and length field), at most 65,536 bytes.
   * @param options - `expectedAad`, the associated data the sender used (default none).
   * @returns An opener ready for the first chunk.
   * @throws {InvalidArgumentError} if `secretKey` is not a {@link SecretKey}, or `header` or `expectedAad` is not bytes.
   * @throws {MalformedCiphertextError} if the header is longer than 65,536 bytes or is not a valid stream header.
   * @throws {AlgorithmMismatchError} if the header's algorithm differs from the key's.
   * @throws {UnsupportedAlgorithmError} if the header names an algorithm that streams do not support.
   */
  static start(secretKey: SecretKey, header: Uint8Array, options: OpenStreamOptions = {}): StreamOpener {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    const h = bytes(header, 'header').slice();
    if (h.length > MAX_HEADER_LEN) throw new MalformedCiphertextError('Stream header is too large.');
    return new StreamOpener(
      call((w) => w.StreamCipher.startOpening(secretKey._wasm, h, bytes(options.expectedAad ?? new Uint8Array(), 'expectedAad'))),
    );
  }

  /**
   * Opens the next chunk.
   *
   * `last` must be true exactly for the final chunk: it is part of the nonce, so a stream cut short fails authentication. A ciphertext of a
   * length the core does not allow ends the stream.
   * @param ciphertext - One chunk's ciphertext and tag: exactly `chunkSize + 16` bytes, or 16 to `chunkSize + 16` bytes for the last chunk.
   * @param last - True when this is the final chunk.
   * @returns The plaintext of the chunk.
   * @throws {DecryptionAuthenticationError} if it was modified, reordered, dropped, truncated, or the key or AAD is wrong.
   * @throws {MalformedCiphertextError} if the ciphertext length is not allowed for this chunk.
   * @throws {InvalidArgumentError} if `ciphertext` is not bytes or the stream has already ended.
   */
  open(ciphertext: Uint8Array, last: boolean): Uint8Array {
    const data = bytes(ciphertext, 'ciphertext');
    const native = this.#native;
    const cipher = this.#cipher;
    if (native === null) return call(() => cipher.openChunk(data, last));
    const nonce = call(() => cipher.prepareOpen(data.length, last));
    const plain = native.aead.decrypt(native.key, nonce, native.aad, data);
    // On failure the core opens the same chunk itself: it raises its own error and ends the stream.
    if (plain === null) return call(() => cipher.openChunk(data, last));
    call(() => cipher.commit(last));
    return plain;
  }

  /** Wipes the native key copy, if any, and releases the core cipher and its key. */
  free(): void {
    if (this.#native !== null) wipe(this.#native.key);
    this.#cipher.free();
  }
  /** Calls {@link StreamOpener.free}, so the opener can be declared with `using`. */
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
  /** Number of bytes currently queued. */
  length = 0;

  /** Appends `piece` (without copying it); empty pieces are ignored. The caller must not change `piece` afterwards. */
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
 * Input is re-cut into chunks of `chunkSize` bytes. A full chunk is sealed only once more data has arrived behind it, so the final chunk, which
 * holds the remaining 0 to `chunkSize` bytes, is always sealed as the last one. The sealer is freed when the generator finishes or is closed.
 * @param publicKey - The recipient's hybrid KEM key or `ML-KEM-1024` key.
 * @param source - The plaintext, as an async or sync iterable of byte arrays.
 * @param options - `aad` and `chunkSize` (see {@link SealStreamOptions}).
 * @returns An async generator of the encrypted pieces.
 * @throws {UnsupportedAlgorithmError} for a key that is not a hybrid KEM key or `ML-KEM-1024`.
 * @throws {InvalidArgumentError} for a `chunkSize` that is not an integer from 1,024 to 16,777,216, or a piece of `source` that is not bytes.
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

/** Prefixes `ciphertext` with its length as a big-endian u32: one chunk frame of the wire format. */
function frame(ciphertext: Uint8Array): Uint8Array {
  return concat([u32(ciphertext.length), ciphertext]);
}

/**
 * Decrypts a stream produced by {@link sealStream}. The source may deliver the bytes in pieces of any size. Yields the plaintext chunk by chunk.
 * It throws on the first chunk that fails; a truncated, extended, reordered or modified stream never completes silently.
 *
 * The prelude is read first (magic, then the header length, which must be 1 to 65,536); each frame length must be 16 to `chunkSize + 16`. A
 * frame is the last one when the source has no byte after it. The opener is freed when the generator finishes, throws or is closed.
 * @param secretKey - The recipient's KEM secret key.
 * @param source - The encrypted stream, as an async or sync iterable of byte arrays of any sizes.
 * @param options - `expectedAad`, the associated data the sender used (default none).
 * @returns An async generator of the plaintext chunks.
 * @throws {DecryptionAuthenticationError} on authentication failure; {@link MalformedCiphertextError} for a malformed prelude or frame.
 * @throws {AlgorithmMismatchError} if the header's algorithm differs from the key's.
 * @throws {UnsupportedAlgorithmError} if the header names an algorithm that streams do not support.
 * @throws {InvalidArgumentError} if `secretKey` is not a {@link SecretKey} or a piece of `source` is not bytes.
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

  try {
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
  } finally {
    // The consumer stopped early or a chunk failed: release the source (a file handle, a socket) instead of leaving it open.
    if (!ended) await iterator.return?.();
  }
}

/**
 * Convenience: encrypts a whole buffer. Returns the complete encrypted stream as one array.
 * @param publicKey - The recipient's hybrid KEM key or `ML-KEM-1024` key.
 * @param data - The plaintext.
 * @param options - `aad` and `chunkSize` (see {@link SealStreamOptions}).
 * @returns The encrypted stream (prelude and frames) in one array.
 * @throws {UnsupportedAlgorithmError} for a key that is not a hybrid KEM key or `ML-KEM-1024`.
 * @throws {InvalidArgumentError} for a `chunkSize` outside 1,024 to 16,777,216 or a `data` that is not bytes.
 */
export async function sealBytes(publicKey: PublicKey, data: Uint8Array, options: SealStreamOptions = {}): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const piece of sealStream(publicKey, [bytes(data, 'data')], options)) parts.push(piece);
  return concat(parts);
}

/**
 * Convenience: decrypts a whole buffer produced by {@link sealBytes}.
 * @param secretKey - The recipient's KEM secret key.
 * @param data - The complete encrypted stream.
 * @param options - `expectedAad`, the associated data the sender used (default none).
 * @returns The plaintext in one array.
 * @throws {DecryptionAuthenticationError} on authentication failure; {@link MalformedCiphertextError} for a malformed or truncated stream.
 * @throws {AlgorithmMismatchError} if the stream's algorithm differs from the key's.
 * @throws {InvalidArgumentError} if `secretKey` is not a {@link SecretKey} or `data` is not bytes.
 */
export async function openBytes(secretKey: SecretKey, data: Uint8Array, options: OpenStreamOptions = {}): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const piece of openStream(secretKey, [bytes(data, 'data')], options)) parts.push(piece);
  return concat(parts);
}
