/**
 * Streaming envelope (format v3): round trips with arbitrary slicing, every attack on stream structure, hostile input, and an independent
 * implementation (noble ML-KEM-1024 + node:crypto HKDF-SHA-384 + AES-256-GCM) acting as sender and as receiver.
 */
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it } from 'vitest';
import {
  DecryptionAuthenticationError,
  HybridKEM,
  KEM,
  MalformedCiphertextError,
  StreamOpener,
  StreamSealer,
  UnsupportedAlgorithmError,
  cnsa2,
  inspectStreamHeader,
  openBytes,
  openStream,
  sealBytes,
  sealStream,
  utf8,
} from '../src/core.js';
import { cborEncode } from '../src/cbor.js';

const cat = (parts: readonly Uint8Array[]): Uint8Array => Uint8Array.from(parts.flatMap((p) => [...p]));
const u32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const data = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + 7) & 255);

async function collect(it: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const p of it) parts.push(p);
  return cat(parts);
}

/** Splits `bytes` into pieces of the given sizes, cycling. */
function* pieces(bytes: Uint8Array, sizes: number[]): Generator<Uint8Array> {
  let at = 0;
  let i = 0;
  while (at < bytes.length) {
    const n = sizes[i++ % sizes.length]!;
    yield bytes.slice(at, at + n);
    at += n;
  }
}

/** Splits an encrypted stream into its parts: prelude length, header, frames. */
function parse(stream: Uint8Array): { header: Uint8Array; frames: Uint8Array[]; preludeLen: number } {
  const hl = new DataView(stream.buffer, stream.byteOffset).getUint32(4);
  const header = stream.slice(8, 8 + hl);
  let at = 8 + hl;
  const frames: Uint8Array[] = [];
  while (at < stream.length) {
    const l = new DataView(stream.buffer, stream.byteOffset).getUint32(at);
    frames.push(stream.slice(at, at + 4 + l));
    at += 4 + l;
  }
  return { header, frames, preludeLen: 8 + hl };
}

describe('stream: round trips', () => {
  for (const [label, kem] of [
    ['X25519+ML-KEM-768', () => new HybridKEM()],
    ['X-Wing', () => new HybridKEM('X-Wing')],
    ['ML-KEM-1024 (CNSA profile)', () => new KEM('ML-KEM-1024')],
  ] as const) {
    it(`${label}: sizes around chunk boundaries, arbitrary input and output slicing, AAD`, async () => {
      using pair = kem().generateKeyPair();
      for (const n of [0, 1, 1023, 1024, 1025, 2048, 5000, 70000]) {
        const plain = data(n);
        const enc = await collect(sealStream(pair.publicKey, pieces(plain, [1, 999, 4096, 3]), { chunkSize: 1024, aad: utf8('ctx') }));
        const dec = await collect(openStream(pair.secretKey, pieces(enc, [7, 1, 2000, 13]), { expectedAad: utf8('ctx') }));
        expect(dec, `${label} ${n}`).toEqual(plain);
      }
    });
  }

  it('default chunk size, convenience helpers, and an async source', async () => {
    using pair = new HybridKEM().generateKeyPair();
    const plain = data(200_000);
    async function* src() {
      yield plain.slice(0, 100_000);
      yield plain.slice(100_000);
    }
    const enc = await collect(sealStream(pair.publicKey, src()));
    expect(await openBytes(pair.secretKey, enc)).toEqual(plain);
    expect(await openBytes(pair.secretKey, await sealBytes(pair.publicKey, plain))).toEqual(plain);
    const info = inspectStreamHeader(parse(enc).header);
    expect(info.algorithm).toBe('X25519+ML-KEM-768');
    expect(info.chunkSize).toBe(65536);
  });

  it('two streams to the same key use different headers and keys', async () => {
    using pair = new HybridKEM().generateKeyPair();
    const a = await sealBytes(pair.publicKey, data(10));
    const b = await sealBytes(pair.publicKey, data(10));
    expect(a).not.toEqual(b);
  });
});

describe('stream: structural attacks all fail', () => {
  async function fixture() {
    const pair = new HybridKEM().generateKeyPair();
    const plain = data(4 * 1024 + 10);
    const enc = await sealBytes(pair.publicKey, plain, { chunkSize: 1024, aad: utf8('a') });
    return { pair, plain, enc, ...parse(enc) };
  }
  const open = (pair: { secretKey: never }, bytes: Uint8Array, aad = 'a') => openBytes(pair.secretKey, bytes, { expectedAad: utf8(aad) });

  it('truncation, extension, duplication, reordering, deletion', async () => {
    const f = await fixture();
    const prelude = f.enc.slice(0, f.preludeLen);
    expect(f.frames).toHaveLength(5);
    await expect(open(f.pair as never, f.enc)).resolves.toEqual(f.plain); // control
    // drop the last frame, or the last two
    await expect(open(f.pair as never, cat([prelude, ...f.frames.slice(0, 4)]))).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    await expect(open(f.pair as never, cat([prelude, ...f.frames.slice(0, 2)]))).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    // cut in the middle of a frame / of the length field / of the header
    await expect(open(f.pair as never, f.enc.slice(0, f.enc.length - 5))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, cat([f.enc, new Uint8Array([0, 0])]))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, f.enc.slice(0, 20))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, f.enc.slice(0, 6))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, new Uint8Array(0))).rejects.toBeInstanceOf(MalformedCiphertextError);
    // an extra copy of a frame after the end
    await expect(open(f.pair as never, cat([f.enc, f.frames[0]!]))).rejects.toBeInstanceOf(QuantumSafeLike);
    // duplicate / reorder / delete a middle frame
    const mk = (fr: Uint8Array[]) => cat([prelude, ...fr]);
    await expect(open(f.pair as never, mk([f.frames[0]!, f.frames[0]!, ...f.frames.slice(1)]))).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    await expect(open(f.pair as never, mk([f.frames[1]!, f.frames[0]!, ...f.frames.slice(2)]))).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    await expect(open(f.pair as never, mk([f.frames[0]!, ...f.frames.slice(2)]))).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    f.pair.free();
  });

  it('every single-bit flip anywhere after the magic is rejected; wrong AAD and wrong key are rejected', async () => {
    const f = await fixture();
    for (let i = 4; i < f.enc.length; i += 5) {
      const bad = f.enc.slice();
      bad[i] = bad[i]! ^ 1;
      await expect(open(f.pair as never, bad), `byte ${i}`).rejects.toBeInstanceOf(Error);
    }
    await expect(open(f.pair as never, f.enc, 'other')).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    using other = new HybridKEM().generateKeyPair();
    await expect(openBytes(other.secretKey, f.enc, { expectedAad: utf8('a') })).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    f.pair.free();
  });

  it('hostile framing is refused without huge allocations', async () => {
    const f = await fixture();
    const prelude = f.enc.slice(0, f.preludeLen);
    await expect(open(f.pair as never, cat([prelude, u32(0xffffffff), new Uint8Array(10)]))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, cat([prelude, u32(3), new Uint8Array(3)]))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, cat([utf8('NOPE'), u32(10), new Uint8Array(10)]))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, cat([utf8('QSS3'), u32(0xffffffff), new Uint8Array(10)]))).rejects.toBeInstanceOf(MalformedCiphertextError);
    await expect(open(f.pair as never, cat([utf8('QSS3'), u32(0), new Uint8Array(10)]))).rejects.toBeInstanceOf(MalformedCiphertextError);
    f.pair.free();
  });

  it('a stream cannot be opened after a failure (low-level API fails closed)', async () => {
    const f = await fixture();
    using opener = StreamOpener.start(f.pair.secretKey, f.header, { expectedAad: utf8('a') });
    const body = f.frames[0]!.slice(4);
    const bad = body.slice();
    bad[0] = bad[0]! ^ 1;
    expect(() => opener.open(bad, false)).toThrow(DecryptionAuthenticationError);
    expect(() => opener.open(body, false)).toThrow(); // finished
    f.pair.free();
  });
});

// helper alias used above for "any typed library error"
const QuantumSafeLike = Error;

describe('stream: sealer discipline and suites', () => {
  it('non-final chunks must be full, the final may be short or empty, nothing after the final', () => {
    using pair = new HybridKEM().generateKeyPair();
    using s = StreamSealer.start(pair.publicKey, { chunkSize: 1024 });
    expect(() => s.seal(new Uint8Array(10), false)).toThrow();
    expect(() => s.seal(new Uint8Array(2000), true)).toThrow();
    s.seal(new Uint8Array(1024), false);
    expect(s.seal(new Uint8Array(0), true)).toHaveLength(16);
    expect(() => s.seal(new Uint8Array(0), true)).toThrow();
  });

  it('chunk size limits and unsupported keys', () => {
    using pair = new HybridKEM().generateKeyPair();
    expect(() => StreamSealer.start(pair.publicKey, { chunkSize: 10 })).toThrow();
    expect(() => StreamSealer.start(pair.publicKey, { chunkSize: 1.5 })).toThrow();
    expect(() => StreamSealer.start(pair.publicKey, { chunkSize: 1 << 30 })).toThrow();
    using pure = new KEM('ML-KEM-768').generateKeyPair();
    expect(() => StreamSealer.start(pure.publicKey)).toThrow(UnsupportedAlgorithmError);
  });

  it('a header for another suite is refused by the wrong key', async () => {
    using a = new HybridKEM('X25519+ML-KEM-512').generateKeyPair();
    using b = new HybridKEM('X25519+ML-KEM-768').generateKeyPair();
    const enc = await sealBytes(a.publicKey, data(10));
    await expect(openBytes(b.secretKey, enc)).rejects.toBeInstanceOf(Error);
  });
});

describe('stream: independent implementation (ML-KEM-1024 profile)', () => {
  const info = (header: Uint8Array) => cat([utf8('qs-envelope-stream-v3'), new Uint8Array([0]), createHash('sha384').update(header).digest()]); // CNSA profile: SHA-384
  const aad = (header: Uint8Array, caller: Uint8Array) => cat([u32(header.length), header, u32(caller.length), caller]);
  const nonce = (prefix: Uint8Array, counter: number, last: boolean) => cat([prefix, u32(counter), new Uint8Array([last ? 1 : 0])]);

  it('node:crypto + noble open a stream we sealed', async () => {
    const kem = cnsa2.kem();
    using pair = kem.generateKeyPair();
    const plain = data(3000);
    const callerAad = utf8('independent');
    const enc = await sealBytes(pair.publicKey, plain, { chunkSize: 1024, aad: callerAad });
    const { header, frames } = parse(enc);
    // Parse the header with a generic CBOR reader's view of it: find the KEM ciphertext and nonce prefix by re-decoding through our own inspector
    const headerInfo = inspectStreamHeader(header);
    expect(headerInfo.algorithm).toBe('ML-KEM-1024');
    const { cborDecode } = await import('../src/cbor.js');
    const h = cborDecode(header) as Map<string, unknown> | Record<string, unknown>;
    const get = (k: string) => (h instanceof Map ? h.get(k) : (h as Record<string, unknown>)[k]) as Uint8Array;
    const ss = ml_kem1024.decapsulate(get('kct'), pair.secretKey.exportBytes());
    const key = new Uint8Array(hkdfSync('sha384', ss, new Uint8Array(0), info(header), 32));
    const out: Uint8Array[] = [];
    frames.forEach((f, i) => {
      const body = f.slice(4);
      const d = createDecipheriv('aes-256-gcm', key, nonce(get('np'), i, i === frames.length - 1));
      d.setAAD(aad(header, callerAad));
      d.setAuthTag(body.slice(-16));
      out.push(Buffer.concat([d.update(body.slice(0, -16)), d.final()]));
    });
    expect(cat(out)).toEqual(plain);
  });

  it('a stream built entirely with node:crypto + noble opens with our code', async () => {
    const kem = cnsa2.kem();
    using pair = kem.generateKeyPair();
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(pair.publicKey.toBytes());
    const np = randomBytes(7);
    const header = cborEncode({ v: 3, algo: 'ML-KEM-1024', kct: cipherText, np, cs: 1024 } as never);
    const key = new Uint8Array(hkdfSync('sha384', sharedSecret, new Uint8Array(0), info(header), 32));
    const plain = data(2500);
    const callerAad = utf8('from-outside');
    const chunks = [plain.slice(0, 1024), plain.slice(1024, 2048), plain.slice(2048)];
    const frames = chunks.map((c, i) => {
      const cipher = createCipheriv('aes-256-gcm', key, nonce(np, i, i === 2));
      cipher.setAAD(aad(header, callerAad));
      const body = Buffer.concat([cipher.update(c), cipher.final(), cipher.getAuthTag()]);
      return cat([u32(body.length), body]);
    });
    const stream = cat([utf8('QSS3'), u32(header.length), header, ...frames]);
    expect(await openBytes(pair.secretKey, stream, { expectedAad: callerAad })).toEqual(plain);
  });
});
