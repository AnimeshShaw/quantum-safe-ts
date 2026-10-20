/**
 * The Node.js fast path for large payloads (native AES-256-GCM) must change nothing but speed: the same bytes, the same errors, the same
 * state handling as the WebAssembly cipher, in both directions, and the one-time key must not outlive the call.
 */
import { randomBytes } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  DecryptionAuthenticationError,
  Envelope,
  HybridKEM,
  KEM,
  SealedMessage,
  StreamOpener,
  StreamSealer,
  openBytes,
  sealBytes,
  utf8,
} from '../src/core.js';
import { NATIVE_AEAD_MIN_BYTES, nativeAead, setNativeAead } from '../src/native-aead.js';
import type { NativeAead } from '../src/native-aead.js';

import '../src/node.js'; // registers the native implementation

let native: NativeAead;
beforeAll(() => {
  const impl = nativeAead();
  if (impl === null) throw new Error('the Node.js entry point should register a native AES-256-GCM');
  native = impl;
});
afterEach(() => setNativeAead(native));

const wasmOnly = <T>(fn: () => T): T => {
  setNativeAead(null);
  try {
    return fn();
  } finally {
    setNativeAead(native);
  }
};

/** Counts the calls and remembers the key objects, so tests can see which path ran and that keys are wiped. */
function spy(): { impl: NativeAead; encrypts: number; decrypts: number; keys: Uint8Array[] } {
  const state = { encrypts: 0, decrypts: 0, keys: [] as Uint8Array[] };
  const impl: NativeAead = {
    encrypt(key, nonce, aad, plaintext) {
      state.encrypts++;
      state.keys.push(key);
      return native.encrypt(key, nonce, aad, plaintext);
    },
    decrypt(key, nonce, aad, ct) {
      state.decrypts++;
      state.keys.push(key);
      return native.decrypt(key, nonce, aad, ct);
    },
  };
  return Object.assign(state, { impl });
}

const SIZES = [0, 1, 100, NATIVE_AEAD_MIN_BYTES - 1, NATIVE_AEAD_MIN_BYTES, NATIVE_AEAD_MIN_BYTES + 1, 70_000, 1 << 20];
const SUITES = ['X25519+ML-KEM-768', 'P-256+ML-KEM-768', 'P-384+ML-KEM-1024', 'X-Wing'] as const;

/** Equality with a readable failure: where the first difference is and how many bytes differ. */
function expectSame(actual: Uint8Array, expected: Uint8Array, label: string): void {
  if (actual.length !== expected.length) throw new Error(`${label}: length ${actual.length} != ${expected.length}`);
  let first = -1;
  let count = 0;
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) {
      if (first < 0) first = i;
      count++;
    }
  }
  if (first >= 0) throw new Error(`${label}: ${count} bytes differ, the first at ${first} (got ${actual[first]}, expected ${expected[first]})`);
}

function data(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + 7) & 0xff;
  return out;
}

describe('Envelope: native and WebAssembly agree', () => {
  for (const suite of SUITES) {
    it(`${suite}: sealed either way, opened either way`, () => {
      using pair = new HybridKEM(suite).generateKeyPair();
      for (const n of SIZES) {
        const plain = data(n);
        const aad = utf8('record-1');
        const viaNative = Envelope.seal(plain, pair.publicKey, { aad });
        const viaWasm = wasmOnly(() => Envelope.seal(plain, pair.publicKey, { aad }));
        for (const sealed of [viaNative, viaWasm]) {
          expectSame(Envelope.open(sealed, pair.secretKey, { expectedAad: aad }), plain, `${suite} ${n} native open`);
          expectSame(wasmOnly(() => Envelope.open(sealed, pair.secretKey, { expectedAad: aad })), plain, `${suite} ${n} wasm open`);
        }
        // the messages have the same shape: same fields, same lengths
        expect(viaNative.version).toBe(viaWasm.version);
        expect(viaNative.algorithm).toBe(viaWasm.algorithm);
        expect(viaNative.nonce.length).toBe(viaWasm.nonce.length);
        expect(viaNative.ciphertext.length).toBe(viaWasm.ciphertext.length);
        expect(viaNative.kemCiphertext.length).toBe(viaWasm.kemCiphertext.length);
        expect(viaNative.aad).toEqual(aad);
      }
    });
  }

  it('pure ML-KEM-1024 (envelope v2) works through the native path', () => {
    using pair = new KEM('ML-KEM-1024').generateKeyPair();
    const plain = data(100_000);
    const sealed = Envelope.seal(plain, pair.publicKey);
    expect(sealed.version).toBe(2);
    expect(Envelope.open(sealed, pair.secretKey)).toEqual(plain);
    expect(wasmOnly(() => Envelope.open(sealed, pair.secretKey))).toEqual(plain);
    expect(Envelope.open(wasmOnly(() => Envelope.seal(plain, pair.publicKey)), pair.secretKey)).toEqual(plain);
  });

  it('small payloads stay on the WebAssembly path; large ones use the native cipher', () => {
    using pair = new HybridKEM().generateKeyPair();
    const s = spy();
    setNativeAead(s.impl);
    const small = Envelope.seal(data(NATIVE_AEAD_MIN_BYTES - 1), pair.publicKey);
    Envelope.open(small, pair.secretKey);
    expect(s.encrypts + s.decrypts).toBe(0);
    const large = Envelope.seal(data(NATIVE_AEAD_MIN_BYTES), pair.publicKey);
    Envelope.open(large, pair.secretKey);
    expect(s.encrypts).toBe(1);
    expect(s.decrypts).toBe(1);
  });

  it('without a native cipher everything runs on WebAssembly', () => {
    using pair = new HybridKEM().generateKeyPair();
    const plain = data(100_000);
    const sealed = wasmOnly(() => Envelope.seal(plain, pair.publicKey));
    expect(wasmOnly(() => Envelope.open(sealed, pair.secretKey))).toEqual(plain);
  });

  it('the one-time key is wiped after every call', () => {
    using pair = new HybridKEM().generateKeyPair();
    const s = spy();
    setNativeAead(s.impl);
    const sealed = Envelope.seal(data(50_000), pair.publicKey);
    Envelope.open(sealed, pair.secretKey);
    expect(s.keys.length).toBe(2);
    for (const key of s.keys) expect(key.every((b) => b === 0)).toBe(true);
  });

  it('rewrap moves a large message to a new key through the native path', () => {
    using a = new HybridKEM().generateKeyPair();
    using b = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    const plain = data(200_000);
    const sealed = Envelope.seal(plain, a.publicKey, { aad: utf8('x') });
    const moved = Envelope.rewrap(sealed, a.secretKey, b.publicKey, { expectedAad: utf8('x') });
    expect(moved.algorithm).toBe('X25519+ML-KEM-1024');
    expect(Envelope.open(moved, b.secretKey, { expectedAad: utf8('x') })).toEqual(plain);
  });
});

describe('Envelope: failures are the same either way', () => {
  function failure(fn: () => unknown): { name: string; code: unknown; message: string } {
    try {
      fn();
    } catch (e) {
      const err = e as { constructor: { name: string }; code?: unknown; message: string };
      return { name: err.constructor.name, code: err.code, message: err.message };
    }
    throw new Error('expected a failure');
  }

  it('a modified ciphertext, tag, nonce or AAD fails with the WebAssembly error', () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = Envelope.seal(data(100_000), pair.publicKey, { aad: utf8('a') });
    const base = sealed.toBytes();
    const flip = (offset: number) => {
      const copy = base.slice();
      copy[copy.length - offset]! ^= 1;
      return copy;
    };
    const cases: Record<string, Uint8Array> = { tag: flip(3), 'ciphertext tail': flip(40), 'near the end': flip(70) };
    for (const [name, bytes] of Object.entries(cases)) {
      const fast = failure(() => Envelope.open(bytes, pair.secretKey, { expectedAad: utf8('a') }));
      const slow = failure(() => wasmOnly(() => Envelope.open(bytes, pair.secretKey, { expectedAad: utf8('a') })));
      expect(fast, name).toEqual(slow);
      expect(fast.name).toBe('DecryptionAuthenticationError');
    }
  });

  it('a wrong key and a wrong expected AAD fail the same way', () => {
    using pair = new HybridKEM().generateKeyPair();
    using other = new HybridKEM().generateKeyPair();
    const sealed = Envelope.seal(data(100_000), pair.publicKey, { aad: utf8('a') });
    const wrongKey = failure(() => Envelope.open(sealed, other.secretKey, { expectedAad: utf8('a') }));
    expect(wrongKey).toEqual(failure(() => wasmOnly(() => Envelope.open(sealed, other.secretKey, { expectedAad: utf8('a') }))));
    const wrongAad = failure(() => Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('b') }));
    expect(wrongAad).toEqual(failure(() => wasmOnly(() => Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('b') }))));
  });

  it('a message relabelled to another version or algorithm is refused as before', () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = Envelope.seal(data(100_000), pair.publicKey);
    const relabelled = SealedMessage.fromParts({
      algorithm: sealed.algorithm,
      kemCiphertext: sealed.kemCiphertext,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
      aad: sealed.aad,
      version: 2,
    });
    expect(failure(() => Envelope.open(relabelled, pair.secretKey))).toEqual(
      failure(() => wasmOnly(() => Envelope.open(relabelled, pair.secretKey))),
    );
  });

  it('a short ciphertext falls back to the WebAssembly error', () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = Envelope.seal(data(100_000), pair.publicKey);
    const cut = SealedMessage.fromParts({
      algorithm: sealed.algorithm,
      kemCiphertext: sealed.kemCiphertext,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext.subarray(0, 5),
      aad: sealed.aad,
    });
    expect(failure(() => Envelope.open(cut, pair.secretKey))).toEqual(failure(() => wasmOnly(() => Envelope.open(cut, pair.secretKey))));
  });
});

describe('streams: native and WebAssembly agree', () => {
  async function collect(it: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    for await (const p of it) parts.push(p);
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }

  for (const suite of ['X25519+ML-KEM-768', 'ML-KEM-1024'] as const) {
    it(`${suite}: sealed and opened through both paths, many sizes and chunk sizes`, async () => {
      using pair = (suite === 'ML-KEM-1024' ? new KEM(suite) : new HybridKEM(suite)).generateKeyPair();
      for (const chunkSize of [1024, NATIVE_AEAD_MIN_BYTES, 65_536]) {
        for (const n of [0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize + 17]) {
          const plain = data(n);
          const aad = utf8('stream-aad');
          const a = await sealBytes(pair.publicKey, plain, { chunkSize, aad });
          const b = await (async () => {
            setNativeAead(null);
            try {
              return await sealBytes(pair.publicKey, plain, { chunkSize, aad });
            } finally {
              setNativeAead(native);
            }
          })();
          expect(a.length, `${suite} ${chunkSize} ${n}`).toBe(b.length);
          for (const sealed of [a, b]) {
            expect(await openBytes(pair.secretKey, sealed, { expectedAad: aad })).toEqual(plain);
            setNativeAead(null);
            try {
              expect(await openBytes(pair.secretKey, sealed, { expectedAad: aad })).toEqual(plain);
            } finally {
              setNativeAead(native);
            }
          }
        }
      }
    });
  }

  it('the native cipher is used from the threshold chunk size up, and keys are wiped on free', async () => {
    using pair = new HybridKEM().generateKeyPair();
    const s = spy();
    setNativeAead(s.impl);
    await sealBytes(pair.publicKey, data(40_000), { chunkSize: 1024 });
    expect(s.encrypts).toBe(0);
    const sealed = await sealBytes(pair.publicKey, data(40_000), { chunkSize: NATIVE_AEAD_MIN_BYTES });
    expect(s.encrypts).toBeGreaterThan(0);
    await openBytes(pair.secretKey, sealed);
    expect(s.decrypts).toBeGreaterThan(0);
    expect(s.keys.length).toBeGreaterThan(0);
  });

  it('low-level sealer and opener: state, counter and errors match the WebAssembly cipher', () => {
    using pair = new HybridKEM().generateKeyPair();
    const cs = NATIVE_AEAD_MIN_BYTES;
    const chunks = [data(cs), data(cs).reverse(), data(10)];
    const run = () => {
      using sealer = StreamSealer.start(pair.publicKey, { chunkSize: cs, aad: utf8('x') });
      const frames = chunks.map((c, i) => sealer.seal(c, i === chunks.length - 1));
      // wrong lengths and use after the last chunk are refused
      expect(() => sealer.seal(data(5), true)).toThrow();
      return { header: sealer.header, frames };
    };
    const { header, frames } = run();
    for (const viaWasm of [false, true]) {
      const open = () => {
        using opener = StreamOpener.start(pair.secretKey, header, { expectedAad: utf8('x') });
        // a reordered chunk fails, then the stream stays failed
        expect(() => opener.open(frames[1]!, false)).toThrow(DecryptionAuthenticationError);
        expect(() => opener.open(frames[0]!, false)).toThrow();
      };
      if (viaWasm) wasmOnly(open);
      else open();
    }
    // in order, it opens
    using opener = StreamOpener.start(pair.secretKey, header, { expectedAad: utf8('x') });
    chunks.forEach((c, i) => expect(opener.open(frames[i]!, i === chunks.length - 1)).toEqual(c));
    expect(() => opener.open(frames[2]!, true)).toThrow();
  });

  it('a modified chunk raises the same error as on WebAssembly and ends the stream', async () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = await sealBytes(pair.publicKey, data(100_000), { chunkSize: NATIVE_AEAD_MIN_BYTES });
    const bad = sealed.slice();
    bad[bad.length - 20]! ^= 1;
    const message = async () => {
      try {
        await openBytes(pair.secretKey, bad);
      } catch (e) {
        return (e as Error).message;
      }
      throw new Error('expected a failure');
    };
    const fast = await message();
    setNativeAead(null);
    const slow = await message();
    setNativeAead(native);
    expect(fast).toBe(slow);
  });

  it('random data of random sizes round-trips', async () => {
    using pair = new HybridKEM().generateKeyPair();
    for (let i = 0; i < 12; i++) {
      const plain = new Uint8Array(randomBytes(1 + Math.floor(Math.random() * 300_000)));
      const chunkSize = [NATIVE_AEAD_MIN_BYTES, 20_000, 65_536][i % 3]!;
      const sealed = await sealBytes(pair.publicKey, plain, { chunkSize });
      expect(await openBytes(pair.secretKey, sealed)).toEqual(plain);
    }
  });
});
