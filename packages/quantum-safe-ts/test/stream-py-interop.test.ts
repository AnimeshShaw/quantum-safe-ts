/**
 * Streaming envelopes (format v3) made by the REAL quantum-safe-py (>= 1.0.0, `quantum_safe.protocols.stream`): scripts/generate_py_stream_vectors.py.
 * TypeScript must open every one, including the pure ML-KEM-1024 (HKDF-SHA-384) and X-Wing suites, with the caller AAD the sender used.
 * The other direction (TypeScript seals, Python opens) is scripts/gen_stream_vectors.mjs and quantum-safe-py's tests/unit/test_stream.py.
 */
import { describe, expect, it } from 'vitest';
import { DecryptionAuthenticationError, SecretKey, openBytes } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface StreamVector {
  algorithm: string;
  secret_key: string;
  aad: string;
  plaintext: string;
  stream: string;
}
const PY = vectors<{ vectors: StreamVector[] }>('py_stream_vectors.json').vectors;

describe('quantum-safe-py streaming envelopes open in TypeScript', () => {
  it('cover every supported suite and the chunk boundaries', () => {
    expect(new Set(PY.map((v) => v.algorithm))).toEqual(new Set(['X25519+ML-KEM-768', 'P-256+ML-KEM-512', 'P-384+ML-KEM-1024', 'ML-KEM-1024', 'X-Wing']));
    expect(new Set(PY.map((v) => h(v.plaintext).length))).toEqual(new Set([0, 1, 1024, 1025, 2048, 3000]));
  });

  for (const [i, v] of PY.entries()) {
    it(`${v.algorithm}, ${h(v.plaintext).length} bytes [${i}]`, async () => {
      const sk = SecretKey.fromBytes(v.algorithm, h(v.secret_key));
      try {
        const plain = await openBytes(sk, h(v.stream), { expectedAad: h(v.aad) });
        expect(plain).toEqual(h(v.plaintext));
      } finally {
        sk.free();
      }
    });
  }

  it('a wrong AAD fails authentication', async () => {
    const v = PY.find((x) => x.aad !== '')!;
    const sk = SecretKey.fromBytes(v.algorithm, h(v.secret_key));
    try {
      await expect(openBytes(sk, h(v.stream), { expectedAad: new Uint8Array([1]) })).rejects.toBeInstanceOf(DecryptionAuthenticationError);
    } finally {
      sk.free();
    }
  });
});
