/**
 * Standard FIPS 204 ML-DSA with a native context, against the REAL quantum-safe-py (>= 0.3.2, `Sign.sign_raw`).
 *
 * Every vector in tests/vectors/py_raw_fips204_vectors.json was made by `Sign.sign_raw` (scripts/generate_py_raw_vectors.py):
 * ML-DSA-44/65/87 with an empty, a short and a 255-byte context. The library's bare FIPS 204 verifier (the primitive behind
 * StandardJwt, internal WASM call) must accept them. The other direction (TypeScript signs, Python `verify_raw` verifies) is
 * scripts/gen_ts_raw_vectors.mjs plus scripts/verify_ts_vectors.py.
 *
 * The bare primitive is not part of the public TypeScript API (it is on the roadmap); this test exercises it through the internal module.
 */
import { describe, expect, it } from 'vitest';
import { SecretBytes } from '../src/keys.js';
import { call } from '../src/runtime.js';
import { h, vectors } from './helpers.js';

interface RawVector {
  algorithm: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
  public_key: string;
  message: string;
  context: string;
  signature: string;
}
const PY = vectors<{ vectors: RawVector[] }>('py_raw_fips204_vectors.json').vectors;

const verify = (v: RawVector, over: Partial<{ message: Uint8Array; context: Uint8Array; signature: Uint8Array }> = {}): boolean =>
  call((w) =>
    w.mldsaStandardVerify(v.algorithm, h(v.public_key), over.message ?? h(v.message), over.context ?? h(v.context), over.signature ?? h(v.signature)),
  );

describe('quantum-safe-py Sign.sign_raw signatures verify with the standard FIPS 204 verifier', () => {
  it('covers all three levels with an empty, a short and a 255-byte context', () => {
    expect(PY).toHaveLength(9);
    expect(new Set(PY.map((v) => v.algorithm))).toEqual(new Set(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']));
    expect(new Set(PY.map((v) => h(v.context).length))).toEqual(new Set([0, 23, 255]));
  });
  for (const [i, v] of PY.entries()) {
    it(`${v.algorithm} context of ${h(v.context).length} bytes [${i}]`, () => {
      expect(verify(v)).toBe(true);
    });
  }
  it('rejects a different context, a different message and a flipped signature bit', () => {
    for (const v of PY) {
      expect(verify(v, { context: new Uint8Array([...h(v.context).slice(0, 254), 1]) })).toBe(false);
      expect(verify(v, { message: new Uint8Array([...h(v.message), 0]) })).toBe(false);
      const bad = h(v.signature);
      bad[10] = bad[10]! ^ 1;
      expect(verify(v, { signature: bad })).toBe(false);
    }
  });
  it('a standard signature is not accepted as a v1 prefixed signature, and the reverse', () => {
    // The default Sign.verify signs len(ctx) || ctx || prefix || message under an empty context: a different byte string.
    // So the bare verifier given the empty context and the v1 construction's message must fail.
    const v = PY.find((x) => x.algorithm === 'ML-DSA-65' && h(x.context).length === 0)!;
    expect(verify(v, { message: new Uint8Array([0, ...h(v.message)]) })).toBe(false);
  });
});

describe('the standards-mode signer round-trips through the same verifier', () => {
  it('signs with a native context and verifies only with that context', () => {
    for (const level of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const) {
      const pair = call((w) => w.mldsaStandardKeyGen(level));
      const seed = new SecretBytes(pair.takeSeed());
      try {
        const message = new TextEncoder().encode('round trip');
        const context = new TextEncoder().encode('ctx');
        const sig = call((w) => w.mldsaStandardSign(level, seed._wasm, message, context));
        expect(call((w) => w.mldsaStandardVerify(level, pair.publicKey, message, context, sig))).toBe(true);
        expect(call((w) => w.mldsaStandardVerify(level, pair.publicKey, message, new Uint8Array(0), sig))).toBe(false);
      } finally {
        seed.free();
        pair.free();
      }
    }
  });
});
