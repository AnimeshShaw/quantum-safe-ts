/**
 * X-Wing against the REAL quantum-safe-py (>= 0.4.0, `quantum_safe.kem.xwing.XWing`).
 *
 * tests/vectors/py_xwing_vectors.json is made by scripts/generate_py_xwing_vectors.py. TypeScript must decapsulate Python's ciphertexts to
 * Python's shared secrets, and a ciphertext it makes for a Python public key must decapsulate under the Python secret key (so both
 * halves of the key derivation agree). The other direction (TypeScript makes, Python decapsulates) is scripts/gen_xwing_vectors.mjs and
 * quantum-safe-py's tests/unit/test_xwing.py.
 */
import { describe, expect, it } from 'vitest';
import { HybridKEM, PublicKey, SecretKey } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface XwVector {
  secret_key: string;
  public_key: string;
  ciphertext: string;
  shared_secret: string;
}
const PY = vectors<{ vectors: XwVector[] }>('py_xwing_vectors.json').vectors;
const kem = new HybridKEM('X-Wing');

describe('quantum-safe-py X-Wing', () => {
  it('is not a vacuous fixture', () => {
    expect(PY.length).toBeGreaterThanOrEqual(12);
    expect(new Set(PY.map((v) => v.public_key)).size).toBeGreaterThanOrEqual(6);
  });

  for (const [i, v] of PY.entries()) {
    it(`decapsulates Python's ciphertext to Python's shared secret [${i}]`, () => {
      const sk = SecretKey.fromBytes('X-Wing', h(v.secret_key));
      try {
        const ss = kem.decapsulate(sk, h(v.ciphertext));
        try {
          expect(ss.exportBytes()).toEqual(h(v.shared_secret));
        } finally {
          ss.free();
        }
      } finally {
        sk.free();
      }
    });

    it(`a ciphertext made for Python's public key decapsulates under Python's secret key [${i}]`, () => {
      const pk = PublicKey.fromBytes('X-Wing', h(v.public_key));
      const sk = SecretKey.fromBytes('X-Wing', h(v.secret_key));
      try {
        const { ciphertext, sharedSecret } = kem.encapsulate(pk);
        const back = kem.decapsulate(sk, ciphertext);
        try {
          expect(back.exportBytes()).toEqual(sharedSecret.exportBytes());
        } finally {
          back.free();
          sharedSecret.free();
        }
      } finally {
        sk.free();
        pk.free?.();
      }
    });
  }
});
