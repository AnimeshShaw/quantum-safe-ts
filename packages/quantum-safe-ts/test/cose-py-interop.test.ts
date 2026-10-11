/**
 * COSE_Sign1 messages made by the REAL quantum-safe-py (>= 0.4.0, `quantum_safe.protocols.cose`): scripts/generate_py_cose_vectors.py.
 * TypeScript must verify every one (tagged, untagged, detached, with external AAD). The other direction (TypeScript signs, Python verifies)
 * is scripts/gen_cose_vectors.mjs and quantum-safe-py's tests/unit/test_cose.py; RFC 9964's own examples are in cose.test.ts.
 */
import { describe, expect, it } from 'vitest';
import { cose } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface CoseVector {
  algorithm: string;
  case: string;
  public_key: string;
  external_aad: string;
  payload: string;
  detached: boolean;
  message: string;
}
const PY = vectors<{ vectors: CoseVector[] }>('py_cose_vectors.json').vectors;

describe('quantum-safe-py COSE_Sign1 verifies in TypeScript', () => {
  it('covers every level and option', () => {
    expect(new Set(PY.map((v) => v.algorithm))).toEqual(new Set(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']));
    expect(new Set(PY.map((v) => v.case))).toEqual(new Set(['tagged with kid', 'untagged', 'external aad', 'detached', 'empty payload']));
  });
  for (const [i, v] of PY.entries()) {
    it(`${v.algorithm}: ${v.case} [${i}]`, () => {
      const opts = { externalAad: h(v.external_aad), ...(v.detached ? { detachedPayload: h(v.payload) } : {}) };
      expect(cose.verify1(h(v.message), h(v.public_key), opts)).toEqual(h(v.payload));
    });
  }
});
