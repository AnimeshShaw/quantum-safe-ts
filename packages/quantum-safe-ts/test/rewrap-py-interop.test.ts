/**
 * Re-wrap interop with quantum-safe-py 0.4.0 (`Envelope.rewrap`): Python-made re-wrapped messages open here, and the Python-sealed originals
 * re-wrap here to messages that open under the new key. The other direction (TypeScript's) is scripts/gen_rewrap_vectors.mjs and
 * quantum-safe-py's tests/unit/test_ts_rewrap_interop.py.
 */
import { describe, expect, it } from 'vitest';
import { Envelope, PublicKey, SecretKey, SealedMessage } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface Vector {
  label: string;
  from: string;
  to: string;
  plaintext: string;
  aad: string;
  old_secret_pem: string;
  new_secret_pem: string;
  new_public_pem: string;
  original: string;
  rewrapped: string;
}
const PY = vectors<{ vectors: Vector[] }>('py_rewrap_vectors.json').vectors;

describe('quantum-safe-py re-wrapped envelopes', () => {
  for (const v of PY) {
    it(`${v.label}: opens under the new key; the original re-wraps here`, () => {
      const newSecret = SecretKey.fromPem(v.new_secret_pem);
      const aad = h(v.aad);
      const pythonMoved = SealedMessage.fromBytes(h(v.rewrapped));
      expect(pythonMoved.algorithm).toBe(v.to);
      expect(Envelope.open(pythonMoved, newSecret, { expectedAad: aad })).toEqual(h(v.plaintext));

      const original = SealedMessage.fromBytes(h(v.original));
      expect(original.algorithm).toBe(v.from);
      const mine = Envelope.rewrap(original, SecretKey.fromPem(v.old_secret_pem), PublicKey.fromPem(v.new_public_pem), { expectedAad: aad });
      expect(mine.algorithm).toBe(v.to);
      expect(mine.aad).toEqual(aad);
      expect(Envelope.open(mine, newSecret, { expectedAad: aad })).toEqual(h(v.plaintext));
    });
  }
});
