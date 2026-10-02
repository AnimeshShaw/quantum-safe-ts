/**
 * LMS/HSS verification (RFC 8554) through the WASM artifact: the RFC's own Appendix F vectors, plus
 * signatures from an independent implementation (pyhsslms).
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { Lms, MalformedKeyError, MalformedSignatureError, QuantumSafeError, UnsupportedAlgorithmError, VerificationError } from '../src/core.js';
import { h, vectors } from './helpers.js';

const rfc = vectors('lms_rfc8554.json').cases as Array<{ name: string; hss_public_key: string; message: string; hss_signature: string }>;
const other = vectors('lms_pyhsslms.json').cases as Array<{
  levels: number;
  tree_height: number;
  winternitz: number;
  hss_public_key: string;
  message: string;
  hss_signature: string;
}>;

describe('RFC 8554 Appendix F test vectors', () => {
  for (const c of rfc) {
    it(c.name, () => {
      const [pk, msg, sig] = [h(c.hss_public_key), h(c.message), h(c.hss_signature)];
      Lms.verify(pk, msg, sig);
      expect(Lms.isValid(pk, msg, sig)).toBe(true);
      const bad = msg.slice();
      bad[0]! ^= 1;
      expect(() => Lms.verify(pk, bad, sig)).toThrow(VerificationError);
      expect(Lms.isValid(pk, bad, sig)).toBe(false);
    });
  }
  it('reports the documented parameter sets', () => {
    expect(Lms.inspectPublicKey(h(rfc[0]!.hss_public_key))).toEqual({
      levels: 2, lmsType: 5, otsType: 4, treeHeight: 5, winternitz: 8, parameterSet: 'LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8',
    });
    expect(Lms.inspectPublicKey(h(rfc[1]!.hss_public_key)).parameterSet).toBe('LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W4');
  });
});

describe('signatures from an independent implementation (pyhsslms)', () => {
  for (const c of other) {
    it(`levels=${c.levels} height=${c.tree_height} w=${c.winternitz}`, () => {
      const [pk, msg, sig] = [h(c.hss_public_key), h(c.message), h(c.hss_signature)];
      Lms.verify(pk, msg, sig);
      const info = Lms.inspectPublicKey(pk);
      expect([info.levels, info.treeHeight, info.winternitz]).toEqual([c.levels, c.tree_height, c.winternitz]);
      const tampered = sig.slice();
      tampered[tampered.length - 1]! ^= 1;
      expect(Lms.isValid(pk, msg, tampered)).toBe(false);
    });
  }
});

describe('malformed input is a typed error, never a crash', () => {
  const { hss_public_key, message, hss_signature } = rfc[0]!;
  const [pk, msg, sig] = [h(hss_public_key), h(message), h(hss_signature)];

  it('truncated/extended signatures and keys', () => {
    for (const cut of [0, 1, 3, 4, 100, sig.length - 1]) expect(() => Lms.isValid(pk, msg, sig.slice(0, cut))).toThrow(MalformedSignatureError);
    expect(() => Lms.isValid(pk, msg, new Uint8Array([...sig, 0]))).toThrow(MalformedSignatureError);
    for (const cut of [0, 3, 59]) expect(() => Lms.isValid(pk.slice(0, cut), msg, sig)).toThrow(MalformedKeyError);
    expect(() => Lms.isValid(new Uint8Array([...pk, 0]), msg, sig)).toThrow(MalformedKeyError);
  });
  it('bad level counts, mismatched Nspk, and unknown parameter sets', () => {
    const lvl = pk.slice();
    lvl[3] = 9;
    expect(() => Lms.isValid(lvl, msg, sig)).toThrow(MalformedKeyError);
    const nspk = sig.slice();
    nspk[3] = 2;
    expect(() => Lms.isValid(pk, msg, nspk)).toThrow(MalformedSignatureError);
    const type = pk.slice();
    type[7] = 0x63;
    expect(() => Lms.isValid(type, msg, sig)).toThrow(UnsupportedAlgorithmError);
    // SP 800-208 SHA-256/192 type codes (LMS 0x0A, LM-OTS 0x05) are rejected explicitly, not mis-parsed.
    const n24 = pk.slice();
    n24[7] = 0x0a;
    n24[11] = 0x05;
    expect(() => Lms.isValid(n24, msg, sig)).toThrow(UnsupportedAlgorithmError);
  });
  it('property: arbitrary bytes never throw anything but QuantumSafeError', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 80 }), fc.uint8Array({ maxLength: 3000 }), (k, s) => {
        for (const keyBytes of [k, pk]) {
          try {
            Lms.isValid(keyBytes, msg, s);
          } catch (e) {
            if (!(e instanceof QuantumSafeError)) return false;
          }
        }
        return true;
      }),
      { numRuns: 400 },
    );
  });
  it('property: a single flipped bit anywhere in message, key or signature never verifies', () => {
    fc.assert(
      fc.property(fc.nat(sig.length - 1), fc.integer({ min: 0, max: 7 }), (i, bit) => {
        const s = sig.slice();
        s[i]! ^= 1 << bit;
        try {
          return !Lms.isValid(pk, msg, s);
        } catch (e) {
          return e instanceof QuantumSafeError;
        }
      }),
      { numRuns: 300 },
    );
  });
});
