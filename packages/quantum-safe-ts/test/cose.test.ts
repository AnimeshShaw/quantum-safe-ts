/**
 * COSE_Sign1 with ML-DSA and AKP COSE keys (RFC 9964, the COSE half; the JOSE half is StandardJwt).
 *
 * Independent known answers: tests/vectors/rfc9964_cose_vectors.json is RFC 9964 Appendix A (ML-DSA-44/65/87: an all-zero-seed key, a
 * COSE_Sign1 with the key id in the protected header, and the exact bytes that are signed). Signing is hedged, so the RFC's signature
 * bytes cannot be reproduced; the RFC's signed bytes (the Sig_structure) and public key (from the all-zero seed) must be, and the
 * RFC's signatures must verify.
 */
import { describe, expect, it } from 'vitest';
import { Sign, VerificationError, cose, utf8 } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface RfcVector {
  algorithm: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
  cose_alg: number;
  seed: string;
  kid: string;
  public_key: string;
  payload: string;
  sign1: string;
  to_be_signed: string;
  signature: string;
}
const RFC = vectors<{ vectors: RfcVector[] }>('rfc9964_cose_vectors.json').vectors;
const PAYLOAD = utf8('hello post quantum signatures');

describe('RFC 9964 Appendix A', () => {
  for (const v of RFC) {
    describe(v.algorithm, () => {
      it('verifies the RFC signature and returns the payload', () => {
        expect(cose.verify1(h(v.sign1), h(v.public_key))).toEqual(PAYLOAD);
      });

      it('the all-zero seed derives the RFC public key', () => {
        const signer = new Sign(v.algorithm);
        using pair = signer.standardKeyPairFromSeed(h(v.seed));
        expect(pair.publicKey).toEqual(h(v.public_key));
      });

      it('builds the RFC to-be-signed bytes from the RFC protected header', () => {
        const info = cose.inspectSign1(h(v.sign1));
        expect(info.algorithm).toBe(v.algorithm);
        expect(info.coseAlg).toBe(v.cose_alg);
        expect(info.kid).toEqual(h(v.kid));
        expect(info.tagged).toBe(true);
        expect(cose.sigStructure(info.protectedHeader, PAYLOAD)).toEqual(h(v.to_be_signed));
      });

      it('our COSE_Sign1 with the same seed, key id and payload signs the same bytes and verifies', () => {
        const signer = new Sign(v.algorithm);
        using pair = signer.standardKeyPairFromSeed(h(v.seed));
        const blob = cose.sign1(PAYLOAD, pair, { kid: h(v.kid) });
        const info = cose.inspectSign1(blob);
        expect(cose.sigStructure(info.protectedHeader, PAYLOAD)).toEqual(h(v.to_be_signed));
        expect(cose.verify1(blob, pair.publicKey)).toEqual(PAYLOAD);
        // the RFC's own protected header is byte-identical to ours
        expect(info.protectedHeader).toEqual(cose.inspectSign1(h(v.sign1)).protectedHeader);
      });

      it('rejects changed external AAD, payload, signature', () => {
        const data = h(v.sign1);
        expect(() => cose.verify1(data, h(v.public_key), { externalAad: utf8('x') })).toThrow(VerificationError);
        const bad = Uint8Array.from(data);
        bad[bad.length - 1] = bad[bad.length - 1]! ^ 1; // last signature byte
        expect(() => cose.verify1(bad, h(v.public_key))).toThrow(VerificationError);
      });
    });
  }
});

describe('sign1 / verify1', () => {
  const signer = new Sign('ML-DSA-65');

  it('round-trips tagged and untagged', () => {
    using pair = signer.generateStandardKeyPair();
    const tagged = cose.sign1(utf8('m'), pair, { kid: utf8('key-1') });
    const untagged = cose.sign1(utf8('m'), pair, { tagged: false });
    expect(cose.inspectSign1(tagged).tagged).toBe(true);
    expect(cose.inspectSign1(untagged).tagged).toBe(false);
    expect(cose.verify1(tagged, pair.publicKey)).toEqual(utf8('m'));
    expect(cose.verify1(untagged, pair.publicKey)).toEqual(utf8('m'));
  });

  it('binds external AAD', () => {
    using pair = signer.generateStandardKeyPair();
    const blob = cose.sign1(utf8('m'), pair, { externalAad: utf8('ctx') });
    expect(cose.verify1(blob, pair.publicKey, { externalAad: utf8('ctx') })).toEqual(utf8('m'));
    expect(() => cose.verify1(blob, pair.publicKey)).toThrow(VerificationError);
  });

  it('supports a detached payload', () => {
    using pair = signer.generateStandardKeyPair();
    const blob = cose.sign1(utf8('big document'), pair, { detached: true });
    expect(cose.inspectSign1(blob).detached).toBe(true);
    expect(cose.verify1(blob, pair.publicKey, { detachedPayload: utf8('big document') })).toEqual(utf8('big document'));
    expect(() => cose.verify1(blob, pair.publicKey, { detachedPayload: utf8('other') })).toThrow(VerificationError);
    expect(() => cose.verify1(blob, pair.publicKey)).toThrow();
  });

  it('refuses another key and another level', () => {
    using a = signer.generateStandardKeyPair();
    using b = signer.generateStandardKeyPair();
    using other = new Sign('ML-DSA-44').generateStandardKeyPair();
    const blob = cose.sign1(utf8('m'), a);
    expect(() => cose.verify1(blob, b.publicKey)).toThrow(VerificationError);
    expect(() => cose.verify1(blob, other.publicKey)).toThrow();
  });

  it('is strict about structure', () => {
    using pair = signer.generateStandardKeyPair();
    const good = cose.sign1(utf8('m'), pair);
    const bads: Uint8Array[] = [
      new Uint8Array(0),
      new Uint8Array([0xff]),
      new Uint8Array([...good, 0]), // trailing bytes
      new Uint8Array([0x83, 0x40, 0xa0, 0x40]), // three elements
      new Uint8Array([0xd8, 0x62, 0x84, 0x40, 0xa0, 0x40, 0x40]), // tag 98 (COSE_Sign)
      new Uint8Array([0x84, 0x41, 0xa0, 0xa0, 0x40, 0x40]), // protected = h'a0'? algorithm missing
    ];
    for (const bad of bads) expect(() => cose.verify1(bad, pair.publicKey)).toThrow();
  });
});

describe('COSE keys', () => {
  for (const v of RFC) {
    it(`${v.algorithm}: public key encodes to the RFC shape and decodes back`, () => {
      const encoded = cose.encodeKey(v.algorithm, h(v.public_key), { kid: h(v.kid) });
      const decoded = cose.decodeKey(encoded);
      expect(decoded.algorithm).toBe(v.algorithm);
      expect(decoded.publicKey).toEqual(h(v.public_key));
      expect(decoded.kid).toEqual(h(v.kid));
      expect(decoded.seed).toBeUndefined();
    });

    it(`${v.algorithm}: a private key carries the 32-byte seed in label -2`, () => {
      const signer = new Sign(v.algorithm);
      using pair = signer.standardKeyPairFromSeed(h(v.seed));
      const encoded = cose.encodePrivateKey(pair, { kid: h(v.kid) });
      const decoded = cose.decodeKey(encoded);
      expect(decoded.seed).toEqual(h(v.seed));
      expect(decoded.publicKey).toEqual(h(v.public_key));
      using back = cose.keyPairFromCoseKey(encoded);
      expect(back.publicKey).toEqual(h(v.public_key));
    });
  }

  it('rejects malformed keys', () => {
    const v = RFC[0]!;
    const pub = h(v.public_key);
    const ok = cose.encodeKey(v.algorithm, pub);
    expect(cose.decodeKey(ok).algorithm).toBe('ML-DSA-44');
    expect(() => cose.decodeKey(new Uint8Array([0x01]))).toThrow();
    expect(() => cose.encodeKey('ML-DSA-44', pub.slice(1))).toThrow();
  });
});
