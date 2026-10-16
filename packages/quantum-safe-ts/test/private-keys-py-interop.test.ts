/**
 * Seed keys shared with quantum-safe-py 0.4.0 (its optional `cryptography` backend): private AKP JWKs (RFC 9964 `priv` is the 32-byte seed) and
 * private COSE keys made by Python. TypeScript must derive the same public keys from the seeds, verify what Python signed, and sign with
 * Python's keys. The other direction (TypeScript's keys in Python) is scripts/gen_private_key_vectors.mjs and quantum-safe-py's
 * tests/unit/test_seed_interop.py. Also checks RFC 9964 Appendix A.1's all-zero JWKs (tests/vectors/rfc9964_jose_vectors.json).
 */
import { describe, expect, it } from 'vitest';
import { Sign, StandardJwt, cose, fromBase64Url, utf8 } from '../src/index.js';
import type { AkpJwk, MlDsaJoseAlg } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface PrivVector {
  algorithm: MlDsaJoseAlg;
  private_jwk: AkpJwk;
  public_jwk: AkpJwk;
  token: string;
  cose_private_key: string;
  cose_sign1: string;
  cose_payload: string;
}
const PY = vectors<{ vectors: PrivVector[] }>('py_private_vectors.json').vectors;

interface JoseVector {
  algorithm: MlDsaJoseAlg;
  kid: string;
  pub_b64u: string;
  priv_b64u: string;
  jws: string;
  to_be_signed_hex: string;
  signature_hex: string;
}
const JOSE = vectors<{ vectors: JoseVector[] }>('rfc9964_jose_vectors.json').vectors;

describe('RFC 9964 Appendix A.1 (JOSE)', () => {
  for (const v of JOSE) {
    it(`${v.algorithm}: the all-zero private JWK derives the RFC public JWK`, () => {
      const priv: AkpJwk = { kty: 'AKP', alg: v.algorithm, pub: v.pub_b64u, priv: v.priv_b64u, kid: v.kid };
      const pub = StandardJwt.publicJwk(priv);
      expect(pub.pub).toBe(v.pub_b64u);
      expect(pub.kid).toBe(v.kid);
      expect('priv' in pub).toBe(false);
    });

    it(`${v.algorithm}: the RFC JWS signature verifies over its signing input`, () => {
      const [hh, pp, ss] = v.jws.split('.') as [string, string, string];
      expect(utf8(`${hh}.${pp}`)).toEqual(h(v.to_be_signed_hex));
      new Sign(v.algorithm).verifyRaw(utf8(`${hh}.${pp}`), fromBase64Url(ss), fromBase64Url(v.pub_b64u));
    });
  }
});

describe('Python-made private keys', () => {
  for (const v of PY) {
    describe(v.algorithm, () => {
      it('derives the same public JWK from the seed', () => {
        const pub = StandardJwt.publicJwk(v.private_jwk);
        expect(pub.pub).toBe(v.public_jwk.pub);
      });

      it("verifies Python's token and signs a token that verifies", () => {
        expect(StandardJwt.verify(v.token, v.public_jwk).sub).toBe('from-python');
        const mine = StandardJwt.sign({ sub: 'from-ts-with-py-key' }, v.private_jwk, { expiresIn: 0 });
        expect(StandardJwt.verify(mine, v.public_jwk).sub).toBe('from-ts-with-py-key');
      });

      it("reads Python's private COSE key, verifies Python's COSE_Sign1 and signs with the key", () => {
        const decoded = cose.decodeKey(h(v.cose_private_key));
        expect(decoded.seed).toEqual(fromBase64Url(v.private_jwk.priv!));
        expect(decoded.publicKey).toEqual(fromBase64Url(v.public_jwk.pub));
        expect(cose.verify1(h(v.cose_sign1), decoded.publicKey)).toEqual(h(v.cose_payload));
        using pair = cose.keyPairFromCoseKey(h(v.cose_private_key));
        const mine = cose.sign1(utf8('signed in ts'), pair);
        expect(cose.verify1(mine, decoded.publicKey)).toEqual(utf8('signed in ts'));
      });
    });
  }
});
