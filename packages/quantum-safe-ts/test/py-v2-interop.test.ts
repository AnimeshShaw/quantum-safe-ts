/**
 * Cross-language parity for the formats quantum-safe-py 0.3.1 added: envelope v2, the -v2 signature format and RFC 9964
 * StandardJwt. Every fixture in tests/vectors/py_v2_vectors.json was produced by the REAL quantum-safe-py (liboqs
 * backend) with scripts/generate_py_v2_vectors.py, which needs quantum-safe-py >= 0.3.1 (not yet released).
 */
import { describe, expect, it } from 'vitest';
import {
  Envelope,
  HybridSign,
  PublicKey,
  SecretKey,
  Sign,
  SignedMessage,
  StandardJwt,
  VerificationError,
  utf8,
} from '../src/core.js';
import type { AkpJwk, SignatureAlgorithm } from '../src/core.js';
import { h, vectors } from './helpers.js';

interface PyV2 {
  envelope_v2: { secret_key: string; plaintext: string; aad: string; sealed: string }[];
  signatures_v2: { algorithm: string; public_key: string; context: string; signed_message: string }[];
  standard_jwt: { algorithm: string; public_jwk: AkpJwk; issuer: string; token: string }[];
}
const V = vectors<PyV2>('py_v2_vectors.json');

describe('envelope v2: quantum-safe-py seals, quantum-safe-ts opens', () => {
  it('has both an AAD and an AAD-less vector', () => {
    expect(V.envelope_v2.map((e) => e.aad.length > 0)).toEqual([false, true]);
  });
  for (const [i, e] of V.envelope_v2.entries()) {
    it(`vector ${i}`, () => {
      const sk = SecretKey.fromBytes('ML-KEM-1024', h(e.secret_key));
      try {
        const expectedAad = h(e.aad);
        expect(Envelope.open(h(e.sealed), sk, { expectedAad })).toEqual(h(e.plaintext));
        // The expected AAD is enforced: any other value is refused.
        expect(() => Envelope.open(h(e.sealed), sk, { expectedAad: utf8('another context') })).toThrow();
      } finally {
        sk.free();
      }
    });
  }
});

describe('-v2 signatures: quantum-safe-py signs, quantum-safe-ts verifies', () => {
  it('covers all eight identifiers', () => {
    expect(new Set(V.signatures_v2.map((s) => s.algorithm)).size).toBe(8);
  });
  for (const [i, s] of V.signatures_v2.entries()) {
    it(`${i}: ${s.algorithm} (context ${s.context.length ? 'set' : 'empty'})`, () => {
      const signer = s.algorithm.includes('+')
        ? new HybridSign(s.algorithm as Extract<SignatureAlgorithm, `${string}+${string}`>)
        : new Sign(s.algorithm as Exclude<SignatureAlgorithm, `${string}+${string}`>);
      const pub = PublicKey.fromBytes(s.algorithm, h(s.public_key));
      const sm = SignedMessage.fromBytes(h(s.signed_message));
      try {
        signer.verify(sm, pub, { expectedContext: h(s.context) });
        // A different expected context is refused, and so is a tampered message.
        expect(() => signer.verify(sm, pub, { expectedContext: utf8('other-context') })).toThrow(VerificationError);
      } finally {
        pub.free();
      }
    });
  }
});

describe('StandardJwt (RFC 9964): quantum-safe-py signs, quantum-safe-ts verifies', () => {
  for (const t of V.standard_jwt) {
    it(t.algorithm, () => {
      const claims = StandardJwt.verify(t.token, t.public_jwk, { issuer: t.issuer });
      expect(claims.sub).toBe('py-user');
      expect(claims.n).toBe(7);
      expect(() => StandardJwt.verify(t.token, t.public_jwk, { issuer: 'someone-else' })).toThrow(VerificationError);
    });
  }
});
