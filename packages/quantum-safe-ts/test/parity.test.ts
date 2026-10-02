/**
 * Cross-language parity against the REAL quantum-safe-py (liboqs backend), through the WASM
 * artifact. Every fixture in tests/vectors/suite_vectors.json was produced by
 * scripts/generate_suite_vectors.py.
 */
import { describe, expect, it } from 'vitest';
import {
  Envelope,
  HybridKEM,
  HybridSign,
  JWTVerifier,
  KEM,
  KeyPair,
  PublicKey,
  SealedMessage,
  SecretKey,
  Sign,
  SignedMessage,
  toHex,
  utf8,
} from '../src/core.js';
import type { KemAlgorithm, SignatureAlgorithm } from '../src/core.js';
import { h, vectors } from './helpers.js';

const V = vectors('suite_vectors.json');

describe('KEM: every quantum-safe-py ciphertext decapsulates to the same secret', () => {
  for (const k of V.kem) {
    it(k.algorithm, () => {
      const kem = k.algorithm.includes('+')
        ? new HybridKEM(k.algorithm as KemAlgorithm)
        : new KEM(k.algorithm);
      using secret = SecretKey.fromBytes(k.algorithm, h(k.secret_key));
      using shared = kem.decapsulate(secret, h(k.ciphertext));
      expect(toHex(shared.exportBytes())).toBe(k.shared_secret);
      // We can encapsulate to python's public key, and python's secret key can open it.
      using pub = PublicKey.fromBytes(k.algorithm, h(k.public_key));
      const enc = kem.encapsulate(pub);
      using back = kem.decapsulate(secret, enc.ciphertext);
      expect(toHex(back.exportBytes())).toBe(toHex(enc.sharedSecret.exportBytes()));
      enc.sharedSecret.free();
    });
  }
});

describe('Envelope: every quantum-safe-py sealed message opens', () => {
  for (const e of V.envelope) {
    it(e.algorithm, () => {
      using secret = SecretKey.fromBytes(e.algorithm, h(e.secret_key));
      const sealed = SealedMessage.fromBytes(h(e.sealed));
      expect(sealed.algorithm).toBe(e.algorithm);
      expect(toHex(sealed.aad)).toBe(e.aad);
      expect(toHex(Envelope.open(sealed, secret))).toBe(e.plaintext);
      // The hex form (to_hex in python) round-trips as well.
      expect(SealedMessage.fromHex(sealed.toHex()).toHex()).toBe(e.sealed);
    });
  }
  it('the original single-suite envelope vector from the glue fixtures still opens', () => {
    const g = vectors('glue_vectors.json').envelope_roundtrip;
    using secret = SecretKey.fromBytes(g.algorithm, h(g.secret_key));
    expect(toHex(Envelope.open(SealedMessage.fromBytes(h(g.sealed)), secret))).toBe(g.plaintext);
  });
});

describe('Key serialization is byte-identical to quantum-safe-py', () => {
  for (const k of V.keys) {
    it(k.algorithm, () => {
      using pub = PublicKey.fromCbor(h(k.public_cbor));
      using sec = SecretKey.fromCbor(h(k.secret_cbor));
      expect(toHex(pub.toBytes())).toBe(k.public_raw);
      expect(toHex(sec.exportBytes())).toBe(k.secret_raw);
      expect(pub.migrationState).toBe(k.migration_state);
      expect(toHex(pub.toCbor())).toBe(k.public_cbor);
      expect(toHex(sec.toCbor())).toBe(k.secret_cbor);
      expect(pub.toPem()).toBe(k.public_pem);
      expect(sec.toPem()).toBe(k.secret_pem);
      expect(JSON.parse(pub.toJwk())).toEqual(k.public_jwk);
      expect(pub.fingerprint()).toBe(k.fingerprint);
      expect(pub.fingerprintColon()).toBe(k.fingerprint_colon);
      using fromPem = PublicKey.fromPem(k.public_pem);
      expect(fromPem.fingerprint()).toBe(k.fingerprint);
      using fromJwk = PublicKey.fromJwk(k.public_jwk);
      expect(fromJwk.fingerprint()).toBe(k.fingerprint);
      using fromSecretPem = SecretKey.fromPem(k.secret_pem);
      expect(toHex(fromSecretPem.exportBytes())).toBe(k.secret_raw);
      using bundle = KeyPair.fromCborBundle(h(k.bundle));
      expect(toHex(bundle.toCborBundle())).toBe(k.bundle);
    });
  }
});

describe('Signatures: every quantum-safe-py signature verifies', () => {
  for (const s of V.signatures) {
    const label = `${s.algorithm} hedged=${s.hedged}`;
    const signer = s.algorithm.includes('+')
      ? new HybridSign(s.algorithm as never)
      : new Sign(s.algorithm as never);
    it(label, () => {
      using pub = PublicKey.fromBytes(s.algorithm, h(s.public_key));
      const sm = SignedMessage.fromCbor(h(s.signed_message));
      expect(toHex(sm.message)).toBe(s.message);
      expect(toHex(sm.context)).toBe(s.context);
      expect(toHex(sm.signature)).toBe(s.signature_blob);
      expect(sm.signature[0] === 32).toBe(s.hedged);
      signer.verify(sm, pub);
      // Negative control: a flipped message byte must fail.
      const bad = SignedMessage.fromParts({
        message: Uint8Array.from(sm.message, (b, i) => (i === 0 ? b ^ 1 : b)),
        signature: sm.signature,
        algorithm: sm.algorithm,
        context: sm.context,
        isHybrid: sm.isHybrid,
      });
      expect(() => signer.verify(bad, pub)).toThrowError(/verification/i);
    });
    it(`${label}: a python secret key signs messages that verify here`, () => {
      using sec = SecretKey.fromBytes(s.algorithm, h(s.secret_key));
      using pub = PublicKey.fromBytes(s.algorithm, h(s.public_key));
      const sm = signer.sign(utf8('signed by ts with a py key'), sec, { context: utf8('c') });
      signer.verify(sm, pub);
    });
  }
});

describe('JWT (quantum-safe-py mode): python-issued tokens verify', () => {
  for (const t of V.jwt) {
    it(t.algorithm, () => {
      using pub = PublicKey.fromBytes(t.algorithm, h(t.public_key));
      const claims = new JWTVerifier(pub, { issuer: t.issuer }).verify(t.token);
      expect(claims.sub).toBe('user-123');
      expect(claims.role).toBe('admin');
      expect(claims.iss).toBe(t.issuer);
      // Wrong issuer, wrong context and a tampered token are all rejected.
      expect(() => new JWTVerifier(pub, { issuer: 'https://evil.example' }).verify(t.token)).toThrowError(/verification/i);
      expect(() => new JWTVerifier(pub).verify(t.token, { context: utf8('other') })).toThrowError(/verification/i);
      const [hd, pl, sg] = t.token.split('.');
      const forged = `${hd}.${btoa(JSON.stringify({ sub: 'attacker' })).replace(/=+$/, '')}.${sg}`;
      expect(() => new JWTVerifier(pub).verify(forged)).toThrowError(/verification/i);
      expect(pl.length).toBeGreaterThan(0);
    });
  }
});
