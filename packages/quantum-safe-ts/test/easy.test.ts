import { describe, expect, it } from 'vitest';
import {
  DecryptionAuthenticationError,
  InvalidArgumentError,
  KeyParseError,
  PublicKey,
  QuantumSafeError,
  SecretKey,
  VerificationError,
  easy,
  toHex,
  utf8,
} from '../src/core.js';
import { h, vectors } from './helpers.js';

const V = vectors('suite_vectors.json');

describe('easy: encryption', () => {
  it('round-trips strings and bytes with the defaults', () => {
    const { publicKey, secretKey, algorithm } = easy.generateEncryptionKeys();
    expect(algorithm).toBe('X25519+ML-KEM-768');
    expect(publicKey).toContain('BEGIN QUANTUM SAFE PUBLIC KEY');
    expect(secretKey).toContain('BEGIN QUANTUM SAFE SECRET KEY');
    const sealed = easy.encrypt(publicKey, 'attack at dawn', { aad: 'msg-1' });
    expect(new TextDecoder().decode(easy.decrypt(secretKey, sealed))).toBe('attack at dawn');
    const bin = Uint8Array.of(0, 1, 2, 255);
    expect(easy.decrypt(secretKey, easy.encrypt(publicKey, bin))).toEqual(bin);
  });

  it('works for each hybrid family and X-Wing', () => {
    for (const a of ['X25519+ML-KEM-512', 'X25519+ML-KEM-1024', 'P-256+ML-KEM-768', 'X-Wing'] as const) {
      const k = easy.generateEncryptionKeys(a);
      expect(k.algorithm).toBe(a);
      expect(easy.decrypt(k.secretKey, easy.encrypt(k.publicKey, 'x'))).toEqual(utf8('x'));
    }
  });

  it('fails closed: wrong key, tampering, garbage, wrong types', () => {
    const a = easy.generateEncryptionKeys();
    const b = easy.generateEncryptionKeys();
    const sealed = easy.encrypt(a.publicKey, 'secret');
    expect(() => easy.decrypt(b.secretKey, sealed)).toThrow(QuantumSafeError);
    const bad = sealed.slice();
    bad[bad.length - 5]! ^= 1;
    expect(() => easy.decrypt(a.secretKey, bad)).toThrow(QuantumSafeError);
    expect(() => easy.encrypt('not a pem', 'x')).toThrow(KeyParseError);
    expect(() => easy.decrypt(a.secretKey, new Uint8Array(3))).toThrow(QuantumSafeError);
    expect(() => easy.encrypt(a.publicKey, 42 as never)).toThrow(InvalidArgumentError);
    // a signing key is not an encryption key
    const s = easy.generateSigningKeys();
    expect(() => easy.encrypt(s.publicKey, 'x')).toThrow(QuantumSafeError);
  });

  it("opens messages sealed by the real quantum-safe-py (fixtures), using PEM keys", () => {
    for (const e of V.envelope) {
      using sk = SecretKey.fromBytes(e.algorithm, h(e.secret_key));
      expect(toHex(easy.decrypt(sk.toPem(), h(e.sealed)))).toBe(e.plaintext);
    }
  });

  it('a wrong-key failure is an authentication error, not a crash', () => {
    const a = easy.generateEncryptionKeys();
    const b = easy.generateEncryptionKeys();
    expect(() => easy.decrypt(b.secretKey, easy.encrypt(a.publicKey, 'x'))).toThrow(DecryptionAuthenticationError);
  });
});

describe('easy: signatures', () => {
  it('signs and verifies with the default hybrid, returning the message', () => {
    const k = easy.generateSigningKeys();
    expect(k.algorithm).toBe('Ed25519+ML-DSA-65');
    const signed = easy.sign(k.secretKey, 'pay 10', { context: 'payments' });
    expect(new TextDecoder().decode(easy.verify(k.publicKey, signed, { context: 'payments' }))).toBe('pay 10');
  });

  it('pure ML-DSA and SLH-DSA also work', () => {
    for (const a of ['ML-DSA-44', 'ML-DSA-87', 'SLH-DSA-SHAKE-128f'] as const) {
      const k = easy.generateSigningKeys(a);
      expect(easy.verify(k.publicKey, easy.sign(k.secretKey, 'm'))).toEqual(utf8('m'));
    }
  });

  it('rejects a different context (replay across purposes), a different key, and tampering', () => {
    const k = easy.generateSigningKeys();
    const other = easy.generateSigningKeys();
    const signed = easy.sign(k.secretKey, 'm', { context: 'a' });
    expect(() => easy.verify(k.publicKey, signed)).toThrow(VerificationError);
    expect(() => easy.verify(k.publicKey, signed, { context: 'b' })).toThrow(VerificationError);
    expect(() => easy.verify(other.publicKey, signed, { context: 'a' })).toThrow(QuantumSafeError);
    const bad = signed.slice();
    bad[Math.floor(bad.length / 2)]! ^= 1;
    expect(() => easy.verify(k.publicKey, bad, { context: 'a' })).toThrow(QuantumSafeError);
  });

  it("verifies signed messages produced by the real quantum-safe-py (fixtures)", () => {
    for (const s of V.signatures) {
      using pub = PublicKey.fromBytes(s.algorithm, h(s.public_key));
      expect(toHex(easy.verify(pub.toPem(), h(s.signed_message), { context: h(s.context), hedged: s.hedged }))).toBe(s.message);
      expect(easy.isValid(pub.toPem(), h(s.signed_message), { context: h(s.context), hedged: !s.hedged })).toBe(false);
    }
  });
});
