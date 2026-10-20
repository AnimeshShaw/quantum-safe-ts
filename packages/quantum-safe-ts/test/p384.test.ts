/**
 * P-384 hybrids: `P-384+ML-KEM-1024` and `P-384+ML-DSA-87` (and its `-v2` form), for estates that hold CNSA 1.0 P-384 keys. Same conventions
 * as the P-256 hybrids with the curve's own sizes: public key = SEC1 point (97 B) / raw x||y (96 B), secret key = PKCS#8 PEM text, the ECDH
 * output is used whole (48 B), ECDSA signs with SHA-384, and the `-v2` classical half is raw r||s (96 B, low-S). quantum-safe-py 1.0.0 reads
 * and writes the same bytes (p384-py-interop through the suite, stream, rewrap and v2 vectors).
 */
import { describe, expect, it } from 'vitest';
import { DecryptionAuthenticationError, Envelope, HybridKEM, HybridSign, Upgrader, VerificationError, easy, utf8 } from '../src/index.js';

const split = (packed: Uint8Array): [Uint8Array, Uint8Array] => {
  const n = (packed[0]! << 8) | packed[1]!;
  return [packed.slice(2, 2 + n), packed.slice(2 + n)];
};

describe('P-384+ML-KEM-1024', () => {
  const kem = new HybridKEM('P-384+ML-KEM-1024');

  it('round-trips and has the documented sizes', () => {
    using pair = kem.generateKeyPair();
    expect(pair.publicKey.algorithm).toBe('P-384+ML-KEM-1024');
    const [c, p] = split(pair.publicKey.toBytes());
    expect(c.length).toBe(97);
    expect(p.length).toBe(1568);
    const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
    using ss = sharedSecret;
    using again = kem.decapsulate(pair.secretKey, ciphertext);
    expect(again.exportBytes()).toEqual(ss.exportBytes());
  });

  it('the secret key holds the classical half as PKCS#8 PEM text, as the P-256 hybrids do', () => {
    using pair = kem.generateKeyPair();
    const [c] = split(pair.secretKey.exportBytes());
    expect(new TextDecoder().decode(c)).toContain('BEGIN PRIVATE KEY');
  });

  it('other ML-KEM levels are not offered for P-384', () => {
    expect(() => new HybridKEM('P-384+ML-KEM-768' as never)).toThrow();
    expect(() => new HybridKEM('P-384+ML-KEM-512' as never)).toThrow();
  });

  it('seals, opens, and moves a P-256 envelope to a P-384 key', () => {
    using p384 = kem.generateKeyPair();
    const sealed = Envelope.seal(utf8('secret'), p384.publicKey, { aad: utf8('x') });
    expect(sealed.algorithm).toBe('P-384+ML-KEM-1024');
    expect(Envelope.open(sealed, p384.secretKey, { expectedAad: utf8('x') })).toEqual(utf8('secret'));
    expect(() => Envelope.open(sealed, p384.secretKey, { expectedAad: utf8('y') })).toThrow(DecryptionAuthenticationError);
    using p256 = new HybridKEM('P-256+ML-KEM-768').generateKeyPair();
    const old = Envelope.seal(utf8('migrate'), p256.publicKey);
    const moved = Envelope.rewrap(old, p256.secretKey, p384.publicKey);
    expect(Envelope.open(moved, p384.secretKey)).toEqual(utf8('migrate'));
  });

  it('works through the easy layer', () => {
    const { publicKey, secretKey } = easy.generateEncryptionKeys('P-384+ML-KEM-1024');
    expect(new TextDecoder().decode(easy.decrypt(secretKey, easy.encrypt(publicKey, 'hello p384')))).toBe('hello p384');
  });

  it('upgrades a P-384 key (PKCS#8 PEM secret, 97-byte public point) and the hybrid key works', () => {
    using base = kem.generateKeyPair();
    const [cPub] = split(base.publicKey.toBytes());
    const [cSec] = split(base.secretKey.exportBytes());
    const r = Upgrader.upgradeKemKey({ classicalSecret: cSec, classicalPublic: cPub, classicalAlgorithm: 'P-384', targetPqc: 'ML-KEM-1024' });
    using up = r.keyPair;
    expect(r.newAlgorithm).toBe('P-384+ML-KEM-1024');
    const { ciphertext, sharedSecret } = kem.encapsulate(up.publicKey);
    using ss = sharedSecret;
    using rec = kem.decapsulate(up.secretKey, ciphertext);
    expect(rec.exportBytes()).toEqual(ss.exportBytes());
  });
});

describe('P-384+ML-DSA-87', () => {
  it('v1: signs and verifies with a context, refuses another, and has a 96-byte classical public key', () => {
    const signer = new HybridSign('P-384+ML-DSA-87');
    using pair = signer.generateKeyPair();
    const [c] = split(pair.publicKey.toBytes());
    expect(c.length).toBe(96);
    const sm = signer.sign(utf8('payload'), pair.secretKey, { context: utf8('ctx') });
    signer.verify(sm, pair.publicKey, { expectedContext: utf8('ctx') });
    expect(() => signer.verify(sm, pair.publicKey, { expectedContext: utf8('other') })).toThrow(VerificationError);
  });

  it('v2: a 96 + 4627 byte blob that verifies, and tampering is refused', () => {
    const signer = new HybridSign('P-384+ML-DSA-87-v2');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('payload'), pair.secretKey);
    expect(sm.signature.length).toBe(96 + 4627);
    signer.verify(sm, pair.publicKey);
    const bad = sm.signature.slice();
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    const forged = signer.sign(utf8('payload'), pair.secretKey);
    expect(() => signer.verify({ ...forged, signature: bad } as never, pair.publicKey)).toThrow();
  });

  it('only ML-DSA-87 is offered for P-384', () => {
    expect(() => new HybridSign('P-384+ML-DSA-65' as never)).toThrow();
    expect(() => new HybridSign('P-384+ML-DSA-44' as never)).toThrow();
  });

  it('upgrades a P-384 signing key (raw x||y public)', () => {
    const signer = new HybridSign('P-384+ML-DSA-87');
    using base = signer.generateKeyPair();
    const [cPub] = split(base.publicKey.toBytes());
    const [cSec] = split(base.secretKey.exportBytes());
    const r = Upgrader.upgradeSigningKey({ classicalSecret: cSec, classicalPublic: cPub, classicalAlgorithm: 'P-384', targetPqc: 'ML-DSA-87' });
    using up = r.keyPair;
    const signed = signer.sign(utf8('p384 upgrade'), up.secretKey);
    expect(() => signer.verify(signed, up.publicKey)).not.toThrow();
  });
});
