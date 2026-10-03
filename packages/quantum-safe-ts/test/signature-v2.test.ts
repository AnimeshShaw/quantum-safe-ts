/**
 * Signature format v2 (`<suite>-v2`): behaviour, the attacks the quantum-safe-py construction allows, and independent verification of both
 * halves (noble and Node WebCrypto for ML-DSA, node:crypto for Ed25519) from the documented definition of M2.
 */
import { createPublicKey, verify as nodeVerify, webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  AlgorithmMismatchError,
  HybridSign,
  JWTSigner,
  JWTVerifier,
  PublicKey,
  Sign,
  SignedMessage,
  VerificationError,
  cnsa2,
  sigSuites,
  utf8,
} from '../src/core.js';

const concatBytes = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(parts.flatMap((p) => [...p]));
const LABEL = utf8('quantum-safe-sig-v2');
const m2 = (algorithm: string, ctx: Uint8Array, message: Uint8Array) =>
  concatBytes(new Uint8Array([algorithm.length]), utf8(algorithm), new Uint8Array([ctx.length]), ctx, message);

const V2_NAMES = sigSuites()
  .filter((s) => s.format === 'v2')
  .map((s) => s.name);

describe('format v2: registry', () => {
  it('lists eight v2 suites, none readable by quantum-safe-py, none for SLH-DSA', () => {
    expect(V2_NAMES.sort()).toEqual(
      [
        'ML-DSA-44-v2',
        'ML-DSA-65-v2',
        'ML-DSA-87-v2',
        'Ed25519+ML-DSA-44-v2',
        'Ed25519+ML-DSA-65-v2',
        'Ed25519+ML-DSA-87-v2',
        'P-256+ML-DSA-44-v2',
        'P-256+ML-DSA-65-v2',
      ].sort(),
    );
    for (const s of sigSuites().filter((x) => x.format === 'v2')) expect(s.pyCompatible).toBe(false);
    expect(sigSuites().filter((s) => s.format !== 'v2').every((s) => !s.name.endsWith('-v2'))).toBe(true);
  });
  it('v1 suites are unchanged', () => {
    expect(sigSuites().filter((s) => s.format !== 'v2')).toHaveLength(3 + 5 + 12);
  });
});

describe('format v2: sign and verify', () => {
  for (const name of V2_NAMES) {
    it(`${name} round-trips, binds the context, and rejects tampering`, () => {
      const signer = name.includes('+') ? new HybridSign(name as never) : new Sign(name as never);
      using pair = signer.generateKeyPair();
      expect(pair.publicKey.algorithm).toBe(name);
      const sm = signer.sign(utf8('hello v2'), pair.secretKey, { context: utf8('app-1') });
      signer.verify(sm, pair.publicKey, { expectedContext: utf8('app-1') });
      // the wire object survives serialisation
      signer.verify(SignedMessage.fromCbor(sm.toCbor()), pair.publicKey, { expectedContext: utf8('app-1') });
      expect(() => signer.verify(sm, pair.publicKey)).toThrow(VerificationError); // default expected context is empty
      expect(() => signer.verify(sm, pair.publicKey, { expectedContext: utf8('app-2') })).toThrow(VerificationError);
      const flipped = sm.signature.slice();
      const at = flipped.length >> 1;
      flipped[at] = flipped[at]! ^ 1;
      expect(() => signer.verifyBytes(utf8('hello v2'), flipped, pair.publicKey, { context: utf8('app-1') })).toThrow(VerificationError);
      expect(() => signer.verifyBytes(utf8('hello v2!'), sm.signature, pair.publicKey, { context: utf8('app-1') })).toThrow(VerificationError);
      expect(() => signer.verifyBytes(utf8('hello v2'), concatBytes(sm.signature, new Uint8Array(1)), pair.publicKey, { context: utf8('app-1') })).toThrow(
        VerificationError,
      );
    });
  }

  it('hedged:false has no effect on v2 (no prefix exists) and verification does not depend on it', () => {
    const a = new Sign('ML-DSA-44-v2', { hedged: false });
    const b = new Sign('ML-DSA-44-v2');
    using pair = a.generateKeyPair();
    const sm = a.sign(utf8('m'), pair.secretKey);
    b.verify(sm, pair.publicKey);
    a.verify(sm, pair.publicKey);
  });
});

describe('format v2: the v1 attacks do not apply', () => {
  it('moving message bytes around cannot produce a valid signature on a suffix', () => {
    const signer = new HybridSign('Ed25519+ML-DSA-44-v2');
    using pair = signer.generateKeyPair();
    const message = utf8('PAY alice 5 USD\nPAY mallory 1000000 USD\n');
    const sm = signer.sign(message, pair.secretKey);
    for (let k = 1; k < message.length; k++) {
      expect(() => signer.verifyBytes(message.slice(k), sm.signature, pair.publicKey)).toThrow(VerificationError);
      // and with a "prefix" taken from the front of the blob, as the v1 forgery does
      expect(() => signer.verifyBytes(message.slice(k), concatBytes(new Uint8Array([k]), message.slice(0, k), sm.signature), pair.publicKey)).toThrow(
        VerificationError,
      );
    }
  });

  it('v1 and v2 never cross: keys are tagged, signatures differ in meaning', () => {
    const v1 = new Sign('ML-DSA-44');
    const v2 = new Sign('ML-DSA-44-v2');
    using k1 = v1.generateKeyPair();
    using k2 = v2.generateKeyPair();
    expect(() => v1.sign(utf8('m'), k2.secretKey)).toThrow(AlgorithmMismatchError);
    expect(() => v2.sign(utf8('m'), k1.secretKey)).toThrow(AlgorithmMismatchError);
    const s1 = v1.sign(utf8('m'), k1.secretKey);
    expect(() => v2.verify(s1, k2.publicKey)).toThrow(AlgorithmMismatchError);
    // forcing a v1 blob through the v2 verifier of the SAME key bytes (re-tagged) fails
    const retagged = PublicKey.fromBytes('ML-DSA-44-v2', k1.publicKey.toBytes());
    expect(() => v2.verifyBytes(utf8('m'), s1.signature, retagged)).toThrow(VerificationError);
  });

  it('there is no second spelling of the signature: appending or removing a byte fails', () => {
    const signer = new HybridSign('P-256+ML-DSA-44-v2');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('one spelling'), pair.secretKey);
    for (const sig of [sm.signature.slice(1), sm.signature.slice(0, -1), concatBytes(sm.signature, new Uint8Array([0]))]) {
      expect(() => signer.verifyBytes(utf8('one spelling'), sig, pair.publicKey)).toThrow(VerificationError);
    }
  });
});

describe('format v2: independent verification of each half', () => {
  const message = utf8('independent check');
  const ctx = utf8('ctx-1');

  it('ML-DSA-65-v2: noble ML-DSA verifies it with context quantum-safe-sig-v2 over M2', () => {
    const signer = new Sign('ML-DSA-65-v2');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(message, pair.secretKey, { context: ctx });
    const input = m2('ML-DSA-65-v2', ctx, message);
    expect(ml_dsa65.verify(sm.signature, input, pair.publicKey.toBytes(), { context: LABEL })).toBe(true);
    expect(ml_dsa65.verify(sm.signature, input, pair.publicKey.toBytes(), { context: utf8('') })).toBe(false);
    expect(ml_dsa65.verify(sm.signature, m2('ML-DSA-65-v2', utf8('other'), message), pair.publicKey.toBytes(), { context: LABEL })).toBe(false);
  });

  it('ML-DSA-65-v2: Node WebCrypto verifies it (if this Node supports ML-DSA)', async () => {
    const subtle = webcrypto.subtle as unknown as { importKey: (...a: unknown[]) => Promise<unknown>; verify: (...a: unknown[]) => Promise<boolean> };
    let key: unknown;
    try {
      const signer = new Sign('ML-DSA-65-v2');
      using pair = signer.generateKeyPair();
      const sm = signer.sign(message, pair.secretKey, { context: ctx });
      key = await subtle.importKey('raw-public', pair.publicKey.toBytes(), { name: 'ML-DSA-65' }, false, ['verify']);
      const input = m2('ML-DSA-65-v2', ctx, message);
      expect(await subtle.verify({ name: 'ML-DSA-65', context: LABEL }, key, sm.signature, input)).toBe(true);
    } catch (e) {
      if (key === undefined) return; // this Node build has no ML-DSA in WebCrypto
      throw e;
    }
  });

  it('Ed25519+ML-DSA-44-v2: both halves verify independently over the documented bytes', () => {
    const signer = new HybridSign('Ed25519+ML-DSA-44-v2');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(message, pair.secretKey, { context: ctx });
    const raw = pair.publicKey.toBytes(); // u16_be(len) || classical || pqc
    const cLen = (raw[0]! << 8) | raw[1]!;
    const cPub = raw.slice(2, 2 + cLen);
    const pPub = raw.slice(2 + cLen);
    const cSig = sm.signature.slice(0, 64);
    const pSig = sm.signature.slice(64);
    const input = m2('Ed25519+ML-DSA-44-v2', ctx, message);
    expect(ml_dsa44.verify(pSig, input, pPub, { context: LABEL })).toBe(true);
    const spki = concatBytes(Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]), cPub);
    const edKey = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    expect(nodeVerify(null, concatBytes(LABEL, new Uint8Array([0]), input), edKey, cSig)).toBe(true);
    expect(nodeVerify(null, input, edKey, cSig)).toBe(false); // the label is part of what Ed25519 signs
  });
});

describe('format v2: CNSA 2.0 reporting', () => {
  it('ML-DSA-87-v2 is evaluated like ML-DSA-87; the hybrid is partial', () => {
    expect(cnsa2.checkSignature('ML-DSA-87-v2').ok).toBe(true);
    expect(cnsa2.checkSignature('Ed25519+ML-DSA-87-v2').finding).toBe('partial');
    expect(cnsa2.checkSignature('ML-DSA-65-v2').ok).toBe(false);
    expect(cnsa2.checkSignature('SLH-DSA-SHAKE-128s-v2').ok).toBe(false);
  });
});

describe('format v2: JWT with v2 keys', () => {
  it('JWTSigner/JWTVerifier accept v2 keys and the token cannot be verified by a v1 key', () => {
    using pair = new HybridSign('Ed25519+ML-DSA-44-v2').generateKeyPair();
    const token = new JWTSigner(pair).sign({ sub: 'v2-user' }, { expiresIn: 60 });
    expect(new JWTVerifier(pair.publicKey).verify(token).sub).toBe('v2-user');
    expect(JSON.parse(new TextDecoder().decode(Uint8Array.from(Buffer.from(token.split('.')[0]!, 'base64url')))).alg).toBe('Ed25519+ML-DSA-44-v2');
    using v1 = new HybridSign('Ed25519+ML-DSA-44').generateKeyPair();
    expect(() => new JWTVerifier(v1.publicKey).verify(token)).toThrow();
  });
});
