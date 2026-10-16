/**
 * The default hybrid signature suite is `Ed25519+ML-DSA-65-v2` (roadmap 0.2.0, decision D5), in step with quantum-safe-py 0.4.0.
 *
 * `-v2` has no hedging prefix, signs a domain-separated wrapped message under FIPS 204's native context and is byte-compatible with
 * quantum-safe-py. The previous default format stays reachable under its own identifier and its signatures keep verifying when it is
 * named. The two formats are never confused.
 */
import { describe, expect, it } from 'vitest';
import { AlgorithmMismatchError, DEFAULT_HYBRID_SIGNATURE, HybridSign, easy, utf8 } from '../src/index.js';

describe('default hybrid signature suite', () => {
  it('is the -v2 format', () => {
    expect(DEFAULT_HYBRID_SIGNATURE).toBe('Ed25519+ML-DSA-65-v2');
    expect(new HybridSign().algorithm).toBe('Ed25519+ML-DSA-65-v2');
  });

  it('signs and verifies, and the message names the v2 suite', () => {
    const signer = new HybridSign();
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('hello'), pair.secretKey, { context: utf8('ctx') });
    expect(sm.algorithm).toBe('Ed25519+ML-DSA-65-v2');
    signer.verify(sm, pair.publicKey, { expectedContext: utf8('ctx') });
  });

  it('the previous default is available by name and keeps verifying', () => {
    const old = new HybridSign('Ed25519+ML-DSA-65');
    expect(old.algorithm).toBe('Ed25519+ML-DSA-65');
    using pair = old.generateKeyPair();
    const sm = old.sign(utf8('legacy'), pair.secretKey, { context: utf8('c') });
    old.verify(sm, pair.publicKey, { expectedContext: utf8('c') });
  });

  it('hedged: false without a suite selects the original format (v2 is always hedged)', () => {
    const s = new HybridSign(undefined, { hedged: false });
    expect(s.algorithm).toBe('Ed25519+ML-DSA-65');
    expect(s.hedged).toBe(false);
  });

  it('formats are not confused in either direction', () => {
    const old = new HybridSign('Ed25519+ML-DSA-65');
    const cur = new HybridSign();
    using kOld = old.generateKeyPair();
    using kNew = cur.generateKeyPair();
    const smOld = old.sign(utf8('m'), kOld.secretKey, { context: utf8('c') });
    const smNew = cur.sign(utf8('m'), kNew.secretKey, { context: utf8('c') });
    expect(() => cur.verify(smOld, kOld.publicKey, { expectedContext: utf8('c') })).toThrow(AlgorithmMismatchError);
    expect(() => old.verify(smNew, kNew.publicKey, { expectedContext: utf8('c') })).toThrow(AlgorithmMismatchError);
    expect(() => cur.sign(utf8('m'), kOld.secretKey)).toThrow(AlgorithmMismatchError);
  });

  it('the easy layer follows the default', () => {
    const keys = easy.generateSigningKeys();
    expect(keys.algorithm).toBe('Ed25519+ML-DSA-65-v2');
    const signed = easy.sign(keys.secretKey, 'doc', { context: 'c' });
    expect(easy.verify(keys.publicKey, signed, { context: 'c' })).toEqual(utf8('doc'));
  });
});
