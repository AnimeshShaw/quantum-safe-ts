/**
 * What omitting `expectedContext` / `expectedAad` does, and the developer-facing warnings (decision D4, audit item X-C1).
 *
 * Signatures: omitted `expectedContext` means "expect an empty context". A message that carries a context is rejected (fail closed) and a
 * warning says why; the thrown error stays the opaque `VerificationError`.
 * Envelopes: omitted `expectedAad` means "accept any AAD" (it is authenticated), and a warning is emitted when the message carries AAD.
 * Neither warning fires when the argument is passed, or when nothing is bound. Each fires once per call site, can be silenced, can be
 * routed to a handler, and never contains the context or AAD value. quantum-safe-py behaves the same.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Envelope, HybridKEM, HybridSign, Sign, VerificationError, easy, utf8, warnings } from '../src/index.js';
import type { QuantumSafeWarning } from '../src/index.js';

let seen: QuantumSafeWarning[] = [];
beforeEach(() => {
  seen = [];
  warnings.reset();
  warnings.onWarning((w) => seen.push(w));
});
afterEach(() => warnings.reset());

describe('signatures: omitted expectedContext', () => {
  for (const make of [() => new Sign('ML-DSA-44'), () => new HybridSign('Ed25519+ML-DSA-44')] as const) {
    const label = make().algorithm;
    it(`${label}: rejects a message that carries a context, and says why`, () => {
      const signer = make();
      using pair = signer.generateKeyPair();
      const sm = signer.sign(utf8('pay alice'), pair.secretKey, { context: utf8('payments') });
      expect(() => signer.verify(sm, pair.publicKey)).toThrow(VerificationError);
      expect(seen).toHaveLength(1);
      expect(seen[0]!.code).toBe('QS_CONTEXT_OMITTED');
      expect(seen[0]!.message).toMatch(/non-empty context/);
      expect(seen[0]!.message).not.toContain('payments');
    });

    it(`${label}: silent when the message carries no context`, () => {
      const signer = make();
      using pair = signer.generateKeyPair();
      const sm = signer.sign(utf8('hello'), pair.secretKey);
      signer.verify(sm, pair.publicKey);
      expect(seen).toHaveLength(0);
    });

    it(`${label}: silent when the context is passed (right or wrong)`, () => {
      const signer = make();
      using pair = signer.generateKeyPair();
      const sm = signer.sign(utf8('m'), pair.secretKey, { context: utf8('payments') });
      signer.verify(sm, pair.publicKey, { expectedContext: utf8('payments') });
      expect(() => signer.verify(sm, pair.publicKey, { expectedContext: utf8('refunds') })).toThrow(VerificationError);
      expect(seen).toHaveLength(0);
    });
  }

  it('isValid returns false and warns once, without throwing', () => {
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('m'), pair.secretKey, { context: utf8('c') });
    expect(signer.isValid(sm, pair.publicKey)).toBe(false);
    expect(seen).toHaveLength(1);
  });

  it('easy.verify without a context warns the same way', () => {
    const keys = easy.generateSigningKeys('ML-DSA-44');
    const signed = easy.sign(keys.secretKey, 'm', { context: 'purpose' });
    expect(() => easy.verify(keys.publicKey, signed)).toThrow(VerificationError);
    expect(seen.map((w) => w.code)).toEqual(['QS_CONTEXT_OMITTED']);
    expect(easy.verify(keys.publicKey, signed, { context: 'purpose' })).toEqual(utf8('m'));
    expect(seen).toHaveLength(1);
  });
});

describe('call-site dedupe, silencing, handlers', () => {
  it('warns once per call site', () => {
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('m'), pair.secretKey, { context: utf8('c') });
    for (let i = 0; i < 5; i++) {
      expect(signer.isValid(sm, pair.publicKey)).toBe(false); // one source line, five calls
    }
    expect(seen).toHaveLength(1);
    expect(signer.isValid(sm, pair.publicKey)).toBe(false); // a different line warns again
    expect(seen).toHaveLength(2);
  });

  it('can be silenced by code, and un-silenced', () => {
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('m'), pair.secretKey, { context: utf8('c') });
    warnings.silence('QS_CONTEXT_OMITTED');
    signer.isValid(sm, pair.publicKey);
    expect(seen).toHaveLength(0);
    warnings.unsilence('QS_CONTEXT_OMITTED');
    signer.isValid(sm, pair.publicKey);
    expect(seen).toHaveLength(1);
  });

  it('routes to process.emitWarning when no handler is set', () => {
    warnings.onWarning(null);
    const got: Array<{ name: string; code?: string }> = [];
    const listener = (w: Error & { code?: string }): void => {
      if (w.code === 'QS_CONTEXT_OMITTED') got.push({ name: w.name, code: w.code });
    };
    process.on('warning', listener);
    try {
      const signer = new Sign('ML-DSA-44');
      using pair = signer.generateKeyPair();
      const sm = signer.sign(utf8('m'), pair.secretKey, { context: utf8('c') });
      signer.isValid(sm, pair.publicKey);
    } finally {
      return new Promise<void>((resolve) =>
        setImmediate(() => {
          process.off('warning', listener);
          expect(got).toEqual([{ name: 'QuantumSafeWarning', code: 'QS_CONTEXT_OMITTED' }]);
          resolve();
        }),
      );
    }
  });
});

describe('envelopes: omitted expectedAad', () => {
  const kem = new HybridKEM();

  it('accepts and warns when the message carries AAD', () => {
    using pair = kem.generateKeyPair();
    const sealed = Envelope.seal(utf8('data'), pair.publicKey, { aad: utf8('tenant-secret-id') });
    expect(Envelope.open(sealed, pair.secretKey)).toEqual(utf8('data'));
    expect(seen).toHaveLength(1);
    expect(seen[0]!.code).toBe('QS_AAD_OMITTED');
    expect(seen[0]!.message).not.toContain('tenant-secret-id');
  });

  it('is silent without AAD, and silent when expectedAad is passed (and checked)', () => {
    using pair = kem.generateKeyPair();
    const plain = Envelope.seal(utf8('data'), pair.publicKey);
    expect(Envelope.open(plain, pair.secretKey)).toEqual(utf8('data'));
    const bound = Envelope.seal(utf8('data'), pair.publicKey, { aad: utf8('user-42') });
    expect(Envelope.open(bound, pair.secretKey, { expectedAad: utf8('user-42') })).toEqual(utf8('data'));
    expect(() => Envelope.open(bound, pair.secretKey, { expectedAad: utf8('user-43') })).toThrow();
    expect(seen).toHaveLength(0);
  });

  it('easy.decrypt inherits the behaviour', () => {
    const keys = easy.generateEncryptionKeys();
    const sealed = easy.encrypt(keys.publicKey, utf8('data'), { aad: 'user-42' });
    expect(easy.decrypt(keys.secretKey, sealed)).toEqual(utf8('data'));
    expect(seen.map((w) => w.code)).toEqual(['QS_AAD_OMITTED']);
  });
});
