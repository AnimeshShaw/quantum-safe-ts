/**
 * Attacks found in review, kept as permanent regression tests.
 *
 * 1. Prefix/message boundary confusion. quantum-safe-py's construction signs `len(ctx) || ctx || prefix || message` and stores the prefix
 *    length in the UNSIGNED signature blob. Without a pinned prefix length, anyone can move bytes between prefix and message of a valid
 *    signature and obtain a valid signature on a suffix (or a prefixed) message.
 * 2. Domain separation and AAD binding must be enforced by the verifier/opener, not read from the attacker-supplied container.
 * 3. Upgrader must reject a classical public key that does not belong to the secret.
 * 4. JWT signature spellings must be canonical; JWT must be able to require `exp`.
 */
import { describe, expect, it } from 'vitest';
import {
  DecryptionAuthenticationError,
  Envelope,
  HybridKEM,
  HybridSign,
  InvalidArgumentError,
  JWTSigner,
  JWTVerifier,
  PublicKey,
  QuantumSafeError,
  SealedMessage,
  Sign,
  SignedMessage,
  StandardJwt,
  Upgrader,
  VerificationError,
  easy,
  equalBytes,
  fromBase64Url,
  utf8,
} from '../src/core.js';

const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe('signature prefix/message boundary cannot be moved', () => {
  for (const [label, make] of [
    ['ML-DSA-44', () => new Sign('ML-DSA-44')],
    ['Ed25519+ML-DSA-44', () => new HybridSign('Ed25519+ML-DSA-44')],
  ] as const) {
    it(`${label}: shifting bytes between prefix and message no longer verifies (hedged)`, () => {
      const signer = make();
      using pair = signer.generateKeyPair();
      const msg = utf8('PAY alice 5 USD\nPAY mallory 1000000 USD\n');
      const sm = signer.sign(msg, pair.secretKey);
      expect(signer.isValid(sm, pair.publicKey)).toBe(true);
      const blob = sm.signature; // len(prefix)=32 || R || payload
      const R = blob.slice(1, 33);
      const payload = blob.slice(33);
      // Move the first 16 bytes of the message into the prefix slot (cut inside the message), keeping the same payload.
      const moved = new Uint8Array([48, ...R, ...msg.slice(0, 16), ...payload]);
      const forged = SignedMessage.fromParts({ message: msg.slice(16), signature: moved, algorithm: sm.algorithm, context: sm.context });
      expect(signer.isValid(forged, pair.publicKey)).toBe(false);
      // Empty the prefix and prepend R to the message.
      const empty = new Uint8Array([0, ...payload]);
      const forged2 = SignedMessage.fromParts({ message: new Uint8Array([...R, ...msg]), signature: empty, algorithm: sm.algorithm, context: sm.context });
      expect(signer.isValid(forged2, pair.publicKey)).toBe(false);
      expect(() => signer.verifyBytes(msg.slice(16), moved, pair.publicKey)).toThrow(VerificationError);
    });

    it(`${label}: an un-hedged verifier accepts only an empty prefix, and a hedged one only 32 bytes`, () => {
      const unhedged = label.includes('+') ? new HybridSign(label as never, { hedged: false }) : new Sign(label as never, { hedged: false });
      using pair = unhedged.generateKeyPair();
      const msg = utf8('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH');
      const sm = unhedged.sign(msg, pair.secretKey);
      expect(sm.signature[0]).toBe(0);
      expect(unhedged.isValid(sm, pair.publicKey)).toBe(true);
      // Un-hedged signing has no random prefix, so the boundary could be moved to forge a suffix message: refused.
      const payload = sm.signature.slice(1);
      const moved = new Uint8Array([32, ...msg.slice(0, 32), ...payload]);
      const forged = SignedMessage.fromParts({ message: msg.slice(32), signature: moved, algorithm: sm.algorithm, context: sm.context });
      expect(unhedged.isValid(forged, pair.publicKey)).toBe(false);
      const hedgedVerifier = label.includes('+') ? new HybridSign(label as never) : new Sign(label as never);
      expect(hedgedVerifier.isValid(sm, pair.publicKey)).toBe(false); // a hedged verifier needs a 32-byte prefix: each mode has one spelling
    });
  }
});

describe('verifiers enforce the expected context and AAD', () => {
  it('class verify takes the context from the caller, not from the message', () => {
    const signer = new HybridSign();
    using pair = signer.generateKeyPair();
    const approval = signer.sign(utf8('approve'), pair.secretKey, { context: utf8('login-challenge') });
    expect(() => signer.verify(approval, pair.publicKey, { expectedContext: utf8('payment-approval') })).toThrow(VerificationError);
    expect(() => signer.verify(approval, pair.publicKey)).toThrow(VerificationError);
    signer.verify(approval, pair.publicKey, { expectedContext: utf8('login-challenge') });
  });

  it('Envelope.open and easy.decrypt can bind a message to its context', () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = Envelope.seal(utf8('balance=100'), pair.publicKey, { aad: utf8('account-41') });
    expect(text(Envelope.open(sealed, pair.secretKey))).toBe('balance=100'); // no expectation: opens (documented)
    expect(text(Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('account-41') }))).toBe('balance=100');
    expect(() => Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('account-42') })).toThrow(DecryptionAuthenticationError);
    expect(() => Envelope.open(sealed.toBytes(), pair.secretKey, { expectedAad: utf8('account-42') })).toThrow(DecryptionAuthenticationError);
    const keys = easy.generateEncryptionKeys();
    const ct = easy.encrypt(keys.publicKey, 'x', { aad: 'record-1' });
    expect(easy.decryptText(keys.secretKey, ct, { aad: 'record-1' })).toBe('x');
    expect(() => easy.decrypt(keys.secretKey, ct, { aad: 'record-2' })).toThrow(DecryptionAuthenticationError);
    expect(SealedMessage.fromBytes(ct).aad).toEqual(utf8('record-1'));
  });
});

describe('Upgrader refuses a classical public key that does not match the secret', () => {
  const split = (raw: Uint8Array): [Uint8Array, Uint8Array] => {
    const n = (raw[0]! << 8) | raw[1]!;
    return [raw.slice(2, 2 + n), raw.slice(2 + n)];
  };
  it('KEM: swapped or unrelated halves fail at upgrade time, not at first decryption', () => {
    using a = new HybridKEM().generateKeyPair();
    using b = new HybridKEM().generateKeyPair();
    const [aPub] = split(a.publicKey.toBytes());
    const [bSec] = split(b.secretKey.exportBytes());
    expect(() => Upgrader.upgradeKemKey({ classicalSecret: bSec, classicalPublic: aPub })).toThrow(InvalidArgumentError);
    expect(() => Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(32).fill(1), classicalPublic: new Uint8Array(32).fill(2) })).toThrow(InvalidArgumentError);
  });
  it('signing: swapped or unrelated halves fail at upgrade time', () => {
    using a = new HybridSign().generateKeyPair();
    using b = new HybridSign().generateKeyPair();
    const [aPub] = split(a.publicKey.toBytes());
    const [bSec] = split(b.secretKey.exportBytes());
    expect(() => Upgrader.upgradeSigningKey({ classicalSecret: bSec, classicalPublic: aPub })).toThrow(InvalidArgumentError);
  });
});

describe('JWT hardening', () => {
  it('a negative expiresIn is refused instead of silently producing a token that never expires', () => {
    using pair = new HybridSign().generateKeyPair();
    expect(() => new JWTSigner(pair).sign({ sub: 'u' }, { expiresIn: -100 })).toThrow(InvalidArgumentError);
    expect(() => new JWTSigner(pair).sign({ sub: 'u' }, { expiresIn: Number.NaN })).toThrow(InvalidArgumentError);
    const { privateJwk } = StandardJwt.generateKeyPair('ML-DSA-44');
    expect(() => StandardJwt.sign({ sub: 'u' }, privateJwk, { expiresIn: -1 })).toThrow(InvalidArgumentError);
  });

  it('requireExp rejects a token without exp', () => {
    using pair = new HybridSign().generateKeyPair();
    const forever = new JWTSigner(pair).sign({ sub: 'u' }, { expiresIn: 0 });
    expect(new JWTVerifier(pair.publicKey).verify(forever).sub).toBe('u');
    expect(() => new JWTVerifier(pair.publicKey).verify(forever, { requireExp: true })).toThrow(VerificationError);
    const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-44');
    const std = StandardJwt.sign({ sub: 'u' }, privateJwk, { expiresIn: 0 });
    expect(() => StandardJwt.verify(std, publicJwk, { requireExp: true })).toThrow(VerificationError);
  });

  it('JWT signatures have one accepted spelling (no padding, no non-canonical trailing bits)', () => {
    using pair = new HybridSign().generateKeyPair();
    const token = new JWTSigner(pair).sign({ sub: 'u' }, { expiresIn: 60 });
    const v = new JWTVerifier(pair.publicKey);
    expect(v.verify(token).sub).toBe('u');
    const [h, p, s] = token.split('.');
    expect(() => v.verify(`${h}.${p}.${s}=`)).toThrow(QuantumSafeError);
    expect(() => v.verify(`${h}.${p}.${s}==`)).toThrow(QuantumSafeError);
    // Other spellings of the same bytes (differing only in unused trailing bits) must not verify either.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const original = fromBase64Url(s!);
    const last = alphabet.indexOf(s!.at(-1)!);
    let variants = 0;
    for (const alt of [last ^ 1, last ^ 2, last ^ 3, last ^ 4, last ^ 8, last ^ 16]) {
      const variant = `${s!.slice(0, -1)}${alphabet[alt]}`;
      if (variant === s || !equalBytes(fromBase64Url(variant), original)) continue;
      variants++;
      expect(() => v.verify(`${h}.${p}.${variant}`), variant).toThrow(QuantumSafeError);
    }
    expect(variants).toBeGreaterThanOrEqual(0); // the number of spare bits depends on the signature length
  });

  it('a hedged:false verifier is needed for tokens from an un-hedged signer', () => {
    using pair = new HybridSign().generateKeyPair();
    const token = new JWTSigner(pair, { hedged: false }).sign({ sub: 'u' }, { expiresIn: 60 });
    expect(() => new JWTVerifier(pair.publicKey).verify(token)).toThrow(VerificationError);
    expect(new JWTVerifier(pair.publicKey, { hedged: false }).verify(token).sub).toBe('u');
  });
});

describe('cross-realm and view inputs are accepted', () => {
  it('accepts ArrayBuffer and typed-array views', () => {
    using pair = new HybridKEM().generateKeyPair();
    const bytes = utf8('hello');
    const asBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
    const sealed = Envelope.seal(asBuffer as never, pair.publicKey);
    expect(text(Envelope.open(sealed, pair.secretKey))).toBe('hello');
    const view = new DataView(asBuffer);
    expect(text(Envelope.open(Envelope.seal(view as never, pair.publicKey), pair.secretKey))).toBe('hello');
  });
  it('error names are stable strings and QuantumSafeError.is recognises them', () => {
    try {
      easy.decrypt('bad', new Uint8Array(1));
    } catch (e) {
      expect(QuantumSafeError.is(e)).toBe(true);
      expect((e as QuantumSafeError).name).toMatch(/Error$/);
    }
    expect(QuantumSafeError.is(new Error('x'))).toBe(false);
  });
});

describe('parsers refuse hostile CBOR shapes before allocating', () => {
  it('rejects oversized sealed messages, trailing bytes, duplicate keys and amplification inputs', () => {
    using pair = new HybridKEM().generateKeyPair();
    const good = Envelope.seal(utf8('x'), pair.publicKey).toBytes();
    expect(() => SealedMessage.fromBytes(new Uint8Array([...good, 0]))).toThrow(QuantumSafeError); // trailing byte
    expect(() => SealedMessage.fromBytes(new Uint8Array(11 * 1024 * 1024))).toThrow(QuantumSafeError); // over the 10 MB cap
    // {"v":1,"v":2}: first-wins here but last-wins in other CBOR libraries, so duplicates are refused
    expect(() => SealedMessage.fromBytes(Uint8Array.from([0xa2, 0x61, 0x76, 0x01, 0x61, 0x76, 0x02]))).toThrow(QuantumSafeError);
    // a 5 MB array of one-byte items (decodes to hundreds of MB if built as a value tree): must be refused immediately
    const amplify = new Uint8Array(5_000_000).fill(0x80);
    amplify[0] = 0x9f; // indefinite-length array
    const t0 = performance.now();
    expect(() => PublicKey.fromCbor(amplify)).toThrow(QuantumSafeError);
    expect(performance.now() - t0).toBeLessThan(1000);
    const sized = new Uint8Array(5_000_000).fill(0x00);
    sized.set([0x9a, 0x00, 0x4c, 0x4b, 0x40], 0); // definite array claiming 5,000,000 items
    expect(() => SignedMessage.fromCbor(sized)).toThrow(QuantumSafeError);
  });
});
