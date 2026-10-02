/**
 * Differential tests against independent implementations: @noble/post-quantum (pure JS) and
 * Node's native WebCrypto (OpenSSL). A bug in our Rust core or bindings that also happened to
 * agree with quantum-safe-py would still be caught here.
 */
import { createCipheriv, createDecipheriv, hkdfSync as nodeHkdf, randomBytes, webcrypto } from 'node:crypto';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { slh_dsa_shake_128f, slh_dsa_sha2_128f } from '@noble/post-quantum/slh-dsa.js';
import { describe, expect, it } from 'vitest';
import {
  Envelope,
  HybridKEM,
  KEM,
  PublicKey,
  SealedMessage,
  SecretKey,
  Sign,
  SignedMessage,
  StandardJwt,
  cnsa2,
  deriveMasterKey,
  fromBase64Url,
  toBase64Url,
  toHex,
  utf8,
} from '../src/core.js';
import type { MlDsaJoseAlg } from '../src/core.js';

const eq = (a: Uint8Array, b: Uint8Array) => expect(toHex(a)).toBe(toHex(b));

/** Feature-detects a native WebCrypto algorithm (SubtleCrypto.supports, Node >= 24.7). */
function nodeSupports(operation: string, algorithm: string): boolean {
  const ctor = (globalThis as { SubtleCrypto?: { supports?: (op: string, alg: string) => boolean } }).SubtleCrypto;
  return ctor?.supports?.(operation, algorithm) === true;
}

describe('pure ML-KEM vs @noble/post-quantum', () => {
  const cases = [
    ['ML-KEM-512', ml_kem512],
    ['ML-KEM-768', ml_kem768],
    ['ML-KEM-1024', ml_kem1024],
  ] as const;
  for (const [name, noble] of cases) {
    it(`${name}: ours encapsulates -> noble decapsulates`, () => {
      const kem = new KEM(name);
      using pair = kem.generateKeyPair();
      const enc = kem.encapsulate(pair.publicKey);
      const sk = pair.secretKey.exportBytes();
      eq(noble.decapsulate(enc.ciphertext, sk), enc.sharedSecret.exportBytes());
      enc.sharedSecret.free();
      sk.fill(0);
    });
    it(`${name}: noble encapsulates -> ours decapsulates`, () => {
      const kem = new KEM(name);
      const { publicKey, secretKey } = noble.keygen();
      const { cipherText, sharedSecret } = noble.encapsulate(publicKey);
      using sk = SecretKey.fromBytes(name, secretKey);
      using ss = kem.decapsulate(sk, cipherText);
      eq(ss.exportBytes(), sharedSecret);
    });
  }
});

describe('CNSA 2.0 envelope v2 verified end to end by independent implementations', () => {
  it('a v2 envelope built ONLY from noble ML-KEM-1024 + Node HKDF-SHA384 + Node AES-256-GCM opens in ours', () => {
    const kem = cnsa2.kem();
    using pair = kem.generateKeyPair();
    // Independent sender: noble encapsulates to our public key; Node derives the key and encrypts.
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(pair.publicKey.toBytes());
    const key = new Uint8Array(nodeHkdf('sha384', sharedSecret, new Uint8Array(0), utf8('qs-envelope-enc-v2-cnsa2'), 32));
    const algo = utf8('ML-KEM-1024');
    const aad = utf8('independent-sender');
    const builtAad = new Uint8Array([2, algo.length, ...algo, ...aad]);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(builtAad);
    const body = Buffer.concat([cipher.update(utf8('built without our code')), cipher.final()]);
    const sealed = SealedMessage.fromParts({
      version: 2,
      algorithm: 'ML-KEM-1024',
      kemCiphertext: cipherText,
      nonce,
      ciphertext: new Uint8Array(Buffer.concat([body, cipher.getAuthTag()])),
      aad,
    });
    expect(new TextDecoder().decode(Envelope.open(sealed, pair.secretKey))).toBe('built without our code');
  });
  it('a v2 envelope sealed by us decrypts with noble + Node primitives only', () => {
    const kem = cnsa2.kem();
    using pair = kem.generateKeyPair();
    const sealed = Envelope.seal(utf8('sealed by ts'), pair.publicKey, { aad: utf8('x') });
    const ss = ml_kem1024.decapsulate(sealed.kemCiphertext, pair.secretKey.exportBytes());
    const key = new Uint8Array(nodeHkdf('sha384', ss, new Uint8Array(0), utf8('qs-envelope-enc-v2-cnsa2'), 32));
    const algo = utf8('ML-KEM-1024');
    const builtAad = new Uint8Array([2, algo.length, ...algo, ...utf8('x')]);
    const d = createDecipheriv('aes-256-gcm', key, sealed.nonce);
    d.setAAD(builtAad);
    d.setAuthTag(sealed.ciphertext.slice(-16));
    const plain = Buffer.concat([d.update(sealed.ciphertext.slice(0, -16)), d.final()]);
    expect(plain.toString()).toBe('sealed by ts');
  });
});

describe('X-Wing vs @noble/post-quantum ml_kem768_x25519 (X-Wing)', () => {
  it('ours -> noble', () => {
    const kem = new HybridKEM('X-Wing');
    using pair = kem.generateKeyPair();
    const enc = kem.encapsulate(pair.publicKey);
    const sk = pair.secretKey.exportBytes();
    eq(ml_kem768_x25519.decapsulate(enc.ciphertext, sk), enc.sharedSecret.exportBytes());
    enc.sharedSecret.free();
  });
  it('noble -> ours', () => {
    const kem = new HybridKEM('X-Wing');
    const { publicKey, secretKey } = ml_kem768_x25519.keygen();
    const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(publicKey);
    using sk = SecretKey.fromBytes('X-Wing', secretKey);
    using ss = kem.decapsulate(sk, cipherText);
    eq(ss.exportBytes(), sharedSecret);
  });
});

describe('quantum-safe-py ML-DSA construction is plain FIPS 204 over len(ctx)||ctx||prefix||msg', () => {
  const cases = [
    ['ML-DSA-44', ml_dsa44],
    ['ML-DSA-65', ml_dsa65],
    ['ML-DSA-87', ml_dsa87],
  ] as const;
  for (const [name, noble] of cases) {
    it(`${name}: our signature verifies in noble with an empty FIPS context`, () => {
      const signer = new Sign(name);
      using pair = signer.generateKeyPair();
      const ctx = utf8('app-v1');
      const msg = utf8('hello post-quantum world');
      const sm = signer.sign(msg, pair.secretKey, { context: ctx });
      const prefixLen = sm.signature[0]!;
      const prefix = sm.signature.slice(1, 1 + prefixLen);
      const rawSig = sm.signature.slice(1 + prefixLen);
      const input = new Uint8Array([ctx.length, ...ctx, ...prefix, ...msg]);
      expect(noble.verify(rawSig, input, pair.publicKey.toBytes())).toBe(true);
      expect(noble.verify(rawSig, input, pair.publicKey.toBytes(), { context: utf8('x') })).toBe(false);
    });
    it(`${name}: a noble signature (python-style input) verifies in ours`, () => {
      const signer = new Sign(name);
      const { publicKey, secretKey } = noble.keygen();
      const ctx = utf8('c');
      const msg = utf8('from noble');
      const input = new Uint8Array([ctx.length, ...ctx, ...msg]); // un-hedged: empty prefix
      const sig = noble.sign(input, secretKey);
      const blob = new Uint8Array([0, ...sig]);
      const sm = SignedMessage.fromParts({ message: msg, signature: blob, algorithm: name, context: ctx });
      using pub = PublicKey.fromBytes(name, publicKey);
      new Sign(name, { hedged: false }).verify(sm, pub, { expectedContext: ctx }); // an empty prefix is the un-hedged mode
    });
    it(`${name}: noble's expanded secret key is accepted by ours`, () => {
      const signer = new Sign(name);
      const { publicKey, secretKey } = noble.keygen();
      using sk = SecretKey.fromBytes(name, secretKey);
      using pub = PublicKey.fromBytes(name, publicKey);
      signer.verify(signer.sign(utf8('m'), sk), pub);
      void signer;
    });
  }
});

describe('SLH-DSA (FIPS 205) vs noble', () => {
  const cases = [
    ['SLH-DSA-SHAKE-128f', slh_dsa_shake_128f],
    ['SLH-DSA-SHA2-128f', slh_dsa_sha2_128f],
  ] as const;
  for (const [name, noble] of cases) {
    it(`${name}: both directions`, () => {
      const signer = new Sign(name);
      using pair = signer.generateKeyPair();
      const msg = utf8('m');
      const sm = signer.sign(msg, pair.secretKey);
      const prefixLen = sm.signature[0]!;
      const prefix = sm.signature.slice(1, 1 + prefixLen);
      const rawSig = sm.signature.slice(1 + prefixLen);
      const input = new Uint8Array([0, ...prefix, ...msg]); // empty context
      expect(noble.verify(rawSig, input, pair.publicKey.toBytes())).toBe(true);

      const kp = noble.keygen();
      const nsig = noble.sign(new Uint8Array([0, ...msg]), kp.secretKey);
      const blob = new Uint8Array([0, ...nsig]);
      using pub = PublicKey.fromBytes(name, kp.publicKey);
      new Sign(name, { hedged: false }).verify(SignedMessage.fromParts({ message: msg, signature: blob, algorithm: name }), pub);
    });
  }
});

describe('standards-mode ML-DSA (RFC 9964) vs noble and Node WebCrypto', () => {
  for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as MlDsaJoseAlg[]) {
    const noble = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 }[alg];
    it(`${alg}: seed -> same public key as noble`, () => {
      const { publicJwk, privateJwk } = StandardJwt.generateKeyPair(alg);
      const seed = fromBase64Url(privateJwk.priv!);
      expect(seed.length).toBe(32);
      eq(fromBase64Url(publicJwk.pub), noble.keygen(seed).publicKey);
      expect(StandardJwt.publicJwk(privateJwk).pub).toBe(publicJwk.pub);
    });
    it(`${alg}: JWS signed by us verifies in noble; noble-signed JWS verifies in ours`, () => {
      const { publicJwk, privateJwk } = StandardJwt.generateKeyPair(alg);
      const token = StandardJwt.sign({ sub: 'alice' }, privateJwk);
      const [h, p, s] = token.split('.');
      const pub = fromBase64Url(publicJwk.pub);
      expect(noble.verify(fromBase64Url(s!), utf8(`${h}.${p}`), pub)).toBe(true);

      const seed = fromBase64Url(privateJwk.priv!);
      const { secretKey } = noble.keygen(seed);
      const header = toBase64Url(utf8(JSON.stringify({ alg, typ: 'JWT' })));
      const payload = toBase64Url(utf8(JSON.stringify({ sub: 'bob' })));
      const sig = noble.sign(utf8(`${header}.${payload}`), secretKey);
      expect(StandardJwt.verify(`${header}.${payload}.${toBase64Url(sig)}`, publicJwk).sub).toBe('bob');
    });
  }

  it('Node WebCrypto verifies our ML-DSA-65 JWS signature (if supported by this Node)', async () => {
    const subtle = webcrypto.subtle as unknown as {
      importKey: (...a: unknown[]) => Promise<unknown>;
      verify: (...a: unknown[]) => Promise<boolean>;
    };
    if (!nodeSupports('verify', 'ML-DSA-65')) return;
    const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65');
    const token = StandardJwt.sign({ sub: 'alice' }, privateJwk);
    const [h, p, s] = token.split('.');
    const key = await subtle.importKey('raw-public', fromBase64Url(publicJwk.pub), { name: 'ML-DSA-65' }, false, ['verify']);
    expect(await subtle.verify({ name: 'ML-DSA-65' }, key, fromBase64Url(s!), utf8(`${h}.${p}`))).toBe(true);
  });
});

describe('Argon2id master key vs Node WebCrypto Argon2id', () => {
  it('matches (19 MiB, 2 passes, 1 lane, 32-byte output)', async () => {
    if (!nodeSupports('importKey', 'Argon2id')) return;
    const password = utf8('correct horse battery staple');
    const salt = utf8('0123456789abcdef');
    using ours = await deriveMasterKey('correct horse battery staple', salt);
    const subtle = webcrypto.subtle as unknown as {
      importKey: (...a: unknown[]) => Promise<unknown>;
      deriveBits: (...a: unknown[]) => Promise<ArrayBuffer>;
    };
    const key = await subtle.importKey('raw-secret', password, 'Argon2id', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'Argon2id', nonce: salt, parallelism: 1, memory: 19 * 1024, passes: 2 }, key, 256);
    eq(ours.exportBytes(), new Uint8Array(bits));
  });
});
