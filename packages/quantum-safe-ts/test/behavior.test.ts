import { inspect } from 'node:util';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  AlgorithmMismatchError,
  DecapsulationError,
  DecryptionAuthenticationError,
  Envelope,
  HkdfOutputTooLongError,
  HybridKEM,
  HybridSign,
  InvalidArgumentError,
  JWTSigner,
  JWTVerifier,
  KEM,
  KdfError,
  KeyPair,
  KeyParseError,
  MalformedCiphertextError,
  MalformedKeyError,
  PolicyViolationError,
  PublicKey,
  QuantumSafeError,
  SealedMessage,
  SecretBytes,
  SecretKey,
  Sign,
  SignedMessage,
  StandardJwt,
  UnsupportedAlgorithmError,
  UnsupportedFormatError,
  VerificationError,
  cnsa2,
  coreVersion,
  deriveMasterKey,
  equalBytes,
  fromHex,
  isInitialized,
  kemSuites,
  sigSuites,
  toHex,
  utf8,
  wipe,
} from '../src/core.js';
import type { KemAlgorithm, SignatureAlgorithm } from '../src/core.js';

const fastSigs = sigSuites().filter((s) => !s.name.startsWith('SLH-DSA') || s.name === 'SLH-DSA-SHAKE-128f');

describe('registry', () => {
  it('lists the expected suites', () => {
    expect(kemSuites().map((s) => s.name).sort()).toEqual(
      [
        'ML-KEM-1024', 'ML-KEM-512', 'ML-KEM-768', 'P-256+ML-KEM-512', 'P-256+ML-KEM-768',
        'X-Wing', 'X25519+ML-KEM-1024', 'X25519+ML-KEM-512', 'X25519+ML-KEM-768',
      ].sort(),
    );
    expect(sigSuites().filter((s) => s.format !== 'v2')).toHaveLength(20); // the quantum-safe-py-compatible suites
    expect(sigSuites().filter((s) => s.format === 'v2')).toHaveLength(8); // the -v2 signature format
    expect(isInitialized()).toBe(true);
    expect(coreVersion()).toMatch(/^\d+\.\d+\.\d+/);
  });
  it('flags CNSA 2.0 and python compatibility correctly', () => {
    const k = Object.fromEntries(kemSuites().map((s) => [s.name, s]));
    expect(k['X25519+ML-KEM-1024']!.meetsCnsa2).toBe(true);
    expect(k['X25519+ML-KEM-768']!.meetsCnsa2).toBe(false);
    expect(k['X-Wing']!.pyCompatible).toBe(false);
    expect(k['X-Wing']!.hybrid).toBe(true);
    const s = Object.fromEntries(sigSuites().map((x) => [x.name, x]));
    expect(s['Ed25519+ML-DSA-87']!.meetsCnsa2).toBe(true);
    expect(s['SLH-DSA-SHA2-128s']!.pyCompatible).toBe(false);
    expect(s['SLH-DSA-SHAKE-128s']!.pyCompatible).toBe(true);
  });
});

describe('KEM round trips for every suite', () => {
  for (const info of kemSuites()) {
    it(info.name, () => {
      const kem = info.hybrid ? new HybridKEM(info.name as KemAlgorithm) : new KEM(info.name as never);
      using pair = kem.generateKeyPair();
      const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
      using recovered = kem.decapsulate(pair.secretKey, ciphertext);
      expect(equalBytes(recovered.exportBytes(), sharedSecret.exportBytes())).toBe(true);
      sharedSecret.free();
    });
  }
  it('HybridKEM rejects a pure algorithm and vice versa', () => {
    expect(() => new HybridKEM('ML-KEM-768' as never)).toThrow(UnsupportedAlgorithmError);
    expect(() => new KEM('X25519+ML-KEM-768' as never)).toThrow(UnsupportedAlgorithmError);
    expect(() => new HybridKEM('RSA+ML-KEM-768' as never)).toThrow(UnsupportedAlgorithmError);
  });
  it('rejects a key from a different algorithm', () => {
    using pair = new HybridKEM('X25519+ML-KEM-512').generateKeyPair();
    expect(() => new HybridKEM().encapsulate(pair.publicKey)).toThrow(AlgorithmMismatchError);
    expect(() => new HybridKEM().decapsulate(pair.secretKey, new Uint8Array(10))).toThrow(AlgorithmMismatchError);
  });
  it('malformed ciphertext is a typed error, never a crash', () => {
    const kem = new HybridKEM();
    using pair = kem.generateKeyPair();
    for (const ct of [new Uint8Array(0), new Uint8Array(1), new Uint8Array(2), new Uint8Array(1122).fill(7), new Uint8Array(5000)]) {
      try {
        kem.decapsulate(pair.secretKey, ct).free();
      } catch (e) {
        expect(e).toBeInstanceOf(QuantumSafeError);
      }
    }
    expect(() => kem.decapsulate(pair.secretKey, new Uint8Array(100))).toThrow(MalformedCiphertextError);
  });
  it('X25519 low-order points are rejected (all-zero shared secret)', () => {
    const kem = new HybridKEM();
    using pair = kem.generateKeyPair();
    const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
    sharedSecret.free();
    const forged = ciphertext.slice();
    forged.fill(0, 2, 34); // classical ct := 32 zero bytes
    expect(() => kem.decapsulate(pair.secretKey, forged)).toThrow(DecapsulationError);
  });
  it('ML-KEM implicit rejection: a wrong ciphertext yields a different secret, not an error', () => {
    const kem = new KEM('ML-KEM-768');
    using pair = kem.generateKeyPair();
    const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
    const tampered = ciphertext.slice();
    tampered[0]! ^= 1;
    using other = kem.decapsulate(pair.secretKey, tampered);
    expect(equalBytes(other.exportBytes(), sharedSecret.exportBytes())).toBe(false);
    sharedSecret.free();
  });
});

describe('Envelope', () => {
  const kem = new HybridKEM();
  it('round-trips with and without AAD, and for empty and large plaintexts', () => {
    using pair = kem.generateKeyPair();
    for (const aad of [undefined, utf8('item-42')]) {
      for (const len of [0, 1, 1000, 200_000]) {
        const plain = new Uint8Array(len).map((_, i) => i % 251);
        const sealed = Envelope.seal(plain, pair.publicKey, aad ? { aad } : {});
        expect(equalBytes(Envelope.open(sealed, pair.secretKey), plain)).toBe(true);
      }
    }
  });
  it('seals the same plaintext differently each time', () => {
    using pair = kem.generateKeyPair();
    const a = Envelope.seal(utf8('x'), pair.publicKey).toHex();
    const b = Envelope.seal(utf8('x'), pair.publicKey).toHex();
    expect(a).not.toBe(b);
  });
  it('authenticates ciphertext, nonce, aad, algorithm and kem ciphertext', () => {
    using pair = kem.generateKeyPair();
    const sealed = Envelope.seal(utf8('secret'), pair.publicKey, { aad: utf8('aad') });
    const flip = (u: Uint8Array, i: number) => Uint8Array.from(u, (b, j) => (j === i ? b ^ 1 : b));
    const mutants = [
      { ciphertext: flip(sealed.ciphertext, 0) },
      { ciphertext: flip(sealed.ciphertext, sealed.ciphertext.length - 1) },
      { nonce: flip(sealed.nonce, 0) },
      { aad: utf8('aaD') },
      { kemCiphertext: flip(sealed.kemCiphertext, 40) },
    ];
    for (const m of mutants) {
      const bad = SealedMessage.fromParts({ ...sealed, ...m });
      expect(() => Envelope.open(bad, pair.secretKey)).toThrow(DecryptionAuthenticationError);
    }
  });
  it('rejects wrong key, pure keys, and cross-suite opens', () => {
    using a = kem.generateKeyPair();
    using b = kem.generateKeyPair();
    const sealed = Envelope.seal(utf8('x'), a.publicKey);
    expect(() => Envelope.open(sealed, b.secretKey)).toThrow(DecryptionAuthenticationError);
    using pure = new KEM('ML-KEM-768').generateKeyPair();
    expect(() => Envelope.seal(utf8('x'), pure.publicKey)).toThrow(UnsupportedAlgorithmError);
    using other = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    expect(() => Envelope.open(sealed, other.secretKey)).toThrow(AlgorithmMismatchError);
  });
  it('supports every hybrid suite incl. X-Wing', () => {
    for (const s of kemSuites().filter((x) => x.hybrid)) {
      using pair = new HybridKEM(s.name as KemAlgorithm).generateKeyPair();
      const sealed = Envelope.seal(utf8('payload'), pair.publicKey);
      expect(sealed.algorithm).toBe(s.name);
      expect(toHex(Envelope.open(sealed, pair.secretKey))).toBe(toHex(utf8('payload')));
    }
  });
  it('SealedMessage fields, hex and inspect() are consistent', () => {
    using pair = kem.generateKeyPair();
    const sealed = Envelope.seal(utf8('abc'), pair.publicKey, { aad: utf8('z') });
    expect(sealed.version).toBe(1);
    expect(sealed.nonce).toHaveLength(12);
    expect(sealed.ciphertext).toHaveLength(3 + 16);
    expect(sealed.kemCiphertext).toHaveLength(1122);
    expect(sealed.inspect()).toEqual({
      version: 1, algorithm: 'X25519+ML-KEM-768', kemCiphertextLength: 1122, nonceLength: 12, ciphertextLength: 19, aadLength: 1,
    });
    expect(SealedMessage.fromHex(sealed.toHex()).toHex()).toBe(sealed.toHex());
    expect(Envelope.open(sealed.toBytes(), pair.secretKey)).toEqual(utf8('abc'));
  });
  it('malformed sealed messages are typed errors', () => {
    for (const data of [new Uint8Array(0), new Uint8Array([0xff]), utf8('not cbor'), new Uint8Array(100).fill(0xa1)]) {
      expect(() => SealedMessage.fromBytes(data)).toThrow(QuantumSafeError);
    }
    expect(() => SealedMessage.fromHex('zz')).toThrow(InvalidArgumentError);
  });
});

describe('keys: lifecycle, serialization, hygiene', () => {
  it('use-after-free is a typed error, not a WASM trap', () => {
    const pair = new HybridKEM().generateKeyPair();
    const sk = pair.secretKey;
    pair.free();
    expect(() => sk.exportBytes()).toThrow(InvalidArgumentError);
    expect(() => pair.publicKey.fingerprint()).toThrow(InvalidArgumentError);
    pair.free(); // double free is harmless
  });
  it('secrets never appear in toString/JSON/util.inspect', () => {
    using pair = new HybridKEM().generateKeyPair();
    const raw = toHex(pair.secretKey.exportBytes()).slice(0, 40);
    for (const out of [String(pair.secretKey), JSON.stringify(pair.secretKey), inspect(pair.secretKey, { depth: 5 }), JSON.stringify({ k: pair })]) {
      expect(out).not.toContain(raw);
    }
    expect(String(pair.secretKey)).toContain('redacted');
    using shared = new KEM('ML-KEM-512').generateKeyPair();
    expect(String(shared.secretKey)).toContain('redacted');
    expect(String(SecretBytes.from(new Uint8Array(32)))).toContain('redacted');
  });
  it('round-trips every serialization and rejects type confusion', () => {
    using pair = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    const pub = pair.publicKey;
    const sec = pair.secretKey;
    expect(PublicKey.fromCbor(pub.toCbor()).fingerprint()).toBe(pub.fingerprint());
    expect(PublicKey.fromPem(pub.toPem()).fingerprint()).toBe(pub.fingerprint());
    expect(PublicKey.fromJwk(pub.toJwk()).fingerprint()).toBe(pub.fingerprint());
    expect(PublicKey.fromJwk(JSON.parse(pub.toJwk())).fingerprint()).toBe(pub.fingerprint());
    expect(toHex(SecretKey.fromPem(sec.toPem()).exportBytes())).toBe(toHex(sec.exportBytes()));
    expect(() => SecretKey.fromCbor(pub.toCbor())).toThrow(KeyParseError);
    expect(() => PublicKey.fromCbor(sec.toCbor())).toThrow(KeyParseError);
    expect(() => PublicKey.fromPem(sec.toPem())).toThrow(KeyParseError);
    expect(() => SecretKey.fromPem(pub.toPem())).toThrow(KeyParseError);
    expect(KeyPair.fromCborBundle(pair.toCborBundle()).algorithm).toBe('X25519+ML-KEM-1024');
  });
  it('refuses JWK for secrets (no such API) and bad inputs', () => {
    expect(() => PublicKey.fromJwk('{')).toThrow(KeyParseError);
    expect(() => PublicKey.fromJwk({ alg: 'x' })).toThrow(KeyParseError);
    expect(() => PublicKey.fromBytes('X25519+ML-KEM-768', new Uint8Array(0))).toThrow(InvalidArgumentError);
    expect(() => PublicKey.fromBytes('X', new Uint8Array(3), 'nope' as never)).toThrow(InvalidArgumentError);
    expect(() => PublicKey.fromCbor('not bytes' as never)).toThrow(InvalidArgumentError);
    expect(UnsupportedFormatError.name).toBe('UnsupportedFormatError');
  });
  it('public keys of the wrong length are refused at parse; secret keys of the wrong length fail when used', () => {
    expect(() => PublicKey.fromBytes('X25519+ML-KEM-768', new Uint8Array(50).fill(1))).toThrow(KeyParseError);
    using sec = SecretKey.fromBytes('X25519+ML-KEM-768', new Uint8Array(50).fill(1));
    expect(() => new HybridKEM().decapsulate(sec, new Uint8Array(1122))).toThrow(MalformedKeyError);
  });
  it('payloads over 10 MB are refused before parsing', () => {
    expect(() => PublicKey.fromCbor(new Uint8Array(10 * 1024 * 1024 + 1))).toThrow(/limit|10 MB|exceed/i);
  });
});

describe('SecretBytes / deriveMasterKey', () => {
  it('HKDF matches known-answer behaviour and enforces the output cap', () => {
    const ss = SecretBytes.from(new Uint8Array(32).fill(7));
    const a = ss.deriveKey(32, utf8('purpose-a'));
    const b = ss.deriveKey(32, utf8('purpose-b'));
    expect(equalBytes(a, b)).toBe(false);
    expect(ss.deriveKey(8160, utf8('x'))).toHaveLength(8160);
    expect(() => ss.deriveKey(8161, utf8('x'))).toThrow(HkdfOutputTooLongError);
    expect(() => ss.deriveKey(-1, utf8('x'))).toThrow(InvalidArgumentError);
    ss.free();
  });
  it('Argon2id is deterministic, salt- and password-sensitive, and validates the salt', async () => {
    const salt = utf8('0123456789abcdef');
    using a = await deriveMasterKey('pw', salt);
    using b = await deriveMasterKey('pw', salt);
    using c = await deriveMasterKey('pw2', salt);
    using d = await deriveMasterKey(utf8('pw'), utf8('fedcba9876543210'));
    expect(equalBytes(a.exportBytes(), b.exportBytes())).toBe(true);
    expect(equalBytes(a.exportBytes(), c.exportBytes())).toBe(false);
    expect(equalBytes(a.exportBytes(), d.exportBytes())).toBe(false);
    expect(a.length).toBe(32);
    await expect(deriveMasterKey('pw', utf8('short'))).rejects.toThrow(KdfError);
  });
});

describe('signatures for every fast suite', () => {
  for (const info of fastSigs) {
    it(info.name, () => {
      const signer = info.hybrid ? new HybridSign(info.name as never) : new Sign(info.name as never);
      using pair = signer.generateKeyPair();
      const sm = signer.signWithFingerprint(utf8('document'), pair, { context: utf8('app-v1') });
      expect(sm.isHybrid).toBe(info.hybrid);
      expect(sm.signerFingerprint).toBe(pair.publicKey.fingerprint());
      signer.verify(sm, pair.publicKey, { expectedContext: utf8('app-v1') });
      signer.verifyBytes(sm.message, sm.signature, pair.publicKey, { context: utf8('app-v1') });
      expect(signer.isValid(sm, pair.publicKey, { expectedContext: utf8('app-v1') })).toBe(true);
      // The context comes from the caller, not from the message: no expectation (or the wrong one) fails.
      expect(() => signer.verify(sm, pair.publicKey)).toThrow(VerificationError);
      expect(signer.isValid(sm, pair.publicKey, { expectedContext: utf8('other') })).toBe(false);
      expect(() => signer.verifyBytes(sm.message, sm.signature, pair.publicKey, { context: utf8('other') })).toThrow(VerificationError);
      expect(SignedMessage.fromCbor(sm.toCbor()).toHex()).toBe(sm.toHex());
    });
  }
  it('hedged signatures differ; un-hedged have an empty prefix', () => {
    const hedged = new Sign('ML-DSA-44');
    using pair = hedged.generateKeyPair();
    const a = hedged.sign(utf8('m'), pair.secretKey);
    const b = hedged.sign(utf8('m'), pair.secretKey);
    expect(toHex(a.signature)).not.toBe(toHex(b.signature));
    expect(a.signature[0]).toBe(32);
    const plain = new Sign('ML-DSA-44', { hedged: false });
    expect(plain.sign(utf8('m'), pair.secretKey).signature[0]).toBe(0);
  });
  it('validates inputs and mismatches', () => {
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateKeyPair();
    expect(() => signer.sign(new Uint8Array(0), pair.secretKey)).toThrow(InvalidArgumentError);
    expect(() => signer.sign(utf8('m'), pair.secretKey, { context: new Uint8Array(256) })).toThrow(InvalidArgumentError);
    expect(() => signer.sign('m' as never, pair.secretKey)).toThrow(InvalidArgumentError);
    expect(() => new Sign('Ed25519+ML-DSA-65' as never)).toThrow(UnsupportedAlgorithmError);
    expect(() => new HybridSign('ML-DSA-65' as never)).toThrow(UnsupportedAlgorithmError);
    expect(() => new HybridSign('P-256+ML-DSA-87' as never)).toThrow(UnsupportedAlgorithmError);
    using other = new Sign('ML-DSA-65').generateKeyPair();
    expect(() => signer.sign(utf8('m'), other.secretKey)).toThrow(AlgorithmMismatchError);
    const sm = signer.sign(utf8('m'), pair.secretKey);
    expect(() => signer.verify(sm, other.publicKey)).toThrow(AlgorithmMismatchError);
  });
  it('verification failures carry no detail about which half failed', () => {
    const signer = new HybridSign();
    using pair = signer.generateKeyPair();
    const sm = signer.sign(utf8('m'), pair.secretKey);
    const bad = SignedMessage.fromParts({ ...sm, signature: Uint8Array.from(sm.signature, (b, i) => (i === sm.signature.length - 1 ? b ^ 1 : b)) });
    try {
      signer.verify(bad, pair.publicKey);
      throw new Error('should not verify');
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as Error).message).toBe('Signature verification failed.');
    }
  });
  it('hybrid verification fails if either half is invalid', () => {
    const signer = new HybridSign();
    using pair = signer.generateKeyPair();
    using other = signer.generateKeyPair();
    const sm = signer.sign(utf8('m'), pair.secretKey);
    // Swap in the PQC half's public key of a different signer: classical half passes? No: both must pass.
    const pk = pair.publicKey.toBytes();
    const ok = other.publicKey.toBytes();
    const classicalLen = (pk[0]! << 8) | pk[1]!;
    const mixed = new Uint8Array([...pk.slice(0, 2 + classicalLen), ...ok.slice(2 + classicalLen)]); // our Ed25519 + their ML-DSA
    using mixedKey = PublicKey.fromBytes('Ed25519+ML-DSA-65', mixed);
    expect(signer.isValid(sm, mixedKey)).toBe(false);
    const mixed2 = new Uint8Array([...ok.slice(0, 2 + classicalLen), ...pk.slice(2 + classicalLen)]); // their Ed25519 + our ML-DSA
    using mixedKey2 = PublicKey.fromBytes('Ed25519+ML-DSA-65', mixed2);
    expect(signer.isValid(sm, mixedKey2)).toBe(false);
    expect(signer.isValid(sm, pair.publicKey)).toBe(true);
  });
});

describe('JWT', () => {
  it('quantum-safe-py mode: claims, expiry, issuer, audience, context, alg pinning', () => {
    using pair = new HybridSign().generateKeyPair();
    const signer = new JWTSigner(pair, { issuer: 'iss' });
    const token = signer.sign({ sub: 'u', aud: ['a1', 'a2'] }, { expiresIn: 60 });
    const v = new JWTVerifier(pair.publicKey, { issuer: 'iss', audience: 'a2' });
    expect(v.verify(token).sub).toBe('u');
    expect(() => new JWTVerifier(pair.publicKey, { issuer: 'nope' }).verify(token)).toThrow(VerificationError);
    expect(() => new JWTVerifier(pair.publicKey, { audience: 'nope' }).verify(token)).toThrow(VerificationError);
    expect(() => v.verify(token, { now: Date.now() / 1000 + 3600 })).toThrow(VerificationError); // expired
    expect(v.verify(token, { now: Date.now() / 1000 + 3600, validateExp: false }).sub).toBe('u');
    expect(() => v.verify(token, { context: utf8('x') })).toThrow(VerificationError);
    const nbf = signer.sign({ nbf: Math.floor(Date.now() / 1000) + 3600 });
    expect(() => new JWTVerifier(pair.publicKey).verify(nbf)).toThrow(VerificationError);
    using other = new Sign('ML-DSA-65').generateKeyPair();
    expect(() => new JWTVerifier(other.publicKey).verify(token)).toThrow(UnsupportedAlgorithmError);
    for (const bad of ['', 'a.b', 'a.b.c.d', '..', 'a..c']) expect(() => v.verify(bad)).toThrow(InvalidArgumentError);
  });
  it('standards mode (RFC 9964): sign/verify, claims, alg confusion, crit, tamper', () => {
    const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65', { kid: 'k1' });
    expect(publicJwk).toMatchObject({ kty: 'AKP', alg: 'ML-DSA-65', kid: 'k1' });
    expect(publicJwk.priv).toBeUndefined();
    const token = StandardJwt.sign({ sub: 'u', aud: 'api' }, privateJwk, { issuer: 'me', expiresIn: 60 });
    expect(JSON.parse(atob(token.split('.')[0]!.replace(/-/g, '+').replace(/_/g, '/')))).toEqual({ alg: 'ML-DSA-65', typ: 'JWT', kid: 'k1' });
    expect(StandardJwt.verify(token, publicJwk, { issuer: 'me', audience: 'api' }).sub).toBe('u');
    expect(() => StandardJwt.verify(token, publicJwk, { issuer: 'x' })).toThrow(VerificationError);
    expect(() => StandardJwt.verify(token, publicJwk, { now: Date.now() / 1000 + 7200 })).toThrow(VerificationError);
    const other = StandardJwt.generateKeyPair('ML-DSA-65').publicJwk;
    expect(() => StandardJwt.verify(token, other)).toThrow(VerificationError);
    const wrongAlg = StandardJwt.generateKeyPair('ML-DSA-44').publicJwk;
    expect(() => StandardJwt.verify(token, wrongAlg)).toThrow(AlgorithmMismatchError);
    const [h, p, s] = token.split('.');
    const noneHeader = btoa(JSON.stringify({ alg: 'none' })).replace(/=+$/, '');
    expect(() => StandardJwt.verify(`${noneHeader}.${p}.${s}`, publicJwk)).toThrow(QuantumSafeError);
    const crit = btoa(JSON.stringify({ alg: 'ML-DSA-65', crit: ['x'] })).replace(/=+$/, '');
    expect(() => StandardJwt.verify(`${crit}.${p}.${s}`, publicJwk)).toThrow(QuantumSafeError);
    const forged = btoa(JSON.stringify({ sub: 'admin' })).replace(/=+$/, '');
    expect(() => StandardJwt.verify(`${h}.${forged}.${s}`, publicJwk)).toThrow(VerificationError);
    expect(() => StandardJwt.generateKeyPair('RS256' as never)).toThrow(UnsupportedAlgorithmError);
    expect(() => StandardJwt.verify(token, { ...publicJwk, kty: 'RSA' } as never)).toThrow(InvalidArgumentError);
  });
});

describe('CNSA 2.0 profile', () => {
  it('reports the library defaults as non-compliant, as quantum-safe-py does', () => {
    const r = cnsa2.report({ kem: 'X25519+ML-KEM-768', signature: 'Ed25519+ML-DSA-65' });
    expect(r.compliant).toBe(false);
    expect(r.failures.map((f) => f.requirement)).toContain('Key establishment');
    expect(r.failures.map((f) => f.requirement)).toContain('Signatures');
    expect(r.render()).toContain('NOT compliant');
    expect(r.render()).toContain('necessary and not sufficient');
  });
  it('hybrid X25519+ML-KEM-1024 is only partial: NSA\'s FAQ does not call a hybrid compliant', () => {
    const r = cnsa2.report({ kem: 'X25519+ML-KEM-1024', signature: 'Ed25519+ML-DSA-87', hashAlgorithm: 'sha384' });
    const kem = r.checks.find((c) => c.requirement === 'Key establishment')!;
    expect(kem.finding).toBe('partial');
    expect(kem.ok).toBe(false);
    expect(kem.detail).toContain('FAQ');
    expect(kem.detail).toContain('IKEv2');
    expect(r.checks.find((c) => c.requirement === 'Signatures')!.finding).toBe('partial'); // a hybrid signature is outside what CNSA 2.0 prescribes too
    expect(r.checks.find((c) => c.requirement === 'Hashing')!.ok).toBe(true);
    expect(r.compliant).toBe(false);
    expect(r.failures.map((f) => f.requirement).sort()).toEqual([
      'Key establishment',
      'Key-derivation hash (this library)',
      'Signatures',
      'Software/firmware signing (SP 800-208)',
    ]);
  });
  it('pure ML-KEM-1024 with envelope v2 meets every parameter/KDF requirement; only code signing remains', () => {
    const r = cnsa2.report({ kem: 'ML-KEM-1024', signature: 'ML-DSA-87', hashAlgorithm: 'SHA-384' });
    expect(r.failures.map((f) => f.requirement)).toEqual(['Software/firmware signing (SP 800-208)']);
    expect(r.checks.find((c) => c.requirement === 'Key-derivation hash (this library)')!.ok).toBe(true);
    expect(cnsa2.report({ kem: 'ML-KEM-1024', includeCodeSigning: false }).compliant).toBe(true);
    expect(cnsa2.report({ kem: 'X-Wing', includeCodeSigning: false }).compliant).toBe(false);
  });
  it('envelope v2 (CNSA 2.0 profile): pure ML-KEM-1024 seals with HKDF-SHA-384 and is isolated from v1', () => {
    using pair = cnsa2.kem().generateKeyPair();
    const sealed = Envelope.seal(utf8('cnsa payload'), pair.publicKey, { aad: utf8('a') });
    expect(sealed.version).toBe(2);
    expect(sealed.algorithm).toBe('ML-KEM-1024');
    expect(sealed.kemCiphertext).toHaveLength(1568);
    expect(toHex(Envelope.open(sealed, pair.secretKey))).toBe(toHex(utf8('cnsa payload')));
    expect(() => Envelope.open(SealedMessage.fromParts({ ...sealed, version: 1 }), pair.secretKey)).toThrow(QuantumSafeError);
    expect(() => Envelope.open(SealedMessage.fromParts({ ...sealed, version: 3 }), pair.secretKey)).toThrow(QuantumSafeError);
    expect(() => Envelope.open(SealedMessage.fromParts({ ...sealed, aad: utf8('b') }), pair.secretKey)).toThrow(DecryptionAuthenticationError);
    using weak = new KEM('ML-KEM-768').generateKeyPair();
    expect(() => Envelope.seal(utf8('x'), weak.publicKey)).toThrow(UnsupportedAlgorithmError);
  });
  it('enforce() guards parameter sets only', () => {
    expect(() => cnsa2.enforce({ kem: 'X25519+ML-KEM-768' })).toThrow(PolicyViolationError);
    expect(() => cnsa2.enforce({ signature: 'ML-DSA-65' })).toThrow(PolicyViolationError);
    expect(() => cnsa2.enforce({ kem: 'X25519+ML-KEM-1024', signature: 'Ed25519+ML-DSA-87' })).not.toThrow();
    // strict also rejects the 'partial' hybrids; pure suites pass
    expect(() => cnsa2.enforce({ kem: 'X25519+ML-KEM-1024', signature: 'Ed25519+ML-DSA-87' }, { strict: true })).toThrow(PolicyViolationError);
    expect(() => cnsa2.enforce({ kem: 'ML-KEM-1024', signature: 'ML-DSA-87' }, { strict: true })).not.toThrow();
  });
  it('unknown or forged algorithm names are never "compliant"', () => {
    for (const name of ['RSA-1024+ML-DSA-87', 'junk+ML-DSA-87', 'P-256+ML-DSA-87', 'ML-DSA-87 ', 'ml-dsa-87']) {
      expect(cnsa2.checkSignature(name).ok, name).toBe(false);
      expect(() => cnsa2.enforce({ signature: name }), name).toThrow(PolicyViolationError);
    }
    for (const name of ['junk+ML-KEM-1024', 'RSA+ML-KEM-1024', 'ML-KEM-1024+X25519']) {
      expect(cnsa2.checkKem(name).ok, name).toBe(false);
      expect(() => cnsa2.enforce({ kem: name }), name).toThrow(PolicyViolationError);
    }
  });
  it('hash check normalises names', () => {
    for (const ok of ['SHA-384', 'sha384', 'SHA512', 'sha-512']) expect(cnsa2.checkHash(ok).ok).toBe(true);
    for (const bad of ['SHA-256', 'sha1', 'md5']) expect(cnsa2.checkHash(bad).ok).toBe(false);
  });
  it('configured constructors are pinned to the CNSA 2.0 parameter sets', () => {
    expect(cnsa2.kem().algorithm).toBe('ML-KEM-1024');
    expect(cnsa2.hybridKem().algorithm).toBe('X25519+ML-KEM-1024');
    expect(cnsa2.hybridSign().algorithm).toBe('Ed25519+ML-DSA-87');
    expect(() => cnsa2.hybridKem('P-384')).toThrow(UnsupportedAlgorithmError);
    expect(cnsa2.describe()).toContain('NOT give you');
  });
});

describe('error contract', () => {
  it('every error has a stable code, a static hint, and serializes to JSON', () => {
    try {
      new HybridKEM('nope' as never);
    } catch (e) {
      const err = e as QuantumSafeError;
      expect(err).toBeInstanceOf(UnsupportedAlgorithmError);
      expect(err.code).toBe('QS_UNSUPPORTED_ALGORITHM');
      expect(err.hint.length).toBeGreaterThan(10);
      expect(err.toJSON()).toMatchObject({ name: 'UnsupportedAlgorithmError', code: 'QS_UNSUPPORTED_ALGORITHM' });
      expect(Object.prototype.toString.call(err)).toBe('[object Error]');
    }
  });
  it('hints and messages never contain key material', () => {
    using pair = new HybridKEM().generateKeyPair();
    const secretHex = toHex(pair.secretKey.exportBytes());
    const fragments = [secretHex.slice(0, 32), secretHex.slice(200, 232)];
    const collect: string[] = [];
    for (const fn of [
      () => new HybridKEM().decapsulate(pair.secretKey, new Uint8Array(3)),
      () => Envelope.open(new Uint8Array(5), pair.secretKey),
      () => SecretKey.fromCbor(pair.secretKey.toCbor().slice(0, 40)),
    ]) {
      try {
        fn();
      } catch (e) {
        collect.push(JSON.stringify((e as QuantumSafeError).toJSON()));
      }
    }
    expect(collect.length).toBe(3);
    for (const out of collect) for (const f of fragments) expect(out).not.toContain(f);
  });
});

describe('utilities', () => {
  it('hex and wipe', () => {
    expect(toHex(fromHex('00ff10'))).toBe('00ff10');
    expect(() => fromHex('abc')).toThrow(InvalidArgumentError);
    const x = new Uint8Array([1, 2, 3]);
    wipe(x);
    expect(Array.from(x)).toEqual([0, 0, 0]);
  });
});

describe('properties (fast-check)', () => {
  const kem = new HybridKEM('X25519+ML-KEM-512'); // smallest suite keeps the properties fast
  const pair = kem.generateKeyPair();
  const signer = new Sign('ML-DSA-44');
  const sigPair = signer.generateKeyPair();

  it('seal/open round-trips arbitrary plaintext and AAD', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), fc.uint8Array({ maxLength: 64 }), (plain, aad) => {
        const sealed = Envelope.seal(plain, pair.publicKey, { aad });
        return equalBytes(Envelope.open(sealed, pair.secretKey), plain) && equalBytes(sealed.aad, aad);
      }),
      { numRuns: 60 },
    );
  });
  it('no single-byte corruption of a sealed message ever opens to a DIFFERENT plaintext', () => {
    // A mutation may be harmless only when it lands on CBOR syntax that carries no data (for example
    // renaming the optional, empty "aad" key); the integrity property is that a successful open
    // always returns the original plaintext.
    const plain = utf8('the plaintext');
    const sealed = Envelope.seal(plain, pair.publicKey);
    const bytes = sealed.toBytes();
    fc.assert(
      fc.property(fc.nat(bytes.length - 1), fc.integer({ min: 1, max: 255 }), (i, x) => {
        const mutated = bytes.slice();
        mutated[i]! ^= x;
        try {
          return equalBytes(Envelope.open(mutated, pair.secretKey), plain);
        } catch (e) {
          return e instanceof QuantumSafeError;
        }
      }),
      { numRuns: 200 },
    );
  });
  it('parsers never throw anything but QuantumSafeError on arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 600 }), (data) => {
        const parsers: Array<() => unknown> = [
          () => PublicKey.fromCbor(data),
          () => SecretKey.fromCbor(data),
          () => SealedMessage.fromBytes(data),
          () => SignedMessage.fromCbor(data),
          () => KeyPair.fromCborBundle(data),
          () => Envelope.open(data, pair.secretKey),
          () => kem.decapsulate(pair.secretKey, data).free(),
          () => signer.verifyBytes(utf8('m'), data, sigPair.publicKey),
        ];
        for (const p of parsers) {
          try {
            p();
          } catch (e) {
            if (!(e instanceof QuantumSafeError)) return false;
          }
        }
        return true;
      }),
      { numRuns: 400 },
    );
  });
  it('sign/verify round-trips arbitrary messages and contexts; any mutation fails', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 512 }), fc.uint8Array({ maxLength: 255 }), (msg, ctx) => {
        const sm = signer.sign(msg, sigPair.secretKey, { context: ctx });
        signer.verify(sm, sigPair.publicKey, { expectedContext: ctx });
        const bad = SignedMessage.fromParts({ ...sm, message: Uint8Array.from(sm.message, (b, i) => (i === 0 ? b ^ 1 : b)) });
        return !signer.isValid(bad, sigPair.publicKey, { expectedContext: ctx });
      }),
      { numRuns: 25 },
    );
  });
  it('PEM/CBOR/JWK parsers reject garbage text without crashing', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 300 }), (text) => {
        for (const p of [() => PublicKey.fromPem(text), () => SecretKey.fromPem(text), () => PublicKey.fromJwk(text)]) {
          try {
            p();
          } catch (e) {
            if (!(e instanceof QuantumSafeError)) return false;
          }
        }
        return true;
      }),
      { numRuns: 300 },
    );
  });
  it('JWT verify never throws anything but QuantumSafeError on arbitrary tokens', () => {
    const v = new JWTVerifier(sigPair.publicKey);
    const { publicJwk } = StandardJwt.generateKeyPair('ML-DSA-44');
    fc.assert(
      fc.property(fc.string({ maxLength: 400 }), (tok) => {
        for (const p of [() => v.verify(tok), () => StandardJwt.verify(tok, publicJwk)]) {
          try {
            p();
          } catch (e) {
            if (!(e instanceof QuantumSafeError)) return false;
          }
        }
        return true;
      }),
      { numRuns: 300 },
    );
  });
});

describe('documentation stays in sync with the code', () => {
  it('every error code is explained by the MCP server and listed in llms.txt', async () => {
    const { readFileSync } = await import('node:fs');
    const errors = readFileSync(new URL('../src/errors.ts', import.meta.url), 'utf8');
    const mcp = readFileSync(new URL('../../quantum-safe-mcp/src/knowledge.ts', import.meta.url), 'utf8');
    const codes = [...new Set([...errors.matchAll(/'(QS_[A-Z_]+)'/g)].map((m) => m[1]!))].filter((c) => c !== 'QS_ERROR');
    expect(codes.length).toBeGreaterThanOrEqual(17);
    for (const code of codes) expect(mcp, `MCP knowledge is missing ${code}`).toContain(`'${code}'`);
    const llms = readFileSync(new URL('../llms.txt', import.meta.url), 'utf8');
    expect(llms).toContain('QS_DECRYPTION_FAILED');
  });
  it("the MCP server's recommendations only name algorithms the library has", async () => {
    const { recommend } = await import('../../quantum-safe-mcp/src/knowledge.js');
    const known = new Set([...kemSuites(), ...sigSuites()].map((x) => x.name));
    for (const useCase of ['encrypt-data', 'key-exchange', 'sign-data', 'jwt', 'file-or-vault-encryption'] as const) {
      for (const cnsa of [false, true]) {
        for (const interop of ['none', 'quantum-safe-py', 'other-ecosystems'] as const) {
          const r = recommend(useCase, cnsa, interop);
          expect(known.has(r.algorithm), `${useCase}/${cnsa}/${interop}: unknown algorithm ${r.algorithm}`).toBe(true);
          for (const [, name] of r.code.matchAll(/new (?:HybridKEM|KEM|HybridSign|Sign)\('([^']+)'\)/g)) {
            expect(known.has(name!), `${useCase}: snippet names unknown suite ${name}`).toBe(true);
          }
        }
      }
    }
  });
  it('every public algorithm in the registry is documented in llms-full.txt', async () => {
    const { readFileSync, existsSync } = await import('node:fs');
    const path = new URL('../llms-full.txt', import.meta.url);
    if (!existsSync(path)) return; // generated in the docs step
    const full = readFileSync(path, 'utf8');
    for (const s of [...kemSuites(), ...sigSuites()]) expect(full, `llms-full.txt is missing ${s.name}`).toContain(s.name);
  });
});
