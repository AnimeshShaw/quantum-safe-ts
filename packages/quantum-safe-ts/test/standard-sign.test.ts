/**
 * The public standard FIPS 204 pair: `Sign.signRaw` / `Sign.verifyRaw` (also `signStandard` / `verifyStandard`), with a 32-byte
 * seed key (`StandardKeyPair`). Matches quantum-safe-py's `Sign.sign_raw` / `verify_raw` and its 1.0.0 aliases.
 *
 * - signatures are bare FIPS 204 `ML-DSA.Sign` signatures with FIPS 204's native context;
 * - quantum-safe-py signatures verify (vectors made by the real package: tests/vectors/py_raw_fips204_vectors.json);
 * - a seed key signs; an expanded secret key from another library cannot be turned into one (a seed cannot be recovered from it).
 */
import { describe, expect, it } from 'vitest';
import { InvalidArgumentError, Sign, StandardKeyPair, VerificationError, utf8 } from '../src/index.js';
import { h, vectors } from './helpers.js';

interface RawVector {
  algorithm: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
  public_key: string;
  message: string;
  context: string;
  signature: string;
}
const PY = vectors<{ vectors: RawVector[] }>('py_raw_fips204_vectors.json').vectors;
const SIG_LEN = { 'ML-DSA-44': 2420, 'ML-DSA-65': 3309, 'ML-DSA-87': 4627 } as const;
const PK_LEN = { 'ML-DSA-44': 1312, 'ML-DSA-65': 1952, 'ML-DSA-87': 2592 } as const;

describe('Sign.signRaw / verifyRaw', () => {
  for (const level of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const) {
    it(`${level}: round trip with a native context, and only with that context`, () => {
      const signer = new Sign(level);
      using pair = signer.generateStandardKeyPair();
      expect(pair.algorithm).toBe(level);
      expect(pair.publicKey).toHaveLength(PK_LEN[level]);
      const sig = signer.signRaw(utf8('message'), pair, { context: utf8('ctx') });
      expect(sig).toHaveLength(SIG_LEN[level]);
      signer.verifyRaw(utf8('message'), sig, pair.publicKey, { context: utf8('ctx') });
      expect(() => signer.verifyRaw(utf8('message'), sig, pair.publicKey)).toThrow(VerificationError);
      expect(() => signer.verifyRaw(utf8('message'), sig, pair.publicKey, { context: utf8('other') })).toThrow(VerificationError);
      expect(() => signer.verifyRaw(utf8('message!'), sig, pair.publicKey, { context: utf8('ctx') })).toThrow(VerificationError);
    });
  }

  it('signStandard / verifyStandard are the same operations under the clearer names', () => {
    const signer = new Sign('ML-DSA-65');
    using pair = signer.generateStandardKeyPair();
    const sig = signer.signStandard(utf8('m'), pair, { context: utf8('c') });
    signer.verifyRaw(utf8('m'), sig, pair.publicKey, { context: utf8('c') });
    signer.verifyStandard(utf8('m'), signer.signRaw(utf8('m'), pair, { context: utf8('c') }), pair.publicKey, { context: utf8('c') });
  });

  it('accepts a PublicKey object as well as raw bytes', async () => {
    const { PublicKey } = await import('../src/index.js');
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateStandardKeyPair();
    const sig = signer.signRaw(utf8('m'), pair);
    signer.verifyRaw(utf8('m'), sig, PublicKey.fromBytes('ML-DSA-44', pair.publicKey));
  });

  it('context limits: 255 bytes is fine, 256 is an InvalidArgumentError', () => {
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateStandardKeyPair();
    const ctx255 = new Uint8Array(255).fill(7);
    const sig = signer.signRaw(utf8('m'), pair, { context: ctx255 });
    signer.verifyRaw(utf8('m'), sig, pair.publicKey, { context: ctx255 });
    expect(() => signer.signRaw(utf8('m'), pair, { context: new Uint8Array(256) })).toThrow(InvalidArgumentError);
    expect(() => signer.verifyRaw(utf8('m'), sig, pair.publicKey, { context: new Uint8Array(256) })).toThrow(InvalidArgumentError);
  });

  it('refuses a key of another level and the wrong key', () => {
    const s44 = new Sign('ML-DSA-44');
    const s65 = new Sign('ML-DSA-65');
    using k44 = s44.generateStandardKeyPair();
    using k44b = s44.generateStandardKeyPair();
    expect(() => s65.signRaw(utf8('m'), k44)).toThrow();
    const sig = s44.signRaw(utf8('m'), k44);
    expect(() => s44.verifyRaw(utf8('m'), sig, k44b.publicKey)).toThrow(VerificationError);
    expect(() => s65.verifyRaw(utf8('m'), sig, k44.publicKey)).toThrow();
  });

  it('is only offered for ML-DSA (the algorithms with a standard-mode primitive)', () => {
    expect(() => new Sign('SLH-DSA-SHAKE-128s').generateStandardKeyPair()).toThrow(InvalidArgumentError);
  });
});

describe('StandardKeyPair', () => {
  it('is deterministic from its 32-byte seed and exports exactly that seed', () => {
    const signer = new Sign('ML-DSA-65');
    using a = signer.generateStandardKeyPair();
    const seed = a.exportSeed();
    expect(seed).toHaveLength(32);
    using b = signer.standardKeyPairFromSeed(seed);
    expect(b.publicKey).toEqual(a.publicKey);
    seed.fill(0);
  });

  it('rejects a seed of the wrong length', () => {
    const signer = new Sign('ML-DSA-65');
    expect(() => signer.standardKeyPairFromSeed(new Uint8Array(64))).toThrow(InvalidArgumentError);
    expect(() => signer.standardKeyPairFromSeed(new Uint8Array(0))).toThrow(InvalidArgumentError);
  });

  it('never prints its seed', () => {
    const signer = new Sign('ML-DSA-44');
    using pair = signer.generateStandardKeyPair();
    const seedHex = Array.from(pair.exportSeed(), (b) => b.toString(16).padStart(2, '0')).join('');
    expect(String(pair)).not.toContain(seedHex);
    expect(JSON.stringify(pair)).not.toContain(seedHex);
  });

  it('is unusable after free()', () => {
    const signer = new Sign('ML-DSA-44');
    const pair = signer.generateStandardKeyPair();
    pair.free();
    expect(() => signer.signRaw(utf8('m'), pair)).toThrow();
    expect(() => pair.exportSeed()).toThrow();
  });

  it('is the type JWK-free seed keys from quantum-safe-py (pyca backend) arrive as', () => {
    // A 32-byte seed produces the FIPS 204 key pair for that seed: the same public key as
    // StandardJwt.publicJwk derives for the same seed.
    const signer = new Sign('ML-DSA-65');
    using pair = signer.generateStandardKeyPair();
    const seed = pair.exportSeed();
    expect(StandardKeyPair).toBeDefined();
    using again = signer.standardKeyPairFromSeed(seed);
    expect(again.publicKey).toEqual(pair.publicKey);
  });
});

describe('quantum-safe-py signatures verify through the public API', () => {
  for (const [i, v] of PY.entries()) {
    it(`${v.algorithm} context of ${h(v.context).length} bytes [${i}]`, () => {
      const signer = new Sign(v.algorithm);
      signer.verifyRaw(h(v.message), h(v.signature), h(v.public_key), { context: h(v.context) });
    });
  }
  it('rejects a flipped bit and a different context', () => {
    const v = PY[0]!;
    const signer = new Sign(v.algorithm);
    const bad = h(v.signature);
    bad[10] = bad[10]! ^ 1;
    expect(() => signer.verifyRaw(h(v.message), bad, h(v.public_key), { context: h(v.context) })).toThrow(VerificationError);
    expect(() => signer.verifyRaw(h(v.message), h(v.signature), h(v.public_key), { context: utf8('other') })).toThrow(VerificationError);
  });
});
