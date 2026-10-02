/**
 * The "easy" layer: string and byte in, string and byte out, no handles to free.
 *
 * ```ts
 * import { easy } from 'quantum-safe-ts';
 * const { publicKey, secretKey } = easy.generateEncryptionKeys();
 * const sealed = easy.encrypt(publicKey, 'attack at dawn');
 * const plain = easy.decrypt(secretKey, sealed);
 * ```
 *
 * Keys are PEM strings (`QUANTUM SAFE PUBLIC KEY` / `QUANTUM SAFE SECRET KEY`), which quantum-safe-py reads and writes too. Everything
 * here is a thin wrapper over the class API ({@link HybridKEM}, {@link Envelope}, {@link HybridSign}); the WASM objects it creates
 * are freed before each function returns.
 *
 * **Trade-off, stated plainly:** a secret key held as a string lives in the JavaScript heap, where this library cannot wipe it and where
 * a heap dump or a logger can see it. When that matters, use the class API with `using`/`.free()` and keep keys inside WASM memory.
 * Also: `encrypt`/`decrypt` use the quantum-safe-py-compatible envelope (HKDF-SHA-256); for CNSA 2.0 use `cnsa2.kem()`.
 */
import type { KemAlgorithm, SignatureAlgorithm } from './algorithms.js';
import { DEFAULT_HYBRID_SIGNATURE, DEFAULT_KEM } from './algorithms.js';
import { Envelope } from './envelope.js';
import { InvalidArgumentError, VerificationError } from './errors.js';
import { HybridKEM, KEM } from './kem.js';
import { PublicKey, SecretKey } from './keys.js';
import { HybridSign, Sign, SignedMessage } from './signatures.js';

/** A key pair as PEM strings. The secret key is a plain string: see the module note. */
export interface EasyKeyPair {
  /** PEM public key. Safe to share. */
  publicKey: string;
  /** PEM secret key. Treat like a password. */
  secretKey: string;
  algorithm: string;
}

/** Options for {@link verify}, {@link verifyText} and {@link isValid}. */
export interface VerifyOptions {
  /** The context the message was signed with (default: none). Verification fails if it differs. */
  context?: Data;
  /**
   * Whether the signer used hedging (default true, as quantum-safe-py does). Set `false` only for signatures made with hedging disabled:
   * the verifier must know which, because accepting either would make signatures on other messages forgeable (see `HybridSign.hedged`).
   */
  hedged?: boolean;
}

/** Text or bytes. Text is UTF-8 encoded. */
export type Data = Uint8Array | string;

const toBytes = (d: Data, name: string): Uint8Array => {
  if (typeof d === 'string') return new TextEncoder().encode(d);
  if (d instanceof Uint8Array) return d;
  throw new InvalidArgumentError(`${name} must be a string or Uint8Array.`);
};

const isPureKem = (a: string) => a.startsWith('ML-KEM-');
const isHybrid = (a: string) => a.includes('+') || a === 'X-Wing';

/** Generates an encryption key pair. Default `X25519+ML-KEM-768`. */
export function generateEncryptionKeys(algorithm: KemAlgorithm = DEFAULT_KEM): EasyKeyPair {
  using pair = (isPureKem(algorithm) ? new KEM(algorithm as 'ML-KEM-768') : new HybridKEM(algorithm)).generateKeyPair();
  return { publicKey: pair.publicKey.toPem(), secretKey: pair.secretKey.toPem(), algorithm: pair.algorithm };
}

/**
 * Encrypts `data` to a public key. The result is a self-describing sealed message (CBOR) that only the matching secret key opens.
 * `aad` (optional) is authenticated but not encrypted: it travels inside the message and any change to it makes decryption fail.
 * @throws {KeyParseError} if `publicKey` is not a valid PEM public key.
 */
export function encrypt(publicKey: string, data: Data, options: { aad?: Data } = {}): Uint8Array {
  using pub = PublicKey.fromPem(publicKey);
  const aad = options.aad === undefined ? undefined : toBytes(options.aad, 'aad');
  return Envelope.seal(toBytes(data, 'data'), pub, aad ? { aad } : {}).toBytes();
}

/**
 * Decrypts a message made by {@link encrypt} (or by quantum-safe-py's `Envelope.seal`). Returns bytes: use {@link decryptText} for a string.
 *
 * `options.aad` binds the message to a context: if given, decryption fails unless the message was sealed with exactly that `aad`. Without it
 * any message sealed to your key opens, whatever its AAD (anyone with your public key can seal one). This is anonymous encryption; it does not
 * say who sent the message, so sign separately when that matters.
 * @throws {DecryptionAuthenticationError} if the key is wrong, the message was modified, or `aad` does not match.
 */
export function decrypt(secretKey: string, sealed: Uint8Array, options: { aad?: Data } = {}): Uint8Array {
  using sec = SecretKey.fromPem(secretKey);
  return Envelope.open(sealed, sec, options.aad === undefined ? {} : { expectedAad: toBytes(options.aad, 'aad') });
}

/** Like {@link decrypt} but decodes the plaintext as UTF-8 text. */
export function decryptText(secretKey: string, sealed: Uint8Array, options: { aad?: Data } = {}): string {
  return new TextDecoder().decode(decrypt(secretKey, sealed, options));
}

/** Generates a signing key pair. Default `Ed25519+ML-DSA-65` (both signatures must verify). */
export function generateSigningKeys(algorithm: SignatureAlgorithm = DEFAULT_HYBRID_SIGNATURE): EasyKeyPair {
  using pair = (isHybrid(algorithm) ? new HybridSign(algorithm as 'Ed25519+ML-DSA-65') : new Sign(algorithm as 'ML-DSA-65')).generateKeyPair();
  return { publicKey: pair.publicKey.toPem(), secretKey: pair.secretKey.toPem(), algorithm: pair.algorithm };
}

/**
 * Signs `message`. The result is a self-contained signed message (CBOR). `context` is a domain-separation label that is part of what is
 * signed (at most 255 bytes): use a different one per purpose, and pass the same one to {@link verify}.
 */
export function sign(secretKey: string, message: Data, options: { context?: Data } = {}): Uint8Array {
  using sec = SecretKey.fromPem(secretKey);
  const context = options.context === undefined ? new Uint8Array() : toBytes(options.context, 'context');
  const signer = isHybrid(sec.algorithm) ? new HybridSign(sec.algorithm as 'Ed25519+ML-DSA-65') : new Sign(sec.algorithm as 'ML-DSA-65');
  return signer.sign(toBytes(message, 'message'), sec, { context }).toCbor();
}

/**
 * Verifies a signed message and returns the message it carries. Throws unless the signature is valid **and** its context equals
 * `options.context` (default: empty), so a signature made for one purpose cannot be replayed for another.
 * @throws {VerificationError} if the signature is invalid, made by another key, or has a different context.
 */
export function verify(publicKey: string, signed: Uint8Array, options: VerifyOptions = {}): Uint8Array {
  using pub = PublicKey.fromPem(publicKey);
  const sm = SignedMessage.fromCbor(signed);
  const expectedContext = options.context === undefined ? new Uint8Array() : toBytes(options.context, 'context');
  const hedged = options.hedged ?? true;
  const signer = isHybrid(pub.algorithm) ? new HybridSign(pub.algorithm as 'Ed25519+ML-DSA-65', { hedged }) : new Sign(pub.algorithm as 'ML-DSA-65', { hedged });
  signer.verify(sm, pub, { expectedContext });
  return sm.message;
}

/** Like {@link verify} but returns the message decoded as UTF-8 text. */
export function verifyText(publicKey: string, signed: Uint8Array, options: VerifyOptions = {}): string {
  return new TextDecoder().decode(verify(publicKey, signed, options));
}

/** Like {@link verify} but returns `true` or `false` instead of throwing {@link VerificationError}. Malformed input still throws. */
export function isValid(publicKey: string, signed: Uint8Array, options: VerifyOptions = {}): boolean {
  try {
    verify(publicKey, signed, options);
    return true;
  } catch (e) {
    if ((e as { code?: string }).code === 'QS_VERIFICATION_FAILED') return false;
    throw e;
  }
}
