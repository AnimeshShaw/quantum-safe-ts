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
  /** Canonical algorithm string of the pair, e.g. `X25519+ML-KEM-768`. */
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

/** Returns `d` as bytes (strings are UTF-8 encoded); throws {@link InvalidArgumentError} naming `name` for any other type. */
const toBytes = (d: Data, name: string): Uint8Array => {
  if (typeof d === 'string') return new TextEncoder().encode(d);
  if (d instanceof Uint8Array) return d;
  throw new InvalidArgumentError(`${name} must be a string or Uint8Array.`);
};

/** True for the pure ML-KEM names (`ML-KEM-512/768/1024`), which use the `KEM` class instead of `HybridKEM`. */
const isPureKem = (a: string) => a.startsWith('ML-KEM-');
/** True for hybrid names (those containing `+`, and `X-Wing`), which use `HybridSign` / `HybridKEM`. */
const isHybrid = (a: string) => a.includes('+') || a === 'X-Wing';

/**
 * Generates an encryption key pair. Default `X25519+ML-KEM-768`.
 * @param algorithm - KEM algorithm: a hybrid name (see `kemSuites()`) or a pure `ML-KEM-*` name.
 * @returns The PEM-encoded public and secret keys and the algorithm string. The WASM key objects are freed before returning.
 * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported KEM name.
 * @throws {NotInitializedError} if `init()` has not completed.
 * @example
 * ```ts
 * const { publicKey, secretKey } = easy.generateEncryptionKeys();
 * ```
 */
export function generateEncryptionKeys(algorithm: KemAlgorithm = DEFAULT_KEM): EasyKeyPair {
  using pair = (isPureKem(algorithm) ? new KEM(algorithm as 'ML-KEM-768') : new HybridKEM(algorithm)).generateKeyPair();
  return { publicKey: pair.publicKey.toPem(), secretKey: pair.secretKey.toPem(), algorithm: pair.algorithm };
}

/**
 * Encrypts `data` to a public key. The result is a self-describing sealed message (CBOR) that only the matching secret key opens.
 * `aad` (optional) is authenticated but not encrypted: it travels inside the message and any change to it makes decryption fail.
 * @param publicKey - PEM public key of the recipient, as returned by {@link generateEncryptionKeys}.
 * @param data - Plaintext; a string is UTF-8 encoded.
 * @param options.aad - Additional authenticated data (string or bytes). Stored in the clear inside the message. Default: none.
 * @returns The CBOR bytes of the sealed message.
 * @throws {KeyParseError} if `publicKey` is not a valid PEM public key.
 * @throws {InvalidArgumentError} if `data` or `aad` is neither a string nor a `Uint8Array`.
 * @throws {UnsupportedAlgorithmError} if the key is neither a hybrid KEM key nor a pure ML-KEM-1024 key.
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
 * @param secretKey - PEM secret key of the recipient.
 * @param sealed - The CBOR bytes returned by {@link encrypt}.
 * @param options.aad - The AAD the message must carry (string or bytes). Default: not checked.
 * @returns The plaintext bytes.
 * @throws {DecryptionAuthenticationError} if the key is wrong, the message was modified, or `aad` does not match.
 * @throws {KeyParseError} if `secretKey` is not a valid PEM secret key.
 * @throws {MalformedCiphertextError} if `sealed` is not a valid sealed message.
 * @throws {AlgorithmMismatchError} if the message was sealed to a different algorithm than the key's.
 * @throws {InvalidArgumentError} if `aad` is neither a string nor a `Uint8Array`.
 * @example
 * ```ts
 * const sealed = easy.encrypt(publicKey, 'hello', { aad: 'order-17' });
 * const plain = easy.decrypt(secretKey, sealed, { aad: 'order-17' });
 * ```
 */
export function decrypt(secretKey: string, sealed: Uint8Array, options: { aad?: Data } = {}): Uint8Array {
  using sec = SecretKey.fromPem(secretKey);
  return Envelope.open(sealed, sec, options.aad === undefined ? {} : { expectedAad: toBytes(options.aad, 'aad') });
}

/**
 * Like {@link decrypt} but decodes the plaintext as UTF-8 text. Invalid UTF-8 sequences decode to U+FFFD.
 * @param secretKey - PEM secret key of the recipient.
 * @param sealed - The CBOR bytes returned by {@link encrypt}.
 * @param options.aad - The AAD the message must carry. Default: not checked.
 * @returns The plaintext as a string.
 * @throws {DecryptionAuthenticationError} if the key is wrong, the message was modified, or `aad` does not match.
 * @throws {KeyParseError} if `secretKey` is not a valid PEM secret key.
 * @throws {MalformedCiphertextError} if `sealed` is not a valid sealed message.
 */
export function decryptText(secretKey: string, sealed: Uint8Array, options: { aad?: Data } = {}): string {
  return new TextDecoder().decode(decrypt(secretKey, sealed, options));
}

/**
 * Generates a signing key pair. Default `Ed25519+ML-DSA-65-v2` (`DEFAULT_HYBRID_SIGNATURE`); for hybrid suites both signatures must verify.
 * @param algorithm - Signature algorithm: a hybrid name (containing `+`) or a single-algorithm name (see `sigSuites()`).
 * @returns The PEM-encoded public and secret keys and the algorithm string. The WASM key objects are freed before returning.
 * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported signature name.
 * @throws {NotInitializedError} if `init()` has not completed.
 */
export function generateSigningKeys(algorithm: SignatureAlgorithm = DEFAULT_HYBRID_SIGNATURE): EasyKeyPair {
  using pair = (isHybrid(algorithm) ? new HybridSign(algorithm as 'Ed25519+ML-DSA-65') : new Sign(algorithm as 'ML-DSA-65')).generateKeyPair();
  return { publicKey: pair.publicKey.toPem(), secretKey: pair.secretKey.toPem(), algorithm: pair.algorithm };
}

/**
 * Signs `message`. The result is a self-contained signed message (CBOR). `context` is a domain-separation label that is part of what is
 * signed (at most 255 bytes): use a different one per purpose, and pass the same one to {@link verify}.
 * The signer type (hybrid or single) follows the algorithm of `secretKey`; signatures are hedged.
 * @param secretKey - PEM secret key from {@link generateSigningKeys}.
 * @param message - The message to sign; a string is UTF-8 encoded. Must not be empty.
 * @param options.context - Domain-separation label (string or bytes, at most 255 bytes). Default: empty.
 * @returns The CBOR bytes of the signed message, which carries the message itself.
 * @throws {KeyParseError} if `secretKey` is not a valid PEM secret key.
 * @throws {InvalidArgumentError} if `message` is empty, `message` or `context` has the wrong type, or `context` is over 255 bytes.
 * @example
 * ```ts
 * const signed = easy.sign(secretKey, 'release 1.2.3', { context: 'myapp-release' });
 * const message = easy.verify(publicKey, signed, { context: 'myapp-release' });
 * ```
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
 * @param publicKey - PEM public key of the signer.
 * @param signed - The CBOR bytes returned by {@link sign}.
 * @param options - Expected `context` and `hedged` mode; see {@link VerifyOptions}.
 * @returns The message carried by the signed message, as bytes.
 * @throws {VerificationError} if the signature is invalid, made by another key, or has a different context.
 * @throws {KeyParseError} if `publicKey` is not a valid PEM public key or `signed` is not a valid signed message.
 * @throws {AlgorithmMismatchError} if the key's algorithm differs from the signed message's.
 * @throws {InvalidArgumentError} if `context` is neither a string nor a `Uint8Array`.
 */
export function verify(publicKey: string, signed: Uint8Array, options: VerifyOptions = {}): Uint8Array {
  using pub = PublicKey.fromPem(publicKey);
  const sm = SignedMessage.fromCbor(signed);
  const hedged = options.hedged ?? true;
  const signer = isHybrid(pub.algorithm) ? new HybridSign(pub.algorithm as 'Ed25519+ML-DSA-65', { hedged }) : new Sign(pub.algorithm as 'ML-DSA-65', { hedged });
  // Omitted context means "expect none": the library then warns if the message carries one (QS_CONTEXT_OMITTED).
  signer.verify(sm, pub, options.context === undefined ? {} : { expectedContext: toBytes(options.context, 'context') });
  return sm.message;
}

/**
 * Like {@link verify} but returns the message decoded as UTF-8 text. Invalid UTF-8 sequences decode to U+FFFD.
 * @param publicKey - PEM public key of the signer.
 * @param signed - The CBOR bytes returned by {@link sign}.
 * @param options - Expected `context` and `hedged` mode; see {@link VerifyOptions}.
 * @returns The signed message as a string.
 * @throws {VerificationError} if the signature is invalid, made by another key, or has a different context.
 * @throws {KeyParseError} if `publicKey` is not a valid PEM public key or `signed` is not a valid signed message.
 */
export function verifyText(publicKey: string, signed: Uint8Array, options: VerifyOptions = {}): string {
  return new TextDecoder().decode(verify(publicKey, signed, options));
}

/**
 * Like {@link verify} but returns `true` or `false` instead of throwing {@link VerificationError}. Malformed input still throws.
 * @param publicKey - PEM public key of the signer.
 * @param signed - The CBOR bytes returned by {@link sign}.
 * @param options - Expected `context` and `hedged` mode; see {@link VerifyOptions}.
 * @returns `true` when the signature and context are valid, `false` on a verification failure.
 * @throws {KeyParseError} if `publicKey` is not a valid PEM public key or `signed` is not a valid signed message.
 * @throws {AlgorithmMismatchError} if the key's algorithm differs from the signed message's.
 */
export function isValid(publicKey: string, signed: Uint8Array, options: VerifyOptions = {}): boolean {
  try {
    verify(publicKey, signed, options);
    return true;
  } catch (e) {
    if ((e as { code?: string }).code === 'QS_VERIFICATION_FAILED') return false;
    throw e;
  }
}
