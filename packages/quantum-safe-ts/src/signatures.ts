import { DEFAULT_HYBRID_SIGNATURE, DEFAULT_SIGNATURE, sigSuites } from './algorithms.js';
import type { SignatureAlgorithm, SuiteInfo } from './algorithms.js';
import { AlgorithmMismatchError, InvalidArgumentError, UnsupportedAlgorithmError } from './errors.js';
import { KeyPair, PublicKey, SecretKey } from './keys.js';
import { call } from './runtime.js';
import { bytes, fromHex, toHex } from './utils.js';

const MAX_CONTEXT = 255;

/** Non-secret metadata of a signed message. */
export interface SignedInfo {
  readonly algorithm: string;
  readonly isHybrid: boolean;
  readonly messageLength: number;
  readonly signatureLength: number;
  readonly contextLength: number;
  readonly signerFingerprint: string;
  readonly signedAt: number;
}

/**
 * A message together with its signature and metadata, self-contained and serialized as CBOR
 * identical to quantum-safe-py's `SignedMessage`.
 */
export class SignedMessage {
  /** The signed message bytes. */
  readonly message: Uint8Array;
  /** Signature blob: `len(prefix) ‖ prefix ‖ payload` (hybrid payload is CBOR with both signatures). */
  readonly signature: Uint8Array;
  /** Algorithm, e.g. `Ed25519+ML-DSA-65`. */
  readonly algorithm: string;
  /** Domain-separation context (at most 255 bytes). Part of what is signed. */
  readonly context: Uint8Array;
  /** Hex fingerprint of the signer's public key, or `''`. Metadata, not authenticated. */
  readonly signerFingerprint: string;
  /** Unix time in seconds when signed. Metadata only: **not** covered by the signature. */
  readonly signedAt: number;
  /** True for classical+PQC hybrid signatures. */
  readonly isHybrid: boolean;
  readonly #cbor: Uint8Array;

  private constructor(cbor: Uint8Array) {
    this.#cbor = cbor;
    const p = call((w) => w.signedMessageParse(cbor));
    try {
      this.message = p.message;
      this.signature = p.signature;
      this.algorithm = p.algorithm;
      this.context = p.context;
      this.signerFingerprint = p.signerFingerprint;
      this.signedAt = p.signedAt;
      this.isHybrid = p.isHybrid;
    } finally {
      p.free();
    }
  }

  /** Parses CBOR from {@link SignedMessage.toCbor} or quantum-safe-py `SignedMessage.to_cbor()`. */
  static fromCbor(data: Uint8Array): SignedMessage {
    return new SignedMessage(bytes(data, 'data').slice());
  }
  /** Parses a hex string produced by {@link SignedMessage.toHex}. */
  static fromHex(hex: string): SignedMessage {
    return SignedMessage.fromCbor(fromHex(hex));
  }
  /** Assembles a signed message from stored fields (for example separate database columns). */
  static fromParts(parts: {
    message: Uint8Array;
    signature: Uint8Array;
    algorithm: string;
    context?: Uint8Array;
    signerFingerprint?: string;
    signedAt?: number;
    isHybrid?: boolean;
  }): SignedMessage {
    const cbor = call((w) =>
      w.signedMessageEncode(
        bytes(parts.message, 'message'),
        bytes(parts.signature, 'signature'),
        parts.algorithm,
        bytes(parts.context ?? new Uint8Array(), 'context'),
        parts.signerFingerprint ?? '',
        parts.signedAt ?? Date.now() / 1000,
        parts.isHybrid ?? parts.algorithm.includes('+'),
      ),
    );
    return new SignedMessage(cbor);
  }

  /** CBOR serialization (copy). */
  toCbor(): Uint8Array {
    return this.#cbor.slice();
  }
  toHex(): string {
    return toHex(this.#cbor);
  }
  /** Non-secret metadata without echoing the message. */
  inspect(): SignedInfo {
    return JSON.parse(call((w) => w.signedMessageInspect(this.#cbor))) as SignedInfo;
  }
  toString(): string {
    return `SignedMessage(${this.algorithm}, msg=${this.message.length} B)`;
  }
}

/** Options for signing. */
export interface SignOptions {
  /** Domain-separation context, at most 255 bytes. Include app name and protocol version. */
  context?: Uint8Array;
  /** Fingerprint of the signer's public key to record in the message (metadata only). */
  signerFingerprint?: string;
}

function lookup(algorithm: string, hybrid: boolean): SuiteInfo {
  const info = sigSuites().find((s) => s.name === algorithm);
  if (!info || info.hybrid !== hybrid) {
    throw new UnsupportedAlgorithmError(
      `'${String(algorithm)}' is not a supported ${hybrid ? 'hybrid' : 'single-algorithm'} signature algorithm.`,
    );
  }
  return info;
}

abstract class BaseSigner {
  readonly algorithm: SignatureAlgorithm;
  readonly info: SuiteInfo;
  /** True when each signature is prefixed with 32 random bytes (default; see quantum-safe-py). */
  readonly hedged: boolean;

  protected constructor(algorithm: string, hybrid: boolean, hedged: boolean) {
    this.info = lookup(algorithm, hybrid);
    this.algorithm = this.info.name as SignatureAlgorithm;
    this.hedged = hedged;
  }

  /** Generates a signing key pair. Free it (or use `using`) when done. */
  generateKeyPair(): KeyPair {
    return new KeyPair(call((w) => w.sigGenerateKeyPair(this.algorithm)));
  }

  /**
   * Signs `message`.
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {InvalidArgumentError} for an empty message or a context over 255 bytes.
   */
  sign(message: Uint8Array, secretKey: SecretKey, options: SignOptions = {}): SignedMessage {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    this.#check(secretKey.algorithm);
    const context = bytes(options.context ?? new Uint8Array(), 'context');
    if (context.length > MAX_CONTEXT) throw new InvalidArgumentError('context must be at most 255 bytes.');
    const cbor = call((w) =>
      w.sigSign(
        secretKey._wasm,
        bytes(message, 'message'),
        context,
        !this.hedged,
        options.signerFingerprint ?? '',
        Date.now() / 1000,
      ),
    );
    return SignedMessage.fromCbor(cbor);
  }

  /** Signs and records `keyPair.publicKey.fingerprint()` in the message. */
  signWithFingerprint(message: Uint8Array, keyPair: KeyPair, options: Omit<SignOptions, 'signerFingerprint'> = {}) {
    return this.sign(message, keyPair.secretKey, {
      ...options,
      signerFingerprint: keyPair.publicKey.fingerprint(),
    });
  }

  /**
   * Verifies a signed message. For hybrids **both** signatures must be valid.
   * @throws {VerificationError} if the signature does not verify (no detail on why, by design).
   * @throws {AlgorithmMismatchError} if key and message algorithms differ.
   */
  verify(signed: SignedMessage, publicKey: PublicKey): void {
    if (!(signed instanceof SignedMessage)) throw new InvalidArgumentError('signed must be a SignedMessage.');
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    this.#check(publicKey.algorithm);
    if (signed.algorithm !== this.algorithm) {
      throw new AlgorithmMismatchError(`Signed message algorithm '${signed.algorithm}' does not match '${this.algorithm}'.`);
    }
    call((w) => w.sigVerify(signed.toCbor(), publicKey._wasm));
  }

  /** Verifies a detached `message` + `signature` blob + `context` without a SignedMessage. */
  verifyBytes(message: Uint8Array, signature: Uint8Array, publicKey: PublicKey, options: { context?: Uint8Array } = {}): void {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    this.#check(publicKey.algorithm);
    call((w) =>
      w.sigVerifyParts(
        this.algorithm,
        bytes(message, 'message'),
        bytes(signature, 'signature'),
        bytes(options.context ?? new Uint8Array(), 'context'),
        publicKey._wasm,
      ),
    );
  }

  /** Like {@link verify} but returns a boolean instead of throwing {@link VerificationError}. */
  isValid(signed: SignedMessage, publicKey: PublicKey): boolean {
    try {
      this.verify(signed, publicKey);
      return true;
    } catch (e) {
      if ((e as { code?: string }).code === 'QS_VERIFICATION_FAILED') return false;
      throw e;
    }
  }

  #check(algorithm: string): void {
    if (algorithm !== this.algorithm) {
      throw new AlgorithmMismatchError(`Key algorithm '${algorithm}' does not match this signer ('${this.algorithm}').`);
    }
  }
}

/**
 * Single-algorithm signatures: ML-DSA-44/65/87 or SLH-DSA (FIPS 205), matching quantum-safe-py's
 * `Sign`. Hedged by default.
 *
 * Note: quantum-safe-py's context handling is a message prefix, not FIPS 204's native context
 * parameter, so these signatures verify under a generic ML-DSA library only if it reconstructs
 * `len(ctx) ‖ ctx ‖ prefix ‖ message`. For interoperable signatures use the standards-mode JWT.
 *
 * @example
 * ```ts
 * const signer = new Sign(); // ML-DSA-65
 * using pair = signer.generateKeyPair();
 * const sm = signer.sign(utf8('hello'), pair.secretKey, { context: utf8('myapp-v1') });
 * signer.verify(sm, pair.publicKey);
 * ```
 */
export class Sign extends BaseSigner {
  constructor(algorithm: Exclude<SignatureAlgorithm, `${string}+${string}`> = DEFAULT_SIGNATURE, options: { hedged?: boolean } = {}) {
    super(algorithm, false, options.hedged ?? true);
  }
}

/**
 * Hybrid classical + post-quantum signatures (default `Ed25519+ML-DSA-65`), matching
 * quantum-safe-py's `HybridSign`. Both sub-signatures are verified unconditionally and both must
 * be valid.
 *
 * @example
 * ```ts
 * const signer = new HybridSign('Ed25519+ML-DSA-87'); // CNSA 2.0 parameter set
 * ```
 */
export class HybridSign extends BaseSigner {
  constructor(
    algorithm: Extract<SignatureAlgorithm, `${string}+${string}`> = DEFAULT_HYBRID_SIGNATURE,
    options: { hedged?: boolean } = {},
  ) {
    super(algorithm, true, options.hedged ?? true);
  }
}
