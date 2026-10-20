import { DEFAULT_HYBRID_SIGNATURE, DEFAULT_SIGNATURE, ORIGINAL_HYBRID_SIGNATURE, sigSuites } from './algorithms.js';
import type { SignatureAlgorithm, SuiteInfo } from './algorithms.js';
import { AlgorithmMismatchError, InvalidArgumentError, UnsupportedAlgorithmError, VerificationError } from './errors.js';
import { KeyPair, PublicKey, SecretBytes, SecretKey } from './keys.js';
import { call } from './runtime.js';
import { warnOnce } from './warnings.js';
import { StandardKeyPair, STANDARD_SEED_LENGTH, checkStandardAlgorithm } from './standard.js';
import { bytes, equalBytes, fromHex, toHex } from './utils.js';

/** Longest allowed signature context, in bytes (the FIPS 204 limit). */
const MAX_CONTEXT = 255;

/** Non-secret metadata of a signed message. */
export interface SignedInfo {
  /** Algorithm the message was signed with, e.g. `Ed25519+ML-DSA-65`. */
  readonly algorithm: string;
  /** True for classical+PQC hybrid signatures. */
  readonly isHybrid: boolean;
  /** Length of the signed message in bytes. */
  readonly messageLength: number;
  /** Length of the signature blob in bytes. */
  readonly signatureLength: number;
  /** Length of the context in bytes. */
  readonly contextLength: number;
  /** Hex fingerprint of the signer's public key recorded in the message, or `''`. Not authenticated. */
  readonly signerFingerprint: string;
  /** Unix time in seconds when signed. Not covered by the signature. */
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
  /** The CBOR encoding this object was parsed from; `toCbor()` and `toHex()` return it (a copy for `toCbor()`). */
  readonly #cbor: Uint8Array;

  /** Parses `cbor` through the core and copies the fields out; use the static factories. */
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

  /**
   * Parses CBOR from {@link SignedMessage.toCbor} or quantum-safe-py `SignedMessage.to_cbor()`. The input is copied.
   * @param data - CBOR-encoded signed message.
   * @returns The parsed message.
   * @throws {InvalidArgumentError} if `data` is not bytes, or the encoded message is empty.
   * @throws {KeyParseError} if `data` is not a valid signed message.
   */
  static fromCbor(data: Uint8Array): SignedMessage {
    return new SignedMessage(bytes(data, 'data').slice());
  }
  /**
   * Alias of {@link SignedMessage.fromCbor}, matching `SealedMessage.fromBytes`.
   * @param data - CBOR-encoded signed message.
   * @returns The parsed message.
   * @throws {KeyParseError} if `data` is not a valid signed message.
   */
  static fromBytes(data: Uint8Array): SignedMessage {
    return SignedMessage.fromCbor(data);
  }
  /**
   * Parses a hex string produced by {@link SignedMessage.toHex}.
   * @param hex - Hex of the CBOR encoding, either case.
   * @returns The parsed message.
   * @throws {InvalidArgumentError} if `hex` is not valid hex.
   * @throws {KeyParseError} if the decoded bytes are not a valid signed message.
   */
  static fromHex(hex: string): SignedMessage {
    return SignedMessage.fromCbor(fromHex(hex));
  }
  /**
   * Assembles a signed message from stored fields (for example separate database columns).
   * @param parts - The fields. `context` defaults to empty, `signerFingerprint` to `''`, `signedAt` to the current time in seconds,
   * and `isHybrid` to whether `algorithm` contains `+`.
   * @returns The message re-parsed from its CBOR encoding. The signature is not verified.
   * @throws {InvalidArgumentError} if `message` or `signature` is empty, `context` is over 255 bytes, or a byte field is not bytes.
   */
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

  /**
   * Alias of {@link SignedMessage.toCbor}, matching `SealedMessage.toBytes`.
   * @returns A fresh copy of the CBOR bytes.
   */
  toBytes(): Uint8Array {
    return this.toCbor();
  }
  /**
   * CBOR serialization (copy).
   * @returns A fresh copy of the CBOR bytes.
   */
  toCbor(): Uint8Array {
    return this.#cbor.slice();
  }
  /**
   * Lowercase hex of {@link SignedMessage.toCbor}.
   * @returns The hex string.
   */
  toHex(): string {
    return toHex(this.#cbor);
  }
  /**
   * Non-secret metadata without echoing the message.
   * @returns Algorithm, lengths, signer fingerprint and signing time.
   * @throws {NotInitializedError} if the WASM module is not initialised.
   */
  inspect(): SignedInfo {
    return JSON.parse(call((w) => w.signedMessageInspect(this.#cbor))) as SignedInfo;
  }
  /** Short description with the algorithm and message length; contains no message data. */
  toString(): string {
    return `SignedMessage(${this.algorithm}, msg=${this.message.length} B)`;
  }
}

/** Options for signing. */
export interface SignOptions {
  /** Domain-separation context, at most 255 bytes. Include app name and protocol version. */
  context?: Uint8Array;
  /** Fingerprint of the signer's public key to record in the message (metadata only). Default: none (`''`). */
  signerFingerprint?: string;
}

/**
 * Finds the suite named `algorithm` in {@link sigSuites}; its `hybrid` flag must equal `hybrid`.
 * Throws {@link UnsupportedAlgorithmError} when the name is unknown or is of the other kind (hybrid versus single).
 */
function lookup(algorithm: string, hybrid: boolean): SuiteInfo {
  const info = sigSuites().find((s) => s.name === algorithm);
  if (!info || info.hybrid !== hybrid) {
    throw new UnsupportedAlgorithmError(
      `'${String(algorithm)}' is not a supported ${hybrid ? 'hybrid' : 'single-algorithm'} signature algorithm.`,
    );
  }
  return info;
}

/** Shared implementation of {@link Sign} and {@link HybridSign}: one instance is bound to one algorithm and one hedging mode. */
abstract class BaseSigner {
  /** Canonical algorithm string. */
  readonly algorithm: SignatureAlgorithm;
  /** Suite metadata (NIST level, CNSA 2.0 status, format, ...). */
  readonly info: SuiteInfo;
  /**
   * True when each signature is prefixed with 32 random bytes (default; see quantum-safe-py).
   *
   * On a **verifier** this is also a security setting: the signed bytes are `len(ctx) || ctx || prefix || message` and the prefix length is
   * stored in the *unsigned* signature blob, so a verifier that accepted any prefix length would let anyone move bytes between the prefix and
   * the message of a valid signature and obtain a "valid" signature on a different message (a prefix or suffix of the signed one).
   * Verification therefore requires the prefix length to be exactly 32 when `hedged` is true and 0 when it is false. To verify signatures made
   * without hedging (quantum-safe-py `hedged=False`), construct the verifier with `{ hedged: false }`.
   * Does not apply to the `-v2` formats, which have no prefix (and always hedge inside ML-DSA).
   */
  readonly hedged: boolean;

  /**
   * Binds the instance to `algorithm` and a hedging mode. Passing `hedged: false` with a `-v2` suite emits the `QS_HEDGED_IGNORED` warning.
   * @param algorithm - Canonical algorithm string.
   * @param hybrid - Whether `algorithm` must be a hybrid (`true`) or a single-algorithm (`false`) suite.
   * @param hedged - Whether signatures carry the 32-byte random prefix.
   * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported suite of that kind.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  protected constructor(algorithm: string, hybrid: boolean, hedged: boolean) {
    this.info = lookup(algorithm, hybrid);
    this.algorithm = this.info.name as SignatureAlgorithm;
    this.hedged = hedged;
    if (!hedged && this.algorithm.endsWith('-v2')) {
      // Kept lenient so existing code keeps working; said out loud so nobody believes they got deterministic signatures.
      warnOnce(
        'QS_HEDGED_IGNORED',
        `hedged: false has no effect on ${this.algorithm}: the -v2 formats have no prefix and always hedge inside ML-DSA, so signatures are ` +
          'made and verified exactly as with hedged: true. Remove the option, or name the original format (for example Ed25519+ML-DSA-65) if ' +
          'you need unhedged signatures. quantum-safe-py raises ValueError for this combination.',
      );
    }
  }

  /**
   * The blob is `len(prefix) || prefix || payload`; the length must match this verifier's hedging mode (see {@link hedged}).
   * Throws {@link VerificationError} on an empty blob or a different prefix length; format v2 blobs are not checked.
   */
  #requirePrefix(blob: Uint8Array): void {
    if (this.info.format === 'v2') return; // format v2 has no prefix: the blob is the signature itself
    const want = this.hedged ? 32 : 0;
    if (blob.length === 0 || blob[0] !== want) throw new VerificationError();
  }

  /**
   * Generates a signing key pair. Free it (or use `using`) when done.
   * @returns A new key pair for this signer's algorithm.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  generateKeyPair(): KeyPair {
    return new KeyPair(call((w) => w.sigGenerateKeyPair(this.algorithm)));
  }

  /**
   * Signs `message`.
   * @param message - The bytes to sign; must not be empty.
   * @param secretKey - Secret key for this signer's algorithm.
   * @param options - See {@link SignOptions}; `context` defaults to empty. `signedAt` is set to the current time in seconds.
   * @returns A self-contained {@link SignedMessage}.
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {InvalidArgumentError} for an empty message or a context over 255 bytes.
   * @throws {SigningError} if the core fails to produce a signature.
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

  /**
   * Signs and records `keyPair.publicKey.fingerprint()` in the message.
   * @param message - The bytes to sign; must not be empty.
   * @param keyPair - Key pair for this signer's algorithm; its secret key signs.
   * @param options - Signing options without `signerFingerprint`; `context` defaults to empty.
   * @returns A self-contained {@link SignedMessage} carrying the signer's fingerprint.
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {InvalidArgumentError} for an empty message or a context over 255 bytes.
   */
  signWithFingerprint(message: Uint8Array, keyPair: KeyPair, options: Omit<SignOptions, 'signerFingerprint'> = {}) {
    return this.sign(message, keyPair.secretKey, {
      ...options,
      signerFingerprint: keyPair.publicKey.fingerprint(),
    });
  }

  /**
   * Verifies a signed message. For hybrids **both** signatures must be valid.
   *
   * The signature covers the message's context, and this method requires it to equal `options.expectedContext` (default: empty, i.e. no
   * context), so a signature made for one purpose cannot be accepted for another. Pass the context you signed with. (Reading the context from
   * the message itself would let an attacker choose it.)
   * @param signed - The signed message to check.
   * @param publicKey - Public key of the signer, for this signer's algorithm.
   * @param options.expectedContext - The context the message must carry. Default: empty.
   * @throws {VerificationError} if the signature does not verify, or the context differs from `expectedContext` (no detail on why, by design).
   * @throws {AlgorithmMismatchError} if key and message algorithms differ.
   * @throws {InvalidArgumentError} if an argument has the wrong type.
   * @example
   * ```ts
   * const sm = signer.sign(utf8('hello'), pair.secretKey, { context: utf8('myapp-v1') });
   * signer.verify(sm, pair.publicKey, { expectedContext: utf8('myapp-v1') }); // throws VerificationError on failure
   * ```
   */
  verify(signed: SignedMessage, publicKey: PublicKey, options: { expectedContext?: Uint8Array } = {}): void {
    if (!(signed instanceof SignedMessage)) throw new InvalidArgumentError('signed must be a SignedMessage.');
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    this.#check(publicKey.algorithm);
    if (signed.algorithm !== this.algorithm) {
      throw new AlgorithmMismatchError(`Signed message algorithm '${signed.algorithm}' does not match '${this.algorithm}'.`);
    }
    this.#requirePrefix(signed.signature);
    if (options.expectedContext === undefined && signed.context.length > 0) {
      warnOnce(
        'QS_CONTEXT_OMITTED',
        'verify() was called without expectedContext but the message carries a non-empty context, so it is rejected: omitting ' +
          "expectedContext means 'expect an empty context'. Pass the context you expect.",
      );
    }
    call((w) => w.sigVerify(signed.toCbor(), publicKey._wasm));
    if (!equalBytes(signed.context, bytes(options.expectedContext ?? new Uint8Array(), 'expectedContext'))) throw new VerificationError();
  }

  /**
   * Verifies a detached `message` + `signature` blob + `context` without a SignedMessage.
   * The inputs are copied once so the checks and the verification see the same bytes.
   * @param message - The signed message bytes.
   * @param signature - The signature blob (`SignedMessage.signature`).
   * @param publicKey - Public key of the signer, for this signer's algorithm.
   * @param options.context - The context the signature was made with. Default: empty.
   * @throws {VerificationError} if the signature does not verify (no detail on why, by design).
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {InvalidArgumentError} if an argument has the wrong type.
   */
  verifyBytes(message: Uint8Array, signature: Uint8Array, publicKey: PublicKey, options: { context?: Uint8Array } = {}): void {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    this.#check(publicKey.algorithm);
    // Copy once: the check and the verification must see the same bytes even if the caller's buffer is shared with another thread.
    const sig = bytes(signature, 'signature').slice();
    const msg = bytes(message, 'message').slice();
    const ctx = bytes(options.context ?? new Uint8Array(), 'context').slice();
    this.#requirePrefix(sig);
    call((w) => w.sigVerifyParts(this.algorithm, msg, sig, ctx, publicKey._wasm));
  }

  /**
   * Like {@link verify} but returns a boolean instead of throwing {@link VerificationError}.
   * @param signed - The signed message to check.
   * @param publicKey - Public key of the signer.
   * @param options.expectedContext - The context the message must carry. Default: empty.
   * @returns `true` when valid, `false` on a verification failure.
   * @throws {AlgorithmMismatchError} if key and message algorithms differ.
   * @throws {InvalidArgumentError} if an argument has the wrong type.
   */
  isValid(signed: SignedMessage, publicKey: PublicKey, options: { expectedContext?: Uint8Array } = {}): boolean {
    try {
      this.verify(signed, publicKey, options);
      return true;
    } catch (e) {
      if ((e as { code?: string }).code === 'QS_VERIFICATION_FAILED') return false;
      throw e;
    }
  }

  /** Throws {@link AlgorithmMismatchError} unless `algorithm` equals this signer's algorithm. */
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
  /**
   * Creates a single-algorithm signer.
   * @param algorithm - An ML-DSA or SLH-DSA name (see `sigSuites()`), including the `-v2` ML-DSA names. Default `ML-DSA-65`.
   * @param options.hedged - Prefix each signature with 32 random bytes. Default `true`; has no effect for `-v2` names.
   * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported single-algorithm suite.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  constructor(algorithm: Exclude<SignatureAlgorithm, `${string}+${string}`> = DEFAULT_SIGNATURE, options: { hedged?: boolean } = {}) {
    super(algorithm, false, options.hedged ?? true);
  }

  // ---- Standard FIPS 204 (interoperable): bare ML-DSA.Sign with a native context ---------------------------------------------

  /**
   * Generates a standards-mode key pair (a 32-byte seed and the FIPS 204 public key) for this signer's ML-DSA level. Free it or use `using`.
   * @returns A new {@link StandardKeyPair}.
   * @throws {InvalidArgumentError} for an algorithm without a standards-mode signer (SLH-DSA and the `-v2` names).
   */
  generateStandardKeyPair(): StandardKeyPair {
    const level = checkStandardAlgorithm(this.algorithm);
    const pair = call((w) => w.mldsaStandardKeyGen(level));
    try {
      const seed = new SecretBytes(pair.takeSeed());
      return new StandardKeyPair(level, pair.publicKey, seed);
    } finally {
      pair.free();
    }
  }

  /**
   * Rebuilds a standards-mode key pair from its 32-byte seed. The seed is copied into WebAssembly memory; wipe your own copy.
   * If deriving the public key fails, the copied seed is freed before the error propagates.
   * @param seed - The 32-byte ML-DSA seed.
   * @returns A {@link StandardKeyPair} that owns the copied seed.
   * @throws {InvalidArgumentError} if the seed is not 32 bytes, or the algorithm has no standards-mode signer (SLH-DSA and the `-v2` names).
   */
  standardKeyPairFromSeed(seed: Uint8Array): StandardKeyPair {
    const level = checkStandardAlgorithm(this.algorithm);
    if (!(seed instanceof Uint8Array) || seed.length !== STANDARD_SEED_LENGTH) {
      throw new InvalidArgumentError(`A seed is exactly ${STANDARD_SEED_LENGTH} bytes.`);
    }
    const secret = SecretBytes.from(seed);
    try {
      const publicKey = call((w) => w.mldsaStandardPublicFromSeed(level, secret._wasm));
      return new StandardKeyPair(level, publicKey, secret);
    } catch (e) {
      secret.free();
      throw e;
    }
  }

  /**
   * Signs `message` as standard FIPS 204 `ML-DSA.Sign`: the message is signed exactly as given, `context` is FIPS 204's native context
   * (at most 255 bytes), and the randomness is FIPS 204's own. Returns the bare signature: no prefix, no wrapper, no metadata.
   * Any FIPS 204 implementation verifies it from the same message, context and public key (quantum-safe-py: `Sign.verify_raw`).
   *
   * Use {@link Sign.sign} (a {@link SignedMessage}) when both ends are quantum-safe; use this when the other side is not.
   * @param message - The bytes to sign.
   * @param key - A key pair from {@link Sign.generateStandardKeyPair} or {@link Sign.standardKeyPairFromSeed} at this signer's level.
   * @param options.context - FIPS 204 context, at most 255 bytes. Default: empty.
   * @returns The bare FIPS 204 signature bytes.
   * @throws {AlgorithmMismatchError} if the key belongs to a different level.
   * @throws {InvalidArgumentError} for a context over 255 bytes, a key that is not a {@link StandardKeyPair}, or an algorithm without a
   * standards-mode signer.
   * @example
   * ```ts
   * const signer = new Sign('ML-DSA-65');
   * using pair = signer.generateStandardKeyPair();
   * const sig = signer.signRaw(utf8('hello'), pair, { context: utf8('myapp') });
   * signer.verifyRaw(utf8('hello'), sig, pair.publicKey, { context: utf8('myapp') });
   * ```
   */
  signRaw(message: Uint8Array, key: StandardKeyPair, options: { context?: Uint8Array } = {}): Uint8Array {
    if (!(key instanceof StandardKeyPair)) throw new InvalidArgumentError('key must be a StandardKeyPair (see generateStandardKeyPair).');
    const level = checkStandardAlgorithm(this.algorithm);
    if (key.algorithm !== level) {
      throw new AlgorithmMismatchError(`Key algorithm '${key.algorithm}' does not match this signer ('${level}').`);
    }
    const context = bytes(options.context ?? new Uint8Array(), 'context');
    if (context.length > MAX_CONTEXT) throw new InvalidArgumentError('context must be at most 255 bytes.');
    return call((w) => w.mldsaStandardSign(level, key._seed._wasm, bytes(message, 'message'), context));
  }

  /**
   * Verifies a standard FIPS 204 signature made by any implementation (including quantum-safe-py `Sign.sign_raw`).
   * `publicKey` is the FIPS 204 encoded key as bytes, or a {@link PublicKey} of this signer's algorithm.
   * @param message - The signed bytes.
   * @param signature - The bare FIPS 204 signature.
   * @param publicKey - The FIPS 204 encoded public key, or a {@link PublicKey} of this signer's algorithm.
   * @param options.context - FIPS 204 context the signature was made with, at most 255 bytes. Default: empty.
   * @throws {VerificationError} if the signature, message or context is wrong (no detail on which, by design).
   * @throws {AlgorithmMismatchError} if a {@link PublicKey} belongs to a different algorithm.
   * @throws {InvalidArgumentError} for a context over 255 bytes, a wrong argument type, or an algorithm without a standards-mode signer.
   */
  verifyRaw(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array | PublicKey, options: { context?: Uint8Array } = {}): void {
    const level = checkStandardAlgorithm(this.algorithm);
    let pk: Uint8Array;
    if (publicKey instanceof PublicKey) {
      if (publicKey.algorithm !== this.algorithm) {
        throw new AlgorithmMismatchError(`Key algorithm '${publicKey.algorithm}' does not match this signer ('${this.algorithm}').`);
      }
      pk = publicKey.toBytes();
    } else {
      pk = bytes(publicKey, 'publicKey');
    }
    const context = bytes(options.context ?? new Uint8Array(), 'context');
    if (context.length > MAX_CONTEXT) throw new InvalidArgumentError('context must be at most 255 bytes.');
    const ok = call((w) => w.mldsaStandardVerify(level, pk, bytes(message, 'message'), context, bytes(signature, 'signature')));
    if (!ok) throw new VerificationError();
  }

  /**
   * The standard FIPS 204 signature of `message`. Identical to {@link Sign.signRaw}; the name says what it is.
   * @param message - The bytes to sign.
   * @param key - A standards-mode key pair at this signer's level.
   * @param options.context - FIPS 204 context, at most 255 bytes. Default: empty.
   * @returns The bare FIPS 204 signature bytes.
   * @throws {AlgorithmMismatchError} if the key belongs to a different level.
   * @throws {InvalidArgumentError} for a context over 255 bytes or a key that is not a {@link StandardKeyPair}.
   */
  signStandard(message: Uint8Array, key: StandardKeyPair, options: { context?: Uint8Array } = {}): Uint8Array {
    return this.signRaw(message, key, options);
  }

  /**
   * Verifies a standard FIPS 204 signature. Identical to {@link Sign.verifyRaw}.
   * @param message - The signed bytes.
   * @param signature - The bare FIPS 204 signature.
   * @param publicKey - The FIPS 204 encoded public key, or a {@link PublicKey} of this signer's algorithm.
   * @param options.context - FIPS 204 context the signature was made with. Default: empty.
   * @throws {VerificationError} if the signature, message or context is wrong.
   * @throws {AlgorithmMismatchError} if a {@link PublicKey} belongs to a different algorithm.
   * @throws {InvalidArgumentError} for a context over 255 bytes or a wrong argument type.
   */
  verifyStandard(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array | PublicKey, options: { context?: Uint8Array } = {}): void {
    this.verifyRaw(message, signature, publicKey, options);
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
  /**
   * @param algorithm Default `Ed25519+ML-DSA-65-v2`. With `hedged: false` and no algorithm the original format `Ed25519+ML-DSA-65` is used,
   * because `-v2` is always hedged inside ML-DSA and has no unhedged mode.
   * @param options.hedged Prefix each signature with 32 random bytes. Default `true`; has no effect for `-v2` names.
   * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported hybrid signature suite.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  constructor(algorithm?: Extract<SignatureAlgorithm, `${string}+${string}`>, options: { hedged?: boolean } = {}) {
    const hedged = options.hedged ?? true;
    super(algorithm ?? (hedged ? DEFAULT_HYBRID_SIGNATURE : ORIGINAL_HYBRID_SIGNATURE), true, hedged);
  }
}
