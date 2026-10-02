/**
 * Error hierarchy. Every error thrown by this library is a {@link QuantumSafeError}.
 *
 * Each class carries a stable machine-readable {@link QuantumSafeError.code} and a short,
 * static {@link QuantumSafeError.hint} describing the usual fix. Hints never contain key
 * material, plaintext, or caller input. Class names mirror quantum-safe-py where an
 * equivalent exists.
 *
 * Match with `instanceof`, or on `code`; never parse `message`.
 */

/** Base class for every error this library throws. */
export class QuantumSafeError extends Error {
  /** Stable machine-readable identifier, e.g. `QS_DECRYPTION_FAILED`. */
  readonly code: string;
  /** One-line, static suggestion for fixing the problem. Contains no sensitive data. */
  readonly hint: string;

  constructor(message: string, code = 'QS_ERROR', hint = '') {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.hint = hint;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** JSON-safe description, useful for logs and for coding agents. */
  toJSON(): { name: string; code: string; message: string; hint: string } {
    return { name: this.name, code: this.code, message: this.message, hint: this.hint };
  }
}

/** Thrown when the WASM module has not been initialised yet. Call `await init()` first. */
export class NotInitializedError extends QuantumSafeError {
  constructor() {
    super(
      'quantum-safe-ts has not been initialised.',
      'QS_NOT_INITIALIZED',
      "Call `await init()` once at startup. (On Node.js it initialises automatically when imported from 'quantum-safe-ts'.)",
    );
  }
}

/** A cryptographic operation failed. */
export class CryptoError extends QuantumSafeError {}

/** Decapsulation failed (invalid classical component). */
export class DecapsulationError extends CryptoError {
  constructor(message: string) {
    super(message, 'QS_DECAPSULATION_FAILED', 'The ciphertext was not produced for this key, or is corrupted.');
  }
}

/** AEAD authentication failed: wrong key, wrong AAD, or tampered ciphertext. */
export class DecryptionAuthenticationError extends CryptoError {
  constructor(message: string) {
    super(
      message,
      'QS_DECRYPTION_FAILED',
      'Check that you are using the recipient secret key, the same `aad`, and that the data was not modified.',
    );
  }
}

/** A signature failed to verify. Deliberately carries no detail on *why*. */
export class VerificationError extends CryptoError {
  constructor(message = 'Signature verification failed.') {
    super(
      message,
      'QS_VERIFICATION_FAILED',
      'The message, context, signature, or public key does not match. Verify with the signer’s public key and the same context.',
    );
  }
}

/** Signing failed (for example RNG unavailable). */
export class SigningError extends CryptoError {
  constructor(message: string) {
    super(message, 'QS_SIGNING_FAILED', 'Check that the secret key is intact and matches the chosen algorithm.');
  }
}

/** A key has the wrong length, wrong encoding, or does not belong to the stated algorithm. */
export class MalformedKeyError extends CryptoError {
  constructor(message: string) {
    super(
      message,
      'QS_MALFORMED_KEY',
      'Use keys produced by this library or quantum-safe-py for the same algorithm; check for truncation or encoding changes.',
    );
  }
}

/** A ciphertext, sealed message or signature blob is truncated or structurally invalid. */
export class MalformedCiphertextError extends CryptoError {
  constructor(message: string) {
    super(
      message,
      'QS_MALFORMED_CIPHERTEXT',
      'The data is truncated or not in the expected format. Pass the exact bytes produced by seal()/encapsulate().',
    );
  }
}

/** Key/message algorithm identifiers disagree. */
export class AlgorithmMismatchError extends CryptoError {
  constructor(message: string) {
    super(
      message,
      'QS_ALGORITHM_MISMATCH',
      'Use a key generated for the same algorithm string as the sealed message / signed message.',
    );
  }
}

/** HKDF output length exceeds the RFC 5869 limit for SHA-256 (8160 bytes). */
export class HkdfOutputTooLongError extends CryptoError {
  constructor(message: string) {
    super(message, 'QS_HKDF_OUTPUT_TOO_LONG', 'Request at most 8160 bytes from deriveKey().');
  }
}

/** Password-based key derivation failed (for example, salt shorter than 8 bytes). */
export class KdfError extends CryptoError {
  constructor(message: string) {
    super(message, 'QS_KDF_FAILED', 'Use a random salt of at least 16 bytes and a non-empty password.');
  }
}

/** Serialization or parsing failure. */
export class SerializationError extends QuantumSafeError {}

/** A key could not be parsed from PEM, CBOR or JWK. */
export class KeyParseError extends SerializationError {
  constructor(message: string) {
    super(
      message,
      'QS_KEY_PARSE_ERROR',
      'Check the format (PEM/CBOR/JWK), the key type (public vs secret), and that the data is complete.',
    );
  }
}

/** A key was written by a newer, unsupported format version. */
export class IncompatibleKeyVersionError extends SerializationError {
  constructor(message: string) {
    super(message, 'QS_INCOMPATIBLE_KEY_VERSION', 'Upgrade quantum-safe-ts to read keys written by a newer version.');
  }
}

/** A payload exceeded the 10 MB parsing limit. */
export class PayloadTooLargeError extends SerializationError {
  constructor(message: string) {
    super(message, 'QS_PAYLOAD_TOO_LARGE', 'Payloads over 10 MB are refused before parsing. Check you passed the right data.');
  }
}

/** The requested serialization is not supported (for example, a secret key as JWK). */
export class UnsupportedFormatError extends SerializationError {
  constructor(message: string) {
    super(message, 'QS_UNSUPPORTED_FORMAT', 'Export secret keys as CBOR or PEM; JWK is for public keys only.');
  }
}

/** The algorithm name is unknown or not approved. */
export class UnsupportedAlgorithmError extends QuantumSafeError {
  constructor(message: string) {
    super(
      message,
      'QS_UNSUPPORTED_ALGORITHM',
      'Use kemSuites() / sigSuites() to list valid names, e.g. "X25519+ML-KEM-768" or "Ed25519+ML-DSA-65".',
    );
  }
}

/** A caller-supplied argument is invalid (wrong type, empty message, over-long context …). */
export class InvalidArgumentError extends QuantumSafeError {
  constructor(message: string) {
    super(message, 'QS_INVALID_ARGUMENT', 'Check the argument types and limits in the API documentation.');
  }
}

/** A configured security policy (for example CNSA 2.0 enforcement) rejected an algorithm. */
export class PolicyViolationError extends QuantumSafeError {
  constructor(message: string) {
    super(
      message,
      'QS_POLICY_VIOLATION',
      'Use cnsa2.hybridKem() / cnsa2.hybridSign() for CNSA 2.0 compliant algorithms.',
    );
  }
}

/** Maps the `kind` tag attached by the WASM layer to a typed error. Internal. */
export function fromWasmError(e: unknown): Error {
  if (e instanceof QuantumSafeError) return e;
  const kind = (e as { kind?: unknown } | null)?.kind;
  const message = e instanceof Error ? e.message : String(e);
  switch (kind) {
    case 'unsupported_algorithm':
      return new UnsupportedAlgorithmError(message);
    case 'algorithm_mismatch':
      return new AlgorithmMismatchError(message);
    case 'malformed_key':
      return new MalformedKeyError(message);
    case 'malformed_ciphertext':
      return new MalformedCiphertextError(message);
    case 'classical_failure':
      return new DecapsulationError(message);
    case 'decryption_failed':
      return new DecryptionAuthenticationError(message);
    case 'hkdf_output_too_long':
      return new HkdfOutputTooLongError(message);
    case 'kdf_failed':
      return new KdfError(message);
    case 'key_parse_error':
      return new KeyParseError(message);
    case 'incompatible_key_version':
      return new IncompatibleKeyVersionError(message);
    case 'payload_too_large':
      return new PayloadTooLargeError(message);
    case 'unsupported_format':
      return new UnsupportedFormatError(message);
    case 'verification_failed':
      return new VerificationError(message);
    case 'signing_failed':
      return new SigningError(message);
    case 'invalid_argument':
      return new InvalidArgumentError(message);
    default:
      // A Rust panic surfaces as a WebAssembly.RuntimeError; never leak its text as a crypto verdict.
      return new CryptoError(
        e instanceof WebAssembly.RuntimeError ? 'Internal error in the WASM module.' : message,
        'QS_INTERNAL_ERROR',
        'This is a bug. Please report it at https://github.com/AnimeshShaw/quantum-safe-ts/issues without secret data.',
      );
  }
}
