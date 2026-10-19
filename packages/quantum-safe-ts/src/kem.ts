import { DEFAULT_KEM, kemSuites } from './algorithms.js';
import type { KemAlgorithm, SuiteInfo } from './algorithms.js';
import { AlgorithmMismatchError, InvalidArgumentError, UnsupportedAlgorithmError } from './errors.js';
import { KeyPair, PublicKey, SecretBytes, SecretKey } from './keys.js';
import { call } from './runtime.js';
import { bytes } from './utils.js';

/** Result of {@link HybridKEM.encapsulate}. */
export interface Encapsulation {
  /** Send this to the key holder (`HybridCipherText.to_bytes()` in quantum-safe-py). */
  readonly ciphertext: Uint8Array;
  /** The 32-byte shared secret. Free it (or use `using`) when done; derive keys with `deriveKey()`. */
  readonly sharedSecret: SecretBytes;
}

/**
 * Finds the suite named `algorithm` in {@link kemSuites}; its `hybrid` flag must equal `hybrid`.
 * Throws {@link UnsupportedAlgorithmError} when the name is unknown or is of the other kind (hybrid versus pure).
 */
function lookup(algorithm: string, hybrid: boolean): SuiteInfo {
  const info = kemSuites().find((s) => s.name === algorithm);
  if (!info || info.hybrid !== hybrid) {
    throw new UnsupportedAlgorithmError(
      `'${String(algorithm)}' is not a supported ${hybrid ? 'hybrid' : 'pure'} KEM algorithm.`,
    );
  }
  return info;
}

/** Shared implementation of {@link HybridKEM} and {@link KEM}: one instance is bound to one algorithm. */
abstract class BaseKem {
  /** Canonical algorithm string. */
  readonly algorithm: KemAlgorithm;
  /** Suite metadata (NIST level, CNSA 2.0 status, …). */
  readonly info: SuiteInfo;

  /**
   * Binds the instance to `algorithm`.
   * @param algorithm - Canonical algorithm string.
   * @param hybrid - Whether `algorithm` must be a hybrid (`true`) or a pure ML-KEM (`false`) suite.
   * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported suite of that kind.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  protected constructor(algorithm: string, hybrid: boolean) {
    this.info = lookup(algorithm, hybrid);
    this.algorithm = this.info.name as KemAlgorithm;
  }

  /**
   * Generates a key pair. Free it (or use `using`) when done.
   * @returns A new key pair for this KEM's algorithm.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  generateKeyPair(): KeyPair {
    return new KeyPair(call((w) => w.kemGenerateKeyPair(this.algorithm)));
  }

  /**
   * Encapsulates a fresh shared secret to `publicKey`.
   * @param publicKey - The recipient's public key for this KEM's algorithm.
   * @returns The ciphertext to send and the 32-byte shared secret; free the secret when done.
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {MalformedKeyError} if the key bytes are invalid.
   * @throws {InvalidArgumentError} if `publicKey` is not a {@link PublicKey} or has been freed.
   */
  encapsulate(publicKey: PublicKey): Encapsulation {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    this.#check(publicKey.algorithm);
    return call((w) => {
      const enc = w.kemEncapsulate(publicKey._wasm);
      try {
        const ciphertext = enc.ciphertext;
        const sharedSecret = new SecretBytes(enc.takeSharedSecret());
        return { ciphertext, sharedSecret };
      } finally {
        enc.free();
      }
    });
  }

  /**
   * Recovers the shared secret from `ciphertext`.
   *
   * ML-KEM uses implicit rejection (FIPS 203): a ciphertext that was not produced for this key
   * yields a pseudorandom secret rather than an error, so a wrong ciphertext is detected
   * downstream (for example by AEAD authentication), not here.
   * @param secretKey - The recipient's secret key for this KEM's algorithm.
   * @param ciphertext - The `ciphertext` field of the {@link Encapsulation} returned by `encapsulate()`.
   * @returns The shared secret; free it when done.
   * @throws {MalformedCiphertextError} if the ciphertext has the wrong structure or length.
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {DecapsulationError} if the classical component of a hybrid fails.
   * @throws {InvalidArgumentError} if `secretKey` is not a {@link SecretKey}, has been freed, or `ciphertext` is not bytes.
   */
  decapsulate(secretKey: SecretKey, ciphertext: Uint8Array): SecretBytes {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    this.#check(secretKey.algorithm);
    return new SecretBytes(call((w) => w.kemDecapsulate(secretKey._wasm, bytes(ciphertext, 'ciphertext'))));
  }

  /** Throws {@link AlgorithmMismatchError} unless `algorithm` equals this KEM's algorithm. */
  #check(algorithm: string): void {
    if (algorithm !== this.algorithm) {
      throw new AlgorithmMismatchError(`Key algorithm '${algorithm}' does not match this KEM ('${this.algorithm}').`);
    }
  }
}

/**
 * Hybrid classical + post-quantum KEM. Default: `X25519+ML-KEM-768`, byte-compatible with
 * quantum-safe-py's `HybridKEM`. Also accepts `X-Wing` (interoperable with other X-Wing implementations and
 * with quantum-safe-py 1.0.0's `XWing`).
 *
 * @example
 * ```ts
 * await init(); // no-op on Node.js
 * const kem = new HybridKEM();
 * using pair = kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
 * using recovered = kem.decapsulate(pair.secretKey, ciphertext);
 * ```
 */
export class HybridKEM extends BaseKem {
  /**
   * Creates a hybrid KEM.
   * @param algorithm - A hybrid KEM name (see `kemSuites()`). Default `X25519+ML-KEM-768`.
   * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported hybrid KEM.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  constructor(algorithm: KemAlgorithm = DEFAULT_KEM) {
    super(algorithm, true);
  }
}

/**
 * Pure ML-KEM (`ML-KEM-512/768/1024`), matching quantum-safe-py's `KEM`. Not recommended for new
 * deployments during the transition period; prefer {@link HybridKEM}.
 */
export class KEM extends BaseKem {
  /**
   * Creates a pure ML-KEM instance.
   * @param algorithm - `ML-KEM-512`, `ML-KEM-768` or `ML-KEM-1024`. Default `ML-KEM-768`.
   * @throws {UnsupportedAlgorithmError} if `algorithm` is not a supported pure KEM.
   * @throws {NotInitializedError} if `init()` has not completed.
   */
  constructor(algorithm: Extract<KemAlgorithm, 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024'> = 'ML-KEM-768') {
    super(algorithm, false);
  }
}
