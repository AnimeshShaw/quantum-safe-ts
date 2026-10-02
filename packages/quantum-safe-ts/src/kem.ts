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

function lookup(algorithm: string, hybrid: boolean): SuiteInfo {
  const info = kemSuites().find((s) => s.name === algorithm);
  if (!info || info.hybrid !== hybrid) {
    throw new UnsupportedAlgorithmError(
      `'${String(algorithm)}' is not a supported ${hybrid ? 'hybrid' : 'pure'} KEM algorithm.`,
    );
  }
  return info;
}

abstract class BaseKem {
  /** Canonical algorithm string. */
  readonly algorithm: KemAlgorithm;
  /** Suite metadata (NIST level, CNSA 2.0 status, …). */
  readonly info: SuiteInfo;

  protected constructor(algorithm: string, hybrid: boolean) {
    this.info = lookup(algorithm, hybrid);
    this.algorithm = this.info.name as KemAlgorithm;
  }

  /** Generates a key pair. Free it (or use `using`) when done. */
  generateKeyPair(): KeyPair {
    return new KeyPair(call((w) => w.kemGenerateKeyPair(this.algorithm)));
  }

  /**
   * Encapsulates a fresh shared secret to `publicKey`.
   * @throws {AlgorithmMismatchError} if the key belongs to a different algorithm.
   * @throws {MalformedKeyError} if the key bytes are invalid.
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
   * @throws {MalformedCiphertextError} if the ciphertext has the wrong structure or length.
   */
  decapsulate(secretKey: SecretKey, ciphertext: Uint8Array): SecretBytes {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    this.#check(secretKey.algorithm);
    return new SecretBytes(call((w) => w.kemDecapsulate(secretKey._wasm, bytes(ciphertext, 'ciphertext'))));
  }

  #check(algorithm: string): void {
    if (algorithm !== this.algorithm) {
      throw new AlgorithmMismatchError(`Key algorithm '${algorithm}' does not match this KEM ('${this.algorithm}').`);
    }
  }
}

/**
 * Hybrid classical + post-quantum KEM. Default: `X25519+ML-KEM-768`, byte-compatible with
 * quantum-safe-py's `HybridKEM`. Also accepts `X-Wing` (TypeScript-only, interoperable with
 * other X-Wing implementations, not readable by quantum-safe-py).
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
  constructor(algorithm: KemAlgorithm = DEFAULT_KEM) {
    super(algorithm, true);
  }
}

/**
 * Pure ML-KEM (`ML-KEM-512/768/1024`), matching quantum-safe-py's `KEM`. Not recommended for new
 * deployments during the transition period; prefer {@link HybridKEM}.
 */
export class KEM extends BaseKem {
  constructor(algorithm: Extract<KemAlgorithm, 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024'> = 'ML-KEM-768') {
    super(algorithm, false);
  }
}
