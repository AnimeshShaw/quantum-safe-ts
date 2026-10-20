import { call } from './runtime.js';

/** Key-encapsulation algorithm identifiers. Hybrid names are `<classical>+<ML-KEM level>`. */
export type KemAlgorithm =
  | 'X25519+ML-KEM-512'
  | 'X25519+ML-KEM-768'
  | 'X25519+ML-KEM-1024'
  | 'P-256+ML-KEM-512'
  | 'P-256+ML-KEM-768'
  | 'P-384+ML-KEM-1024'
  | 'X-Wing'
  | 'ML-KEM-512'
  | 'ML-KEM-768'
  | 'ML-KEM-1024';

/** Base names of the signature suites that also exist in format v2 (the `-v2` identifiers append the suffix to these). */
export type V2Base =
  | 'Ed25519+ML-DSA-44'
  | 'Ed25519+ML-DSA-65'
  | 'Ed25519+ML-DSA-87'
  | 'P-256+ML-DSA-44'
  | 'P-256+ML-DSA-65'
  | 'P-384+ML-DSA-87'
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87';

/**
 * Signature format v2 identifiers (`<suite>-v2`): a format without the quantum-safe-py prefix construction. Its ML-DSA half signs a wrapped
 * message `M2` under the FIPS 204 context `quantum-safe-sig-v2`, so a standard FIPS 204 library can verify it only by rebuilding `M2`; see the
 * signatures guide. quantum-safe-py 0.3.2 or later reads and writes these;
 * quantum-safe-py 0.3.0 fails closed on the unknown identifier.
 */
export type SignatureAlgorithmV2 = `${V2Base}-v2`;

/** Signature algorithm identifiers. */
export type SignatureAlgorithm =
  | SignatureAlgorithmV2
  | 'Ed25519+ML-DSA-44'
  | 'Ed25519+ML-DSA-65'
  | 'Ed25519+ML-DSA-87'
  | 'P-256+ML-DSA-44'
  | 'P-256+ML-DSA-65'
  | 'P-384+ML-DSA-87'
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  | 'SLH-DSA-SHAKE-128s'
  | 'SLH-DSA-SHAKE-128f'
  | 'SLH-DSA-SHAKE-192s'
  | 'SLH-DSA-SHAKE-192f'
  | 'SLH-DSA-SHAKE-256s'
  | 'SLH-DSA-SHAKE-256f'
  | 'SLH-DSA-SHA2-128s'
  | 'SLH-DSA-SHA2-128f'
  | 'SLH-DSA-SHA2-192s'
  | 'SLH-DSA-SHA2-192f'
  | 'SLH-DSA-SHA2-256s'
  | 'SLH-DSA-SHA2-256f';

/** PQC migration state attached to a key (mirrors quantum-safe-py `MigrationState`). */
export type MigrationState = 'classical_only' | 'hybrid_transition' | 'pqc_preferred' | 'pqc_only';

/** Description of one algorithm suite. */
export interface SuiteInfo {
  /** Canonical algorithm string (wire-visible). */
  readonly name: string;
  /** True when a classical algorithm is combined with the post-quantum one. */
  readonly hybrid: boolean;
  /** NIST security category of the post-quantum component. */
  readonly nistLevel: number;
  /** True if the suite satisfies the CNSA 2.0 parameter requirement (ML-KEM-1024 / ML-DSA-87). */
  readonly meetsCnsa2: boolean;
  /**
   * True if quantum-safe-py 0.3.0 (its original release) can read/produce data for this suite. The `-v2` signature suites
   * (`format: 'v2'`) report `false` because 0.3.0 cannot read them; quantum-safe-py 0.3.2 or later can.
   */
  readonly pyCompatible: boolean;
  /** `'v2'` for the signature format v2 (absent for every other suite). */
  readonly format?: 'v2';
}

/** Default hybrid KEM (quantum-safe-py default). NIST category 3; below CNSA 2.0's ML-KEM-1024. */
export const DEFAULT_KEM = 'X25519+ML-KEM-768' as const satisfies KemAlgorithm;
/**
 * Default hybrid signature (quantum-safe-py's default too): the `-v2` format (no hedging prefix, FIPS 204 native context). The original
 * format is `Ed25519+ML-DSA-65`; name it to keep using it.
 */
export const DEFAULT_HYBRID_SIGNATURE = 'Ed25519+ML-DSA-65-v2' as const satisfies SignatureAlgorithm;
/** The original (prefix) format of the default hybrid suite: used when `hedged: false` is requested without naming a suite. */
export const ORIGINAL_HYBRID_SIGNATURE = 'Ed25519+ML-DSA-65' as const satisfies SignatureAlgorithm;
/** Default pure signature. */
export const DEFAULT_SIGNATURE = 'ML-DSA-65' as const satisfies SignatureAlgorithm;

/** Parsed KEM suite list, filled by the first {@link kemSuites} call and reused afterwards. */
let kemCache: SuiteInfo[] | null = null;
/** Parsed signature suite list, filled by the first {@link sigSuites} call and reused afterwards. */
let sigCache: SuiteInfo[] | null = null;

/**
 * Lists every key-encapsulation suite this build supports.
 * The list comes from the WASM core on the first call and is cached for the lifetime of the module.
 * @returns One {@link SuiteInfo} per KEM algorithm string.
 * @throws {NotInitializedError} if `init()` has not completed and the list is not cached yet.
 * @example
 * ```ts
 * const names = kemSuites().filter((s) => s.meetsCnsa2).map((s) => s.name);
 * ```
 */
export function kemSuites(): readonly SuiteInfo[] {
  kemCache ??= JSON.parse(call((w) => w.kemSuites())) as SuiteInfo[];
  return kemCache;
}

/**
 * Lists every signature suite this build supports.
 * The list comes from the WASM core on the first call and is cached for the lifetime of the module.
 * @returns One {@link SuiteInfo} per signature algorithm string.
 * @throws {NotInitializedError} if `init()` has not completed and the list is not cached yet.
 */
export function sigSuites(): readonly SuiteInfo[] {
  sigCache ??= JSON.parse(call((w) => w.sigSuites())) as SuiteInfo[];
  return sigCache;
}

/**
 * Version of the bundled WASM core.
 * @returns The version string reported by the core.
 * @throws {NotInitializedError} if `init()` has not completed.
 */
export function coreVersion(): string {
  return call((w) => w.version());
}
