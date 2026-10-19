/**
 * CNSA 2.0 parameter-set profile (NSA Commercial National Security Algorithm Suite 2.0).
 *
 * CNSA 2.0 mandates specific *parameter sets*, not merely algorithm families: ML-KEM-1024 for key
 * establishment, ML-DSA-87 for signatures, AES-256, SHA-384/512, and LMS/XMSS (SP 800-208) for
 * software and firmware signing. A deployment on ML-KEM-768 uses a FIPS 203 algorithm and is still
 * not CNSA 2.0 aligned.
 *
 * **Scope.** Selecting compliant parameter sets is necessary and not sufficient. This profile stops a deployment from silently
 * sitting below the mandated parameter sets, and says so in its output.
 *
 * Mirrors `quantum_safe.compliance.cnsa2` in quantum-safe-py: both libraries give the same verdicts. Three
 * points are worth stating, each grounded in the NSA CNSA 2.0 FAQ and algorithm specification:
 *
 *  1. **Hybrid is outside what CNSA 2.0 prescribes; pure ML-KEM-1024 satisfies key establishment.**
 *     NSA's CNSA 2.0 FAQ (December 2024, Ver. 2.1) says NSA will not require hybrid products for security
 *     purposes and that a hybrid should not be used on NSS mission systems except for exceptions NSA
 *     specifically recommends (the one it names is IKEv2, which keeps CNSA 1.0 key establishment
 *     fortified by ML-KEM-1024). So every hybrid, including `X25519+ML-KEM-1024`, is reported `partial`,
 *     not compliant. The recommended CNSA 2.0 key establishment is pure `ML-KEM-1024` ({@link kem}).
 *  2. **Key-derivation hash.** The hybrid combiner and envelope v1 use HKDF-SHA-256 (for byte-compatibility
 *     with quantum-safe-py), below CNSA 2.0's SHA-384/512. Envelope v2 (pure ML-KEM-1024 + HKDF-SHA-384 +
 *     AES-256-GCM, which quantum-safe-py reads and writes as well) removes that gap, and the report says
 *     which one applies.
 *  3. **`X-Wing` is ML-KEM-768 based** and is never CNSA 2.0 compliant.
 */
import type { KemAlgorithm } from './algorithms.js';
import { HybridKEM, KEM } from './kem.js';
import { HybridSign } from './signatures.js';
import { PolicyViolationError, UnsupportedAlgorithmError } from './errors.js';

/** Key-establishment parameter set required by CNSA 2.0. */
export const CNSA2_KEM = 'ML-KEM-1024';
/** Signature parameter set required by CNSA 2.0. */
export const CNSA2_SIGNATURE = 'ML-DSA-87';
/** Symmetric cipher required by CNSA 2.0. */
export const CNSA2_SYMMETRIC = 'AES-256';
/** Hash functions permitted by CNSA 2.0. */
export const CNSA2_HASHES = ['SHA-384', 'SHA-512'] as const;
/** SP 800-208 stateful hash-based schemes required for software/firmware signing. */
export const CNSA2_CODE_SIGNING = ['LMS', 'XMSS'] as const;
/**
 * Classical partners {@link hybridKem} can build, the same list as quantum-safe-py's `CNSA2_HYBRID_CLASSICAL`. A
 * hybrid is reported `partial` (see the module comment); {@link kem} is the compliant configuration.
 */
export const CNSA2_HYBRID_CLASSICAL = ['X25519', 'P-384'] as const;

/** Outcome of one checked requirement. */
export type Finding = 'compliant' | 'non-compliant' | 'not-covered' | 'partial';

/** Result of checking one requirement. */
export interface CheckResult {
  /** Name of the requirement, e.g. `Key establishment`. */
  readonly requirement: string;
  /** Outcome of the check. */
  readonly finding: Finding;
  /** Explanation of the outcome. */
  readonly detail: string;
  /** The value CNSA 2.0 expects, when the check compares values. */
  readonly expected?: string;
  /** The value found, when the check compares values and one was determined. */
  readonly actual?: string;
  /** True only when `finding` is `compliant`. */
  readonly ok: boolean;
}

/** Result of {@link report}: the individual checks and the overall verdict. */
export interface ComplianceReport {
  /** Every requirement that was evaluated, in order. */
  readonly checks: readonly CheckResult[];
  /** True only if every checked requirement passed. Gaps count against compliance. */
  readonly compliant: boolean;
  /** The checks whose finding is not `compliant` (this includes `partial` findings). */
  readonly failures: readonly CheckResult[];
  /**
   * Human-readable rendering.
   * @returns A multi-line text with one `[PASS]`, `[FAIL]`, `[GAP ]` or `[PART]` entry per check, the overall verdict and the disclaimer.
   */
  render(): string;
  /**
   * JSON-safe form.
   * @returns The overall verdict, the checks and the disclaimer text.
   */
  toJSON(): { compliant: boolean; checks: readonly CheckResult[]; disclaimer: string };
}

/** Text appended to every rendered and JSON report: the report covers parameter selection only. */
const DISCLAIMER =
  'This reports parameter selection only. Selecting the right parameters is necessary and not sufficient for CNSA 2.0.';

/** Builds a {@link CheckResult}; `ok` is true only for `compliant`, and `actual` is kept only together with `expected`. */
function result(
  requirement: string,
  finding: Finding,
  detail: string,
  expected?: string,
  actual?: string,
): CheckResult {
  const r: CheckResult = { requirement, finding, detail, ok: finding === 'compliant' };
  return expected === undefined ? r : { ...r, expected, ...(actual !== undefined ? { actual } : {}) };
}

/** The post-quantum parameter set of a suite name: drops a `-v2` suffix and any classical partner before the last `+`. */
const pqcHalf = (algorithm: string): string => {
  const name = algorithm.endsWith('-v2') ? algorithm.slice(0, -3) : algorithm; // the v2 signature format uses the same ML-DSA parameter sets
  return name.includes('+') ? name.split('+').pop()! : name;
};

// Names this library actually implements. A selection is only evaluated if its WHOLE name is one of these: 'RSA-1024+ML-DSA-87' is not 'compliant'.
/** Whole-name pattern of the KEM names this library implements; anything else is not evaluated. */
const KNOWN_KEM = /^(?:ML-KEM-(?:512|768|1024)|X-Wing|X25519\+ML-KEM-(?:512|768|1024)|P-256\+ML-KEM-(?:512|768)|P-384\+ML-KEM-1024)$/;
/** Whole-name pattern of the signature names this library implements (including `-v2`); anything else is not evaluated. */
const KNOWN_SIGNATURE =
  /^(?:ML-DSA-(?:44|65|87)(?:-v2)?|Ed25519\+ML-DSA-(?:44|65|87)(?:-v2)?|P-256\+ML-DSA-(?:44|65)(?:-v2)?|P-384\+ML-DSA-87(?:-v2)?|SLH-DSA-(?:SHAKE|SHA2)-(?:128|192|256)[sf])$/;
/** The `non-compliant` result for a name that is not one of the names matched by `KNOWN_KEM` / `KNOWN_SIGNATURE`. */
const unknown = (requirement: string, algorithm: string): CheckResult =>
  result(requirement, 'non-compliant', `'${algorithm}' is not an algorithm name this library implements, so it cannot be evaluated.`);

/**
 * Checks a KEM selection. Pure `ML-KEM-1024` is compliant. A hybrid whose post-quantum half is ML-KEM-1024
 * is `partial`: the parameter set is right, but NSA's CNSA 2.0 FAQ does not call a hybrid compliant (hybrids
 * are not required and not to be used on NSS mission systems except NSA-specified exceptions such as IKEv2).
 * A name this library does not implement is `non-compliant`, as is any other parameter set.
 * @param algorithm - KEM algorithm name, e.g. `ML-KEM-1024` or `X25519+ML-KEM-1024`.
 * @returns The finding for key establishment.
 */
export function checkKem(algorithm: string): CheckResult {
  if (!KNOWN_KEM.test(algorithm)) return unknown('Key establishment', algorithm);
  const pqc = pqcHalf(algorithm);
  if (pqc !== CNSA2_KEM) {
    return result(
      'Key establishment',
      'non-compliant',
      `${algorithm} resolves to ${pqc}; CNSA 2.0 requires ${CNSA2_KEM}. Lower parameter sets are FIPS 203 algorithms but are not this suite.`,
      CNSA2_KEM,
      pqc,
    );
  }
  if (!algorithm.includes('+')) {
    return result('Key establishment', 'compliant', `${algorithm} is pure ${CNSA2_KEM} (hybrid is optional under CNSA 2.0).`, CNSA2_KEM, pqc);
  }
  return result(
    'Key establishment',
    'partial',
    `${algorithm} uses ${CNSA2_KEM}, as required, but a hybrid is outside what CNSA 2.0 prescribes. NSA's CNSA 2.0 FAQ (December 2024, Ver. 2.1) says NSA will not require hybrid products for security purposes and that a hybrid should not be used on NSS mission systems except for exceptions NSA specifically recommends (the one it names is IKEv2, which keeps CNSA 1.0 key establishment fortified by ML-KEM-1024). ` +
      `Use pure ${CNSA2_KEM} (cnsa2.kem()).`,
    `${CNSA2_KEM} (pure, not hybrid)`,
    algorithm,
  );
}

/**
 * Checks a signature selection. Pure `ML-DSA-87` is compliant. A hybrid whose post-quantum half is ML-DSA-87 is `partial`, for the same reason a
 * hybrid KEM is: the parameter set is right, but a hybrid is outside what CNSA 2.0 prescribes (see {@link checkKem}).
 * A name this library does not implement is `non-compliant`, as is any other parameter set.
 * @param algorithm - Signature algorithm name, e.g. `ML-DSA-87` or `Ed25519+ML-DSA-87`; a `-v2` suffix is accepted.
 * @returns The finding for signatures.
 */
export function checkSignature(algorithm: string): CheckResult {
  if (!KNOWN_SIGNATURE.test(algorithm)) return unknown('Signatures', algorithm);
  const pqc = pqcHalf(algorithm);
  if (pqc === CNSA2_SIGNATURE && algorithm.includes('+')) {
    return result(
      'Signatures',
      'partial',
      `${algorithm} uses ${CNSA2_SIGNATURE}, as required, but a hybrid is outside what CNSA 2.0 prescribes. NSA's CNSA 2.0 FAQ (December 2024, Ver. 2.1) says NSA will not require hybrid products for security purposes and that a hybrid should not be used on NSS mission systems except for exceptions NSA specifically recommends (the one it names is IKEv2, which keeps CNSA 1.0 key establishment fortified by ML-KEM-1024). ` +
        `Use pure ${CNSA2_SIGNATURE}.`,
      `${CNSA2_SIGNATURE} (pure, not hybrid)`,
      algorithm,
    );
  }
  return pqc === CNSA2_SIGNATURE
    ? result('Signatures', 'compliant', `${algorithm} uses ${CNSA2_SIGNATURE}.`, CNSA2_SIGNATURE, pqc)
    : result(
        'Signatures',
        'non-compliant',
        `${algorithm} resolves to ${pqc}; CNSA 2.0 requires ${CNSA2_SIGNATURE}.`,
        CNSA2_SIGNATURE,
        pqc,
      );
}

/**
 * Checks a hash function name (`SHA-384`, `sha512`, …). The comparison is case-insensitive and the hyphen after `SHA` is optional.
 * @param algorithm - Hash function name.
 * @returns `compliant` for SHA-384 and SHA-512, `non-compliant` otherwise.
 */
export function checkHash(algorithm: string): CheckResult {
  const normalised = algorithm.toUpperCase().replace('SHA', 'SHA-').replace('SHA--', 'SHA-');
  const expected = CNSA2_HASHES.join(' or ');
  return (CNSA2_HASHES as readonly string[]).includes(normalised)
    ? result('Hashing', 'compliant', `${algorithm} is permitted.`, expected, normalised)
    : result(
        'Hashing',
        'non-compliant',
        `${algorithm} is not permitted; CNSA 2.0 requires SHA-384 or SHA-512.`,
        expected,
        normalised,
      );
}

/**
 * The finding for this library's own key-derivation hash: `compliant` only for pure `ML-KEM-1024` (HKDF-SHA-384), otherwise `non-compliant`
 * (HKDF-SHA-256).
 */
function kdfCheck(kem: string): CheckResult {
  if (kem === CNSA2_KEM) {
    return result(
      'Key-derivation hash (this library)',
      'compliant',
      'Pure ML-KEM-1024 envelopes (envelope v2, also read and written by quantum-safe-py) derive the AES-256-GCM key with HKDF-SHA-384.',
      CNSA2_HASHES.join(' or '),
      'SHA-384',
    );
  }
  return result(
    'Key-derivation hash (this library)',
    'non-compliant',
    "This library's quantum-safe-py-compatible hybrid combiner and envelope v1 use HKDF-SHA-256 so that data stays byte-compatible. " +
      'CNSA 2.0 requires SHA-384 or SHA-512 for key derivation. Use pure ML-KEM-1024 (envelope v2, HKDF-SHA-384) to meet it.',
    CNSA2_HASHES.join(' or '),
    'SHA-256',
  );
}

/** The fixed `partial` finding for the SP 800-208 software/firmware signing requirement. */
const CODE_SIGNING = result(
  'Software/firmware signing (SP 800-208)',
  'partial',
  'CNSA 2.0 requires LMS or XMSS (SP 800-208). quantum-safe-ts verifies LMS/HSS signatures (RFC 8554, SHA-256 M32/N32: Lms.verify) and signs one LMS tree in Node.js with write-ahead ' +
    'durable state (LmsSigner); it does not implement XMSS. SP 800-208 also requires key generation inside a validated cryptographic module, ' +
    'which is a property of the deployment, not of a library.',
  CNSA2_CODE_SIGNING.join(' or '),
  'LMS verification; Node.js LMS signing with durable state',
);

/** Options for {@link report}. */
export interface ReportOptions {
  /** KEM algorithm to evaluate with {@link checkKem}. Default: not evaluated. */
  kem?: string;
  /** Signature algorithm to evaluate with {@link checkSignature}. Default: not evaluated. */
  signature?: string;
  /** Hash function to evaluate with {@link checkHash}. Default: not evaluated. */
  hashAlgorithm?: string;
  /** Evaluate the SP 800-208 software/firmware signing requirement (default true). */
  includeCodeSigning?: boolean;
  /** Evaluate this library's own SHA-256 key-derivation hash (default true when `kem` is set). */
  includeLibraryKdf?: boolean;
}

/**
 * Evaluates a configuration against the CNSA 2.0 parameter requirements.
 * `compliant` is true only when at least one check ran and every check is `compliant`. The software/firmware signing check is `partial`, so with
 * the default `includeCodeSigning` the report is never fully compliant; pass `includeCodeSigning: false` to leave it out.
 * @param options - What to evaluate; see {@link ReportOptions}.
 * @returns The checks, the overall verdict and rendering helpers.
 * @example
 * ```ts
 * console.log(cnsa2.report({ kem: 'X25519+ML-KEM-768' }).render());
 * ```
 */
export function report(options: ReportOptions = {}): ComplianceReport {
  const checks: CheckResult[] = [];
  if (options.kem !== undefined) checks.push(checkKem(options.kem));
  if (options.signature !== undefined) checks.push(checkSignature(options.signature));
  if (options.hashAlgorithm !== undefined) checks.push(checkHash(options.hashAlgorithm));
  if (options.kem !== undefined && (options.includeLibraryKdf ?? true)) checks.push(kdfCheck(options.kem));
  if (options.includeCodeSigning ?? true) checks.push(CODE_SIGNING);
  const failures = checks.filter((c) => !c.ok);
  const compliant = checks.length > 0 && failures.length === 0;
  const marks: Record<Finding, string> = {
    compliant: 'PASS',
    'non-compliant': 'FAIL',
    'not-covered': 'GAP ',
    partial: 'PART',
  };
  return {
    checks,
    compliant,
    failures,
    render() {
      const lines = ['CNSA 2.0 parameter-set report', '='.repeat(60)];
      for (const c of checks) lines.push(`  [${marks[c.finding]}] ${c.requirement}`, `         ${c.detail}`);
      lines.push('='.repeat(60));
      lines.push(compliant ? 'OVERALL: compliant parameter selection' : `OVERALL: NOT compliant (${failures.length} issue(s))`);
      lines.push(DISCLAIMER);
      return lines.join('\n');
    },
    toJSON: () => ({ compliant, checks, disclaimer: DISCLAIMER }),
  };
}

/**
 * Throws if the post-quantum half of a selection falls below the CNSA 2.0 *parameter sets*. The hybrid
 * classical-component rule, code signing and the key-derivation hash are not evaluated here, so this is a
 * guard against accidentally using ML-KEM-768 / ML-DSA-65, not a compliance certificate (see {@link report}).
 *
 * By default a hybrid such as `X25519+ML-KEM-1024` passes (its post-quantum half is right) although {@link report} calls it `partial`. Pass
 * `{ strict: true }` to fail on anything that is not fully `compliant` there, for example when using this as a CI gate.
 * A name this library does not implement always fails.
 * @param selection - The KEM and signature names to check; a field left out is not checked.
 * @param options.strict - Fail unless {@link checkKem} / {@link checkSignature} report `compliant`. Default `false`.
 * @throws {PolicyViolationError} if a selection falls below the CNSA 2.0 parameter sets (or, with `strict`, is not fully compliant).
 * @example
 * ```ts
 * cnsa2.enforce({ kem: 'ML-KEM-1024', signature: 'ML-DSA-87' }); // passes
 * cnsa2.enforce({ kem: 'X25519+ML-KEM-768' }); // throws PolicyViolationError
 * ```
 */
export function enforce(selection: { kem?: string; signature?: string } = {}, options: { strict?: boolean } = {}): void {
  const failures: string[] = [];
  if (selection.kem !== undefined && (options.strict || !KNOWN_KEM.test(selection.kem) ? !checkKem(selection.kem).ok : pqcHalf(selection.kem) !== CNSA2_KEM)) {
    failures.push(checkKem(selection.kem).detail);
  }
  if (selection.signature !== undefined && (options.strict || !KNOWN_SIGNATURE.test(selection.signature) ? !checkSignature(selection.signature).ok : pqcHalf(selection.signature) !== CNSA2_SIGNATURE)) {
    failures.push(checkSignature(selection.signature).detail);
  }
  if (failures.length > 0) {
    throw new PolicyViolationError(`Configuration is not CNSA 2.0 compliant: ${failures.join('; ')}`);
  }
}

/**
 * Pure ML-KEM-1024: the CNSA 2.0 key-establishment algorithm. NSA does not require hybrid and says not to use one
 * on NSS mission systems except NSA-specified exceptions, so this is the recommended choice. Seal data with it via
 * `Envelope.seal()`: a pure ML-KEM-1024 key produces an envelope v2 (HKDF-SHA-384 + AES-256-GCM; quantum-safe-py
 * reads and writes the same bytes).
 * @returns A {@link KEM} bound to `ML-KEM-1024`.
 * @example
 * ```ts
 * const k = cnsa2.kem();
 * using pair = k.generateKeyPair();
 * const sealed = Envelope.seal(data, pair.publicKey);
 * ```
 */
export function kem(): KEM {
  return new KEM('ML-KEM-1024');
}

/**
 * A hybrid KEM pinned to ML-KEM-1024 (`X25519+ML-KEM-1024`, or `P-384+ML-KEM-1024` for estates that hold CNSA 1.0 P-384 keys). Reported as `partial` by {@link report}: hybrids are
 * outside what CNSA 2.0 prescribes. Kept for quantum-safe-py compatibility (it is what quantum-safe-py's
 * `cnsa2.hybrid_kem()` returns, and it reports it `partial` too). Use {@link kem} for a compliant configuration.
 * @param classical - The classical partner: `X25519` (default) or `P-384`.
 * @returns A {@link HybridKEM} bound to `<classical>+ML-KEM-1024`.
 * @throws {UnsupportedAlgorithmError} for any partner outside {@link CNSA2_HYBRID_CLASSICAL}.
 */
export function hybridKem(classical: (typeof CNSA2_HYBRID_CLASSICAL)[number] = 'X25519'): HybridKEM {
  if (!(CNSA2_HYBRID_CLASSICAL as readonly string[]).includes(classical)) {
    throw new UnsupportedAlgorithmError(
      `classical partner '${String(classical)}' is not available for a CNSA 2.0 hybrid; choose from ${CNSA2_HYBRID_CLASSICAL.join(', ')}, or use kem().`,
    );
  }
  return new HybridKEM(`${classical}+ML-KEM-1024` as KemAlgorithm);
}

/**
 * A hybrid signer pinned to the CNSA 2.0 parameter set (`Ed25519+ML-DSA-87`, or `P-384+ML-DSA-87` with `classical: 'P-384'`).
 * It uses the original (prefix) signature format, not `-v2`. Reported as `partial` by {@link report}, like every hybrid.
 * @param options.hedged - Prefix each signature with 32 random bytes. Default `true`.
 * @param options.classical - The classical partner: `Ed25519` (default) or `P-384`.
 * @returns A {@link HybridSign} bound to `<classical>+ML-DSA-87`.
 * @throws {UnsupportedAlgorithmError} if the combination is not a supported suite.
 */
export function hybridSign(options: { hedged?: boolean; classical?: 'Ed25519' | 'P-384' } = {}): HybridSign {
  const { classical = 'Ed25519', ...rest } = options;
  return new HybridSign(`${classical}+ML-DSA-87`, rest);
}

/**
 * Concrete steps to move a deployment onto CNSA 2.0 parameter sets, with the limits stated.
 * @returns Multi-line plain text.
 */
export function describe(): string {
  return [
    'To select CNSA 2.0 parameter sets:',
    '',
    "  import { cnsa2, Envelope } from 'quantum-safe-ts';",
    '  const kem = cnsa2.kem();           // pure ML-KEM-1024 (hybrid is optional under CNSA 2.0)',
    '  const sealed = Envelope.seal(data, kemPublicKey); // envelope v2: HKDF-SHA-384 + AES-256-GCM',
    '  const signer = cnsa2.hybridSign(); // Ed25519 + ML-DSA-87 (or new Sign("ML-DSA-87"))',
    '',
    `Use ${CNSA2_HASHES.join(' or ')} for hashing and ${CNSA2_SYMMETRIC} for symmetric encryption.`,
    '',
    'Beyond parameter selection:',
    '',
    `  1. Software and firmware signing: CNSA 2.0 requires ${CNSA2_CODE_SIGNING.join(' or ')} (SP 800-208). LMS is verified in every runtime and signed in`,
    '     Node.js (LmsSigner, quantum-safe-ts/lms-signer); XMSS is not implemented, and SP 800-208 expects key generation inside a validated module.',
    '  2. SHA-384/512 key derivation with hybrids: the hybrid combiner and envelope v1 use HKDF-SHA-256 for byte-compatibility with quantum-safe-py.',
    '     Pure ML-KEM-1024 (envelope v2) uses HKDF-SHA-384.',
    '  3. A CNSA 2.0 hybrid: NSA\'s FAQ does not define one (hybrids are not required and not to be used on NSS mission systems',
    '     except NSA-specified exceptions such as IKEv2). Use pure ML-KEM-1024 and ML-DSA-87.',
  ].join('\n');
}
