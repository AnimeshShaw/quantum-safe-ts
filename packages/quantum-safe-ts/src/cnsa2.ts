/**
 * CNSA 2.0 parameter-set profile (NSA Commercial National Security Algorithm Suite 2.0).
 *
 * CNSA 2.0 mandates specific *parameter sets*, not merely algorithm families: ML-KEM-1024 for key
 * establishment, ML-DSA-87 for signatures, AES-256, SHA-384/512, and LMS/XMSS (SP 800-208) for
 * software and firmware signing. A deployment on ML-KEM-768 uses a FIPS 203 algorithm and is still
 * not CNSA 2.0 aligned.
 *
 * **Scope limit, stated plainly.** Selecting compliant parameter sets is necessary and nowhere near
 * sufficient. CNSA 2.0 compliance for National Security Systems runs through FIPS 140-3 validated
 * modules (a CMVP outcome from an accredited laboratory). This library is not a validated module and
 * nothing here makes it one. This profile only stops a deployment from silently sitting below the
 * mandated parameter sets, and says so in its output.
 *
 * Mirrors `quantum_safe.compliance.cnsa2` in quantum-safe-py, plus one extra check: this library's
 * hybrid KEM combiner and envelope key derivation use HKDF-SHA-256 (required for byte compatibility
 * with quantum-safe-py), which is below CNSA 2.0's SHA-384/512 requirement for those components.
 */
import { HybridKEM } from './kem.js';
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
/** Classical partners quantum-safe-py allows in CNSA 2.0 hybrids. Only `X25519` is implemented here. */
export const CNSA2_HYBRID_CLASSICAL = ['X25519', 'P-384'] as const;

/** Outcome of one checked requirement. */
export type Finding = 'compliant' | 'non-compliant' | 'not-covered' | 'partial';

export interface CheckResult {
  readonly requirement: string;
  readonly finding: Finding;
  readonly detail: string;
  readonly expected?: string;
  readonly actual?: string;
  readonly ok: boolean;
}

export interface ComplianceReport {
  readonly checks: readonly CheckResult[];
  /** True only if every checked requirement passed. Gaps count against compliance. */
  readonly compliant: boolean;
  readonly failures: readonly CheckResult[];
  /** Human-readable rendering. */
  render(): string;
  /** JSON-safe form. */
  toJSON(): { compliant: boolean; checks: readonly CheckResult[]; disclaimer: string };
}

const DISCLAIMER =
  'This reports parameter selection only. CNSA 2.0 compliance for National Security Systems runs through ' +
  'FIPS 140-3 validated modules; this library is not a validated module and this report is not a validation.';

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

const pqcHalf = (algorithm: string): string => (algorithm.includes('+') ? algorithm.split('+').pop()! : algorithm);

/** Checks a KEM selection; a hybrid passes when its post-quantum half is ML-KEM-1024. */
export function checkKem(algorithm: string): CheckResult {
  const pqc = pqcHalf(algorithm);
  return pqc === CNSA2_KEM
    ? result('Key establishment', 'compliant', `${algorithm} uses ${CNSA2_KEM}.`, CNSA2_KEM, pqc)
    : result(
        'Key establishment',
        'non-compliant',
        `${algorithm} resolves to ${pqc}; CNSA 2.0 requires ${CNSA2_KEM}. Lower parameter sets are FIPS 203 algorithms but are not this suite.`,
        CNSA2_KEM,
        pqc,
      );
}

/** Checks a signature selection; a hybrid passes when its post-quantum half is ML-DSA-87. */
export function checkSignature(algorithm: string): CheckResult {
  const pqc = pqcHalf(algorithm);
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

/** Checks a hash function name (`SHA-384`, `sha512`, …). */
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

const KDF_NOTE = result(
  'Key-derivation hash (this library)',
  'non-compliant',
  "This library's hybrid KEM combiner and envelope key derivation use HKDF-SHA-256 so that data stays byte-compatible with " +
    'quantum-safe-py. CNSA 2.0 requires SHA-384 or SHA-512 for key derivation. A SHA-384 suite is on the roadmap; until then ' +
    'the combiner/envelope hash is below the suite even when ML-KEM-1024 is selected.',
  CNSA2_HASHES.join(' or '),
  'SHA-256',
);

const CODE_SIGNING = result(
  'Software/firmware signing (SP 800-208)',
  'not-covered',
  'CNSA 2.0 requires LMS or XMSS (SP 800-208). Neither is implemented in quantum-safe-ts yet (LMS verification is planned). ' +
    'SP 800-208 also requires key generation inside a validated module, which is a property of the deployment, not of a library.',
  CNSA2_CODE_SIGNING.join(' or '),
);

/** Options for {@link report}. */
export interface ReportOptions {
  kem?: string;
  signature?: string;
  hashAlgorithm?: string;
  /** Evaluate the SP 800-208 software/firmware signing requirement (default true). */
  includeCodeSigning?: boolean;
  /** Evaluate this library's own SHA-256 key-derivation hash (default true when `kem` is set). */
  includeLibraryKdf?: boolean;
}

/**
 * Evaluates a configuration against the CNSA 2.0 parameter requirements.
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
  if (options.kem !== undefined && (options.includeLibraryKdf ?? true)) checks.push(KDF_NOTE);
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
 * Throws if the selections fall below CNSA 2.0 *parameter-set* requirements. Code signing and the
 * library's own KDF hash are not evaluated here (no selection can satisfy them today), so this is
 * a guard against accidentally using ML-KEM-768 / ML-DSA-65, not a compliance certificate.
 * @throws {PolicyViolationError}
 */
export function enforce(selection: { kem?: string; signature?: string } = {}): void {
  const rep = report({ ...selection, includeCodeSigning: false, includeLibraryKdf: false });
  if (!rep.compliant) {
    throw new PolicyViolationError(`Configuration is not CNSA 2.0 compliant: ${rep.failures.map((f) => f.detail).join('; ')}`);
  }
}

/**
 * A hybrid KEM pinned to the CNSA 2.0 parameter set (`X25519+ML-KEM-1024`). Pinned so a future
 * change to the library default cannot silently move a CNSA-targeted deployment below the suite.
 * @throws {UnsupportedAlgorithmError} for `P-384`, which quantum-safe-py names but does not implement.
 */
export function hybridKem(classical: 'X25519' | 'P-384' = 'X25519'): HybridKEM {
  if (classical === 'P-384') {
    throw new UnsupportedAlgorithmError('P-384 hybrids are not implemented (quantum-safe-py lists them but does not support them either).');
  }
  return new HybridKEM('X25519+ML-KEM-1024');
}

/** A hybrid signer pinned to the CNSA 2.0 parameter set (`Ed25519+ML-DSA-87`). */
export function hybridSign(options: { hedged?: boolean } = {}): HybridSign {
  return new HybridSign('Ed25519+ML-DSA-87', options);
}

/** Concrete steps to move a deployment onto CNSA 2.0 parameter sets, with the limits stated. */
export function describe(): string {
  return [
    'To select CNSA 2.0 parameter sets:',
    '',
    "  import { cnsa2 } from 'quantum-safe-ts';",
    '  const kem = cnsa2.hybridKem();    // X25519 + ML-KEM-1024',
    '  const signer = cnsa2.hybridSign(); // Ed25519 + ML-DSA-87',
    '',
    `Use ${CNSA2_HASHES.join(' or ')} for hashing and ${CNSA2_SYMMETRIC} for symmetric encryption.`,
    '',
    'Things this does NOT give you:',
    '',
    `  1. Software and firmware signing: CNSA 2.0 requires ${CNSA2_CODE_SIGNING.join(' or ')} (SP 800-208); not implemented yet.`,
    '  2. SHA-384/512 key derivation: the combiner and envelope use HKDF-SHA-256 for compatibility with quantum-safe-py.',
    '  3. Validation: CNSA 2.0 compliance for National Security Systems runs through FIPS 140-3 validated modules.',
    '     Selecting the right parameters is necessary and not sufficient, and no self-assessment produces a CMVP certificate.',
  ].join('\n');
}
