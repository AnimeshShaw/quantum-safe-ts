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
 * Classical partners once listed for CNSA 2.0 hybrids. Only `X25519` is implemented (here and in quantum-safe-py).
 * `P-384` is listed but not implemented, and a hybrid would still be reported `partial` (see the module comment).
 */
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
  'This reports parameter selection only. Selecting the right parameters is necessary and not sufficient for CNSA 2.0.';

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

const pqcHalf = (algorithm: string): string => {
  const name = algorithm.endsWith('-v2') ? algorithm.slice(0, -3) : algorithm; // the v2 signature format uses the same ML-DSA parameter sets
  return name.includes('+') ? name.split('+').pop()! : name;
};

// Names this library actually implements. A selection is only evaluated if its WHOLE name is one of these: 'RSA-1024+ML-DSA-87' is not 'compliant'.
const KNOWN_KEM = /^(?:ML-KEM-(?:512|768|1024)|X-Wing|X25519\+ML-KEM-(?:512|768|1024)|P-256\+ML-KEM-(?:512|768))$/;
const KNOWN_SIGNATURE =
  /^(?:ML-DSA-(?:44|65|87)(?:-v2)?|Ed25519\+ML-DSA-(?:44|65|87)(?:-v2)?|P-256\+ML-DSA-(?:44|65)(?:-v2)?|SLH-DSA-(?:SHAKE|SHA2)-(?:128|192|256)[sf])$/;
const unknown = (requirement: string, algorithm: string): CheckResult =>
  result(requirement, 'non-compliant', `'${algorithm}' is not an algorithm name this library implements, so it cannot be evaluated.`);

/**
 * Checks a KEM selection. Pure `ML-KEM-1024` is compliant. A hybrid whose post-quantum half is ML-KEM-1024
 * is `partial`: the parameter set is right, but NSA's CNSA 2.0 FAQ does not call a hybrid compliant (hybrids
 * are not required and not to be used on NSS mission systems except NSA-specified exceptions such as IKEv2).
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

const CODE_SIGNING = result(
  'Software/firmware signing (SP 800-208)',
  'partial',
  'CNSA 2.0 requires LMS or XMSS (SP 800-208). quantum-safe-ts verifies LMS/HSS signatures (RFC 8554, SHA-256 M32/N32: Lms.verify) but does not sign ' +
    '(LMS signing is stateful and unsafe without a durable state store) and does not implement XMSS. SP 800-208 also requires key generation inside ' +
    'a validated cryptographic module, which is a property of the deployment, not of a library.',
  CNSA2_CODE_SIGNING.join(' or '),
  'LMS verification only',
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
 * @throws {PolicyViolationError}
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
 */
export function kem(): KEM {
  return new KEM('ML-KEM-1024');
}

/**
 * A hybrid KEM pinned to ML-KEM-1024 (`X25519+ML-KEM-1024`). Reported as `partial` by {@link report}: hybrids are
 * outside what CNSA 2.0 prescribes. Kept for quantum-safe-py compatibility (it is what quantum-safe-py's
 * `cnsa2.hybrid_kem()` returns, and it reports it `partial` too). Use {@link kem} for a compliant configuration.
 * @throws {UnsupportedAlgorithmError} for `P-384`, which is not implemented here or in quantum-safe-py.
 */
export function hybridKem(classical: 'X25519' | 'P-384' = 'X25519'): HybridKEM {
  if (classical === 'P-384') {
    throw new UnsupportedAlgorithmError('P-384 hybrids are not implemented (neither here nor in quantum-safe-py), and a hybrid would still be reported partial.');
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
    "  import { cnsa2, Envelope } from 'quantum-safe-ts';",
    '  const kem = cnsa2.kem();           // pure ML-KEM-1024 (hybrid is optional under CNSA 2.0)',
    '  const sealed = Envelope.seal(data, kemPublicKey); // envelope v2: HKDF-SHA-384 + AES-256-GCM',
    '  const signer = cnsa2.hybridSign(); // Ed25519 + ML-DSA-87 (or new Sign("ML-DSA-87"))',
    '',
    `Use ${CNSA2_HASHES.join(' or ')} for hashing and ${CNSA2_SYMMETRIC} for symmetric encryption.`,
    '',
    'Things this does NOT give you:',
    '',
    `  1. Software and firmware signing: CNSA 2.0 requires ${CNSA2_CODE_SIGNING.join(' or ')} (SP 800-208); not implemented yet.`,
    '  2. SHA-384/512 key derivation with hybrids: the hybrid combiner and envelope v1 use HKDF-SHA-256 for byte-compatibility with quantum-safe-py.',
    '     Pure ML-KEM-1024 (envelope v2) uses HKDF-SHA-384.',
    '  3. A CNSA 2.0 hybrid: NSA\'s FAQ does not define one (hybrids are not required and not to be used on NSS mission systems',
    '     except NSA-specified exceptions such as IKEv2). Use pure ML-KEM-1024 and ML-DSA-87.',
  ].join('\n');
}
