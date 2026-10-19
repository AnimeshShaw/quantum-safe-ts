/**
 * Developer-facing advisories.
 *
 * quantum-safe-ts throws typed errors for failures and keeps those errors opaque on purpose. A *warning* is different: it is for the
 * developer, says what to change, never contains a secret or a context/AAD value, and does not alter the result of the call.
 *
 * Three exist:
 * - `QS_CONTEXT_OMITTED`: `verify()` was called without `expectedContext` for a message that carries a non-empty context. Omitting it means
 *   "expect an empty context", so the message is rejected; the warning says why.
 * - `QS_AAD_OMITTED`: `Envelope.open()` (or `easy.decrypt`) was called without `expectedAad` for a message that carries AAD. The message was
 *   opened, but the opener did not check what the AAD was bound to.
 * - `QS_HEDGED_IGNORED`: a signer was built with `hedged: false` and a `-v2` suite. The `-v2` formats have no prefix and always hedge inside
 *   ML-DSA, so the option has no effect; signatures are made and verified exactly as with `hedged: true`. quantum-safe-py raises
 *   `ValueError` for the same combination.
 *
 * Each warning is emitted once per call site. By default it goes to Node's `process.emitWarning` (type `QuantumSafeWarning`) or to
 * `console.warn` where `process` does not exist. Silence a code with {@link warnings.silence}, or take over delivery with
 * {@link warnings.onWarning}.
 */

/** The warning codes the library can emit. */
export type QuantumSafeWarningCode = 'QS_CONTEXT_OMITTED' | 'QS_AAD_OMITTED' | 'QS_HEDGED_IGNORED';

/** One advisory. */
export interface QuantumSafeWarning {
  /** Which advisory this is. */
  readonly code: QuantumSafeWarningCode;
  /** What to change; never contains a secret, a context or an AAD value. */
  readonly message: string;
}

/** Receiver of warnings installed with {@link warnings.onWarning}. */
type Handler = (warning: QuantumSafeWarning) => void;

/** Codes that are currently silenced. */
const silenced = new Set<string>();
/** Keys (`code@call site`) already emitted; each is emitted once. */
const seenSites = new Set<string>();
/** Custom delivery function, or `null` for the default (`process.emitWarning` or `console.warn`). */
let handler: Handler | null = null;

/** Controls for the library's developer advisories. */
export const warnings = {
  /**
   * Stops emitting `code`.
   * @param codes - One or more warning codes.
   */
  silence(...codes: QuantumSafeWarningCode[]): void {
    for (const c of codes) silenced.add(c);
  },
  /**
   * Resumes emitting `code`.
   * @param codes - One or more warning codes.
   */
  unsilence(...codes: QuantumSafeWarningCode[]): void {
    for (const c of codes) silenced.delete(c);
  },
  /**
   * Delivers warnings to `fn` instead of `process.emitWarning` / `console.warn`. Pass `null` to restore the default.
   * @param fn - Receives each emitted {@link QuantumSafeWarning}, or `null` for the default delivery.
   */
  onWarning(fn: Handler | null): void {
    handler = fn;
  },
  /** Clears silencing, the handler and the once-per-call-site memory. For tests. */
  reset(): void {
    silenced.clear();
    seenSites.clear();
    handler = null;
  },
} as const;

// A frame belongs to the library itself when it is inside this package's built or source files.
/** Matches stack lines that belong to this package, so that `callSite()` can skip them. */
const OWN_FRAME = /quantum-safe-ts[\\/](?:packages[\\/]quantum-safe-ts[\\/])?(?:dist|src)[\\/]|node_modules[\\/]quantum-safe-ts[\\/]/;

/**
 * The first stack frame outside the library: where the application made the call.
 * @returns The trimmed stack line, or `'unknown'` when every frame belongs to the library.
 */
function callSite(): string {
  const stack = new Error().stack ?? '';
  for (const line of stack.split('\n').slice(1)) {
    if (!line.includes('at ')) continue;
    if (OWN_FRAME.test(line)) continue;
    return line.trim();
  }
  return 'unknown';
}

/**
 * @internal Emits `message` for `code` once per application call site.
 * Does nothing when `code` is silenced or the call site has already produced this code. Delivery goes to the handler from
 * {@link warnings.onWarning}, else to `process.emitWarning`, else to `console.warn`.
 * @param code - Warning code.
 * @param message - Text for the developer; must not contain secrets.
 */
export function warnOnce(code: QuantumSafeWarningCode, message: string): void {
  if (silenced.has(code)) return;
  const key = `${code}@${callSite()}`;
  if (seenSites.has(key)) return;
  seenSites.add(key);
  const warning: QuantumSafeWarning = { code, message };
  if (handler !== null) {
    handler(warning);
    return;
  }
  const proc = (globalThis as { process?: { emitWarning?: (m: string, o: object) => void } }).process;
  if (typeof proc?.emitWarning === 'function') {
    proc.emitWarning(message, { type: 'QuantumSafeWarning', code });
  } else {
    console.warn(`[${code}] ${message}`);
  }
}
