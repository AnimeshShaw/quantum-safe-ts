/**
 * Developer-facing advisories.
 *
 * quantum-safe-ts throws typed errors for failures and keeps those errors opaque on purpose. A *warning* is different: it is for the
 * developer, says what to change, never contains a secret or a context/AAD value, and does not alter the result of the call.
 *
 * Two exist:
 * - `QS_CONTEXT_OMITTED`: `verify()` was called without `expectedContext` for a message that carries a non-empty context. Omitting it means
 *   "expect an empty context", so the message is rejected; the warning says why.
 * - `QS_AAD_OMITTED`: `Envelope.open()` (or `easy.decrypt`) was called without `expectedAad` for a message that carries AAD. The message was
 *   opened, but the opener did not check what the AAD was bound to.
 *
 * Each warning is emitted once per call site. By default it goes to Node's `process.emitWarning` (type `QuantumSafeWarning`) or to
 * `console.warn` where `process` does not exist. Silence a code with {@link warnings.silence}, or take over delivery with
 * {@link warnings.onWarning}.
 */

/** The warning codes the library can emit. */
export type QuantumSafeWarningCode = 'QS_CONTEXT_OMITTED' | 'QS_AAD_OMITTED';

/** One advisory. */
export interface QuantumSafeWarning {
  readonly code: QuantumSafeWarningCode;
  readonly message: string;
}

type Handler = (warning: QuantumSafeWarning) => void;

const silenced = new Set<string>();
const seenSites = new Set<string>();
let handler: Handler | null = null;

/** Controls for the library's developer advisories. */
export const warnings = {
  /** Stops emitting `code`. */
  silence(...codes: QuantumSafeWarningCode[]): void {
    for (const c of codes) silenced.add(c);
  },
  /** Resumes emitting `code`. */
  unsilence(...codes: QuantumSafeWarningCode[]): void {
    for (const c of codes) silenced.delete(c);
  },
  /** Delivers warnings to `fn` instead of `process.emitWarning` / `console.warn`. Pass `null` to restore the default. */
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
const OWN_FRAME = /quantum-safe-ts[\\/](?:packages[\\/]quantum-safe-ts[\\/])?(?:dist|src)[\\/]|node_modules[\\/]quantum-safe-ts[\\/]/;

/** The first stack frame outside the library: where the application made the call. */
function callSite(): string {
  const stack = new Error().stack ?? '';
  for (const line of stack.split('\n').slice(1)) {
    if (!line.includes('at ')) continue;
    if (OWN_FRAME.test(line)) continue;
    return line.trim();
  }
  return 'unknown';
}

/** @internal Emits `message` for `code` once per application call site. */
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
