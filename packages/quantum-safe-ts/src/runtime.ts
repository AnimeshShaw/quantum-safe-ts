/**
 * WASM loader. The WASM module is private to this package; everything public goes through the
 * typed facade, which converts errors and validates inputs before crossing the boundary.
 */
import * as glue from '../wasm/quantum_safe_wasm.js';
import { NotInitializedError, fromWasmError } from './errors.js';

/** The raw wasm-bindgen module. Internal. */
export type WasmApi = typeof glue;

/** The initialised WASM module, or `null` before initialisation completes. */
let ready: WasmApi | null = null;
/** The in-flight initialisation shared by concurrent `init()` calls; reset to `null` when it fails so a later call can retry. */
let loading: Promise<void> | null = null;
/** Supplier of the .wasm source registered by the entry point; used when `init()` gets no `wasm` option. */
let defaultSource: (() => Promise<InitSource> | InitSource) | null = null;

/**
 * What `init()` can instantiate from: raw bytes, a `WebAssembly.Module`, a `Response` (or promise of
 * one), or a URL. Typed loosely (`object`) so consumers need neither the DOM nor WebAssembly typings.
 */
export type InitSource = Uint8Array | ArrayBuffer | string | object;

/**
 * @internal Registers how the entry point obtains the .wasm bytes.
 * @param fn - Returns the source (or a promise of it) that `init()` uses when called without `options.wasm`.
 */
export function setDefaultSource(fn: () => Promise<InitSource> | InitSource): void {
  defaultSource = fn;
}

/**
 * Initialises the WASM module. Idempotent and safe to call concurrently.
 *
 * - **Node.js** (`import 'quantum-safe-ts'`): initialises automatically; `init()` is a no-op.
 * - **Browsers, Deno, Bun, edge runtimes**: call `await init()` once before using the library.
 * - **Cloudflare Workers** (which forbid compiling WASM from bytes): pass the precompiled module:
 *   `await init({ wasm: (await import('quantum-safe-ts/quantum_safe_wasm_bg.wasm')).default })`.
 *
 * Once the module is ready, later calls return immediately. While a load is in progress, the `options` of further calls are ignored and they
 * wait for that load. After a failed load the next call starts a new one.
 *
 * @param options.wasm Optional custom source: bytes, a `WebAssembly.Module`, a `Response`, or a URL.
 * @returns A promise that resolves when the module is ready.
 * @throws {NotInitializedError} if no source is given and the entry point registered none (for example the slim entry without `options.wasm`).
 * @throws {CryptoError} if instantiating the module fails (code `QS_INTERNAL_ERROR`).
 * @example
 * ```ts
 * import { init } from 'quantum-safe-ts';
 * await init(); // no-op on Node.js
 * ```
 */
export async function init(options: { wasm?: InitSource } = {}): Promise<void> {
  if (ready) return;
  if (!loading) {
    loading = (async () => {
      try {
        const source = options.wasm ?? (await defaultSource?.());
        if (source === undefined) throw new NotInitializedError();
        await glue.default({ module_or_path: source as never });
        ready = glue;
      } catch (e) {
        loading = null;
        throw fromWasmError(e);
      }
    })();
  }
  await loading;
}

/**
 * @internal Synchronous initialisation from bytes (used by the Node entry). Does nothing when the module is already ready.
 * @param bytes - The .wasm bytes or a compiled `WebAssembly.Module`.
 */
export function initSyncFromBytes(bytes: Uint8Array | object): void {
  if (ready) return;
  glue.initSync({ module: bytes as never });
  ready = glue;
}

/**
 * True once the WASM module is ready.
 * @returns `false` before initialisation completes, `true` afterwards.
 */
export function isInitialized(): boolean {
  return ready !== null;
}

/**
 * @internal The initialised WASM module.
 * @returns The module API.
 * @throws {NotInitializedError} if initialisation has not completed.
 */
export function wasm(): WasmApi {
  if (!ready) throw new NotInitializedError();
  return ready;
}

/**
 * @internal Runs a WASM call, converting thrown values to typed errors.
 * @param fn - Receives the module API and returns the result.
 * @returns The value returned by `fn`.
 * @throws {NotInitializedError} if initialisation has not completed.
 * @throws {QuantumSafeError} the typed error for anything `fn` throws (see `fromWasmError`).
 */
export function call<T>(fn: (w: WasmApi) => T): T {
  const w = wasm();
  try {
    return fn(w);
  } catch (e) {
    throw fromWasmError(e);
  }
}
