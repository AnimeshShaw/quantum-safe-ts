/**
 * WASM loader. The WASM module is private to this package; everything public goes through the
 * typed facade, which converts errors and validates inputs before crossing the boundary.
 */
import * as glue from '../wasm/quantum_safe_wasm.js';
import { NotInitializedError, fromWasmError } from './errors.js';

/** The raw wasm-bindgen module. Internal. */
export type WasmApi = typeof glue;

let ready: WasmApi | null = null;
let loading: Promise<void> | null = null;
let defaultSource: (() => Promise<InitSource> | InitSource) | null = null;

/** What `init()` can instantiate from. */
export type InitSource = BufferSource | WebAssembly.Module | Response | Promise<Response> | URL | string;

/** @internal Registers how the entry point obtains the .wasm bytes. */
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
 * @param options.wasm Optional custom source: bytes, a `WebAssembly.Module`, a `Response`, or a URL.
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

/** @internal Synchronous initialisation from bytes (used by the Node entry). */
export function initSyncFromBytes(bytes: BufferSource | WebAssembly.Module): void {
  if (ready) return;
  glue.initSync({ module: bytes as never });
  ready = glue;
}

/** True once the WASM module is ready. */
export function isInitialized(): boolean {
  return ready !== null;
}

/** @internal */
export function wasm(): WasmApi {
  if (!ready) throw new NotInitializedError();
  return ready;
}

/** @internal Runs a WASM call, converting thrown values to typed errors. */
export function call<T>(fn: (w: WasmApi) => T): T {
  const w = wasm();
  try {
    return fn(w);
  } catch (e) {
    throw fromWasmError(e);
  }
}
