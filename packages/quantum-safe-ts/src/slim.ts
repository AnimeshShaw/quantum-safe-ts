/**
 * quantum-safe-ts slim entry: the same API, but the WebAssembly module is NOT embedded in the JavaScript.
 *
 * Use it when bundle size matters (the default entry carries about 600 KiB gzipped of base64). You must supply the module yourself, once,
 * before using any API:
 *
 * ```ts
 * import { init } from 'quantum-safe-ts/slim';
 * // Vite:    import wasmUrl from 'quantum-safe-ts/wasm?url';  await init({ wasm: fetch(wasmUrl) });
 * // webpack: await init({ wasm: fetch(new URL('quantum-safe-ts/wasm', import.meta.url)) });
 * // Workers: await init({ wasm: (await import('quantum-safe-ts/quantum_safe_wasm_bg.wasm')).default });
 * // Node:    await init({ wasm: readFileSync(require.resolve('quantum-safe-ts/wasm')) });
 * ```
 *
 * Calling an API before `init` throws `NotInitializedError`.
 */
export * from './core.js';
