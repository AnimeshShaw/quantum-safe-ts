# Runtimes and bundlers

Every row below is exercised by a test that installs the **packed npm tarball** into a fresh project and runs the same end-to-end smoke test
(the fixture matrix in `tests/fixtures/`). A runtime that is not in this table is not claimed.

| Environment | What to do |
|---|---|
| Node.js 22, 24 (ESM and CommonJS); 20 works but is end of life | Nothing. The WebAssembly initialises when you import the package. `await init()` is a harmless no-op. |
| Chromium, Firefox, WebKit | `await init()` once before any other call. No bundler configuration. |
| Vite 7 (React 19), webpack 5, esbuild | Default configuration, no WASM plugin. |
| Next.js 16 (App Router, Turbopack and webpack) | Use it in client components or server code. Server bundles use the embedded WASM. |
| SvelteKit 2 | Client-side, with `await init()`. |
| Cloudflare Workers | Pass the precompiled module: `import wasm from 'quantum-safe-ts/quantum_safe_wasm_bg.wasm'; await init({ wasm });`. Workers do not allow compiling WebAssembly from bytes. |
| Deno 2, Bun | From `node_modules`, with `await init()`. |
| Chrome extensions (Manifest V3) | Add `'wasm-unsafe-eval'` to the extension content security policy. |

**Not supported yet:** React Native. Calling any API before initialisation throws `NotInitializedError` with a hint.

## Initialising

`init()` is idempotent and safe to call concurrently; call it once at start-up and `await` it.

```ts test
import { init, isInitialized, easy } from 'quantum-safe-ts';

await init();                    // on Node.js this is a no-op because the package initialised itself on import
await init();                    // calling it again, or concurrently, is fine
if (!isInitialized()) throw new Error('not initialised');
const { publicKey } = easy.generateEncryptionKeys();
if (!publicKey.startsWith('-----BEGIN')) throw new Error('unexpected key');
```

`init()` accepts a custom source: `init({ wasm })` with bytes (`Uint8Array`/`ArrayBuffer`), a `WebAssembly.Module`, a `Response` (or a promise of
one), or a URL string. With no argument the default entry uses the WebAssembly embedded in the package.

## Per environment

**Browser with a bundler (Vite, webpack, esbuild, Next.js client, SvelteKit).** Nothing to configure; the module is embedded in the JavaScript.

```ts no-run
// Runs in a browser bundle; covered by the vite-react, webpack-browser, esbuild-browser, next-app and sveltekit fixtures.
import { init, easy } from 'quantum-safe-ts';

await init();
const { publicKey, secretKey } = easy.generateEncryptionKeys();
```

**Cloudflare Workers.** The platform forbids compiling WebAssembly from bytes, so import the `.wasm` file (the bundler hands you a
precompiled module) and pass it to `init`.

```ts no-run
// Runs in a Worker; covered by the cloudflare-workers fixture (workerd via wrangler).
import { init, easy } from 'quantum-safe-ts';
import wasm from 'quantum-safe-ts/quantum_safe_wasm_bg.wasm';

export default {
  async fetch(): Promise<Response> {
    await init({ wasm });
    const { publicKey } = easy.generateEncryptionKeys();
    return new Response(publicKey);
  },
};
```

**Deno and Bun.** `deno add npm:quantum-safe-ts` or `bun add quantum-safe-ts`, then `await init()` once.

**Chrome extension (Manifest V3).** Add `'wasm-unsafe-eval'` to `content_security_policy.extension_pages`, for example
`"script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"`. Without it the browser refuses to instantiate WebAssembly.

**Next.js.** In client components call `await init()` (for example in an effect). In server code, route handlers and server actions, import
and use it directly; the server bundle uses the embedded WebAssembly, which keeps working when the framework bundles server code and
`node_modules` is not laid out on disk.

## Mixed ESM and CommonJS

The package ships both builds, and each has its own copy of the classes and its own WebAssembly instance. An application that loads it both ways
(an ESM app with a CommonJS dependency, or some Jest setups) can see `instanceof QuantumSafeError` fail across the two, and cannot pass a key
made by one copy to the other. Use `QuantumSafeError.is(e)` instead of `instanceof`, and import the library one way throughout.

## Size

About 410 KiB gzipped of WebAssembly (compiled for speed: the size-optimised build was about 285 KiB and 2-3x slower). The default entry embeds it
as base64 so no bundler plugin is needed, which costs about 600 KiB gzipped of JavaScript in a bundle, whichever single function you import
(tree-shaking cannot drop algorithms). If bytes matter, use the **slim entry**: `import { init } from 'quantum-safe-ts/slim'` has the same API
with no embedded WebAssembly (about 150 KB of JavaScript, about 35 KiB gzipped); you serve the 410 KiB gzipped `.wasm` file yourself and pass it
once:

```ts no-run
// Vite shown; webpack: new URL('quantum-safe-ts/wasm', import.meta.url). The slim entry is covered by the package tests (slim.test.ts).
import { init } from 'quantum-safe-ts/slim';
import wasmUrl from 'quantum-safe-ts/wasm?url';

await init({ wasm: fetch(wasmUrl) });
```

The `.wasm` then caches independently of your JavaScript and loads in parallel. Any call before `init` throws `NotInitializedError`.

## Passwords in browsers

`deriveMasterKey` (Argon2id, 19 MiB) takes tens of milliseconds on a desktop CPU and more on phones, and it blocks while it runs. Run it in a
Web Worker so the page stays responsive.

## Which Node.js and TypeScript versions

| Tool | Version |
|---|---|
| Node.js | 22 or 24 (20 works; `engines` requires 20 or newer) |
| TypeScript | 5.2 or newer for `using`; the shipped `.d.ts` compiles with `skipLibCheck: false` (the `ts-consumer` fixture checks this) |
| Module systems | ESM and CommonJS |
| Browsers | Current Chromium, Firefox and WebKit |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `NotInitializedError` | Not on Node.js, or `init()` not awaited | `await init()` before the first call |
| A `CompileError` or CSP violation mentioning WebAssembly, `unsafe-eval` or `wasm-unsafe-eval` | A content security policy forbids WebAssembly | Add `'wasm-unsafe-eval'` to `script-src` |
| In a Worker: an error that WebAssembly code generation is disallowed | Workers need a precompiled module | Pass the imported `.wasm` to `init({ wasm })` |
| `instanceof QuantumSafeError` is false | Two copies of the library (ESM and CommonJS) | `QuantumSafeError.is(e)`; import one way |
| `using` is a syntax error | TypeScript older than 5.2 or a target that lacks it | Upgrade, or call `.free()` in a `finally` |
| Bundle is much larger than expected | Default entry embeds the WebAssembly | Use `quantum-safe-ts/slim` |
