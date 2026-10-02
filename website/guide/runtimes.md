# Runtimes and bundlers

Every row is exercised by a test that installs the **packed npm tarball** into a fresh project and runs the same end-to-end smoke test.

| Environment | What to do |
|---|---|
| Node.js 20 (end of life), 22, 24 (ESM and CommonJS) | Nothing. The WebAssembly initialises when you import the package. `await init()` is a harmless no-op. |
| Chromium, Firefox, WebKit | `await init()` once before any other call. No bundler configuration. |
| Vite 7 (React 19), webpack 5, esbuild | Default configuration, no WASM plugin. |
| Next.js 16 (App Router, Turbopack and webpack) | Use it in client components or server code. Server bundles use the embedded WASM. |
| SvelteKit 2 | Client-side, with `await init()`. |
| Cloudflare Workers | Pass the precompiled module: `import wasm from 'quantum-safe-ts/quantum_safe_wasm_bg.wasm'; await init({ wasm });` Workers do not allow compiling WebAssembly from bytes. |
| Deno 2, Bun | From `node_modules`, with `await init()`. |
| Chrome extensions (Manifest V3) | Add `'wasm-unsafe-eval'` to the extension content security policy. |

**Mixed ESM and CommonJS.** The package ships both builds, and each has its own copy of the classes and its own WebAssembly instance. An application that loads it both ways (an ESM app with a CommonJS dependency, or some Jest setups) can see `instanceof QuantumSafeError` fail across the two, and cannot pass a key made by one copy to the other. Use `QuantumSafeError.is(e)` instead of `instanceof`, and import the library one way throughout.

**Not supported yet:** React Native. Calling any API before initialisation throws `NotInitializedError` with a hint.

## Size

About 283 KiB gzipped of WebAssembly. The default entry embeds it as base64 so no bundler plugin is needed, which costs about 430 KiB gzipped
of JavaScript in a bundle, whichever single function you import (tree-shaking cannot drop algorithms). If bytes matter, import the `.wasm` separately and pass it to `init`.

## Passwords in browsers

`deriveMasterKey` (Argon2id, 19 MiB) takes tens of milliseconds on a desktop CPU and more on phones, and it blocks while it runs. Run it in a Web Worker so the page stays responsive.
