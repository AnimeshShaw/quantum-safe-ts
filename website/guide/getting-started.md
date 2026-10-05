# Getting started

This page takes you from nothing to a working encrypt/decrypt and sign/verify in a few minutes, in whichever JavaScript environment you use.
Every code block on this page is executed by the test suite, so what you read here runs.

## 1. Install

```bash
npm install quantum-safe-ts
```

The package ships ESM and CommonJS builds and its own TypeScript types. It has no install scripts and no native build step: the Rust core is
already compiled to WebAssembly inside the package. Node.js 20 or newer is required for the npm tooling; the library itself runs wherever
WebAssembly does.

| Environment | Install and first line |
|---|---|
| **Node.js** 22 or 24 (20 works but is end of life) | `npm install quantum-safe-ts`, then `import { easy } from 'quantum-safe-ts'`. It initialises itself. |
| **Browser with a bundler** (Vite, webpack, esbuild, Next.js, SvelteKit) | Same install. Call `await init()` once before any other call. No bundler plugin or configuration. |
| **Deno 2** | `deno add npm:quantum-safe-ts`, then `await init()` once. |
| **Bun** | `bun add quantum-safe-ts`, then `await init()` once. |
| **Cloudflare Workers** | Pass the precompiled module: `import wasm from 'quantum-safe-ts/quantum_safe_wasm_bg.wasm'; await init({ wasm });` |
| **Chrome extension (Manifest V3)** | Add `'wasm-unsafe-eval'` to the extension's content security policy, then `await init()`. |

More detail, including bundle size and the `slim` entry, is on the [runtimes page](/guide/runtimes).

## 2. Encrypt and decrypt in five lines

The `easy` layer takes strings and bytes and returns strings and bytes. There is nothing to free.

```ts test
import { easy } from 'quantum-safe-ts';

const { publicKey, secretKey } = easy.generateEncryptionKeys(); // PEM strings; X25519 + ML-KEM-768
const sealed = easy.encrypt(publicKey, 'attack at dawn', { aad: 'msg-1' }); // Uint8Array
const plain = easy.decryptText(secretKey, sealed, { aad: 'msg-1' });
if (plain !== 'attack at dawn') throw new Error('round trip failed');
```

`publicKey` can be given to anyone. `secretKey` stays with whoever must read the message. The `aad` ("associated data") is a label that is
authenticated but not encrypted: the reader must supply the same label, so a message cannot be moved to a different context unnoticed. The
[concepts page](/guide/concepts) explains why.

## 3. Sign and verify in five lines

```ts test
import { easy } from 'quantum-safe-ts';

const keys = easy.generateSigningKeys();                        // Ed25519 + ML-DSA-65, PEM strings
const signed = easy.sign(keys.secretKey, 'release 1.2.3', { context: 'myapp-release-v1' });
const message = easy.verifyText(keys.publicKey, signed, { context: 'myapp-release-v1' }); // throws unless valid
if (message !== 'release 1.2.3') throw new Error('round trip failed');
```

`verify` takes the **context you expect**. It does not read the context from the message, because an attacker controls the message. If the
signature is wrong, the message was altered, or the context differs, it throws `VerificationError`.

::: tip What the easy layer trades away
Your secret key is a plain string in the JavaScript heap, where this library cannot wipe it and where a logger or a heap dump can see it.
That is fine for many uses. When it is not, use the class API below, which keeps secret keys inside WebAssembly memory.
:::

## 4. The class API

Secret keys stay inside WebAssembly memory. The owned secret buffers are zeroized when you call `.free()` or leave a `using` scope. (Copies
made while passing arguments or parsing may remain in WebAssembly memory; see the [security model](/guide/security).)

```ts test
import { init, HybridKEM, Envelope, utf8 } from 'quantum-safe-ts';

await init(); // required outside Node.js; a harmless no-op on Node.js

const kem = new HybridKEM();            // X25519 + ML-KEM-768
using pair = kem.generateKeyPair();     // freed (and its owned buffers zeroized) at the end of the scope

const sealed = Envelope.seal(utf8('attack at dawn'), pair.publicKey, { aad: utf8('msg-1') });
const plain = Envelope.open(sealed, pair.secretKey, { expectedAad: utf8('msg-1') });
if (new TextDecoder().decode(plain) !== 'attack at dawn') throw new Error('round trip failed');
```

`using` needs TypeScript 5.2 or newer (or a runtime that supports explicit resource management). Without it, call `pair.free()` in a `finally`.

## 5. Check that it works

Three quick checks you can run in any project:

```ts test
import { coreVersion, isInitialized, kemSuites, sigSuites } from 'quantum-safe-ts';

console.log('initialised:', isInitialized());            // true on Node.js; true after init() elsewhere
console.log('core version:', coreVersion());
console.log('KEM suites:', kemSuites().map((s) => s.name).join(', '));
console.log('signature suites:', sigSuites().length);
if (!isInitialized() || kemSuites().length < 9) throw new Error('library not ready');
```

If any call throws `NotInitializedError`, you are outside Node.js and have not awaited `init()` yet. Other errors are described in the
[error reference](/guide/errors).

To see the library work end to end against the Python implementation, or to scan your own code for classical cryptography you still need to
migrate, see [Interop with quantum-safe-py](/guide/python-interop) and the [audit tool](/tools/audit).

## 6. Which algorithms, in one line

| You want | Use |
|---|---|
| The sensible default | `X25519+ML-KEM-768` to encrypt, `Ed25519+ML-DSA-65` to sign (what `easy` uses) |
| Data that Python (quantum-safe-py) must read | The defaults; formats are byte-compatible both ways |
| Data that other ecosystems (not Python) must read | `X-Wing` to encrypt and [`StandardJwt`](/guide/jwt) for tokens |
| The CNSA 2.0 parameter sets | pure `ML-KEM-1024` and `ML-DSA-87` ([details](/guide/standards)) |

[Choosing what to use](/guide/choosing) has the full decision table, including when **not** to use this library.

## Where next

- Copy-paste solutions: [Quick start recipes](/guide/quick-start) and the [Cookbook](/guide/cookbook).
- Understand the ideas: [Concepts](/guide/concepts).
- Feature by feature: [Key encapsulation](/guide/kem), [Encryption](/guide/encryption), [Signatures](/guide/signatures),
  [Streaming](/guide/streaming), [JWT](/guide/jwt), [Keys](/guide/keys), [Migration](/guide/migration).
- Something broke: [Errors](/guide/errors) and [Troubleshooting and FAQ](/guide/faq).
