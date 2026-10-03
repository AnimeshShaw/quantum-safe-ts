# quantum-safe-ts

Hybrid post-quantum cryptography for **TypeScript and JavaScript**: ML-KEM, ML-DSA, SLH-DSA, hybrid X25519 / Ed25519 / P-256 + post-quantum
encryption and signatures, post-quantum JWTs, and a CNSA 2.0 profile. A memory-safe Rust core compiled to WebAssembly, behind a fully typed
API, byte-compatible with [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py).

> **Status: pre-1.0, experimental.** Not independently audited. Not FIPS 140-3 / CMVP validated. NIST ACVP results are conformance
> *evidence*, not a validation. JavaScript and WebAssembly runtimes give no constant-time guarantee. Do not protect real secrets with it
> until an independent review is published. See [SECURITY.md](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/SECURITY.md).

```bash
npm install quantum-safe-ts
```

> Not published yet: until the first release, build from source (see the repository's CONTRIBUTING.md).

## Quick start

The shortest path: strings and bytes in, strings and bytes out, nothing to free.

```ts test
import { easy } from 'quantum-safe-ts';

const { publicKey, secretKey } = easy.generateEncryptionKeys();     // PEM strings, X25519 + ML-KEM-768
const sealed = easy.encrypt(publicKey, 'attack at dawn');           // Uint8Array
const plain = easy.decrypt(secretKey, sealed);                      // Uint8Array
if (new TextDecoder().decode(plain) !== 'attack at dawn') throw new Error('round trip failed');

const signer = easy.generateSigningKeys();                           // Ed25519 + ML-DSA-65
const signed = easy.sign(signer.secretKey, 'pay 10', { context: 'payments' });
const message = easy.verify(signer.publicKey, signed, { context: 'payments' }); // throws unless valid
if (new TextDecoder().decode(message) !== 'pay 10') throw new Error('verify failed');
```

On Node.js this works immediately. In browsers, Deno, Bun and edge runtimes call `await init()` once first (see below).

When you need to keep secret keys inside WebAssembly memory and wipe them on demand, use the class API. (`using` needs TypeScript 5.2+ with `lib` including `ESNext.Disposable`, and runs natively on Node 24+; elsewhere transpile it or write `try { ... } finally { pair.free(); }`.)

```ts test
import { init, HybridKEM, Envelope, utf8 } from 'quantum-safe-ts';

await init(); // required outside Node.js; a no-op on Node.js

const kem = new HybridKEM();          // X25519 + ML-KEM-768
using pair = kem.generateKeyPair();   // `using` wipes the secret key from WASM memory on scope exit

const sealed = Envelope.seal(utf8('attack at dawn'), pair.publicKey, { aad: utf8('msg-1') });
const plain = Envelope.open(sealed, pair.secretKey); // Uint8Array
if (plain.length !== 14) throw new Error('unexpected length');
```

## What it provides

| Capability | API | Algorithms |
|---|---|---|
| One-call encryption and signing | `easy` | defaults: `X25519+ML-KEM-768`, `Ed25519+ML-DSA-65` |
| Key encapsulation | `HybridKEM`, `KEM` | `X25519+ML-KEM-512/768/1024`, `P-256+ML-KEM-512/768`, `X-Wing`, pure `ML-KEM-512/768/1024` |
| Public-key encryption (anonymous: no sender authentication) | `Envelope`, `SealedMessage` | any hybrid KEM + AES-256-GCM |
| Signatures | `Sign`, `HybridSign`, `SignedMessage` | `ML-DSA-44/65/87`, `Ed25519+ML-DSA-*`, `P-256+ML-DSA-44/65`, SLH-DSA (12 parameter sets); plus the TypeScript-only `-v2` format of each ML-DSA suite |
| Stateful hash-based verification | `Lms` | LMS / HSS (RFC 8554, SHA-256), verification only |
| JWT | `JWTSigner`/`JWTVerifier`, `StandardJwt` | quantum-safe-py-compatible, and RFC 9964 (ML-DSA for JOSE) |
| Password KDF | `deriveMasterKey` | Argon2id |
| Keys | `PublicKey`, `SecretKey`, `KeyPair` | CBOR, PEM, JWK (public), fingerprints, migration state |
| Migration | `Upgrader`, `MigrationStateManager` | classical to hybrid key upgrade, state machine with validated transitions and an audit trail, py store converters |
| Compliance report | `cnsa2.report()`, `cnsa2.enforce()` | CNSA 2.0 parameter check, with limits stated |

Defaults match quantum-safe-py (NIST category 3). **CNSA 2.0 requires ML-KEM-1024 and ML-DSA-87**: use `cnsa2.kem()` and
`ML-DSA-87` (and `cnsa2.hybridSign()` reports `partial`), or run `cnsa2.report()` to see where a configuration falls short.

## Where it runs

Every row is exercised by a test that installs the packed npm tarball into a fresh project.

| Environment | Notes |
|---|---|
| Node.js 20 (end of life), 22, 24 (ESM and CommonJS) | Initialises on import. |
| Chromium, Firefox, WebKit | `await init()`. No bundler configuration (the WASM is embedded). |
| Vite 7, webpack 5, esbuild, Next.js 16, SvelteKit 2 | Default configuration, no WASM plugin. |
| Cloudflare Workers | `await init({ wasm })` with the precompiled module (Workers forbid compiling WASM from bytes). |
| Deno 2, Bun | From `node_modules`. |
| Chrome extensions (Manifest V3) | Needs `'wasm-unsafe-eval'` in the extension CSP. |

Not supported: React Native. About 405 KiB of gzipped WebAssembly (compiled for speed), embedded as base64 in the default entry (about 600 KiB gzipped of JavaScript; import `quantum-safe-ts/slim` and pass the `.wasm` to `init` to avoid that; tree-shaking cannot drop algorithms).

## Compatible with quantum-safe-py, and what that means

Envelopes, keys (CBOR / PEM / JWK), signed messages, signatures, JWTs and migration records are byte-compatible in both directions
and verified in CI against the real Python library. That is *compatibility*, not general interoperability: quantum-safe-py's hybrid
combiner and signature context are its own constructions. They are not X-Wing, not TLS `X25519MLKEM768`, and not FIPS 204's native
context. For data other ecosystems must read, use `HybridKEM('X-Wing')` and `StandardJwt`.

## Errors, memory and secrets

Every failure is a `QuantumSafeError` subclass with a stable `code` (for example `QS_DECRYPTION_FAILED`) and a `hint`. Match with
`instanceof` or `code`, never by parsing `message`. Secret keys live in WASM memory; the owned secret buffers are zeroized on `.free()` (copies made while passing arguments or parsing may remain in WebAssembly memory; see SECURITY.md) by `.free()` or a `using` scope.
Copies you extract (`exportBytes()`, `toPem()`, plaintext, and every key string the `easy` layer hands you) live in the JavaScript heap, where
this library cannot wipe them.

## For AI coding agents

`llms.txt` and `llms-full.txt` ship in this package, and every code example in `llms-full.txt` is executed in CI. Also available:
[`quantum-safe-mcp`](https://github.com/AnimeshShaw/quantum-safe-ts/tree/master/packages/quantum-safe-mcp) (a read-only MCP server) and
[`quantum-safe-audit`](https://github.com/AnimeshShaw/quantum-safe-ts/tree/master/packages/quantum-safe-audit) (finds classical crypto in your code).

## License

Apache-2.0.
