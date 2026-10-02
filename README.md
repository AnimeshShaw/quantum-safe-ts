# quantum-safe-ts

Hybrid post-quantum cryptography for **TypeScript and JavaScript**: ML-KEM, ML-DSA, SLH-DSA,
hybrid X25519/Ed25519/P-256 + PQC envelopes and signatures, PQC JWTs, and a CNSA 2.0 profile.
A memory-safe Rust core compiled to WebAssembly, with a fully typed API. Byte-compatible with
[quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py).

> **Status: pre-1.0, experimental.** Not independently audited. Not FIPS 140-3 / CMVP validated.
> NIST ACVP results are conformance *evidence*, not a validation. JavaScript and WebAssembly runtimes give
> no constant-time guarantee. Do not protect real secrets with it until an independent review is published.
> See [SECURITY.md](SECURITY.md).

```bash
npm install quantum-safe-ts
```

```ts
import { init, HybridKEM, Envelope, utf8 } from 'quantum-safe-ts';

await init(); // required in browsers/Deno/Bun/edge; a no-op on Node.js

const kem = new HybridKEM();          // X25519 + ML-KEM-768
using pair = kem.generateKeyPair();   // `using` wipes the secret key from WASM memory on scope exit

const sealed = Envelope.seal(utf8('attack at dawn'), pair.publicKey, { aad: utf8('msg-1') });
const plain = Envelope.open(sealed, pair.secretKey); // Uint8Array
```

## What it provides

| Capability | API | Algorithms |
|---|---|---|
| Key encapsulation | `HybridKEM`, `KEM` | `X25519+ML-KEM-512/768/1024`, `P-256+ML-KEM-512/768`, `X-Wing`, pure `ML-KEM-512/768/1024` |
| Authenticated encryption | `Envelope`, `SealedMessage` | any hybrid KEM + AES-256-GCM |
| Signatures | `Sign`, `HybridSign`, `SignedMessage` | `ML-DSA-44/65/87`, `Ed25519+ML-DSA-*`, `P-256+ML-DSA-44/65`, SLH-DSA (FIPS 205, 12 sets) |
| JWT | `JWTSigner`/`JWTVerifier`, `StandardJwt` | quantum-safe-py-compatible, and RFC 9964 (ML-DSA for JOSE) |
| Password KDF | `deriveMasterKey` | Argon2id (19 MiB, t=2, p=1) |
| Keys | `PublicKey`, `SecretKey`, `KeyPair` | CBOR, PEM, JWK (public), SHA-256 fingerprints, migration state |
| Compliance | `cnsa2.report()`, `cnsa2.enforce()` | NSA CNSA 2.0 parameter-set check, with limits stated |

The default hybrid is `X25519+ML-KEM-768` (NIST category 3), as in quantum-safe-py. **CNSA 2.0 requires
ML-KEM-1024 / ML-DSA-87**: use `cnsa2.kem()` (pure ML-KEM-1024; sealed as a CNSA-profile envelope with HKDF-SHA-384) and
`cnsa2.hybridSign()`, or run `cnsa2.report()` to see exactly where a configuration falls short. (Hybrid is optional under CNSA 2.0, and the
classical half of a CNSA 2.0 hybrid must be P-384, which is not implemented.)

## Compatibility with quantum-safe-py

Envelopes, keys (CBOR/PEM/JWK/fingerprints), signed messages, signatures and JWTs are **byte-compatible
in both directions** and verified in CI against the real Python library (see
[COMPATIBILITY.md](COMPATIBILITY.md)). Be aware this is compatibility, not general interoperability:
quantum-safe-py's hybrid combiner and signature "context" are its own constructions. They are not
X-Wing, not TLS `X25519MLKEM768`, and not FIPS 204's native context. For data that other ecosystems must read,
use the standards-based options: `HybridKEM('X-Wing')` and `StandardJwt` (RFC 9964).

## Where it runs

Every cell below is exercised by a fixture that installs the **packed npm tarball** into a fresh
project and runs the same end-to-end smoke test (see `tests/fixtures/`).

| Environment | Notes |
|---|---|
| Node.js 20, 22, 24 (ESM and CommonJS) | Initialises on import. Strict TypeScript consumers compile against the published types. |
| Browsers: Chromium, Firefox, WebKit | Call `await init()`. No bundler configuration needed (the WASM is embedded). |
| Vite 7 + React 19, webpack 5, esbuild | Default configs; no WASM plugin. |
| Next.js 16 (App Router; Turbopack and webpack) | Use it from client components or server code. |
| SvelteKit 2 / Svelte 5 | Client-side. |
| Cloudflare Workers | Pass the precompiled module: `await init({ wasm })` (Workers forbid compiling WASM from bytes). |
| Deno 2, Bun | From `node_modules`. |
| Chrome extensions (Manifest V3) | Requires `'wasm-unsafe-eval'` in the extension CSP. |

Not yet supported: React Native (Hermes WebAssembly arrived in RN 0.84; evaluation planned).
Bundle cost: about 284 KB gzipped of WASM; the default entry embeds it (about 416 KB gzipped in a bundle).

## Memory and secrets

Secret keys live in WASM linear memory and are zeroized when you call `.free()` or leave a `using` scope.
Anything you copy out (`exportBytes()`, `toPem()`, plaintext returned by `Envelope.open`) lives in the JS heap
where this library cannot wipe it; call `wipe()` on those copies when done. Errors and `toString()`/`JSON.stringify`
never contain key material.

## Errors

Everything throws a `QuantumSafeError` subclass with a stable `code` (for example `QS_DECRYPTION_FAILED`) and a
static `hint`. Match with `instanceof` or `code`; never parse `message`.

## Using this library with AI coding agents

[`llms.txt`](packages/quantum-safe-ts/llms.txt) and [`llms-full.txt`](packages/quantum-safe-ts/llms-full.txt) ship in the npm
package. [`AGENTS.md`](AGENTS.md) describes how to work on the project. Typed errors carry a `hint` an agent can act on.

## Audit your own code

[`quantum-safe-audit`](packages/quantum-safe-audit) scans JavaScript/TypeScript projects for classical-cryptography
usage (RSA, ECDSA, ECDH, Ed25519, `node:crypto`, WebCrypto, `jose`, `jsonwebtoken`, `node-forge`, ...), reports
quantum-vulnerability and CNSA 2.0 gaps, suggests migrations to this library, and emits SARIF and a CycloneDX 1.6 CBOM.

## Project documents

- [COMPATIBILITY.md](COMPATIBILITY.md): what matches quantum-safe-py, what does not, and why.
- [ROADMAP.md](ROADMAP.md): phased plan.
- [docs/research/](docs/research): ecosystem research, standards alignment, and parity analysis.
- [SECURITY.md](SECURITY.md): threat model summary and vulnerability reporting.
- [CHANGELOG.md](CHANGELOG.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
