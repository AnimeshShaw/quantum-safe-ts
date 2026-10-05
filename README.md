<div align="center">

# quantum-safe-ts

**Hybrid post-quantum cryptography for TypeScript and JavaScript.**

ML-KEM · ML-DSA · SLH-DSA · hybrid envelopes and signatures · PQC JWTs · migration tooling

[![CI](https://github.com/AnimeshShaw/quantum-safe-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/AnimeshShaw/quantum-safe-ts/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-1.0 experimental](https://img.shields.io/badge/status-pre--1.0%20experimental-orange.svg)
![Not audited](https://img.shields.io/badge/security%20audit-none%20yet-red.svg)

[Documentation](https://animeshshaw.github.io/quantum-safe-ts/) · [Which library should I use?](https://animeshshaw.github.io/quantum-safe-ts/compare) · [Compatibility](COMPATIBILITY.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

A memory-safe Rust core compiled to WebAssembly behind a fully typed API, byte-compatible with
[quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py). It runs in Node.js, browsers, Deno, Bun, Cloudflare Workers and Chrome extensions.

> **Status: pre-1.0, experimental.** Not independently audited. Not FIPS 140-3 / CMVP validated. NIST ACVP results are conformance
> *evidence*, not a validation. JavaScript and WebAssembly runtimes give no constant-time guarantee. Do not protect real secrets with it
> until an independent review is published. See [SECURITY.md](SECURITY.md).

```bash
npm install quantum-safe-ts
```

> **Not published yet.** `quantum-safe-ts`, `quantum-safe-audit` and `quantum-safe-mcp` are not on npm yet, and the documentation site and the `@v0.1.0` action tag exist only after the first release. Until then build from source (see [CONTRIBUTING.md](CONTRIBUTING.md)); the commands below show how it will install.

```ts
import { easy } from 'quantum-safe-ts';

const { publicKey, secretKey } = easy.generateEncryptionKeys();   // PEM strings; X25519 + ML-KEM-768
const sealed = easy.encrypt(publicKey, 'attack at dawn');         // Uint8Array
const plain = easy.decrypt(secretKey, sealed);                    // Uint8Array
```

Need secret keys to stay inside WebAssembly memory and be wiped on demand? Use the class API (`HybridKEM`, `Envelope`, `using pair = ...`).
Both styles are in the [getting-started guide](https://animeshshaw.github.io/quantum-safe-ts/guide/getting-started).

## What is in this repository

| Package | What it is | Install |
|---|---|---|
| [`quantum-safe-ts`](packages/quantum-safe-ts) | **The library.** Hybrid KEMs, envelopes, signatures, JWT, keys, Argon2id, migration helpers. | `npm install quantum-safe-ts` |
| [`quantum-safe-audit`](packages/quantum-safe-audit) (alias: `pqc-audit`) | **A scanner** that finds classical (quantum-vulnerable) crypto in JS/TS projects; SARIF and CycloneDX CBOM output. Independent of the library. | `npx quantum-safe-audit scan .` |
| [`quantum-safe-mcp`](packages/quantum-safe-mcp) | **An MCP server** that lets coding agents run the scanner and get algorithm guidance. Depends on the scanner. | `npx quantum-safe-mcp` |
| [GitHub Action](action.yml) | Runs the scanner in CI, uploads SARIF, gates on severity. | `uses: AnimeshShaw/quantum-safe-ts@v0.1.0` |

The Rust core lives in [`crates/`](crates), the WebAssembly bindings in [`bindings/wasm`](bindings/wasm).

## What it provides

| Capability | API | Algorithms |
|---|---|---|
| One-call encryption and signing | `easy` | defaults `X25519+ML-KEM-768`, `Ed25519+ML-DSA-65` |
| Key encapsulation | `HybridKEM`, `KEM` | `X25519+ML-KEM-512/768/1024`, `P-256+ML-KEM-512/768`, `X-Wing`, pure `ML-KEM-512/768/1024` |
| Streaming encryption of large data (experimental, TypeScript-only) | `sealStream`, `openStream` | any hybrid KEM or `ML-KEM-1024`, chunked AES-256-GCM (STREAM) |
| Public-key encryption (anonymous: no sender authentication) | `Envelope`, `SealedMessage` | any hybrid KEM + AES-256-GCM; CNSA 2.0 profile with pure `ML-KEM-1024` + HKDF-SHA-384 (envelope v2; quantum-safe-py 0.3.1+ reads and writes it too) |
| Signatures | `Sign`, `HybridSign`, `SignedMessage` | `ML-DSA-44/65/87`, `Ed25519+ML-DSA-*`, `P-256+ML-DSA-44/65`, SLH-DSA (all 12 FIPS 205 sets); plus the cleaner `-v2` format of each ML-DSA suite (no prefix, FIPS 204 native context; quantum-safe-py 0.3.1+ reads it too) |
| Stateful hash-based signatures | `Lms` | LMS/HSS verification (RFC 8554). Signing is intentionally not provided. |
| JWT | `JWTSigner`/`JWTVerifier`, `StandardJwt` | quantum-safe-py-compatible, and RFC 9964 (ML-DSA for JOSE) |
| Password KDF | `deriveMasterKey` | Argon2id |
| Keys | `PublicKey`, `SecretKey`, `KeyPair` | CBOR, PEM, JWK (public), fingerprints, migration state |
| Migration | `Upgrader`, `MigrationStateManager` | classical to hybrid key upgrade; state machine with validated transitions, an audit trail and cross-process-safe stores; py store converters |
| Compliance report | `cnsa2.report()`, `cnsa2.enforce()` | CNSA 2.0 parameter check, with its limits stated |

## Why this library (and when not to use it)

Raw post-quantum primitives are becoming platform features: Node 24.7+ ships ML-KEM and ML-DSA in WebCrypto (experimental), Cloudflare Workers and Chrome are moving the same way, and
good pure-JavaScript libraries such as `@noble/post-quantum` exist. quantum-safe-ts does not try to win on primitives. It is the layer above:

- **Production formats.** Versioned envelope, key and signed-message formats with typed, fail-closed parsers, not just raw byte arrays.
- **Byte-compatible with quantum-safe-py**, verified in CI against the real Python library in both directions, so a Python service and a
  TypeScript service can share keys, ciphertexts, signatures, tokens and migration state.
- **Evidence.** 1,317 NIST ACVP cases (key-check, pre-hash and externalMu groups are not run; see the standards page), differential tests against independent implementations, cargo-fuzz targets for the main binary parsers plus property tests for the rest, packed-tarball
  tests in 12 real toolchains, a published timing-leakage screen, and a reproducible-build check. Each is reproducible from this repository.
- **Migration tooling.** Find classical crypto, upgrade keys, track progress safely across processes, gate it in CI.
- **Agent-friendly.** `llms.txt`, executed documentation snippets, typed errors with actionable hints, and an MCP server.

Use something simpler if you only need a primitive (see the [decision guide](https://animeshshaw.github.io/quantum-safe-ts/compare)).
Use something else if you need audited or FIPS 140-3 validated code today: this library has had neither.

## Compatibility with quantum-safe-py, and what it means

Envelopes, keys (CBOR, PEM, JWK, fingerprints), signed messages, signatures, JWTs and migration records are **byte-compatible in both
directions** (see [COMPATIBILITY.md](COMPATIBILITY.md)). That is compatibility, not general interoperability: quantum-safe-py's hybrid combiner
and signature context are its own constructions. They are not X-Wing, not TLS `X25519MLKEM768`, and not FIPS 204's native context. For data
that other ecosystems must read, use `HybridKEM('X-Wing')` and `StandardJwt` (RFC 9964).

## Where it runs

Every row is exercised by a fixture that installs the **packed npm tarball** into a fresh project (see [`tests/fixtures/`](tests/fixtures)).

| Environment | Notes |
|---|---|
| Node.js 20 (end of life), 22, 24 (ESM and CommonJS) | Initialises on import. |
| Chromium, Firefox, WebKit | `await init()`. No bundler configuration (the WASM is embedded). |
| Vite 7 + React 19, webpack 5, esbuild, Next.js 16 (Turbopack and webpack), SvelteKit 2 (client side, static adapter) | Default configuration; no WASM plugin. |
| Cloudflare Workers | `await init({ wasm })` with the precompiled module. |
| Deno 2, Bun | From `node_modules`. |
| Chrome extensions (Manifest V3) | Needs `'wasm-unsafe-eval'` in the extension CSP. |

Not supported yet: React Native. The WebAssembly is about 410 KiB gzipped (built for speed; a size-optimised build was 2-3x slower and about 285 KiB); the default entry embeds it as base64, so a bundle grows by about 600 KiB gzipped, and tree-shaking cannot drop algorithms.

## Evidence and how to reproduce it

| Claim | Reproduce |
|---|---|
| 1,317 NIST ACVP known-answer cases pass | `python scripts/fetch_acvp.py && QS_REQUIRE_ACVP=1 cargo test --release -p quantum-safe-core --test acvp` |
| Byte parity with the real quantum-safe-py, both directions | `python scripts/generate_suite_vectors.py` … `python scripts/verify_ts_vectors.py` (see [CONTRIBUTING.md](CONTRIBUTING.md)) |
| Works in 12 real toolchains from the packed tarball | `node tests/fixtures/run.mjs` |
| Differential tests against `@noble/post-quantum` and Node WebCrypto | `npx vitest run test/differential.test.ts` in `packages/quantum-safe-ts` |
| Reproducible WASM build | `node scripts/repro-check.mjs` |

## Using it with AI coding agents

[`llms.txt`](packages/quantum-safe-ts/llms.txt) and [`llms-full.txt`](packages/quantum-safe-ts/llms-full.txt) ship in the npm package, and every
example in `llms-full.txt` is executed in CI. Typed errors carry a `code` and a
`hint` an agent can act on, and [`quantum-safe-mcp`](packages/quantum-safe-mcp) exposes the scanner and guidance over MCP.

## Memory and errors

Secret keys live in WASM memory; the owned secret buffers are zeroized on `.free()` (copies made while passing arguments or parsing may remain in WebAssembly memory; see SECURITY.md) when you call `.free()` or leave a `using` scope. Anything you copy out (`exportBytes()`,
`toPem()`, plaintext, and every key string the `easy` layer returns) lives in the JS heap, where no library can wipe it. Everything throws a
`QuantumSafeError` subclass with a stable `code` (for example `QS_DECRYPTION_FAILED`) and a static `hint`; match with `instanceof` or `code`.

## Contributing, support, security

[CONTRIBUTING.md](CONTRIBUTING.md) · [SUPPORT.md](SUPPORT.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Cite it with [CITATION.cff](CITATION.cff).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
