<div align="center">

# quantum-safe-ts

**Hybrid post-quantum cryptography for TypeScript and JavaScript.**

ML-KEM · ML-DSA · SLH-DSA · hybrid envelopes and signatures · PQC JWTs · migration tooling

[![CI](https://github.com/AnimeshShaw/quantum-safe-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/AnimeshShaw/quantum-safe-ts/actions/workflows/ci.yml)
[![Docs](https://github.com/AnimeshShaw/quantum-safe-ts/actions/workflows/docs.yml/badge.svg)](https://animeshshaw.github.io/quantum-safe-ts/)
[![npm: quantum-safe-ts](https://img.shields.io/npm/v/quantum-safe-ts.svg?label=quantum-safe-ts)](https://www.npmjs.com/package/quantum-safe-ts)
[![npm: quantum-safe-audit](https://img.shields.io/npm/v/quantum-safe-audit.svg?label=quantum-safe-audit)](https://www.npmjs.com/package/quantum-safe-audit)
[![npm: quantum-safe-mcp](https://img.shields.io/npm/v/quantum-safe-mcp.svg?label=quantum-safe-mcp)](https://www.npmjs.com/package/quantum-safe-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Algorithms: FIPS 203/204/205](https://img.shields.io/badge/algorithms-FIPS_203%2F204%2F205-purple.svg)](https://csrc.nist.gov/pubs/fips)
[![NIST ACVP: 1,317 cases](https://img.shields.io/badge/NIST_ACVP-1%2C317_cases_pass-informational.svg)](https://animeshshaw.github.io/quantum-safe-ts/guide/security)
[![Byte-compatible with quantum-safe-py](https://img.shields.io/badge/quantum--safe--py-byte--compatible-green.svg)](COMPATIBILITY.md)
![Runs on: Node, browsers, Deno, Bun, Workers](https://img.shields.io/badge/runs_on-Node_%C2%B7_browsers_%C2%B7_Deno_%C2%B7_Bun_%C2%B7_Workers-lightgrey.svg)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23160434.svg)](https://doi.org/10.5281/zenodo.23160434)

[Documentation](https://animeshshaw.github.io/quantum-safe-ts/) · [What it adds](https://animeshshaw.github.io/quantum-safe-ts/compare) · [Roadmap](ROADMAP.md) · [Compatibility](COMPATIBILITY.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

A memory-safe Rust core compiled to WebAssembly behind a fully typed API, byte-compatible with
[quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py). It runs in Node.js, browsers, Deno, Bun, Cloudflare Workers and Chrome extensions.

```bash
npm install quantum-safe-ts
```

```ts
import { easy } from 'quantum-safe-ts';

const { publicKey, secretKey } = easy.generateEncryptionKeys();   // PEM strings; X25519 + ML-KEM-768
const sealed = easy.encrypt(publicKey, 'attack at dawn');         // Uint8Array
const plain = easy.decrypt(secretKey, sealed);                    // Uint8Array
```

For secret keys that stay inside WebAssembly memory and are wiped on demand, use the class API (`HybridKEM`, `Envelope`, `using pair = ...`).
Both styles are in the [getting-started guide](https://animeshshaw.github.io/quantum-safe-ts/guide/getting-started).

## What it provides

| Capability | API | Algorithms |
|---|---|---|
| One-call encryption and signing | `easy` | `X25519+ML-KEM-768`, `Ed25519+ML-DSA-65-v2` |
| Key encapsulation | `HybridKEM`, `KEM` | `X25519+ML-KEM-512/768/1024`, `P-256+ML-KEM-512/768`, `P-384+ML-KEM-1024`, `X-Wing`, pure `ML-KEM-512/768/1024` |
| Encryption | `Envelope`, `sealStream` / `openStream` | any hybrid KEM + AES-256-GCM; streaming for large data; CNSA 2.0 profile (`ML-KEM-1024`, HKDF-SHA-384) |
| Signatures | `Sign`, `HybridSign`, `cose` | `ML-DSA-44/65/87`, hybrids with Ed25519, P-256 and P-384, SLH-DSA (12 sets), the `-v2` format, standard FIPS 204 `signRaw`, COSE_Sign1 |
| Hash-based signatures | `Lms`, `LmsSigner` | LMS / HSS verification everywhere; LMS signing in Node.js with durable state |
| Tokens | `JWTSigner` / `JWTVerifier`, `StandardJwt` | quantum-safe-py compatible, and RFC 9964 (ML-DSA for JOSE) |
| Keys and passwords | `PublicKey`, `SecretKey`, `KeyPair`, `deriveMasterKey` | CBOR, PEM, JWK, fingerprints, Argon2id |
| Migration | `Upgrader`, `MigrationStateManager` | classical-to-hybrid key upgrade, state machine, cross-process stores |
| Compliance report | `cnsa2.report()`, `cnsa2.enforce()` | CNSA 2.0 parameter check |

## Packages in this repository

| Package | What it is | Install |
|---|---|---|
| [`quantum-safe-ts`](packages/quantum-safe-ts) | The library. | `npm install quantum-safe-ts` |
| [`quantum-safe-audit`](packages/quantum-safe-audit) (alias: `pqc-audit`) | A scanner for classical crypto in JS/TS projects; SARIF and CycloneDX CBOM output. | `npx quantum-safe-audit scan .` |
| [`quantum-safe-mcp`](packages/quantum-safe-mcp) (alias: `pqc-mcp`) | An MCP server: lets coding agents run the scanner and get algorithm guidance. | `npx quantum-safe-mcp` |
| [GitHub Action](https://github.com/marketplace/actions/quantum-safe-audit) ([source](action.yml)) | The scanner in CI: uploads SARIF, gates on severity. | `uses: AnimeshShaw/quantum-safe-ts@v0.1.3` |

## Documentation

| If you want to... | Read |
|---|---|
| Get started, pick an API | [Getting started](https://animeshshaw.github.io/quantum-safe-ts/guide/getting-started), [Choosing what to use](https://animeshshaw.github.io/quantum-safe-ts/guide/choosing) |
| Copy a working recipe | [Cookbook](https://animeshshaw.github.io/quantum-safe-ts/guide/cookbook) |
| Exchange data with a Python service | [Interop with quantum-safe-py](https://animeshshaw.github.io/quantum-safe-ts/guide/python-interop), [Differences](https://animeshshaw.github.io/quantum-safe-ts/guide/differences) |
| See where it runs (bundlers, Workers, Deno, Bun) | [Runtimes](https://animeshshaw.github.io/quantum-safe-ts/guide/runtimes) |
| Sign firmware with LMS | [LMS signing](https://animeshshaw.github.io/quantum-safe-ts/guide/lms-signing) |
| Check CNSA 2.0 parameters | [CNSA 2.0 and standards](https://animeshshaw.github.io/quantum-safe-ts/guide/standards) |
| Memory, errors, evidence and how to reproduce it | [Security](https://animeshshaw.github.io/quantum-safe-ts/guide/security) |
| Use it with an AI coding agent | [`llms.txt`](packages/quantum-safe-ts/llms.txt), [`llms-full.txt`](packages/quantum-safe-ts/llms-full.txt), [`quantum-safe-mcp`](packages/quantum-safe-mcp) |

## Contributing, support, security

[CONTRIBUTING.md](CONTRIBUTING.md) · [SUPPORT.md](SUPPORT.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [ROADMAP.md](ROADMAP.md). Report vulnerabilities
privately through GitHub Security Advisories or by email, as described in [SECURITY.md](SECURITY.md). Cite it with [CITATION.cff](CITATION.cff) or the
Zenodo record, [10.5281/zenodo.23160434](https://doi.org/10.5281/zenodo.23160434), which always resolves to the latest release.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Every npm package carries `THIRD_PARTY_LICENSES.md` (the Rust crates compiled into the
WebAssembly, with their licence texts).
