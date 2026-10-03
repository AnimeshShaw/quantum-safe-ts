# Which library should I use?

Short answer: **use the simplest thing that does the job.** Raw post-quantum primitives are becoming platform features, and several good
libraries provide them. quantum-safe-ts is a *production layer* on top of primitives: formats, envelopes, signatures, tokens, key lifecycle and
migration tooling. Choose it for that layer, not for the primitives.

## Decision guide

| You need | Use |
|---|---|
| A raw ML-KEM or ML-DSA primitive, in Node 24.7+ (or where your runtime has it: Cloudflare Workers behind a flag, Chrome is moving the same way) | The platform's WebCrypto (`SubtleCrypto`). It is native, and the algorithms are experimental in Node today. |
| A raw primitive, pure JavaScript, no WebAssembly | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) |
| Only ML-KEM, tiny and pure TypeScript | `mlkem` |
| HPKE with X-Wing | `@hpke/core` with `@hpke/hybridkem-x-wing` |
| Encrypt files with a post-quantum hybrid identity | `age-encryption` (age format, ML-KEM-768 + X25519 hybrid identities, built on noble) |
| An SDK for JS/TS with X-Wing + AES-256-GCM defaults, a file-encryption CLI, an MCP server and LangChain tools | `@pqc-sdk/core` and its companion packages (young: first published in June 2026 and at 0.11 by late September; evaluate for yourself) |
| WebAssembly bindings to liboqs (research and prototyping) | `@oqs/liboqs-js` (from the Open Quantum Safe project; its README says it is not for production) |
| TLS | Nothing: platforms already negotiate `X25519MLKEM768` (RFC 10024). |
| A **FIPS 140-3 validated module** | None of the JavaScript libraries here, and none that we know of has CMVP validation. |
| **Encrypt a message to a public key, sign data, issue PQC JWTs, serialise keys, and keep it compatible with a Python service** | quantum-safe-ts |
| To **find and plan** classical-crypto removal in a JS/TS codebase | Several tools overlap here: `cdxgen --include-crypto` already derives a crypto inventory (CBOM) from JS/TS source, and small scanners such as `@pqc-sdk/cli`, `cryptosweep` and `kxco-pq-scan` exist. `quantum-safe-audit` adds policy gating, an incomplete-scan-is-an-error rule, SARIF, migration hints that point at working replacement code, and CNSA 2.0 gap reporting. It has not been compared head to head with the others on code it was not written against. |

## How the options differ

| | quantum-safe-ts | @noble/post-quantum | Platform WebCrypto |
|---|---|---|---|
| Implementation | Rust to WebAssembly | Pure JavaScript | Native (OpenSSL / BoringSSL) |
| Primitives | ML-KEM, ML-DSA, SLH-DSA, X-Wing, hybrids | ML-KEM, ML-DSA, SLH-DSA, Falcon, X-Wing and other hybrids | ML-KEM, ML-DSA (varies by runtime) |
| Envelope, signed-message and key formats | Yes, versioned, byte-compatible with quantum-safe-py | No: primitives only | No |
| JWT | Yes, including RFC 9964 | No | No |
| Typed errors with stable codes | Yes | Plain errors | `DOMException` |
| Migration and audit tooling | Yes | No | No |
| Speed (one laptop, see below) | About 3.7 to 4.7 times faster than noble for ML-KEM-768 keygen, encapsulate and decapsulate; about 4 times for ML-DSA-65 sign and verify and 1.9 times for keygen | Baseline | About 2 times faster than ours for ML-KEM-768 encapsulate/decapsulate, async only, ML-KEM only |
| Independent audit | No | Not independently audited (self-audit) | Depends on the engine |
| Works in browsers, Deno, Bun, Workers | Yes | Yes | Only where implemented |
| Constant-time | No guarantee (JS/WASM) | Not claimed | Depends on the engine |

Speeds come from `bench/run-matrix.mjs` on one machine (each benchmark in its own process, pinned to one core, repeated); treat them as indicative, and compare ratios, not absolute numbers (they drifted by almost 4x between sessions on that laptop). See the repository's
`results/bench_matrix.json` for the figures and spread.

**Against native C and Python.** `bench/py_baseline.py` measures liboqs (C, AVX2) through its Python binding and quantum-safe-py on the same machine, pinned the same way (`results/py_baseline.json`). ML-KEM-768 keygen and encapsulate in WebAssembly are about the same speed as liboqs (15.1k and 15.5k against 13.8k and 14.7k operations per second); liboqs is about 2.7 times faster at ML-KEM-768 decapsulation and 3.4 to 4.5 times faster at ML-DSA-65. For the hybrid operations quantum-safe-py performs, this library is about 1.7 times faster at key generation and 1.3 times at encapsulation, about equal at decapsulation, and about 3 times slower at Ed25519+ML-DSA-65 sign and verify. Numbers are for one machine and one runtime and will differ on yours.

**WebCrypto status, as of October 2026.** Node.js 24.7+ ships ML-KEM and ML-DSA (Stability 1.1, experimental); Node 26.10 adds hybrid KEMs; Cloudflare Workers has them behind a compatibility flag. Chrome has cleared an Intent to Ship; check the current state for your target browsers before relying on it.

## When not to use quantum-safe-ts

- You only need a primitive. A smaller dependency is better.
- You want the most widely used, most scrutinised JavaScript implementation: that is `@noble/post-quantum` today (roughly half a million weekly downloads, against none for a package that is not yet published).
- You need audited or validated code today. This library has had neither.
- You cannot add WebAssembly to your runtime (some locked-down environments). Use a pure-JavaScript library.
- You need Falcon / FN-DSA or HQC. Those standards are not final and are not implemented here.
