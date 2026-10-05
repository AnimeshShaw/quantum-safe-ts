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
| Speed | Several times faster than pure JavaScript for ML-KEM and ML-DSA; slower than native code (figures withheld until the first release) | Baseline | Faster than ours for ML-KEM, async only, ML-KEM only |
| Independent audit | No | Not independently audited (self-audit) | Depends on the engine |
| Works in browsers, Deno, Bun, Workers | Yes | Yes | Only where implemented |
| Constant-time | No guarantee (JS/WASM) | Not claimed | Depends on the engine |

**WebCrypto status, as of October 2026.** Node.js 24.7+ ships ML-KEM and ML-DSA (Stability 1.1, experimental); Node 26.10 adds hybrid KEMs; Cloudflare Workers has them behind a compatibility flag. Chrome has cleared an Intent to Ship; check the current state for your target browsers before relying on it.

## When not to use quantum-safe-ts

- You only need a primitive. A smaller dependency is better.
- You want the most widely used, most scrutinised JavaScript implementation: that is `@noble/post-quantum` today. This library is new (0.1.0) and has no track record yet.
- You need audited or validated code today. This library has had neither.
- You cannot add WebAssembly to your runtime (some locked-down environments). Use a pure-JavaScript library.
- You need Falcon / FN-DSA or HQC. Those standards are not final and are not implemented here.
