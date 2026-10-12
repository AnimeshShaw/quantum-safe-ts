# Where quantum-safe-ts differs from quantum-safe-py

The two libraries read and write the same bytes. They are not copies of each other: each follows the conventions of its language and runtime.
This page lists every difference that affects what you can do, and the reason for it, so you can pick the right one or use both. The
formats that cross are in [Interop with quantum-safe-py](/guide/python-interop).

## Algorithms and formats

| | quantum-safe-ts 0.2 | quantum-safe-py 0.4 | Reason |
|---|---|---|---|
| ML-KEM-512/768/1024, hybrids with X25519 and P-256, X-Wing | Yes | Yes | Shared, byte for byte. |
| ML-DSA-44/65/87, hybrids with Ed25519 and P-256, `-v2` | Yes | Yes | Shared. |
| SLH-DSA, all twelve parameter sets | Yes | Yes | Shared; verified in both directions. |
| HQC-128/192/256, BIKE-L1/3/5 | No | Yes (through liboqs) | The TypeScript library implements the standardized algorithms on RustCrypto crates and ships one small WebAssembly module. HQC and BIKE are in liboqs only. |
| COSE_Sign1, private AKP JWKs, streaming envelopes (format v3) | Yes | Yes | Shared; vectors are checked in both directions. |
| LMS verification | Yes, every runtime | Yes (`[lms]` extra, pyhsslms) | Shared. |
| LMS signing | Node.js only; one tree of height 5, 10, 15 or 20; state in a directory | Yes (`[lms]` extra); one tree of height 5 to 25; state in a store you supply | Signing is stateful: it needs state that survives a crash. Node.js has a filesystem for it; browsers and Workers do not, so the TypeScript signer refuses to run there. |
| XMSS | No | No | LMS already satisfies CNSA 2.0's "LMS or XMSS". |
| Hybrid X.509 certificate builder | No | Yes | Python's design is a classical certificate plus a co-signature bundle. Standards-based X.509 for ML-DSA and ML-KEM (IETF LAMPS) is the better target for TypeScript. |
| TLS `SSLContext` configuration | No | Yes | Python-specific. Node.js and current browsers negotiate hybrid TLS natively. |
| Fernet and PyJWT shims | No | Yes | They wrap Python libraries; TypeScript has fix hints in the audit tool and the migration guides instead. |
| Argon2id master-key derivation (`deriveMasterKey`) | Yes | No | Python has no master-password concept. |

## Keys

| | quantum-safe-ts | quantum-safe-py | Reason |
|---|---|---|---|
| Standard ML-DSA secret key | A 32-byte seed (`StandardKeyPair`) | liboqs: 4,032-byte expanded key. With the optional `cryptography` backend: the 32-byte seed | FIPS 204 defines the seed as the key; the RustCrypto implementation works from it. liboqs does not take a seed. |
| Signing with the other library's key | Signs with seed keys; verifies everything | Signs with either; verifies everything | An expanded key has no recoverable seed. For one key that signs in both, use a seed key (`Sign.generateStandardKeyPair()` or Python's `generate_seed_keypair()`). |
| `hedged: false` with a `-v2` suite | Accepted and ignored, with a `QS_HEDGED_IGNORED` warning; an error at the next breaking release | `ValueError` | The `-v2` formats have no unhedged mode. TypeScript kept its documented 0.1.x behaviour so that nothing breaks in between. |
| Zeroization | Rust `zeroize` plus explicit `free()` / `using`; copies in the JavaScript heap cannot be wiped | `ctypes.memset` of secret buffers | Different memory models. |

## Runtimes and packaging

| | quantum-safe-ts | quantum-safe-py |
|---|---|---|
| Backends | One: Rust compiled to WebAssembly, embedded in the package. A native WebCrypto provider was evaluated and not built | liboqs, RustCrypto, or `cryptography`, chosen at run time |
| Where it runs | Node.js, Bun, Deno, browsers, Workers, edge runtimes | CPython |
| Errors | Typed errors with stable `code` and `hint` | Exception hierarchy |
| Warnings (omitted context or AAD) | `process.emitWarning`, type `QuantumSafeWarning`; `warnings.silence()` | `warnings` categories `ContextOmittedWarning` / `AadOmittedWarning` |
| Convenience layer | `easy` (strings and bytes in and out) | the high-level classes only |
| Machine-readable docs | `llms.txt`, `llms-full.txt`, an MCP server | n/a |
| Source scanner | `quantum-safe-audit` scans JavaScript and TypeScript | `qs-audit` scans Python |
| NIST ACVP known-answer cases | 1,317 | 638 |

## Behaviour that is deliberately the same

Both libraries fail closed and say little about why: a wrong context, a wrong AAD, a different hedging mode and a modified byte all raise the
same verification or decryption error. Both ask for the context and AAD you expect, warn once per call site when you omit them, and treat an
omitted `expectedContext` as "expect empty". Both default new hybrid signatures to `Ed25519+ML-DSA-65-v2`.

## Which should I use?

| You | Use |
|---|---|
| Write a browser, edge or Node.js service | quantum-safe-ts |
| Write a Python service, or need HQC or BIKE, or the hybrid X.509 builder | quantum-safe-py |
| Have both, and exchange keys, ciphertexts or signatures | Both: the formats above cross unchanged |
| Sign firmware with LMS | Node.js: `LmsSigner`; Python: the `[lms]` extra. Verify anywhere |
