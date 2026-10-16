# What quantum-safe-ts adds

quantum-safe-ts is a production layer for post-quantum cryptography in TypeScript and JavaScript: the primitives, and the formats, envelopes,
tokens, key lifecycle and migration tooling that a service needs around them. One typed API runs in Node.js, browsers, Deno, Bun and Workers,
and its bytes are the same as [quantum-safe-py](/guide/python-interop)'s.

## What you get

| Layer | What it provides |
|---|---|
| Primitives | ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (all 12 FIPS 205 sets), X-Wing, and hybrids with X25519, P-256 and Ed25519. A memory-safe Rust core compiled to WebAssembly. |
| Envelopes and formats | A versioned encrypted envelope (KEM + AES-256-GCM), streaming encryption for large data, signed messages, and key formats (CBOR, PEM, public-key JWK, fingerprints). Parsers are strict and fail closed. |
| Standards formats | RFC 9964 JOSE/JWT and COSE_Sign1 for ML-DSA, standard FIPS 204 signatures with a native context, X-Wing KEM. |
| Tokens | `JWTSigner` / `JWTVerifier` (quantum-safe-py compatible) and `StandardJwt` (any JOSE library can verify). |
| Key lifecycle | Serialisation, fingerprints, Argon2id master-key derivation, classical-to-hybrid key upgrade, a migration state machine with an audit trail, and cross-process-safe stores. |
| Hash-based signatures | LMS / HSS verification in every runtime; LMS signing in Node.js with write-ahead durable state. |
| Audit and compliance | A scanner for JavaScript and TypeScript with SARIF and CycloneDX CBOM output, a GitHub Action, an MCP server for coding agents, and a CNSA 2.0 parameter report. |
| Python interop | Keys, ciphertexts, signatures, tokens, streams, COSE and migration state are byte-compatible with quantum-safe-py 0.4.0, checked in CI against the real library in both directions. |
| Developer experience | Typed errors with stable codes and hints, a one-call `easy` layer, `llms.txt`, and documentation whose code blocks are executed by the test suite. |

## Reach for it when you need to

- encrypt a message to a public key, or sign data and verify it elsewhere;
- issue post-quantum JWTs, or tokens a standard JOSE library verifies;
- store and move keys in a defined, versioned format;
- keep a Python service and a TypeScript service on the same keys and ciphertexts;
- find classical cryptography in a JavaScript codebase, plan its removal and track the migration.

## Scope

- Implemented: ML-KEM, ML-DSA, SLH-DSA, X-Wing, hybrids, LMS (verification everywhere, signing in Node.js).
- Not implemented: Falcon / FN-DSA and HQC (their standards are in preparation), XMSS, multi-level HSS signing, TLS (platforms negotiate
  `X25519MLKEM768` themselves, RFC 10024).
- Runtime: the WebAssembly is about 455 KiB gzipped. The [runtimes page](/guide/runtimes) lists every tested environment and bundler.
