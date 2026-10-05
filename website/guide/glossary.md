# Glossary

Terms as this documentation uses them. Entries link to the page that explains them in context.

| Term | Meaning |
|---|---|
| **AAD** (associated data) | Data that is authenticated but not encrypted. In an envelope it is stored in clear and bound to the ciphertext; the opener states the value it expects (`expectedAad`). [Encryption](/guide/encryption) |
| **ACVP** | NIST's Automated Cryptographic Validation Protocol: known-answer test vectors. Passing them is evidence of correctness, not a validation. [Security](/guide/security) |
| **AEAD** | Authenticated encryption with associated data. Here: AES-256-GCM. |
| **AKP** | "Algorithm Key Pair": the JWK key type (`kty: "AKP"`) RFC 9964 uses for ML-DSA keys. [JWT](/guide/jwt) |
| **Algorithm binding** | Every key, sealed message and signed message names its algorithm and version, and readers check both. [Concepts](/guide/concepts#versions-and-algorithm-binding) |
| **Anonymous encryption** | Encryption to a public key that does not say who encrypted it. Envelopes and streams are anonymous; sign them if attribution matters. |
| **Argon2id** | A memory-hard password hash. `deriveMasterKey` uses 19 MiB, 2 passes, 1 lane. [Keys](/guide/keys#passwords) |
| **CBOM** | Cryptographic bill of materials: an inventory of the cryptography a system uses (CycloneDX 1.6). [Audit](/tools/audit) |
| **CBOR** | Concise Binary Object Representation: the binary format of keys, sealed messages and signed messages. |
| **CNSA 2.0** | NSA's Commercial National Security Algorithm Suite 2.0: ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512, LMS/XMSS. [CNSA 2.0](/guide/standards) |
| **Compare-and-set** | A write that succeeds only if the stored value is still what the writer last saw. Makes migration transitions safe across processes. [Migration](/guide/migration) |
| **Context** | A label (at most 255 bytes) that ties a signature to one purpose. The verifier states the one it expects (`expectedContext`). [Concepts](/guide/concepts#context-and-aad-the-verifier-says-what-it-expects) |
| **Decapsulation / encapsulation** | The two KEM operations: the sender encapsulates to a public key and gets a ciphertext and a shared secret; the key holder decapsulates the ciphertext to the same secret. [KEM](/guide/kem) |
| **Envelope** | A self-describing, authenticated, public-key encrypted message (`SealedMessage`). v1 for hybrid keys, v2 for pure `ML-KEM-1024`. [Encryption](/guide/encryption) |
| **FIPS 203 / 204 / 205** | The NIST standards for ML-KEM, ML-DSA and SLH-DSA. |
| **FIPS 140-3 / CMVP** | NIST's validation of cryptographic modules. This library is not validated. |
| **Hedged signing** | Signing with fresh randomness mixed in, which blunts some fault attacks. In the default format a verifier must match the signer's mode. [Concepts](/guide/concepts#hedged-signing-and-why-a-verifier-must-match-the-signer) |
| **HKDF** | HMAC-based key derivation (RFC 5869). SHA-256 for v1 envelopes and `deriveKey`, SHA-384 for v2 envelopes. |
| **Hybrid** | A classical algorithm and a post-quantum one used together so that an attacker must break both. [Concepts](/guide/concepts#why-hybrid) |
| **Implicit rejection** | ML-KEM's design: decapsulating a modified ciphertext returns a pseudo-random secret instead of an error. [KEM](/guide/kem#implicit-rejection-a-wrong-ciphertext-does-not-throw) |
| **JWK / JWKS** | JSON Web Key / a set of them. Public keys only are ever served. [JWT](/guide/jwt) |
| **KEM** | Key encapsulation mechanism. [KEM](/guide/kem) |
| **LMS / HSS / XMSS** | Stateful hash-based signature schemes (RFC 8554, SP 800-208). This library verifies LMS/HSS; it does not sign. [Signatures](/guide/signatures) |
| **M2** | The bytes signed in the `-v2` format: `len(algo) ‖ algo ‖ len(ctx) ‖ ctx ‖ message`. [Signatures](/guide/signatures) |
| **MCP** | Model Context Protocol: how a coding agent calls tools. [MCP server](/tools/mcp) |
| **Migration state** | `classical_only → hybrid_transition → pqc_preferred → pqc_only`: where a key is in its move to post-quantum. [Migration](/guide/migration) |
| **ML-KEM / ML-DSA / SLH-DSA** | The NIST post-quantum KEM (lattice), signature (lattice) and hash-based signature. |
| **NSS** | National Security Systems (US). |
| **Parity by fixture** | Proving two libraries agree by having each consume data produced by the real other one. [Interop](/guide/python-interop) |
| **PEM** | Text armour for keys: `-----BEGIN QUANTUM SAFE PUBLIC KEY-----`. |
| **Post-quantum (PQC)** | Cryptography believed to resist a large quantum computer. |
| **SARIF** | Static Analysis Results Interchange Format (2.1.0): how scanner results reach GitHub code scanning. [Action](/tools/github-action) |
| **Shared secret** | The secret both sides of a KEM end up with. Derive keys from it; never use it directly. `SecretBytes` / `SharedSecret`. |
| **STREAM** | A construction for chunked authenticated encryption (counter and last-chunk flag in the nonce). [Streaming](/guide/streaming) |
| **Typed error** | An error with a class, a stable `code` and a static `hint`. [Errors](/guide/errors) |
| **`-v2`** | The cleaner signature format: no prefix, native FIPS 204 context over a wrapped message `M2`, algorithm and context signed. Not a standard signature over your message. [Signatures](/guide/signatures#format-v2-v2) |
| **WebAssembly (WASM)** | The portable binary format the Rust core is compiled to. [Runtimes](/guide/runtimes) |
| **X-Wing** | A hybrid KEM (X25519 + ML-KEM-768) specified in `draft-connolly-cfrg-xwing-kem`, implemented by several libraries. [KEM](/guide/kem#about-x-wing) |
| **X25519 / Ed25519 / P-256** | The classical key exchange, signature and NIST-curve algorithms used as the classical half of hybrids. |
