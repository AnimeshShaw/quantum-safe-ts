# Changelog

All notable changes are documented here. The project follows semantic versioning once 1.0 is reached; until then minor versions may
add capability and, with notice, change behaviour that has not been released. **Wire formats are never changed**: new capability arrives
as a new, explicitly identified algorithm suite.

## [Unreleased] (0.1.0, not yet published to npm)

### Added
- **Rust core** (`quantum-safe-core`): hybrid KEMs `X25519+ML-KEM-512/768/1024` and `P-256+ML-KEM-512/768`, pure ML-KEM, **X-Wing**;
  ML-DSA-44/65/87, hybrid `Ed25519+ML-DSA-*` and `P-256+ML-DSA-44/65`, all 12 SLH-DSA parameter sets; AES-256-GCM envelopes (v1,
  quantum-safe-py compatible) and a CNSA 2.0 envelope (v2: pure ML-KEM-1024, HKDF-SHA-384); Argon2id; key serialization (CBOR, PEM,
  JWK, fingerprints, bundles); `SignedMessage` and signature blobs; standards-mode ML-DSA (FIPS 204 native context, seed keys); **LMS/HSS
  verification** (RFC 8554, SHA-256).
- **WASM bindings and TypeScript package** `quantum-safe-ts`: typed API with `QuantumSafeError` hierarchy (stable `code` and `hint`),
  `using`-compatible memory management, `HybridKEM`/`KEM`, `Envelope`, `Sign`/`HybridSign`, `JWTSigner`/`JWTVerifier` (quantum-safe-py
  compatible) and `StandardJwt` (RFC 9964), `deriveMasterKey`, `Lms`, `cnsa2`, key classes. ESM + CJS + types; zero-config inline WASM.
- **`quantum-safe-audit`**: AST-based JS/TS scanner with 18 rules, SARIF 2.1.0 and CycloneDX 1.6 CBOM output, policy file, suppressions.
- **Migration helpers**: `Upgrader` (classical -> hybrid key upgrade, strip classical half, needs-upgrade check) and
  `MigrationStateManager` (validated transitions, history, progress) over a user-supplied async store.
- **`quantum-safe-mcp`**: read-only, offline, path-confined MCP server for coding agents.
- **Evidence**: bidirectional parity with the real quantum-safe-py (52 checks + 70 WASM tests); 1,317 NIST ACVP cases; RFC 8554 vectors and
  13 independent LMS signatures; differential tests against `@noble/post-quantum` and Node WebCrypto; cargo-fuzz targets and mutation fuzzing;
  runtime/framework fixture matrix against the packed tarball.
- `llms.txt`, `llms-full.txt` (executed snippets), `AGENTS.md`, `SECURITY.md`, `COMPATIBILITY.md`, `ROADMAP.md`, standards-alignment analysis.

### Findings recorded while building (see `docs/research/standards-alignment.md` and `docs/maintainer/UPSTREAM_QUANTUM_SAFE_PY.md`)
- quantum-safe-py's hybrid combiner and ML-DSA context are custom constructions (not X-Wing/RFC 10024/FIPS 204 context), and its CNSA 2.0
  helper reports `X25519+ML-KEM-1024` compliant although the NSA FAQ requires a CNSA 1.0 (P-384) classical half.
- Upstream `ml-dsa` `from_expanded` can panic on malformed keys; this library validates the packed secret-key regions first.
- Found by the fixture matrix and fixed before release: Node entry broke under Next.js server bundling (now embedded WASM); `using`
  declarations failed to typecheck against the published types (now real `Symbol.dispose`); bundlers emitted an unused second copy of the WASM
  (glue patched); consumers without DOM typings could not compile the `.d.ts` (loosened `InitSource`).
