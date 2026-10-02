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
- **`easy` layer**: `generateEncryptionKeys`, `encrypt`, `decrypt`, `generateSigningKeys`, `sign`, `verify` with PEM-string keys and nothing to free;
  `verify` enforces the signing context. `KeyPair.fromKeys` assembles a pair from separately held keys.
- **Migration helpers**: `Upgrader` (X25519, Ed25519 and P-256 classical -> hybrid key upgrade, strip classical half, needs-upgrade check, describe) and
  `MigrationStateManager` (validated transitions, history, progress) over a user-supplied async store. Each key's history is one document written with a
  single compare-and-set, so transitions are atomic across processes and machines when the store's `compareAndSet` is atomic. `FileMigrationStore`
  (`quantum-safe-ts/file-store`, Node only) is a tested single-host implementation. `exportToPyStore` / `importFromPyStore` convert to and from
  quantum-safe-py's store layout, byte-identical to py's. Parity fixtures for the upgrader and the store come from the real quantum-safe-py.
- **GitHub Action** (`action.yml`) for `quantum-safe-audit`: SARIF upload, severity gate, CBOM, CNSA 2.0 option; inputs treated as data and tested against hostile values.
- **Documentation site** (`website/`, VitePress and TypeDoc), "Which library should I use?" page, per-package READMEs, CONTRIBUTING, SUPPORT, CODE_OF_CONDUCT,
  CITATION.cff, Dependabot, CODEOWNERS.
- **Assurance**: timing-leakage screen (`bench/leakage.mjs`) with null controls, a random-vs-random control, a public-key calibration and a harness check;
  pinned repeated benchmarks (`bench/run-matrix.mjs`); reproducible-build check (`scripts/repro-check.mjs`); CycloneDX SBOM and CBOM of the library
  (`scripts/generate-sboms.mjs`); pinned Rust toolchain.
- **`quantum-safe-mcp`**: read-only, offline, path-confined MCP server for coding agents.
- **Evidence**: bidirectional parity with the real quantum-safe-py (58 checks + 70 WASM tests); 1,317 NIST ACVP cases; RFC 8554 vectors and
  13 independent LMS signatures; differential tests against `@noble/post-quantum` and Node WebCrypto; cargo-fuzz targets and mutation fuzzing;
  runtime/framework fixture matrix against the packed tarball.
- `llms.txt`, `llms-full.txt` (executed snippets), `AGENTS.md`, `SECURITY.md`, `COMPATIBILITY.md`, `ROADMAP.md`, and a standards-alignment page on the documentation site.

### Fixed after internal blind reviews (AI-assisted reviewers with no project context; not a human audit)
- **Signature forgery on message suffixes (high).** The py-compatible signing input `len(ctx) || ctx || prefix || message` stores the prefix length in the unsigned signature blob, so a permissive
  verifier let anyone move bytes between prefix and message and obtain a valid signature on a suffix (demonstrated for ML-DSA and the hybrid). Verifiers now pin the prefix length to their hedging
  mode (32 hedged, 0 unhedged); the wire bytes are unchanged. Regression tests in `adversarial.test.ts`.
- Class `verify`/`isValid` now require the expected context (default empty) instead of trusting the context inside the message; `Envelope.open`/`easy.decrypt` accept `expectedAad`; `easy.verify` takes `hedged`.
- Untrusted CBOR is shape-checked before decoding (size cap now also on sealed messages; bounded entries and depth; no indefinite lengths, tags, duplicate keys or trailing bytes), closing a roughly 80x memory amplification.
- `Upgrader` verifies the new key pair (encapsulate/decapsulate or sign/verify) and refuses a classical public key that does not belong to the secret.
- `FileMigrationStore`: owner-token locks with a heartbeat, atomic stale-lock breaking, ownership re-check before each write, bounded read retries, private modes, key-length limit.
- JWT: a negative `expiresIn` is refused (it silently produced a token without `exp`); `requireExp` option; canonical signature spelling only; `hedged` option on `JWTVerifier`; claim failures say so in the message.
- Audit tool: `typescript` is now a real dependency (the scanner crashed from a clean install and, with TypeScript 7, reported a clean scan); incomplete scans (oversize or unreadable files, parse failures, zero files) exit 2 unless `--allow-incomplete`; `--no-config`; SARIF `invocations` report incompleteness. The Action no longer auto-loads the scanned tree's policy file.
- MCP server limits the characters and length of file names and error text it echoes.
- Packaging: stable `error.name` strings and a typed `QsErrorCode`, `QuantumSafeError.is()`, cross-realm `Uint8Array`/`ArrayBuffer` inputs, non-fatal `Symbol.dispose` shim, `esnext.disposable` reference in the emitted declarations, typed `.wasm` subpath, `engines.node >= 20`, source maps without embedded sources.
- Release workflow: build job has no secrets and checks CI for the commit; the publish job needs environment approval and publishes the one packed tarball. CI: `mcp` and packed-tarball jobs, pinned toolchain and wasm-pack, least-privilege permissions.
- Second review round (Rust core and loaders): `ktype` is required when loading a key CBOR (an absent one let secret bytes load as a "public" key); public keys are length-checked per algorithm in CBOR, PEM, JWK and `PublicKey.fromBytes`;
  JWKs must have `kty: "AKP"`; hybrid signature payloads must have exactly four entries; CBOR must use shortest-form integers and lengths; `FileMigrationStore` file names are hex (no case-folding collisions) and ownership is re-checked before every rename retry;
  CNSA 2.0 checks evaluate only algorithm names this library implements and report a hybrid signature as `partial`; verifiers copy shared buffers once before checking.
- Documentation corrections: "audited state machine" wording, anonymous-encryption and AAD limits, fuzzing and SP 800-227 claims, X-Wing status, browser WebCrypto status, size figures, timing table completeness.

### Findings recorded while building
- quantum-safe-py's hybrid combiner and ML-DSA context are custom constructions (not X-Wing/RFC 10024/FIPS 204 context), and its CNSA 2.0
  helper reports `X25519+ML-KEM-1024` compliant although the NSA FAQ requires a CNSA 1.0 (P-384) classical half.
- quantum-safe-py's `Upgrader` documents `backward_compat=True` (old classical senders can still use an upgraded key), but its code packs the key
  as `u16 length || classical || pqc`, which a classical-only sender cannot use; `UpgradeResult.notes` here says so.
- The `quantum-safe-audit` command was renamed from `qs-audit` to `quantum-safe-audit` so it cannot shadow quantum-safe-py's tool on one PATH.
- Found by the timing screen's own controls: a first design appeared to show a fixed-versus-random difference that was an artefact (a lazily created key object
  inside the timed region, then cache locality); the final design removes both, and a public-key-only calibration explains the small residual decapsulation effect.
- Upstream `ml-dsa` `from_expanded` can panic on malformed keys; this library validates the packed secret-key regions first.
- Found by the fixture matrix and fixed before release: Node entry broke under Next.js server bundling (now embedded WASM); `using`
  declarations failed to typecheck against the published types (now real `Symbol.dispose`); bundlers emitted an unused second copy of the WASM
  (glue patched); consumers without DOM typings could not compile the `.d.ts` (loosened `InitSource`).
