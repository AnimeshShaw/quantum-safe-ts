# Changelog

All notable changes are documented here. The project follows semantic versioning once 1.0 is reached; until then minor versions may
add capability and, with notice, change behaviour that has not been released. **Wire formats are never changed**: new capability arrives
as a new, explicitly identified algorithm suite.

## [Unreleased]

- The benchmark and timing-leakage scripts (`bench/`) and the raw results of the last run (`results/`) are now in the repository, with a README that states what they do and do not show. The README previously said they were published and reproducible from the repository, but the files were not committed.

## [0.1.1] - 2026-10-05

Documentation and metadata only; no code or wire-format change.

- Status and disclaimer text removed from the READMEs, the documentation site, SECURITY.md, the llms files and the MCP and scanner output; one statement about timing side channels remains, in the security guide.
- The GitHub Action's description is shorter (a requirement for listing it on the GitHub Marketplace) and its default audit-tool version is 0.1.1.

## [0.1.0] - 2026-10-05

The first release: `quantum-safe-ts`, `quantum-safe-audit`, `quantum-safe-mcp` and the `pqc-audit` and `pqc-mcp` aliases, all at 0.1.0, published to npm with provenance.

### Changed
- **Planned change, announced here: the default hybrid signature suite (`HybridSign()` and the `easy` layer) moves from `Ed25519+ML-DSA-65` to `Ed25519+ML-DSA-65-v2` in the next minor release**, in step with quantum-safe-py 0.4.0. New signatures from the new default will not verify on quantum-safe-py 0.3.0 or earlier. Choose explicitly today if you want a particular format; explicit choices never change. See ROADMAP.md.
- The documentation says what is and is not a standard signature: the default format and `-v2` are not standard FIPS 204 signatures over your message (`-v2` can be verified by a standard library only by rebuilding the wrapped message `M2` and passing the context `quantum-safe-sig-v2`); `StandardJwt` is the interoperable path today. The Python interop guide and MCP knowledge base now pair with quantum-safe-py 0.3.2 or later, and a docs test keeps the old wording out.
- **CNSA 2.0 wording corrected against the primary source.** The text said the classical half of a CNSA 2.0 hybrid "must be P-384". NSA's CNSA 2.0 FAQ (December 2024, Ver. 2.1) does not say that: it says hybrid products are not required and that a hybrid should not be used on NSS mission systems except for exceptions NSA specifically recommends (it names IKEv2, which keeps CNSA 1.0 key establishment fortified by ML-KEM-1024). The verdicts are unchanged (every hybrid is `partial`, pure `ML-KEM-1024` / `ML-DSA-87` are compliant); the explanations in `cnsa2` results, the MCP knowledge, the guides and the LLM docs now say what the FAQ says.
- Documentation no longer says quantum-safe-py cannot read envelope v2, the `-v2` signatures or `StandardJwt` tokens: quantum-safe-py 0.3.1 and 0.3.2 (released on PyPI and GitHub) read and write them, byte for byte; 0.3.2 or later is the version to pair with. quantum-safe-py 0.3.0 cannot. Private `AKP` JWKs (RFC 9964's `priv` is a seed) remain TypeScript-only, because liboqs cannot derive a key pair from a seed. The Python interop guide gains the settings that must match across the libraries (context, hedging mode, AAD).

### Added
- **`pqc-mcp`**, a short alias of `quantum-safe-mcp` (same server), released after it.
- **`THIRD_PARTY_LICENSES.md`** in every npm package (the Rust crates compiled into the WebAssembly, 113 of them, with their licence texts; a statement for the packages that bundle nothing), generated from `cargo metadata` by `scripts/generate-third-party-licenses.mjs` and checked in CI; the pack smoke test checks that every tarball carries LICENSE, NOTICE and it.
- **Standard FIPS 204 ML-DSA interop test** against quantum-safe-py 0.3.2's `Sign.sign_raw()` / `Sign.verify_raw()` in both directions (ML-DSA-44/65/87; empty, short and 255-byte contexts): `tests/vectors/py_raw_fips204_vectors.json`, `tests/vectors/ts_raw_fips204_vectors.json`, `test/py-raw-fips204.test.ts`. The bare primitive is internal for now; a public function is on the roadmap.
- **`ROADMAP.md`**, the public roadmap.
- Interop vectors for the formats quantum-safe-py 0.3.1 added (re-checked against the released 0.3.2): `tests/vectors/py_v2_vectors.json` (made by the real Python library, `scripts/generate_py_v2_vectors.py`; verified by `test/py-v2-interop.test.ts`) and `tests/vectors/ts_v2_vectors.json` (made by this package, `scripts/gen_ts_v2_vectors.mjs`; verified by quantum-safe-py's `tests/interop` and by `scripts/verify_ts_vectors.py`, which skips them on an older Python). Envelope v2, all eight `-v2` identifiers and the three `StandardJwt` levels verify in both directions.
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
- **Assurance**: reproducible-build check (`scripts/repro-check.mjs`); CycloneDX SBOM and CBOM of the library
  (`scripts/generate-sboms.mjs`); pinned Rust toolchain.
- **`quantum-safe-mcp`**: read-only, offline, path-confined MCP server for coding agents (`mcpName` and `server.json` for the MCP Registry).
- **Signature format v2** (`ML-DSA-*-v2`, `Ed25519+ML-DSA-*-v2`, `P-256+ML-DSA-44/65-v2`): additive (quantum-safe-py 0.3.2 or later reads and writes it too). No prefix and no unsigned length byte; the ML-DSA half signs a wrapped message `M2` under the FIPS 204 native context `quantum-safe-sig-v2` (a standard FIPS 204 library can verify it only by rebuilding `M2`; it is not a standard signature over your message); algorithm and context are inside the signed bytes of both halves; one fixed-length encoding (raw low-S P-256); keys carry the `-v2` tag. Verified independently with noble, Node WebCrypto and `node:crypto`.
- **Streaming encryption** (`sealStream`/`openStream`, `StreamSealer`/`StreamOpener`; format v3, TypeScript-only): chunked AES-256-GCM with the STREAM nonce layout, one KEM encapsulation per stream, header and AAD bound into every chunk; truncation, reordering, duplication and extension are detected. Tested against an independent sender and receiver built from noble and `node:crypto`; fuzz target `fuzz_stream`.
- **Speed**: the WebAssembly is compiled with `opt-level = 3` (about 2.5 times faster ML-KEM and 1.7 times faster ML-DSA than the size-optimised build) at about 1.30 MB (421 KB gzipped) instead of 0.86 MB (292 KB).
- **Evidence**: bidirectional parity with the real quantum-safe-py (58 checks + 70 WASM tests); 1,317 NIST ACVP cases; RFC 8554 vectors and
  13 independent LMS signatures; differential tests against `@noble/post-quantum` and Node WebCrypto; cargo-fuzz targets and mutation fuzzing;
  runtime/framework fixture matrix against the packed tarball.
- `llms.txt`, `llms-full.txt` (executed snippets), `SECURITY.md`, `COMPATIBILITY.md`, and a standards-alignment page on the documentation site.

### Fixed after internal reviews
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
  helper (0.3.0) reported `X25519+ML-KEM-1024` compliant, although NSA's CNSA 2.0 FAQ does not call any hybrid compliant (quantum-safe-py 0.3.1 now reports hybrids `partial`).
- quantum-safe-py's `Upgrader` documents `backward_compat=True` (old classical senders can still use an upgraded key), but its code packs the key
  as `u16 length || classical || pqc`, which a classical-only sender cannot use; `UpgradeResult.notes` here says so.
- The `quantum-safe-audit` command was renamed from `qs-audit` to `quantum-safe-audit` so it cannot shadow quantum-safe-py's tool on one PATH.
- Found by the timing screen's own controls: a first design appeared to show a fixed-versus-random difference that was an artefact (a lazily created key object
  inside the timed region, then cache locality); the final design removes both, and a public-key-only calibration explains the small residual decapsulation effect.
- Upstream `ml-dsa` `from_expanded` can panic on malformed keys; this library validates the packed secret-key regions first.
- Found by the fixture matrix and fixed before release: Node entry broke under Next.js server bundling (now embedded WASM); `using`
  declarations failed to typecheck against the published types (now real `Symbol.dispose`); bundlers emitted an unused second copy of the WASM
  (glue patched); consumers without DOM typings could not compile the `.d.ts` (loosened `InitSource`).
