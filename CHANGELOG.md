# Changelog

All notable changes are documented here. The project follows semantic versioning. **Wire formats are never changed**: new capability arrives
as a new, explicitly identified algorithm suite.

## [Unreleased]

### Changed

- README: release and alias badges, a performance section linking the benchmark data attached to the 1.0.0 release. The M8ven score badge.

### Dependencies

- Build and test tooling: tsup 9.0.0, vitest 5.0.5, @types/node 26.6.5, typedoc-plugin-markdown 4.14.0, the codeql-action upload-sarif step 4.39.0. Rust: sha2 0.11.1, serde_json 1.0.154 (also in the fuzz crate). None changes the published behaviour.
- `context7.json`: a plain one-line description.

### Fixed

- `LmsSigner`: a failed directory sync now stops the signing step on every platform except Windows, so an index is never used before it is durable.
- `rewrapDirectory`: the "destination inside the source" and "destination is the source" checks ignore letter case on Windows.
- CI: the parity job installs quantum-safe-py 1.0.0 (it was 0.3.0), and a missing format in the installed quantum-safe-py fails the run instead of being skipped.
- Compiled Python files are no longer tracked.
- CI: quantum-safe-py's own interop tests (X-Wing, streaming, COSE, seed keys, re-wrap) now run in the parity job on vectors generated in this repository on every run; a skipped test fails the job.
- `scripts/generate_migrate_vectors.py` verifies with the context the message was signed with.

## [1.0.0] - 2026-10-20

### Security

- **Linear-time base64url padding removal.** `toBase64Url` / `fromBase64Url` stripped padding with `/=+$/`, which is quadratic on a long run of `=` followed by another character (about 22 s for 300,000 of them). Input from JWTs, key files and the network could be used to stall a process. Behaviour is otherwise unchanged; a test pins both the results and the timing. Reported by CodeQL (`js/polynomial-redos`).
- **`qs-audit` no longer skips code after a closing script tag with attributes.** In Vue/Svelte/HTML files `</script >` or `</script foo>` was not recognised as the end of a block, so what followed was not scanned. It is now, and the closing-tag match is linear. Reported by CodeQL (`js/bad-tag-filter`).
- **Exclude globs match in linear time.** `globToRegExp` collapses repeated wildcards and escapes every other character literally, so a hostile pattern in a policy file cannot cause catastrophic backtracking.

### Added

- **Large messages and streams are about five times faster on Node.js.** `Envelope.seal` / `open` / `rewrap` payloads of 16 KiB or more and `sealStream` / `openStream` / `sealBytes` / `openBytes` with chunks of 16 KiB or more use Node's native AES-256-GCM (1 MiB message: 121 → 521 MiB/s to seal, 129 → 757 MiB/s to open; 64 MiB stream: 104 → 603 MiB/s to seal, 115 → 951 MiB/s to open). The output is byte-for-byte what the WebAssembly cipher produces, errors are the core's own, and the core still makes every check and keeps the nonce counter; only the one-time message key crosses into JavaScript for the call and is wiped. Other runtimes keep the WebAssembly path. New core calls: `envelopeSealPlan`, `envelopeOpenPlan` and `StreamCipher.prepareSeal` / `prepareOpen` / `commit` / `abort` / `takeKey`.
- **COSE_Sign1 and AKP COSE keys for ML-DSA** (`cose.sign1`, `cose.verify1`, `cose.inspectSign1`, `cose.sigStructure`, `cose.encodeKey`, `cose.encodePrivateKey`, `cose.decodeKey`, `cose.keyPairFromCoseKey`): the COSE half of RFC 9964. Checked against the RFC's own Appendix A examples for ML-DSA-44/65/87 (signatures verify, signed bytes reproduced exactly, the all-zero seed derives the RFC public key) and against quantum-safe-py 1.0.0 in both directions. Strict parser: protected algorithm required, `crit` refused, minimal CBOR, unique labels, no trailing bytes. Detached payloads, external AAD, tagged and untagged. New guide: COSE_Sign1.
- **`LmsSigner`: LMS signing in Node.js with write-ahead durable state** (`import { LmsSigner } from 'quantum-safe-ts/lms-signer'`). One LMS tree (an HSS key with one level), SHA-256 with 32-byte hashes, height 5, 10, 15 or 20, Winternitz 1, 2, 4 or 8. The index of the one-time key is made durable (temporary file, `fsync`, rename, directory `fsync`, under a lock file) before a signature exists, so a crash can waste an index and never reuse one; any problem with the state, a lock held elsewhere or an exhausted key makes it refuse; a signature is checked against the tree's root before it is returned. Several processes on one host may share a directory (tested with concurrent child processes). The seed is encrypted at rest (AES-256-GCM under a passphrase-derived scrypt key or a 32-byte key you supply; `{ unprotected: true }` must be asked for) and the counter carries an HMAC keyed from the seed, so a state file edited without the key is refused. It refuses to load in browsers and Workers. Signatures verify with `Lms.verify` and with quantum-safe-py's pyhsslms-based verifier for every Winternitz parameter (`scripts/gen_lms_signer_vectors.mjs`, `tests/vectors/ts_lms_signer_vectors.json`). New guide: LMS signing. Not provided: XMSS, multi-level HSS signing, height 25, the 192-bit and SHAKE parameter sets.
- **P-384 hybrids.** `P-384+ML-KEM-1024` and `P-384+ML-DSA-87` with its `-v2` form, for estates that hold CNSA 1.0 P-384 keys, in the Rust core (`p384` crate, RustCrypto), the WebAssembly and the TypeScript types. Same conventions as the P-256 hybrids with the curve's sizes (public key SEC1 point 97 B or raw `x||y` 96 B, PKCS#8 PEM secret, whole 48-byte ECDH output, ECDSA SHA-384, `-v2` classical half raw `r||s` 96 B low-S); ML-KEM-1024 and ML-DSA-87 are the only levels paired with P-384. `cnsa2.CNSA2_HYBRID_CLASSICAL` is `['X25519', 'P-384']` and `cnsa2.hybridKem('P-384')` / `cnsa2.hybridSign({ classical: 'P-384' })` build them (`hybridKem` previously ignored its argument). Read and written by quantum-safe-py 1.0.0, checked with shared vectors in both directions (suite, `-v2`, streaming and re-wrap vectors). `SuiteInfo.pyCompatible` is `false` for these suites, as for the other 1.0.0 additions: quantum-safe-py 0.3.x does not read them.
- **Envelope re-wrap.** `Envelope.rewrap(sealed, oldSecretKey, newPublicKey, { expectedAad, aad })` opens a message under the old key and seals it to the new one, keeping the AAD. `rewrapDirectory` from the new Node.js subpath `quantum-safe-ts/rewrap` applies it to a directory: never destructive by default, resumable and idempotent, every result verified when `newSecretKey` is given, one failure does not stop the run; the report has `toJSON()` and `toCbom()` (CycloneDX 1.6). Same operation and report shape as quantum-safe-py 1.0.0 (`qs-migrate rewrap`), checked in both directions with shared vectors (`rewrap-py-interop.test.ts`, `scripts/gen_rewrap_vectors.mjs`, `scripts/generate_py_rewrap_vectors.py`).
- **`QS_HEDGED_IGNORED` warning.** `hedged: false` together with a `-v2` suite was always accepted and ignored (the `-v2` formats have no unhedged mode); it now emits this developer warning, once per call site, silenceable like the others. Behaviour is unchanged. quantum-safe-py raises `ValueError` for the combination; TypeScript keeps its lenient behaviour so nothing breaks between versions, and plans an error at the next breaking release.
- **Seed keys shared with quantum-safe-py 1.0.0**: private RFC 9964 JWKs (`StandardJwt.generateKeyPair`, `StandardJwt.sign` with a private JWK) and private COSE keys (`cose.encodePrivateKey`, `cose.keyPairFromCoseKey`) interoperate with Python's new optional `cryptography` backend in both directions. A 32-byte seed made in either library derives the same public key and signs in the other. Checked against RFC 9964 Appendix A (all-zero seed) and with committed vectors both ways (`private-keys-py-interop.test.ts`; generators `scripts/gen_private_key_vectors.mjs`, `scripts/generate_py_private_vectors.py`). No code change was needed; documentation updated.
- **Developer warnings for omitted `expectedContext` / `expectedAad`** (decision D4; matches quantum-safe-py 1.0.0). `verify()` without `expectedContext` already meant "expect an empty context"; a message that carries a context is still rejected with the opaque `VerificationError`, and now a `QS_CONTEXT_OMITTED` warning says why. `Envelope.open()` / `easy.decrypt()` without `expectedAad` still accept any AAD and now emit `QS_AAD_OMITTED` when the message carries one. Once per call site, never containing the value, through `process.emitWarning` (type `QuantumSafeWarning`) or `console.warn`; `warnings.silence()`, `warnings.unsilence()` and `warnings.onWarning()` control delivery. New guide: Context and AAD.
- **`Sign.signRaw()` / `Sign.verifyRaw()`** (aliases `signStandard` / `verifyStandard`): standard FIPS 204 `ML-DSA.Sign` / `Verify` over your own bytes with a native context (at most 255 bytes), for ML-DSA-44, 65 and 87. Tested against quantum-safe-py's `Sign.sign_raw` / `verify_raw` in both directions. Keys are `StandardKeyPair` (a 32-byte seed and the FIPS 204 public key): `Sign.generateStandardKeyPair()`, `Sign.standardKeyPairFromSeed()`, `exportSeed()`, `free()`. A secret key that quantum-safe-py generated through liboqs is an expanded key from which no seed can be recovered, so TypeScript can verify its signatures but cannot sign with it; documented in the guides.

### Changed

- **`quantum-safe-audit` and `quantum-safe-mcp` 0.1.3** (with the `pqc-audit` and `pqc-mcp` aliases and the Action default): `recommend_suite` follows quantum-safe-ts 1.0.0 and quantum-safe-py 1.0.0 (default signature `Ed25519+ML-DSA-65-v2`, X-Wing and RFC 9964 readable by quantum-safe-py 1.0.0, `Sign.signRaw` for standard FIPS 204 signatures) and has two new use cases: `firmware-signing` (`LmsSigner` with `protection`, `Lms.verify`) and `migrate-stored-data` (`Envelope.rewrap`, `rewrapDirectory`). The scanner's replacement hints name the `-v2` default suite and the P-384 hybrid.
- **WebAssembly size budget raised for the P-384 suites.** The module is 1.49 MB raw / 456 KiB gzipped (was 1.30 MB / 411 KiB) and the default entry's JavaScript about 680 KiB gzipped (was about 600 KiB). `quantum-safe-ts/slim` is unchanged in size. The budgets in `scripts/check-size.mjs` were raised deliberately.
- **Streaming envelopes and X-Wing are no longer TypeScript-only**: quantum-safe-py 1.0.0 reads and writes the same bytes (`quantum_safe.protocols.stream`, `quantum_safe.kem.xwing`). Interop vectors are checked in both directions (`stream-py-interop.test.ts`, `xwing-py-interop.test.ts`; generators `scripts/gen_stream_vectors.mjs`, `scripts/generate_py_stream_vectors.py`). Documentation updated; no code or format change.
- **The default hybrid signature suite is now `Ed25519+ML-DSA-65-v2`** (`DEFAULT_HYBRID_SIGNATURE`, `new HybridSign()`, the `easy` layer), in step with quantum-safe-py 1.0.0. Signatures from the new default verify on quantum-safe-py 0.3.1+ (and not on 0.3.0 or earlier). The original format `Ed25519+ML-DSA-65` is unchanged and still works when named (`ORIGINAL_HYBRID_SIGNATURE`); keys carry their format and a signer refuses a key of the other format. `new HybridSign(undefined, { hedged: false })` selects the original format because `-v2` is always hedged. `Sign` (single ML-DSA) keeps `ML-DSA-65`.
- `cnsa2.CNSA2_HYBRID_CLASSICAL` lists `X25519` and `P-384`, the same as quantum-safe-py (`P-384` was listed before it was implemented; it is now). `cnsa2.hybridKem()` accepts only a listed partner (a type error in TypeScript, `UnsupportedAlgorithmError` at runtime).

### Fixed

- **`FileMigrationStore` keys are limited to 100 bytes (was 120).** The file name is the hex of the key plus the temporary-file and lock suffixes, so a key of 101 to 120 bytes could not be written on filesystems with a 255-character name limit; it failed late with an operating-system error. The limit is now explicit and the longest allowed key is tested through `set` and `compareAndSet`.

- **`FileMigrationStore` stale-lock breaking re-checks what it moved**: a lock that replaced the stale one between the age check and the rename is put back instead of removed, so a live holder is not turned into a "lock lost" failure by a concurrent waiter. Writes were never unsafe (ownership is checked before every rename).
- **`quantum-safe-mcp`: `audit_path` no longer honours `qs-audit-ignore` comments**. The scanned repository is untrusted, and a comment in its own code could hide a finding from the agent.
- **`quantum-safe-audit` command line:** an unknown option is a usage error (`--cnsa` used to swallow the next path); an unwritable `--output` or a policy of the wrong shape exits 2 instead of 1 (which means "findings"); a `package.json` that is not valid JSON makes the scan incomplete instead of passing; the help names every policy key and says an incomplete scan wins over findings.
- **`rewrapDirectory`:** refuses a destination inside the source, keeps file permissions on an in-place rewrite, and its CycloneDX report treats a hybrid or ML-KEM source as post-quantum with its real security level.
- **`openStream`** closes its source when the consumer stops early or a chunk fails; **`fromBase64Url`** reports a length of 1 mod 4 as `InvalidArgumentError` (it leaked a `DOMException`); **`FileMigrationStore.keys()`** lists only the files it wrote; **`importHistory`** enforces the 10,000-record limit that reading applies; **`LmsSigner`** accepts `scryptLog2N` 14 to 18 (19 to 22 could never run within the memory limit and failed after the tree was built) and retries a lock that Windows reports as EPERM while another process is deleting it.
- The WebAssembly `SealPlan` no longer traps when `finish()` is called twice.

### Documentation

- The README footer, ROADMAP and CHANGELOG no longer carry the review-request material; `REVIEW_WANTED.md` is removed.
- The README is a short front page (what it provides, install, one example, packages, links); the detail is on the documentation site. The "Which library should I use?" page is now "What quantum-safe-ts adds".
- The benchmark harness times quantum-safe-ts only; the comparison runs and the Python baseline script are no longer part of the repository, and the comparison page no longer carries a speed row.

### Dependencies

- Patched `vite` (6.4.4) and `esbuild` (0.25.12 for the website, 0.28.2 for the packages) through `overrides`, closing the Dependabot alerts; `scripts/requirements.txt` pins `cryptography==50.0.2` for the interop scripts.

## [0.1.2] - 2026-10-06

No code or wire-format change. Packages are now published with npm trusted publishing: the GitHub Actions workflow identity is the credential and there is no stored npm token; every release keeps its npm provenance statement.

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
