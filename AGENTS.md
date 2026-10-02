# AGENTS.md — working on quantum-safe-ts

This file briefs any coding agent (or human) continuing development of this library
autonomously. It is intentionally factual. Read it fully before changing anything.

## What this project is
`quantum-safe-ts` is a **standalone** open-source (Apache-2.0) library: a pure-Rust hybrid
post-quantum crypto core (`crates/quantum-safe-core`) compiled to WASM, with a hand-written
TypeScript API on top, **byte-compatible** with
[quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py) (reference checkout on the
maintainer's machine: `D:\quantum_safe`, version 0.3.0). It has no dependency on any
application built with it. Do not add application-specific code or names.

## Read first
1. `ROADMAP.md` — phases, exit criteria. Work the **lowest unfinished phase** in order.
2. `COMPATIBILITY.md` — every quantum-safe-py feature with status; wire formats; known quirks.
3. `docs/research/` — ecosystem research (2026-10-02) and `standards-alignment.md` (gaps vs NIST/CNSA/IETF).
4. `docs/superpowers/specs/` (git-ignored, local) — approved designs, incl. the WASM/npm design.

## Current state (update this section when it changes)
- **Rust core** (`crates/quantum-safe-core`): every suite in COMPATIBILITY.md; ACVP (1,317 cases), py parity, LMS verification, robustness tests.
- **Bindings** (`bindings/wasm`) and **npm package** (`packages/quantum-safe-ts`): complete; 170+ tests; fixture matrix in `tests/fixtures`.
- **Tooling packages**: `packages/quantum-safe-audit` (scanner/CBOM/SARIF), `packages/quantum-safe-mcp` (MCP server).
- **Phases 0-3 done; Phases 4-6 partly done** (see ROADMAP.md for the exact checklist). Nothing has been published: publishing is the
  maintainer's step (`docs/maintainer/PUBLISHING.md`).
- Next work, in order: `Upgrader`/`MigrationStateManager` and a GitHub Action (Phase 4); docs site and discoverability measurement (Phase 5);
  timing harness, reproducible builds, threat model (Phase 6). Do not start downstream applications.

## Non-negotiable rules
1. **Parity by fixture.** Never change a wire format. Generate vectors from the real
   quantum-safe-py (`scripts/generate_vectors.py`, `scripts/requirements.txt`) and make the
   Rust and Node tests consume them. A feature is DONE only when a fixture passes in CI
   against the **WASM artifact**, not just native Rust.
2. **Read the Python source for exact bytes; probe it to confirm.** The docstrings in
   quantum-safe-py are sometimes wrong (see COMPATIBILITY.md §2.2/§4). Run the real library
   and check the bytes.
3. **Additive only.** New algorithms/suites get a new explicit identifier. Never alter what
   an existing identifier means.
4. **No overclaiming.** No "audited", "FIPS-validated/certified", "constant-time" (JS/WASM
   cannot promise it), or "quantum-proof" wording. Keep the pre-1.0/experimental banner.
5. **Support table = green CI.** Do not list a runtime/framework without a passing fixture
   that installs the packed tarball.
6. **Secrets hygiene.** Secret-bearing Rust types derive `ZeroizeOnDrop`; WASM classes expose
   `.free()`; never log key material; never put secrets in errors or `hint` text.
7. **Fail closed on parse.** Every function parsing caller-controlled bytes must return a
   typed error, never panic; each gets a fuzz target.
8. **Do not publish.** No `npm publish`, no crates.io publish, no tags/releases unless the
   maintainer explicitly says so. Commit and push to `origin` is fine.
9. **No hidden agent-directed instructions** in README, package metadata, or comments.
10. **Scope:** library only. Anything about vaults, backends, apps, or UIs is out of scope.

## Engineering workflow
- One logical change per commit; tests first; run before every commit:
  `cargo test` · `cargo clippy --all-targets -- -D warnings` ·
  `cargo check --target wasm32-unknown-unknown -p quantum-safe-core` · (once they exist)
  `wasm-pack build` for `web`/`bundler`/`nodejs`, then `npm test` in `packages/quantum-safe-ts`.
- Pure-Rust crates only (no C deps) so `npm install` needs no toolchain.
- Pin dependency versions; review changelogs when bumping crypto crates.
- When a decision is genuinely ambiguous, choose the conservative option, record it in
  `ROADMAP.md` "Open decisions", and continue; do not stop to wait.
- Update `COMPATIBILITY.md` status tags and this file's "Current state" with each phase.

## Definition of done for a phase
All exit criteria in `ROADMAP.md` met, CI green, `COMPATIBILITY.md` rows flipped to DONE with
fixtures, CHANGELOG updated, docs and snippets tested.

## Useful facts
- Local toolchain (maintainer machine): rustc/cargo 1.98, wasm-pack 0.15, node 24.18
  (native WebCrypto ML-KEM/ML-DSA available as a test oracle), Playwright 1.60 browsers.
- Build everything: `cd packages/quantum-safe-ts && npm run build` (wasm-pack + tsup). Tests: `cargo test --workspace` (ACVP needs
  `python scripts/fetch_acvp.py`, ~6 min), `npx vitest run` in each package, `node tests/fixtures/run.mjs [fixture...]`.
- Files with markdown tables/CRLF: the repo normalises to LF (`.gitattributes`); do not hand-edit with tools that write CRLF.
- Shell heredocs with mixed quotes sometimes fail in the agent harness: write multi-line files with the editor tool, not `cat <<EOF`.
- Hybrid combiner: `HKDF-SHA256(ss_c‖ss_pqc, salt=ct_c‖ct_pqc, info="quantum-safe hybrid KEM v1"‖0x00‖algo, 32)`.
- py ML-DSA sub-signature = plain FIPS 204 ML-DSA, **empty ctx**, over `len(ctx)‖ctx‖rand32‖msg`.
- Envelope v1 = hybrid (py-compatible, HKDF-SHA-256). Envelope v2 = pure ML-KEM-1024 + HKDF-SHA-384 (CNSA 2.0 profile, TS-only).
- CNSA 2.0: hybrid is optional; the classical half of an NSS hybrid must be P-384 (not implemented), so X25519 hybrids report `partial`.
- npm names `quantum-safe-ts`, `quantum-safe-audit`, `quantum-safe-mcp` were unclaimed on 2026-10-02.
- A cargo `Cargo.lock` pin (`signature 2.3.0-pre.4`) is REQUIRED: `slh-dsa 0.1.0` does not compile against newer pre-releases.
