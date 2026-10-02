# quantum-safe-ts Roadmap

A standalone, Apache-2.0, **library-only** roadmap. Nothing here depends on any product built on top of the library. Companion documents:
[COMPATIBILITY.md](COMPATIBILITY.md) (what matches quantum-safe-py), [docs/research/](docs/research) (ecosystem research and
[standards alignment](docs/research/standards-alignment.md)), [docs/maintainer/](docs/maintainer) (publishing and upstream proposals).

**Principles**
1. **Parity is proven, not assumed.** A feature is "compatible" only when a committed fixture passes in CI against the real WASM artifact.
2. **Support claims are tested.** A runtime or framework appears in the support table only when a fixture that installs the packed tarball is green.
3. **Wire formats are frozen once released.** New capability arrives as a new, explicitly identified suite; never a silent change.
4. **Honesty over marketing.** No "audited", "FIPS validated", "CNSA compliant" or "constant-time" claims that are not true.
5. **Primitives are commodities; the production layer is the product.**

Status key: ✅ done and verified in CI · 🟡 partly done · ⬜ not started · ⏳ waiting on something outside this repository

---

## Phase 0: Hygiene and foundations ✅
Clippy/rustfmt clean, CI, `SECURITY.md`, `NOTICE`, issue/PR templates, `Cargo.lock` tracked (a pinned pre-release `signature` is required by `slh-dsa`).

## Phase 1: v0.1.0 "Envelope, shipped" ✅ (publish step is yours)
- ✅ Zeroization, WASM bindings with deterministic `.free()` and `using`, structured error kinds, hand-written typed facade, full JSDoc.
- ✅ tsup ESM + CJS + `.d.ts`; **zero-config inline-WASM** entry; Node entry that also survives framework server bundling (found and fixed by the Next.js fixture).
- ✅ Parity through the WASM artifact; cargo-fuzz targets (6) plus deterministic mutation tests; CI on GitHub (all green except where noted in the repo's Actions tab).
- ✅ **Fixture matrix** (packed tarball): Node 20/22/24 ESM+CJS, strict TS consumers, esbuild, webpack 5, Vite+React, Next.js (Turbopack and webpack), SvelteKit, Cloudflare Workers (workerd), Deno 2, Bun, Chrome MV3; Chromium/Firefox/WebKit for the browser ones.
- ✅ `llms.txt`, `llms-full.txt` (6 executed snippets), `AGENTS.md`.
- ⏳ `npm publish` (see `docs/maintainer/PUBLISHING.md`).

## Phase 2: v0.2.0 "Keys, formats, strengths" ✅
Key CBOR/PEM/JWK/fingerprints/bundles/migration state; pure KEM and ML-KEM-512/768/1024; hybrids with X25519 and P-256; **X-Wing**; `cnsa2` profile; ACVP KAT harness.

## Phase 3: v0.3.0 "Signatures and JWT" ✅
ML-DSA-44/65/87, `HybridSign` (Ed25519, P-256), all 12 SLH-DSA sets, exact py constructions, `SignedMessage` CBOR, JWT in quantum-safe-py mode and in **RFC 9964 standards mode**; ACVP sigGen/sigVer/keyGen; **bidirectional** parity (52 checks against the real quantum-safe-py).

> **Gate G1 reached: "ready to be consumed".** Envelope, KEM, signatures, keys, errors and JWT are stable enough for a downstream application to depend on. Downstream work is out of scope for this repository and starts only on your call. Note the standing caveat: **unaudited**.

## Phase 4: v0.4.0 "Audit and migration tooling" 🟡
- ✅ `quantum-safe-audit`: AST scanner (JS/TS/Vue/Svelte/Astro, `package.json`), 18 rules, migration hints, SARIF 2.1.0 and CycloneDX 1.6 CBOM **validated against the official schemas**, policy file, suppressions, CLI, labelled corpus, output sanitisation against prompt injection.
- ✅ LMS/HSS verification (RFC 8554), checked against the RFC and pyhsslms.
- 🟡 Differentiation check vs `cdxgen`/`cbom-scan`: positioning is verdicts + policy + fix hints, but a fresh head-to-head survey should precede any marketing claim.
- ⬜ `Upgrader` / `MigrationStateManager` (async store interface; distributed-lock caveat), GitHub Action wrapper.
- ⬜ Independent accuracy measurement of the scanner on third-party repositories (the committed corpus was written by the authors; it is a regression guard, not an accuracy claim).

## Phase 5: v0.5.0 "Agent and developer surface" 🟡
- ✅ `quantum-safe-mcp`: `audit_path`, `list_rules`, `explain_rule`, `recommend_suite`, `explain_error`; read-only, offline, path-confined, injection-tested, stdio e2e.
- ✅ Doc/code sync tests (error codes, algorithms) and executed documentation snippets.
- ⬜ Docs site (TypeDoc + framework), "Which library should I use?" page, per-framework example repos, Claude/Cursor templates.
- ⏳ Context7 / MCP-registry listings (yours; see `docs/maintainer/PUBLISHING.md`).
- ⬜ Discoverability measurement: periodically ask several agents "add post-quantum encryption to my TS app" and record what they recommend. A metric, not a promise.

## Phase 6: v0.6.0 "Assurance and hardening" 🟡
- ✅ Differential testing vs `@noble/post-quantum` and Node WebCrypto/OpenSSL (KEM, X-Wing, ML-DSA, SLH-DSA, HKDF-SHA-384, Argon2id, RFC 9964).
- ✅ cargo-fuzz bounded in CI; ≈1.2M executions per target with no findings in the first runs.
- ✅ Provenance-capable release workflow (manual), size budget, `cargo-deny`.
- ⬜ Timing-leakage harness on the WASM artifact (reported with its limits), reproducible-build check, SBOM + CBOM of the package itself, written threat model.
- ⬜ Optional native-accelerated provider (WebCrypto ML-KEM/ML-DSA) behind the same API, byte-identical or it does not ship.

## Phase 7: v0.7.0+ "Extended algorithms and targets" ⬜
- ⬜ XMSS; LMS signing only behind a documented durable-state interface (may never ship).
- ⏳ **FN-DSA** after FIPS 206 is final; **HQC** after its FIPS is final; never as "standard" earlier.
- ⬜ React Native (Hermes WebAssembly, RN ≥ 0.84) with a device/simulator fixture.
- ⬜ P-384 classical component for a CNSA-conformant hybrid; streaming/chunked envelope v3; standards-based X.509 for ML-DSA/ML-KEM; COSE serialization for RFC 9964.
- ⬜ Per-feature WASM builds (KEM-only, signatures-only) to cut the ~284 KB gzip WASM.

## Phase 8: v1.0.0 "Stable" ⏳
Independent third-party security review of the Rust core, bindings and facade; API freeze, semver and deprecation policy, LTS branch. The experimental banner is removed **only** if the review supports it. CMVP is not pursued by this project.

---

## Release gates

| Gate | Condition |
|---|---|
| Any release | CI green incl. parity + fixture matrix; CHANGELOG; COMPATIBILITY.md updated |
| 0.x → 0.(x+1) | All rows for that phase done with fixtures |
| G1 (end of Phase 3) | **Reached**; downstream use is your call |
| 1.0 | Independent review complete; no open High findings |

## Open decisions
1. **npm name:** `quantum-safe-ts` (unclaimed on 2026-10-02) vs a scope. *Recommendation: unscoped.*
2. **Default hybrid suite:** quantum-safe-py-compatible combiner stays the default (compatibility); X-Wing is the interoperable option. *Decided (yours): keep compat default, ship both.*
3. **Placeholder 0.0.x publish:** *Recommendation: skip it and publish the real 0.1.0* (see `docs/maintainer/PUBLISHING.md` §1).
4. **Upstream proposals to quantum-safe-py:** yours to make; ready-to-use text and test in `docs/maintainer/UPSTREAM_QUANTUM_SAFE_PY.md`.
5. **Scanner engine:** the TypeScript compiler API is used today; revisit (oxc/swc) if cold-start time or install size becomes a complaint.
