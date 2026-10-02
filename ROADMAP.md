# quantum-safe-ts Roadmap

A standalone, Apache-2.0, **library-only** roadmap. Nothing here depends on any product
built on top of the library. Companion docs: [COMPATIBILITY.md](COMPATIBILITY.md) (what
matches quantum-safe-py) and `docs/research/` (evidence and sources).

**Principles**
1. **Parity is proven, not assumed.** A feature is "compatible" only when a committed
   fixture passes in CI against the real WASM artifact.
2. **Support claims are tested.** A runtime or framework appears in the support table only
   when its CI fixture, installing the packed tarball, is green.
3. **Wire formats are frozen once released.** New capability arrives as a new, explicitly
   identified algorithm suite, never as a silent change to an existing one.
4. **Honesty over marketing.** No "audited", "FIPS validated", or "constant-time" claims
   that are not true. Disclose gaps the way quantum-safe-py does.
5. **Primitives are commodities; the production layer is the product.**

Effort sizes: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ 3–5 weeks of focused work.
These are planning estimates, not commitments.

---

## Phase 0 — Hygiene and foundations · S
- Install `clippy`/`rustfmt`, add CI skeleton (test, clippy `-D warnings`, wasm check).
- `SECURITY.md` + disclosure policy, `NOTICE`, honest status banner in README,
  issue/PR templates, `CODEOWNERS`.
- Decide and reserve the npm name (`quantum-safe-ts` is unclaimed as of 2026-10-02).
- Un-ignore `docs/research/` so research ships with the repo (done).

**Exit:** green CI on `master`; name decision recorded.

## Phase 1 — v0.1.0 "Envelope, shipped" · L
Finish the already-approved Plan B, plus the distribution guarantees.
1. `zeroize` hardening in the core crate (`SecretKey`, shared secrets, Argon2 output).
2. `bindings/wasm`: opaque classes, structured error `kind`, explicit `.free()`.
3. `packages/quantum-safe-ts`: hand-written typed facade, error class hierarchy with stable
   `code` + `hint`, input validation before WASM, full JSDoc, `Symbol.dispose` support.
4. Build: three `wasm-pack` targets **plus** a zero-config **inline-WASM** entry; tsup
   ESM+CJS+`.d.ts`; conditional `exports`. Measure bundle size and set a budget.
5. Parity: extended fixture (real ML-KEM-768 keypair + real py-sealed envelope) opened by
   the WASM build under Node/Vitest.
6. `fuzz/` (cargo-fuzz) for every byte-parsing entry point, bounded in CI.
7. **Runtime/framework fixture matrix** installing the packed tarball: Node 20/22/24,
   Deno, Bun, Cloudflare Workers (miniflare), Vite, webpack 5, Next.js (node + edge),
   SvelteKit, esbuild, Chromium/Firefox/WebKit (Playwright), MV3 extension (CSP
   `wasm-unsafe-eval`). Any red cell is removed from the support table, not hidden.
8. Day-one agent surface: `llms.txt`, `AGENTS.md`, README "Using with AI coding agents",
   every README snippet executed in CI.

**Exit:** `npm pack` tarball passes the whole matrix; py→ts envelope parity green; manual
`npm publish` of 0.1.0 with provenance when you decide.

## Phase 2 — v0.2.0 "Keys, formats, strengths" · M–L
- Key CBOR / PEM / JWK, fingerprints, `KeyPair` bundle, `MigrationState`, 10 MB cap,
  version floor/ceiling, detect-and-reject py's JSON fallback.
- Pure `KEM` + `SharedSecret.derive_key`; ML-KEM-512/768/1024; hybrid X25519+ML-KEM-512/1024.
- P-256 hybrid KEM (verify the exact py layout with a vector first; drop if it costs more
  than it is worth).
- `cnsa2` profile: `report()`, `enforce()`, `hybridKem()`.
- **X-Wing** suite as a clearly separate, standards-based algorithm identifier.
- ACVP KAT harness for ML-KEM (keyGen, encap, decap incl. implicit rejection) against the
  WASM artifact; results committed as JSON.
- `SealedMessage` hex helpers and `inspect()`.

**Exit:** every row tagged Phase 2 in COMPATIBILITY.md is **DONE**; ML-KEM ACVP green.

## Phase 3 — v0.3.0 "Signatures and JWT" · L
- ML-DSA-44/65/87 (`ml-dsa`), `HybridSign` Ed25519 (+ P-256 if kept), SLH-DSA (FIPS 205).
- Exact py constructions: message prefix, 32-byte hedge, signature blob, `HybridSignature`
  CBOR, `SignedMessage` CBOR, unconditional verification of both halves.
- JWT in two explicit modes: `compat: "quantum-safe-py"` and standards (**RFC 9964**, AKP JWK).
- ACVP ML-DSA sigVer (py: 45/45) and sigGen where reachable; Wycheproof where available.
- **Bidirectional** parity: ts→py run in a Python CI job (and, separately, propose the same
  test upstream to quantum-safe-py).

**Exit:** rows tagged Phase 3 are **DONE** in both directions; ACVP signature cases green.

> **Gate G1 — "ready to be consumed":** end of Phase 3. Envelope + KEM + signatures + keys
> + errors are stable enough for a downstream application to depend on. Downstream work is
> out of scope for this repo and starts only after you decide.

## Phase 4 — v0.4.0 "Audit and migration tooling" · L
- **`qs-audit` for JS/TS**: AST-based (TypeScript compiler API or oxc/swc) scanner for
  `node:crypto`, WebCrypto `subtle`, `jose`, `jsonwebtoken`, `node-forge`, `tweetnacl`,
  `@noble/*` etc. Rules with severity, quantum-vulnerability flag, and a **fix hint that
  points at working quantum-safe-ts code**.
- CycloneDX 1.6 **CBOM**, SARIF, JSON; policy file; CI exit codes; GitHub Action; `npx`.
- CNSA 2.0 gating; capability detection for native hybrid TLS / WebCrypto PQ support.
- `Upgrader` and `MigrationStateManager` (async store interface; document the
  distributed-lock caveat).
- **Differentiation check first:** before building, re-survey `cdxgen`, `cbom-scan` and
  successors to confirm the verdict + policy + fix-hint niche is still open.

**Exit:** scanner has a labelled test corpus with measured precision/recall; CBOM
validates against the CycloneDX 1.6 schema.

## Phase 5 — v0.5.0 "Agent and developer surface" · M
- `llms-full.txt`, docs site (TypeDoc + a docs framework) with a decision page: *"Which
  library should I use?"* (WebCrypto / noble / quantum-safe-ts / HPKE), including honest
  "use something else" answers.
- **MCP server** (separate package): tools `audit_repo`, `recommend_suite`,
  `explain_error`, `generate_migration_patch`; JSON-schema'd outputs.
- Templates: `AGENTS.md`, `CLAUDE.md`, Cursor rules, a Claude Code skill.
- Register with Context7 and similar indexes; npm keywords, GitHub topics, examples repo
  per framework, tested in CI.
- Measure discoverability: periodically ask several coding agents "add post-quantum
  encryption to my TS app" and record what they recommend. Treat it as a metric, not a promise.

**Exit:** all docs snippets and templates exercised in CI; MCP tools covered by tests.

## Phase 6 — v0.6.0 "Assurance and hardening" · L
- Differential testing: WASM vs `@noble/post-quantum` vs Node WebCrypto vs liboqs vs
  quantum-safe-py, on shared random inputs and on mutated/malformed inputs.
- Timing-leakage harness (two-class + random-vs-random control) on the WASM artifact,
  reported with its limits.
- Optional **native-accelerated provider** (Node/WebCrypto ML-KEM/ML-DSA via
  `SubtleCrypto.supports`) behind the same API, with differential tests; byte-identical
  outputs or it does not ship.
- Reproducible builds, npm **provenance**, SBOM + CBOM of the package itself, `cargo-deny`
  / `cargo-vet`, SLSA-style release workflow.
- Written threat model and security-claims document.

**Exit:** reproducible-build check passes in CI; differential suite has zero unexplained diffs.

## Phase 7 — v0.7.0+ "Extended algorithms and targets" · L (items independent)
- **LMS verify-only** (RFC 8554), then signing behind a durable write-ahead state store.
  XMSS only if demand justifies.
- **FN-DSA** after FIPS 206 is final; **HQC** after its FIPS is final — never as
  "standard" earlier.
- React Native: evaluate Hermes WASM (RN ≥ 0.84) vs native module; ship only with a green
  device-or-simulator fixture.
- Streaming/chunked envelope **v2** (new suite id; v1 untouched).
- Standards-based X.509 for ML-DSA/ML-KEM (IETF LAMPS) instead of py's custom co-signature
  design, unless a concrete need appears.

## Phase 8 — v1.0.0 "Stable" · M + external time
- Independent third-party security review of the Rust core, bindings and facade.
- API freeze, semver and deprecation policy, LTS branch, security-advisory process.
- Remove "experimental" banner **only** if the review supports it. CMVP is not pursued
  by this project.

---

## Release cadence and gates

| Gate | Condition |
|---|---|
| Any release | CI green incl. parity + fixture matrix; CHANGELOG; COMPATIBILITY.md updated |
| 0.x → 0.(x+1) | All rows for that phase **DONE** with fixtures |
| G1 (end Phase 3) | Stable enough for downstream use; downstream starts only on your call |
| 1.0 | Independent review complete; no open High findings |

## Open decisions (none block Phase 0–1)
1. **npm name:** `quantum-safe-ts` (recommended, unclaimed) vs a scope.
2. **Default hybrid suite:** keep py-compatible combiner as default (recommended for
   compatibility) vs X-Wing as default (recommended for interoperability). Both ship.
3. **Publish a 0.0.x placeholder** to hold the name now? (Manual publish remains the policy.)
4. **Scanner engine** (TypeScript compiler API vs oxc/swc): decide at Phase 4 start.
5. **Upstream proposals** to quantum-safe-py (see COMPATIBILITY.md §4): yours to make.
