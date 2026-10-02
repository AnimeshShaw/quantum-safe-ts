# Notes for a follow-up paper or an updated quantum-safe-py paper

Prepared 2026-10-03 for the maintainer. This is raw material, not a draft paper: each item says what the claim is, what evidence exists
**in this repository today**, how to reproduce it, and what must still be done before it can be stated in print. Items that need
experiments we have not run are marked **TO DO**. Nothing here should be quoted as a result unless its reproduction command passes.

## 1. Possible framing

Two options, in increasing ambition:

1. **A short update to the quantum-safe-py paper** (a new section or an erratum + addendum): "A TypeScript/WebAssembly implementation and
   what cross-language parity testing revealed". Fits a 3-5 page addendum.
2. **A short standalone paper** (about 8 pages): *Cross-language conformance, interoperability and standards alignment for a
   post-quantum "production layer"*, using quantum-safe-py (Python) and quantum-safe-ts (TypeScript/WASM) as the case study. The thesis that
   the evidence supports (and that quantum-safe-py's own rubric already adopts): **primitives are commoditising; the contested ground is
   formats, compatibility, migration tooling and honest conformance evidence**.

## 2. Contributions with evidence

| # | Contribution | Evidence in repo | Reproduce |
|---|---|---|---|
| C1 | Byte-level wire compatibility between two independent implementations (Python/liboqs and Rust-WASM) across hybrid KEM, envelope, key CBOR/PEM/JWK, signed messages, hybrid signatures and JWT, **verified in both directions** | 8 KEM + 5 envelope + 8 key + 22 signature + 4 JWT vectors py→ts; 52 checks ts→py | `python scripts/generate_suite_vectors.py`; `cargo test -p quantum-safe-core --test py_parity_kem --test py_parity_sig`; `npx vitest run test/parity.test.ts`; `cargo run -p quantum-safe-core --example gen_ts_vectors && node scripts/gen_ts_js_vectors.mjs && python scripts/verify_ts_vectors.py` |
| C2 | **Differential testing against third-party implementations** exposes what "compatible" does and does not mean: quantum-safe-py's constructions verify under standard primitives only when the construction is reproduced exactly | 27 differential tests vs `@noble/post-quantum` and Node WebCrypto | `npx vitest run test/differential.test.ts` |
| C3 | Broader conformance evidence: **1,317** NIST ACVP cases (ML-KEM, ML-DSA, SLH-DSA; keyGen/sigGen/sigVer/encap/decap) vs 225 in quantum-safe-py; skipped categories enumerated (786 cases) | `results/acvp_ts_native.json` | `python scripts/fetch_acvp.py && QS_REQUIRE_ACVP=1 cargo test --release -p quantum-safe-core --test acvp` |
| C4 | A **CNSA 2.0 interpretation finding**: hybrid is optional and the classical half of an NSS hybrid must be CNSA 1.0 (P-384); pure ML-KEM-1024 satisfies key establishment; the HKDF-SHA-256 combiner violates the SHA-384/512 requirement. quantum-safe-py's helper reports `X25519+ML-KEM-1024` as compliant | `docs/research/standards-alignment.md` §3; `cnsa2.report()` tests | `npx vitest run test/behavior.test.ts -t CNSA` |
| C5 | A **CNSA 2.0 envelope profile** (pure ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM) verified end to end by independent implementations (noble ML-KEM-1024, Node HKDF-SHA-384 and AES-GCM) in both directions | `differential.test.ts` "CNSA 2.0 envelope v2" | as above |
| C6 | **LMS/HSS verification** (the SP 800-208 item no JS library offers) checked against RFC 8554 Appendix F and 13 signatures from an independent implementation | `tests/vectors/lms_*.json`, `lms.test.ts` | `cargo test -p quantum-safe-core lms`; `npx vitest run test/lms.test.ts` |
| C7 | Survey of the JavaScript/TypeScript PQC ecosystem with registry-verified adoption numbers and the native-platform shift (Node ≥ 24.7 WebCrypto ML-KEM/ML-DSA; Node 26.10 hybrid KEMs) | `docs/research/2026-10-02-ecosystem-and-parity-research.md` | re-run the npm/crates.io queries listed there |
| C8 | A **defect-class catalogue** from building and testing a PQC WASM library: upstream decoder panics on malformed expanded ML-DSA keys; bundler-specific failures (Node entry under Next.js server bundling, duplicate WASM assets, DOM-less type consumers, `Symbol.dispose` typing) found only by testing the **packed tarball** in real toolchains | `CHANGELOG.md`; `tests/fixtures/` | `node tests/fixtures/run.mjs` |
| C9 | **Agent-facing surface** (typed errors with hints, `llms.txt`, executed documentation snippets, a read-only path-confined MCP server, an audit tool whose output is sanitised against prompt injection) as an engineering pattern | `packages/quantum-safe-mcp`, `quantum-safe-audit/test` | `npx vitest run` in each package |
| C10 | JS/TS **crypto-asset scanner** emitting schema-valid CycloneDX 1.6 CBOM and SARIF | `quantum-safe-audit` tests | `npx vitest run` |

## 3. Claims in the existing paper/README to reconsider (from `docs/production_readiness_rubric.md` and my reading)

| Existing claim | Issue | Suggested treatment |
|---|---|---|
| "No other Python PQC library publishes [ACVP results]" (README) | True of Python libraries surveyed, but `noble-post-quantum` tests against ACVP and quantum-safe-ts now runs 1,317 cases | Keep the scoped Python claim; do not generalise |
| `cnsa2.hybrid_kem()` compliant | Contradicts the NSA FAQ (classical component must be P-384) | Report as `PARTIAL`; make pure ML-KEM-1024 the compliant example |
| The hybrid construction "is exactly what TLS 1.3 uses" (`kem/hybrid.py`) | The combiner is a custom HKDF construction | Reword; cite as "inspired by" |
| FIPS 204 context/HashML-DSA wording (`backends/liboqs.py`) | The code is a message prefix with empty FIPS context | Reword (this repository's probe and tests show the exact bytes) |
| ML-DSA-87 sizes in the registry | 4864/4595 vs FIPS 204 4896/4627 | Correct |
| Rubric D3 "LMS Partial" and D8/D9 | Still accurate; quantum-safe-ts adds LMS **verification** only | Note as a second data point |

## 4. Experiments worth running (TO DO; none are claimed)

1. **Performance of the WASM build vs pure-JS and native.** `bench/bench.mjs` measures the WASM core against `@noble/post-quantum` and Node's native
   ML-KEM. Needs a pinned, idle machine, several runs, and CPU-frequency control before any number is quoted. Report medians and spreads, state the
   environment, and avoid claiming "constant time" from timing stability (quantum-safe-py's paper already makes that distinction well).
2. **Timing-leakage test on the WASM artifact** with the two-class (fixed-vs-random + random-vs-random control) method from quantum-safe-py's harness,
   run in Node and in a browser. Expectation, to be tested not assumed: WASM engines add JIT/GC noise; ML-DSA rejection sampling leaks by design.
3. **Scanner accuracy on third-party code.** Label a random sample of N public JS/TS repositories independently of the rule author, report precision and
   recall with confidence intervals, and compare against `cdxgen`'s crypto inventory and `cbom-scan`. The committed corpus (written by the authors) is a
   regression guard only.
4. **Agent-discoverability study.** Ask several coding agents, with and without `llms.txt`/MCP, "add post-quantum encryption to my TypeScript app" over
   repeated trials; record which library each recommends and whether the code runs. This is the empirical test of the "go-to library" goal and must be
   reported as an observation with its limitations (model versions, prompts, variance).
5. **Bundle-size and cold-start cost** per runtime (Node, Chromium, Firefox, WebKit, workerd, Bun, Deno): the inline-base64 entry vs a separate `.wasm`.

## 5. Threats to validity to state up front

- Parity fixtures are generated by the same authors' libraries; independent oracles (noble, Node/OpenSSL, pyhsslms, the RFC) mitigate but do not remove this.
- ACVP results are conformance evidence, not CAVP/CMVP validation; 786 vectors (pre-hash, externalMu, key checks) were not run.
- RustCrypto `ml-kem`/`ml-dsa`/`slh-dsa` state they have not been independently audited; neither has this library.
- JavaScript/WASM runtimes give no constant-time guarantee.
- Secondary sources (regional guidance, blogs) were used for BSI/ANSSI/NCSC/ASD timelines; primary documents should be cited in print.

## 6. Reproduction in one place

```bash
# Python <-> TypeScript parity, both directions (needs quantum-safe-py[liboqs]==0.3.0 and the toolchain)
python scripts/generate_suite_vectors.py
cargo test --workspace --exclude quantum-safe-wasm --test py_parity_kem --test py_parity_sig
cd packages/quantum-safe-ts && npm ci && npm run build && npx vitest run
cd ../.. && node scripts/gen_ts_js_vectors.mjs && python scripts/verify_ts_vectors.py
# NIST ACVP
python scripts/fetch_acvp.py && QS_REQUIRE_ACVP=1 cargo test --release -p quantum-safe-core --test acvp
# Fixture matrix
node tests/fixtures/run.mjs
```
