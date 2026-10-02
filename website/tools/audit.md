# quantum-safe-audit

Find classical (quantum-vulnerable) cryptography in JavaScript and TypeScript projects, with concrete migration steps. It is the TypeScript
counterpart of `qs-audit` in quantum-safe-py, and it is a separate package (`quantum-safe-audit`) that does **not** depend on the library.

```bash
npx quantum-safe-audit scan .                                        # human-readable; exits 1 on HIGH or worse
npx quantum-safe-audit scan . --format sarif --output audit.sarif    # GitHub code scanning
npx quantum-safe-audit cbom . --app-name my-app > cbom.json          # CycloneDX 1.6 CBOM
npx quantum-safe-audit explain QSJ010                                # why a rule matters, and the fix
```

The installed command is `quantum-safe-audit`. It is deliberately not called `qs-audit`, which is quantum-safe-py's tool, so both can be
installed side by side.

## What it finds

An AST walk (not grep) over `.js .mjs .cjs .jsx .ts .tsx .mts .cts`, `<script>` blocks in `.vue`, `.svelte` and `.astro`, and the dependencies
in `package.json`: RSA, ECDSA and other curves, ECDH and X25519, Ed25519 and Ed448, DSA, finite-field Diffie-Hellman, classical JOSE algorithms
(RS\*, PS\*, ES\*, EdDSA, RSA-OAEP, ECDH-ES), short RSA keys, embedded private keys, AES-128, DES/3DES/RC4, SHA-1, MD5, and (with `--cnsa2`)
SHA-256 where CNSA 2.0 applies. It also lists the post-quantum algorithms already in use. Every finding names its replacement.

## How it differs from other tools

- **Deterministic and offline.** No LLM, no network. The same input gives the same output, so it is safe to run on untrusted code and to gate CI on.
  An LLM-assisted auditor can reason about code this one cannot parse; this one is predictable and reviewable.
- **Policy, not only inventory.** Severity thresholds, per-rule ignores, path excludes, and exit codes you can enforce.
- **Pointers to working fixes** in quantum-safe-ts, and CNSA 2.0 gap reporting.

## Honest limits

- Static analysis sees what the source names. Algorithms chosen at runtime, built from strings, configured elsewhere or hidden inside
  dependencies are invisible. **An empty result is not evidence of absence.**
- It is an inventory and a migration aid, not a CNSA 2.0 assessment or a FIPS validation.
- Its rules are measured on a labelled corpus written by its authors, which is a regression guard, not an independent accuracy claim.
  Please report false positives and negatives.

## Enrich an SBOM

`quantum-safe-audit sbom bom.json --output bom-pqc.json` adds `quantum-safe:pqc-readiness`, `quantum-safe:reason` and `quantum-safe:action` properties to the npm components of a CycloneDX SBOM, from a small name-based knowledge base with a review date. Components with no record are `UNKNOWN`, never `READY`.

## Output and policy

Formats: `text`, `json`, `sarif` (SARIF 2.1.0) and `cbom` (CycloneDX 1.6). Both machine formats are validated against the official schemas in CI.
Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage or I/O error **or an incomplete scan**: a file skipped for size, an unreadable directory, a file that cannot be parsed, or nothing scanned. An incomplete scan is never reported as a pass (`--allow-incomplete` opts out). Use `--no-config` in CI so the scanned code cannot change its own gate by editing `./.qs-audit.json`.

A policy file `.qs-audit.json`:

```json
{ "failOn": "high", "ignoreRules": ["QSJ050"], "exclude": ["**/test/**", "legacy/**"], "cnsa2": false }
```

Suppress in code with `// qs-audit-ignore QSJ031 legacy ETag compatibility` (same or next line) or `// qs-audit-ignore-file QSJ031`.

Use it from code:

```ts
import { scanPaths, buildCbom, toSarif } from 'quantum-safe-audit';
const report = scanPaths(['.'], { failOn: 'high' });
console.log(report.findings.length);
```
