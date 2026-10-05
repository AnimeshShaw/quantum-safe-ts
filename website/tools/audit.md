# quantum-safe-audit

Find classical (quantum-vulnerable) cryptography in JavaScript and TypeScript projects, with concrete migration steps, and produce the
reports your CI and your auditors consume (SARIF, CycloneDX CBOM). It is the TypeScript counterpart of `qs-audit` in quantum-safe-py. It is a
separate package that does **not** depend on the library, and it is also published under the alias **`pqc-audit`**.

**Use it for** building the inventory a post-quantum migration starts from, for gating CI on new classical cryptography, and for producing a
CBOM. **Do not use it** as proof that a system is quantum-safe or compliant: it reports what the source names (see [Honest limits](#honest-limits)).

::: warning Not published yet
The npm package exists only after the first release. Until then build it from a checkout (`npm run build` in `packages/quantum-safe-audit`) and run
`node packages/quantum-safe-audit/dist/cli.js`.
:::

## Run it

```bash
npx quantum-safe-audit scan .                                        # human-readable; exits 1 on HIGH or worse
npx quantum-safe-audit scan . --format sarif --output audit.sarif    # GitHub code scanning
npx quantum-safe-audit cbom . --app-name my-app > cbom.json          # CycloneDX 1.6 CBOM
npx quantum-safe-audit explain QSJ010                                # why a rule matters, and the fix
npx quantum-safe-audit rules                                         # every rule
npx quantum-safe-audit sbom bom.json --output bom-pqc.json           # enrich a CycloneDX SBOM
```

The installed command is `quantum-safe-audit` (and `pqc-audit` from the alias package). It is deliberately not called `qs-audit`, which is
quantum-safe-py's tool, so both can be installed side by side.

A small project with an RSA key and a SHA-1 hash produces:

```text
[HIGH    ] src/auth.ts:2:30  QSJ001  RSA key generation or use (rsa)
           fix: Encryption/key transport: HybridKEM + Envelope (X25519+ML-KEM-768; CNSA 2.0: pure ML-KEM-1024 via cnsa2.kem()). Signatures: HybridSign (Ed25519+ML-DSA-65; CNSA 2.0: pure ML-DSA-87).
[MEDIUM  ] src/auth.ts:3:23  QSJ030  SHA-1 (sha1)
           fix: SHA-384 or SHA-512.

Scanned 1 file(s): 0 critical, 1 high, 1 medium, 0 low, 0 info.
Static analysis sees only what the source names; an empty result is not evidence of absence. This is an inventory, not a compliance verdict or a FIPS 140-3 validation.
```

and exits with code 1, because a HIGH finding meets the default `--fail-on high`.

## What it finds

An AST walk (not grep) over `.js .mjs .cjs .jsx .ts .tsx .mts .cts`, `<script>` blocks in `.vue`, `.svelte` and `.astro`, `.html` pages,
extensionless Node scripts (`#!/usr/bin/env node`), and the dependencies in `package.json`. Every finding names its replacement.

| Rule | Severity | What |
|---|---|---|
| QSJ001-003 | high | RSA key generation or use; RSA PKCS#1 v1.5 or RSA-SHA signatures; RSA encryption (OAEP, `publicEncrypt`) |
| QSJ010 | high | Elliptic-curve signatures (ECDSA, secp256k1, P-curves) |
| QSJ011 | high | ECDH and X25519/X448 key agreement |
| QSJ012 | high | EdDSA (Ed25519, Ed448) signatures |
| QSJ015, QSJ016 | high | DSA; finite-field Diffie-Hellman |
| QSJ020 | medium | AES-128 |
| QSJ021 | high | DES, 3DES, RC4, Blowfish |
| QSJ030, QSJ031 | medium | SHA-1; MD5 |
| QSJ032 | low | SHA-256 where CNSA 2.0 applies (only with `--cnsa2`) |
| QSJ040 | high | Classical JOSE/JWT algorithms (RS\*, PS\*, ES\*, EdDSA, RSA-OAEP, ECDH-ES) |
| QSJ050 | info | A classical-cryptography library in `package.json` |
| QSJ060 | critical | Private key material embedded in source |
| QSJ070 | critical | RSA key shorter than 2048 bits |
| QSJ900 | info | Post-quantum cryptography already in use (listed so the inventory is complete) |

`quantum-safe-audit rules --json` prints the live list; `explain <id>` prints the explanation, the migration target, an example using
quantum-safe-ts, and references.

## How it differs from other tools

- **Deterministic and offline.** No LLM, no network. The same input gives the same output, so it is safe to run on untrusted code and to gate CI
  on. An LLM-assisted auditor can reason about code this one cannot parse; this one is predictable and reviewable. They complement each other.
- **Policy, not only inventory.** Severity thresholds, per-rule ignores, path excludes, and exit codes you can enforce.
- **Pointers to working fixes** in quantum-safe-ts, and CNSA 2.0 gap reporting.

## Honest limits

- Static analysis sees what the source names. Algorithms chosen at runtime, built from strings, configured elsewhere or hidden inside
  dependencies are invisible. **An empty result is not evidence of absence.**
- It is an inventory and a migration aid, not a CNSA 2.0 assessment or a FIPS validation.
- Its rules are measured on a labelled corpus written by its authors, which is a regression guard, not an independent accuracy claim.
  Please report false positives and negatives.

## Output formats and exit codes

Formats: `text`, `json`, `sarif` (SARIF 2.1.0) and `cbom` (CycloneDX 1.6). Both machine formats are validated against the official schemas in CI.

| Exit code | Meaning |
|---|---|
| `0` | OK: nothing at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` (default `high`) |
| `2` | Usage or I/O error, **or an incomplete scan**: a file skipped for size, an unreadable directory, a file that cannot be parsed, or nothing scanned. An incomplete scan is never reported as a pass (`--allow-incomplete` opts out). |

### The CBOM

`cbom` writes a CycloneDX 1.6 cryptographic bill of materials: one `cryptographic-asset` per algorithm found, with its primitive, classical
security level, NIST quantum security level, OID, and the file, line and column where it appears, plus the rule id and severity as
properties. Post-quantum algorithms already in use are included (omit them with `--no-provided`).

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "detected-RSA-0",
  "name": "RSA",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "pke", "classicalSecurityLevel": 112, "nistQuantumSecurityLevel": 0 },
    "oid": "1.2.840.113549.1.1.1"
  },
  "evidence": { "occurrences": [{ "location": "src/auth.ts", "line": 2, "offset": 29 }] },
  "properties": [{ "name": "quantum-safe:rule-id", "value": "QSJ001" }, { "name": "quantum-safe:severity", "value": "HIGH" }, { "name": "quantum-safe:quantum-vulnerable", "value": "true" }]
}
```

### Enrich an SBOM

`quantum-safe-audit sbom bom.json --output bom-pqc.json` adds `quantum-safe:pqc-readiness`, `quantum-safe:reason` and `quantum-safe:action` properties
to the npm components of a CycloneDX SBOM, from a small name-based knowledge base with a review date. Components with no record are `UNKNOWN`,
never `READY`.

## Options

| Option | Meaning |
|---|---|
| `--format <text\|json\|sarif\|cbom>` | Output format (default `text`) |
| `--output <file>` | Write to a file instead of standard output |
| `--fail-on <critical\|high\|medium\|low\|info\|none>` | Exit 1 at or above this severity (default `high`) |
| `--policy <file>` | JSON policy `{ failOn, ignoreRules, exclude, cnsa2 }`; `./.qs-audit.json` is loaded automatically if present |
| `--exclude <glob>` | Exclude paths (repeatable; `**` and `*` supported) |
| `--ignore-rule <ID>` | Ignore a rule (repeatable) |
| `--cnsa2` | Also report CNSA 2.0 hash gaps (SHA-256) |
| `--no-provided` | Omit the provided post-quantum algorithms from the CBOM |
| `--allow-incomplete` | Do not exit 2 when files were skipped or unanalysable, or nothing was scanned |
| `--no-config` | Do not auto-load `./.qs-audit.json` (CI should use this, or pass `--policy` from a trusted ref) |
| `--no-inline-ignore` | Ignore `// qs-audit-ignore` comments (for gates on untrusted code) |
| `--no-default-excludes` | Also scan `node_modules`, `dist`, `build`, `vendor`, ... (skipped by default; skipped paths are listed as notes) |
| `--app-name <name>` | Application name recorded in the CBOM |

### A policy file

`.qs-audit.json`:

```json
{ "failOn": "high", "ignoreRules": ["QSJ050"], "exclude": ["**/test/**", "legacy/**"], "cnsa2": false }
```

Suppress a finding in code with `// qs-audit-ignore QSJ031 legacy ETag compatibility` (same or next line) or `// qs-audit-ignore-file QSJ031` for a
whole file. Say why in the comment: reviewers read it. Use `--no-config` and `--no-inline-ignore` in CI for code you do not trust: a pull
request could otherwise add an ignore to pass its own check.

## Use it in CI

Use the [GitHub Action](/tools/github-action), or call the CLI yourself:

```bash
npx quantum-safe-audit scan . --no-config --no-inline-ignore --policy ci/qs-audit.json --fail-on high \
  --format sarif --output audit.sarif
```

## Use it from code

```ts test
import { scanPaths, buildCbom, shouldFail, summary } from 'quantum-safe-audit';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'qs-audit-doc-'));
try {
  writeFileSync(join(dir, 'a.ts'), "import crypto from 'node:crypto';\ncrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
  const report = scanPaths([dir]);
  console.log(summary(report));
  if (report.findings.length !== 1 || report.findings[0]!.ruleId !== 'QSJ001') throw new Error('expected one RSA finding');
  if (!shouldFail(report)) throw new Error('a HIGH finding fails the default gate');
  const cbom = buildCbom(report, { appName: 'demo' }) as { bomFormat: string; specVersion: string };
  if (cbom.bomFormat !== 'CycloneDX' || cbom.specVersion !== '1.6') throw new Error('unexpected CBOM');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
```

## Using it from an agent

The [MCP server](/tools/mcp) exposes the same engine to coding agents (`audit_path`, `list_rules`, `explain_rule`).
