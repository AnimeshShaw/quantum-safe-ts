# quantum-safe-audit

Find classical (quantum-vulnerable) cryptography in JavaScript and TypeScript projects, and get concrete migration
steps. Part of [quantum-safe-ts](https://github.com/AnimeshShaw/quantum-safe-ts); the JavaScript/TypeScript counterpart to
`qs-audit` in [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py).

```bash
npx quantum-safe-audit scan .            # human-readable report; exit 1 on HIGH or worse
npx quantum-safe-audit scan . --format sarif --output audit.sarif   # GitHub Code Scanning
npx quantum-safe-audit cbom . --app-name my-app > cbom.json         # CycloneDX 1.6 CBOM
```

(The installed binary is `qs-audit`.)

## What it finds

An AST walk (not grep) over `.js .mjs .cjs .jsx .ts .tsx .mts .cts` plus `<script>` blocks in `.vue`, `.svelte`, `.astro`,
and `package.json` dependencies:

| Rule | Severity | Detects |
|---|---|---|
| QSJ001 / QSJ002 / QSJ003 | high | RSA (`generateKeyPair('rsa')`, `RSA-OAEP`, `RSASSA-PKCS1-v1_5`, `publicEncrypt`, `node-rsa`, `forge.pki.rsa`, ...) |
| QSJ010 / QSJ011 / QSJ012 | high | ECDSA and curves, ECDH / X25519, Ed25519 / Ed448 (`node:crypto`, WebCrypto, `elliptic`, `@noble/curves`, `tweetnacl`, libsodium) |
| QSJ015 / QSJ016 | high | DSA, finite-field Diffie-Hellman |
| QSJ040 | high | Classical JOSE/JWT algorithms (RS*, PS*, ES*, EdDSA, RSA-OAEP, ECDH-ES) when a JOSE library is in use |
| QSJ070 | critical | RSA keys shorter than 2048 bits |
| QSJ060 | critical | Private key material embedded in source |
| QSJ020 / QSJ021 | medium / high | AES-128; DES, 3DES, RC4 |
| QSJ030 / QSJ031 | medium | SHA-1, MD5 |
| QSJ032 | low | SHA-256 where CNSA 2.0 applies (`--cnsa2` only) |
| QSJ050 | info | Classical-crypto library inventory |
| QSJ900 | info | Post-quantum libraries/algorithms already in use |

Every finding carries a migration hint that names the replacement (for example `HybridKEM`, `HybridSign`, `StandardJwt` from
`quantum-safe-ts`). `qs-audit explain QSJ010` prints the rule, the reasoning and a code example.

## Honest limits

- Static analysis sees what the source names. Algorithms chosen at runtime, built from strings, configured outside the code, or
  hidden inside dependencies are invisible, so **an empty result is not evidence of absence**.
- It is an inventory and a migration aid, **not** a CNSA 2.0 assessment or a FIPS 140-3 validation.
- The detection rules are measured on a labelled corpus in this repository (`test/corpus`). That corpus was written by the
  authors, so its 100% precision/recall is a regression guard, not an independent accuracy claim. Treat results on your code
  as a starting point and review them. Please report false positives and negatives.
- JOSE algorithm strings (`RS256`, ...) are reported only when a JOSE library is imported or the string is passed to a
  JOSE call, to avoid flagging algorithm *labels* in unrelated data.

## Output formats

- `text` (default), `json`
- `sarif`: SARIF 2.1.0, validated against the official schema in CI
- `cbom`: CycloneDX 1.6 cryptographic bill of materials, validated against the official schema in CI. One component per
  (algorithm, location), plus the post-quantum algorithms available to migrate to (disable with `--no-provided`).

## CI

```yaml
- run: npx quantum-safe-audit scan . --fail-on high --format sarif --output audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: audit.sarif }
```

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage or I/O error.

## Policy and suppression

`.qs-audit.json`:

```json
{ "failOn": "high", "ignoreRules": ["QSJ050"], "exclude": ["**/test/**", "legacy/**"], "cnsa2": false }
```

In code: `// qs-audit-ignore QSJ031 legacy ETag compatibility` (same or next line) or `// qs-audit-ignore-file QSJ031`.

## Programmatic use

```ts
import { scanPaths, buildCbom, toSarif } from 'quantum-safe-audit';
const report = scanPaths(['.'], { failOn: 'high' });
console.log(report.findings.length, toSarif(report).length, Object.keys(buildCbom(report)));
```

## License

Apache-2.0
