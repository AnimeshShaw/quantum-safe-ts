# pqc-audit

A short alias of [`quantum-safe-audit`](https://www.npmjs.com/package/quantum-safe-audit), the scanner that finds quantum-vulnerable cryptography (RSA, ECDSA, ECDH, Ed25519, weak hashes and ciphers) in JavaScript and TypeScript projects and writes SARIF and CycloneDX CBOM reports.

```bash
npx pqc-audit scan .
```

It installs `quantum-safe-audit` and runs its command unchanged. Documentation, options, rules and exit codes: see the [`quantum-safe-audit` README](https://github.com/AnimeshShaw/quantum-safe-ts/tree/master/packages/quantum-safe-audit#readme).

Apache-2.0.
