# Security Policy

## Status

`quantum-safe-ts` is **pre-1.0 and experimental**. It has **not** been independently
audited, and it is **not** FIPS 140-3 / CMVP validated. Conformance tests against NIST
vectors are evidence of correctness, not a validation. Do not use it to protect real
secrets until a third-party review is published and this notice is removed.

JavaScript and WebAssembly runtimes give **no constant-time guarantee**. Secret-bearing
objects can be wiped on the WASM side with `.free()`, but any copy extracted into the
JavaScript heap is outside this library's control.

## Reporting a vulnerability

Please report privately, not in a public issue:

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on
  <https://github.com/AnimeshShaw/quantum-safe-ts>.
- Include affected version, a minimal reproduction, and impact.

You can expect an acknowledgement within 7 days. We aim to ship a fix or mitigation
within 90 days of a confirmed report and will credit reporters who want credit.

## Scope

In scope: the Rust core (`crates/`), the WASM bindings, the TypeScript package, and the
build/release workflows. Out of scope: vulnerabilities in third-party dependencies that are
not reachable through this library (report those upstream).

## Supported versions

Only the latest released minor version receives fixes while the project is pre-1.0.
