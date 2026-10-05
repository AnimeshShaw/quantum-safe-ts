---
layout: home
hero:
  name: quantum-safe-ts
  text: Hybrid post-quantum cryptography for TypeScript
  tagline: ML-KEM, ML-DSA and SLH-DSA with classical hybrids, envelopes, JWTs and a migration toolkit. A Rust core compiled to WebAssembly, byte-compatible with quantum-safe-py.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Which library should I use?
      link: /compare
    - theme: alt
      text: API reference
      link: /api/
features:
  - title: Three lines to encrypt
    details: "`easy.encrypt(publicKey, data)` and `easy.decrypt(secretKey, sealed)`. Or drop to the class API when you need keys to stay inside WebAssembly memory."
    link: /guide/getting-started
    linkText: Getting started
  - title: Recipes that run
    details: Service-to-service messages, signed releases, tamper-evident logs, rotating JWT keys, row-bound encryption, key migration and Python interop. Every code block on this site is executed by the test suite.
    link: /guide/cookbook
    linkText: Cookbook
  - title: Runs where you do
    details: Node 20 to 24, browsers, Deno, Bun, Cloudflare Workers, Chrome extensions, and the common bundlers. Every row of the support table is tested against the packed npm tarball.
    link: /guide/runtimes
    linkText: Runtimes
  - title: Evidence, not adjectives
    details: 1,317 NIST ACVP cases, differential tests against independent implementations, byte parity with the real Python library in both directions, and fuzzing.
    link: /guide/security
    linkText: Security model
  - title: A migration path
    details: Find classical crypto with quantum-safe-audit, upgrade keys with Upgrader, track progress with a state machine, and gate it in CI with the GitHub Action.
    link: /guide/migration
    linkText: Migrating
  - title: Built for coding agents too
    details: An MCP server, llms.txt, stable error codes with hints. Agents audit a project, pick a suite and fix errors from facts instead of memory.
    link: /tools/mcp
    linkText: MCP server
---

::: warning Pre-1.0 and experimental
Not independently audited. Not FIPS 140-3 validated. NIST ACVP results are conformance evidence, not a validation. JavaScript and
WebAssembly runtimes give no constant-time guarantee. Do not protect real secrets with it until an independent review is published.
See the [security model](/guide/security).
:::
