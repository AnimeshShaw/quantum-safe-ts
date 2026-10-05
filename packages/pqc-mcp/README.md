# pqc-mcp

A short alias of [`quantum-safe-mcp`](https://www.npmjs.com/package/quantum-safe-mcp), the Model Context Protocol server that lets a coding agent scan a JavaScript or TypeScript project for quantum-vulnerable cryptography, choose a post-quantum algorithm suite, and look up `quantum-safe-ts` errors. The server is read-only.

```bash
npx pqc-mcp
```

It installs `quantum-safe-mcp` and runs its server unchanged (stdio). Tools, resources, client set-up for Claude Code, Claude Desktop and Cursor, and limits: see the [MCP server page](https://animeshshaw.github.io/quantum-safe-ts/tools/mcp) and the [`quantum-safe-mcp` README](https://github.com/AnimeshShaw/quantum-safe-ts/tree/master/packages/quantum-safe-mcp#readme).

Pre-1.0 and not independently audited. Apache-2.0.
