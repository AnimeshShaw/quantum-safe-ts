# quantum-safe-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets a coding agent (Claude Code, Cursor, and other MCP clients)
**audit a JavaScript/TypeScript project for quantum-vulnerable cryptography**, **choose a post-quantum algorithm suite**, and **look up
`quantum-safe-ts` error codes**. Part of [quantum-safe-ts](https://github.com/AnimeshShaw/quantum-safe-ts).

It is read-only and offline: it never writes files, never opens the network, and refuses paths outside the root you give it
(symbolic links are resolved before the check). It depends on [`quantum-safe-audit`](https://github.com/AnimeshShaw/quantum-safe-ts/tree/master/packages/quantum-safe-audit) for scanning.

## Use it

```jsonc
// .mcp.json (Claude Code) or your client's MCP settings
{
  "mcpServers": {
    "quantum-safe": { "command": "npx", "args": ["-y", "quantum-safe-mcp@0.1.2"] }
  }
}
```

By default the allowed root is the working directory the client starts the server in; set `QS_MCP_ROOT` to choose another. Pin a version in real configurations.

## Tools

| Tool | What it does |
|---|---|
| `audit_path` | Statically scans a file or directory inside the allowed root for RSA, ECDSA, ECDH, Ed25519, X25519, DSA, DH, weak hashes and ciphers, classical JWT algorithms and embedded private keys. Returns findings with severity, location and a migration hint. |
| `list_rules` | Lists the audit rules (id, severity, title). |
| `explain_rule` | Explains a rule such as `QSJ010` and shows the migration with a code example. |
| `recommend_suite` | Given a use case, returns the algorithm, the API call, a working snippet, compatibility notes and honest caveats (including when a platform primitive is the better choice). |
| `explain_error` | Looks up a `QuantumSafeError` by code or class name: what it means and the usual fix. |

It also serves a short summary of the library as an MCP resource.

## What it is not

- Static analysis sees only what the source names. An empty result is **not** evidence that a project has no classical cryptography.
- It is an inventory and migration aid, not a CNSA 2.0 assessment.
- Text that comes from the scanned repository (comments, string literals) can contain prompt-injection attempts. The server returns only
  short identifier-like details and redacts other literals, but treat everything an agent reads from a hostile repository as data.

## License

Apache-2.0.
