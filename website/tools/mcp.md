# MCP server for coding agents

`quantum-safe-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server. It lets a coding agent audit a project, choose an
algorithm suite, and look up error codes, using the same engine as [`quantum-safe-audit`](/tools/audit). It depends on that package; it does
not depend on the library.

```jsonc
// .mcp.json (Claude Code) or your client's MCP settings
{
  "mcpServers": {
    "quantum-safe": { "command": "npx", "args": ["-y", "quantum-safe-mcp@0.1.0"] }
  }
}
```

The allowed root is the working directory the client starts the server in; set `QS_MCP_ROOT` to choose another. Pin a version.

| Tool | What it does |
|---|---|
| `audit_path` | Scans a file or directory inside the allowed root for classical cryptography. |
| `list_rules`, `explain_rule` | The audit rules, and why one matters and how to migrate. |
| `recommend_suite` | For a use case, the algorithm, the API call, a working snippet, compatibility notes and honest caveats. |
| `explain_error` | A `QuantumSafeError` code or class name, with the usual fix. |

## Safety properties

- **Read-only and offline.** No writes, no network.
- **Path-confined.** Paths are resolved (including symbolic links) before the check, and anything outside the root is refused.
- **Injection-aware.** Text from a scanned repository can contain prompt-injection attempts. Reports include only short identifier-like
  details and redact other literals. Treat anything an agent reads from a hostile repository as data, not instructions.

## Other agent-facing material

- `llms.txt` and `llms-full.txt` ship inside the `quantum-safe-ts` npm package. Every example in `llms-full.txt` is executed in CI.
- Errors carry a stable `code` and a static `hint` that an agent can act on.
