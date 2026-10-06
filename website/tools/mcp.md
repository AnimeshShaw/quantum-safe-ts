# MCP server for coding agents

`quantum-safe-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server. It lets a coding agent (Claude Code, Claude Desktop,
Cursor, VS Code and other MCP clients) **audit a project for classical cryptography, choose an algorithm suite with working code, and look up
error codes**, using the same engine as [`quantum-safe-audit`](/tools/audit). It depends on that package; it does not depend on the library.
It is also published under the short alias **`pqc-mcp`** (same server, same options: `npx pqc-mcp`).

**Use it when** an agent is helping you migrate to post-quantum cryptography or write code with quantum-safe-ts and you want it to answer from
facts rather than memory. **It will not** write or change files, run your code, touch the network, or give a compliance verdict.

## Install and configure

The server speaks MCP over standard input and output (stdio). Every client below starts it as a command. Pin the version.

| Client | How |
|---|---|
| **Claude Code** | `claude mcp add quantum-safe -- npx -y quantum-safe-mcp@0.1.2`, or put the JSON below in `.mcp.json` at the project root |
| **Claude Desktop** | Add the JSON below under `mcpServers` in `claude_desktop_config.json` (Settings, Developer, Edit Config), then restart |
| **Cursor** | Add it to `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for all projects |
| **VS Code** | In `.vscode/mcp.json`, under `servers` (not `mcpServers`), with `"type": "stdio"` |
| **Other clients** | Any client that can launch a stdio MCP server: command `npx`, arguments `-y quantum-safe-mcp@0.1.2` |

```json
{
  "mcpServers": {
    "quantum-safe": {
      "command": "npx",
      "args": ["-y", "quantum-safe-mcp@0.1.2"],
      "env": { "QS_MCP_ROOT": "/path/to/the/project/to/audit" }
    }
  }
}
```

Client configuration formats change; if a file name or key above differs in your client's current documentation, follow the client. The
server itself is just the command above.

**The allowed root.** `audit_path` may read only inside one directory: `QS_MCP_ROOT` if set, otherwise the working directory the client
starts the server in. Set it explicitly when the client launches servers from somewhere else.

## What it exposes

Five tools and one resource. All tools are marked read-only (`readOnlyHint: true`, never destructive).

| Tool | Inputs | What it does |
|---|---|---|
| `audit_path` | `path` (relative to the root, `.` for all), optional `cnsa2` (boolean), `minSeverity` (`critical`, `high`, `medium`, `low`, `info`), `exclude` (up to 20 glob patterns) | Statically scans a file or directory for classical cryptography: RSA, ECDSA, ECDH, Ed25519, X25519, DSA, DH, weak hashes and ciphers, embedded private keys, classical JOSE algorithms, classical dependencies. Returns rule, severity, file, line, message and the migration target for each finding, plus a summary, whether CI would fail, and whether the scan was complete. At most 200 findings are returned. |
| `list_rules` | none | Every rule the scanner can report: id, severity, title, whether it is quantum-vulnerable |
| `explain_rule` | `ruleId` such as `QSJ001` | Why the rule matters, the replacement, a code example using quantum-safe-ts, and references |
| `recommend_suite` | `useCase` (`encrypt-data`, `key-exchange`, `sign-data`, `jwt`, `password-kdf`, `file-or-vault-encryption`), optional `requireCnsa2`, `interoperateWith` (`none`, `quantum-safe-py`, `other-ecosystems`) | The algorithm, the API, a code snippet, compatibility notes, honest caveats and alternatives. It says when a simpler platform primitive (WebCrypto) is the better choice. |
| `explain_error` | `code`: an error code (`QS_DECRYPTION_FAILED`) or class name | What the error means and the usual fix, for every error the library throws |

| Resource | What it is |
|---|---|
| `quantum-safe-ts://llms.txt` | A short, factual summary of the library, for the agent's context |

## Example: auditing a project

You ask the agent: *"Check this project for crypto that a quantum computer breaks and tell me what to change."* The agent calls
`audit_path` with `{ "path": "." }` and receives (excerpt, from a small project with an RSA key and a SHA-1 hash):

```json
{
  "filesScanned": 1,
  "summary": { "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0 },
  "wouldFailCi": true,
  "findings": [
    { "rule": "QSJ001", "severity": "high", "file": "src/auth.ts", "line": 2, "message": "RSA key generation or use (rsa)",
      "migrateTo": "Encryption/key transport: HybridKEM + Envelope (X25519+ML-KEM-768; CNSA 2.0: pure ML-KEM-1024 via cnsa2.kem()). Signatures: HybridSign (Ed25519+ML-DSA-65; CNSA 2.0: pure ML-DSA-87)." },
    { "rule": "QSJ030", "severity": "medium", "file": "src/auth.ts", "line": 3, "message": "SHA-1 (sha1)", "migrateTo": "SHA-384 or SHA-512." }
  ],
  "scanComplete": true,
  "limits": "Static analysis sees only what the source names. An empty result is not evidence of absence. Inventory only: not a CNSA 2.0 assessment. ..."
}
```

The agent can then call `explain_rule` with `QSJ001` for the long explanation and a runnable example, and `recommend_suite` for the code it will
write. A typical exchange:

> **You:** Scan `src/` and fix what a quantum computer would break.
> **Agent:** (calls `audit_path`) Two findings in `src/auth.ts`: RSA key generation (high) and SHA-1 (medium). I'll look up the migration
> for RSA. (calls `explain_rule` QSJ001, then `recommend_suite` for `encrypt-data`) Replace the RSA encryption with a hybrid envelope… Here is the
> change.

## Example: choosing a suite

`recommend_suite` with `{ "useCase": "sign-data", "requireCnsa2": true }` returns pure ML-DSA-87 (a hybrid is only `partial` under CNSA 2.0), with
this code and caveats such as "CNSA 2.0 parameter sets are selected, but compliance depends on more than parameters":

```ts no-run
// Returned verbatim by recommend_suite (sign-data, CNSA 2.0). The same snippet shape runs in the docs test for the suites it names.
import { Sign, utf8 } from 'quantum-safe-ts';
const signer = new Sign('ML-DSA-87');
using pair = signer.generateKeyPair();
const signed = signer.sign(message, pair.secretKey, { context: utf8('myapp-v1-docs') });
signer.verify(signed, pair.publicKey, { expectedContext: utf8('myapp-v1-docs') }); // throws VerificationError on failure
```

(`message` is yours to supply, which is why the snippet is not run as is.)

## Example: an error the agent hit

`explain_error` with `{ "code": "QS_DECRYPTION_FAILED" }`:

```json
{
  "name": "DecryptionAuthenticationError",
  "code": "QS_DECRYPTION_FAILED",
  "meaning": "AES-GCM authentication failed: wrong key, wrong AAD, or tampered data.",
  "fix": "Use the recipient secret key, the same `aad`, and unmodified data. ML-KEM implicit rejection surfaces here, not at decapsulate()."
}
```

## What it will and will not answer

| It will | It will not |
|---|---|
| List classical cryptography it can see in the source, with the replacement | Say a system is quantum-safe, CNSA 2.0 compliant or FIPS validated: the output says it is an inventory |
| Recommend a suite for a use case and give code | Write or edit your files; run your code; call the network |
| Explain every rule and every library error | Find cryptography that is chosen at runtime, built from strings, configured elsewhere or inside dependencies |
| Refuse paths outside the allowed root | Read `/etc`, your home directory or anything a symbolic link points to outside the root |

An empty `audit_path` result is **not** evidence of absence. A call such as `{ "path": "../../etc" }` returns the error "Path does not exist inside the allowed root."

## Safety properties

- **Read-only and offline.** No writes, no network, no process execution; scanned code is never run.
- **Path-confined.** Paths are resolved (including symbolic links) before the check, and anything outside the root is refused.
- **Injection-aware.** Text from a scanned repository can contain prompt-injection attempts. Reports include only short identifier-like
  details; other literals are redacted. File names and parser messages that contain unusual characters are replaced by numbered placeholders,
  and every report says that file names are untrusted data. This limits what a hostile repository can put in front of the model; it cannot make
  arbitrary words safe, so treat anything an agent reads from a hostile repository as data, not instructions.
- **Bounded output.** At most 200 findings per call, with `truncated` set when there are more.
- Pin the version in your client configuration; do not use `latest` for something that feeds an agent's context.

## How the knowledge stays correct

The server's answers are static text in the package, so a test keeps them honest:

- every error code the library defines must be explained by `explain_error` (a test in the library package fails otherwise);
- every algorithm and snippet `recommend_suite` names must be a suite the library actually has (also tested, for every use case and option);
- the tool surface is tested to be exactly the five documented read-only tools and the one resource;
- the CNSA 2.0 wording follows the library's own `cnsa2` report (hybrids are `partial`; pure `ML-KEM-1024` and `ML-DSA-87` are the
  compliant selections).

## Other agent-facing material

`llms.txt` and `llms-full.txt` ship inside the `quantum-safe-ts` npm package, and every example in `llms-full.txt` is executed in CI. Errors carry
a stable `code` and a static `hint` that an agent can act on ([Errors](/guide/errors)).
