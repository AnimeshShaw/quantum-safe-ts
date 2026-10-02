# GitHub Action

Run [`quantum-safe-audit`](/tools/audit) in CI, publish findings to GitHub code scanning, and fail the build at a severity you choose.

::: warning Not released yet
The `@v0.1.0` tag and the npm package exist only after the first release. Until then use `uses: ./` with `package-path` in a checkout of this repository.
:::

```yaml
name: Quantum-safe audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # only needed to upload SARIF

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AnimeshShaw/quantum-safe-ts@v0.1.0   # pin a release tag or, better, its commit SHA
        with:
          path: .
          fail-on: high
          upload-sarif: true
          version: 0.1.0     # pin the audit tool version too
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the workspace. |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none`. |
| `format` | `sarif` | `sarif`, `json`, `text` or `cbom`. |
| `output` | `quantum-safe-audit.sarif` | Report file, relative to the workspace. |
| `upload-sarif` | `false` | Upload the SARIF report to code scanning. Needs `security-events: write`, and code scanning must be available for the repository. |
| `cbom` | `false` | Also write a CycloneDX 1.6 CBOM to `quantum-safe-cbom.json`. |
| `cnsa2` | `false` | Also report CNSA 2.0 hash gaps (SHA-256). |
| `policy` | | Path to a JSON policy file. |
| `exclude` | | Newline-separated glob patterns to exclude. |
| `inline-ignores` | `false` | Honour `// qs-audit-ignore` comments in the scanned code. Off by default: in a gate for untrusted code a pull request could add one to pass its own check. |
| `allow-incomplete` | `false` | Accept a scan in which files were skipped (too large, unreadable, unparseable) or nothing was scanned. By default that is an error: an incomplete scan is never reported as a pass. |
| `version` | `0.1.0` | `quantum-safe-audit` version from npm. Defaults to the version the action release was made with; pin your own exact version in production. |
| `package-path` | | Run a locally built copy instead of npm (for monorepos and this repository's own CI). |

Outputs: `exit-code`, `findings`, `report-file`, `cbom-file`.

## Behaviour you can rely on

- The report is written and uploaded **even when the gate fails**; the job then fails with the scan's exit code.
- **The scanned code cannot rewrite its own gate.** `./.qs-audit.json` is *not* auto-loaded by the Action (a pull request could otherwise exclude its own files or ignore rules). Use the `policy` input with a file from a trusted ref, and require code-owner review for changes to it.
- **Default exclusions are listed, not hidden.** `node_modules`, `dist`, `build`, `vendor` and similar are skipped by default and each skipped directory is reported as a note (and as a SARIF notification); minified files likewise. Symbolic links to directories are errors; links to files are followed. `.github`, extensionless Node scripts (`#!/usr/bin/env node`) and `.html` pages are scanned. A file that must not be skipped can be forced with `--no-default-excludes` through the `policy` file.
- **An incomplete scan is an error.** A file padded past the size limit, an unreadable directory, a file that cannot be parsed, or a scan that covers no files makes the job fail (exit 2) unless you set `allow-incomplete`.
- Inputs are passed to the script as environment variables and validated. A pull request cannot inject shell through an input value,
  and `output` and `path` cannot escape the workspace. The runner script is tested against hostile input values.
- Third-party actions used by the action are pinned by commit SHA.
- The job summary states what the tool is not: an inventory, not a compliance verdict, and an empty result is not proof of absence.

::: warning Take the policy from a trusted ref
On a `pull_request` event the checked-out tree is the pull request's, so a `policy` file from it is attacker-controlled (it can `exclude` its own files or `ignoreRules`). Check out the base branch into a second path (`actions/checkout` with `ref: ${{ github.event.pull_request.base.sha }}` and `path: trusted`) and pass `policy: trusted/.qs-audit.json`. The scanner itself is installed outside the workspace, so a `node_modules/quantum-safe-audit` committed by a pull request is never used.
:::

::: tip Fork pull requests
Uploading SARIF needs a token with `security-events: write`, which read-only fork pull requests do not get. Run with `upload-sarif: false`
there; the gate and the job summary still work.
:::
