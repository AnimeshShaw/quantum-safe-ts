# Publishing to npm and GitHub: what you need to do

Nothing in this repository publishes anything automatically. Publishing stays a deliberate, manual step. This page is the whole
procedure. Everything marked **You** requires your npm/GitHub credentials; everything else is already done.

## 0. What is ready

| Package | npm name | Status |
|---|---|---|
| `packages/quantum-safe-ts` | `quantum-safe-ts` | Builds, tests pass, fixtures green. **The name was unclaimed on 2026-10-02** (re-check below). |
| `packages/quantum-safe-audit` | `quantum-safe-audit` | Builds, tests pass. |
| `packages/quantum-safe-mcp` | `quantum-safe-mcp` | Builds, tests pass. Depends on `quantum-safe-audit`. |

Publish in this order: **audit → quantum-safe-ts → mcp** (mcp depends on audit; the main package has no npm dependency on the others).

## 1. One-time setup (You)

1. Create or use an npm account with **2FA enabled** (`npm profile enable-2fa auth-and-writes`).
2. Check the names are still free (a 404 means free):
   ```bash
   for p in quantum-safe-ts quantum-safe-audit quantum-safe-mcp; do printf "$p -> "; curl -s -o /dev/null -w "%{http_code}\n" https://registry.npmjs.org/$p; done
   ```
   If one is taken, decide on a scope (for example `@animeshshaw/quantum-safe-ts`), change `"name"` in that package's `package.json`, and update
   the install snippets in `README.md`, `llms.txt`, `llms-full.txt` and the MCP knowledge file (a test guards the docs/code sync).
3. Decide whether to publish a **0.0.x placeholder first**. Recommendation: **do not**. Publish a real `0.1.0` directly. A placeholder would
   put an unfinished version in front of agents and humans, and npm's unpublish window is short.

## 2. Pre-flight (You, local machine, ~10 minutes)

```bash
git pull origin master
# CI must be green on GitHub for the commit you are releasing:
gh run list --limit 3

# Rewrite the MCP package's dependency on the audit tool from a local file path to a version range
node scripts/prepare-release.mjs

# quantum-safe-ts (needs Rust, wasm-pack, Node 18+)
cd packages/quantum-safe-ts && npm ci && npm run build && npm run typecheck && npx vitest run && node scripts/check-size.mjs
npm pack --dry-run        # review the file list: dist/, llms*.txt, README.md, LICENSE, NOTICE only; no tests, no wasm/ sources

cd ../quantum-safe-audit && npm ci && npm run build && npx vitest run && npm pack --dry-run
cd ../quantum-safe-mcp && npm ci && npm run build && npx vitest run && npm pack --dry-run
```

Then run the framework fixtures against the tarball once more (needs Playwright browsers; see `tests/fixtures/run.mjs`):

```bash
node tests/fixtures/run.mjs
```

## 3. Publish (You)

```bash
cd packages/quantum-safe-audit && npm publish --access public      # prompts for your 2FA code
cd ../quantum-safe-ts          && npm publish --access public
cd ../quantum-safe-mcp         && npm publish --access public
```

`prepack` rebuilds each package, so `npm publish` ships a fresh build.

### Preferred: publish from GitHub Actions with provenance

npm **provenance** links the tarball to the exact commit and workflow that built it. `.github/workflows/release.yml` does this
(manual trigger only):

1. Create an **automation** access token on npmjs.com (Access Tokens → Generate → Granular, publish rights for the three packages)
   and save it as the repository secret **`NPM_TOKEN`** (Settings → Secrets and variables → Actions).
2. Actions → **Release** → Run workflow → choose the package (`audit`, `quantum-safe-ts` or `mcp`). Run them in the order above.
3. Check the package page for the "Built and signed on GitHub Actions" badge.

## 4. Post-publish checklist (You)

```bash
# Verify from a clean directory, exactly as a user would:
mkdir /tmp/qs-check && cd /tmp/qs-check && npm init -y >/dev/null
npm install quantum-safe-ts quantum-safe-audit quantum-safe-mcp
node -e "import('quantum-safe-ts').then(q => console.log(new q.HybridKEM().algorithm))"
npx quantum-safe-audit --version
```

- Tag the release: `git tag v0.1.0 && git push origin v0.1.0`, then create a GitHub Release (notes from `CHANGELOG.md`).
- Make the repository public-facing: description, topics (`post-quantum`, `pqc`, `ml-kem`, `ml-dsa`, `webassembly`, `typescript`, `cnsa-2.0`,
  `mcp`), social preview. Enable GitHub Private Vulnerability Reporting (Settings → Security) so `SECURITY.md` works.
- Discoverability: submit `quantum-safe-mcp` to the MCP registry and community lists; request a Context7 listing for the repository.
  (No hidden agent-directed text anywhere: everything an agent reads is visible and factual.)
- Optionally publish the crate: not recommended yet (`quantum-safe-core` depends on a pinned pre-release `signature` for `slh-dsa`; see
  `Cargo.lock`). npm is the supported distribution.

## 5. If something goes wrong

- **Never** run `npm publish` for a version whose CI is red.
- A bad release cannot be overwritten. Within 72 hours `npm unpublish quantum-safe-ts@0.1.0` is possible; after that publish a patched
  version and `npm deprecate quantum-safe-ts@0.1.0 "use 0.1.1"`.
- Security issue found after release: follow `SECURITY.md`, publish a fixed version, deprecate the affected range, open a GitHub Security Advisory.
