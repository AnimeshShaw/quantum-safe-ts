#!/usr/bin/env node
// Writes the artifact record of a release: what was built, from which commit and pins.
//
//   npm pack --workspaces --pack-destination dist-release       (or the release workflow's tarballs)
//   node scripts/artifact-record.mjs dist-release --out artifact-record-1.0.0.json
//
// For every .tgz in the directory it records the SHA-256 and size, plus the package versions, the git commit and tag, the SHA-256 of the
// WebAssembly module and of Cargo.lock, and the pinned Rust toolchain. Attach the file to the GitHub release; Zenodo archives the release
// and gives it a DOI, and the record lets anyone check a download against what the release says it contains. Nothing here is secret and
// nothing is signed: it is a plain statement of facts that `node scripts/repro-check.mjs` can be run against.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const git = (...args) => {
  try {
    return execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || 'unknown';
  } catch {
    return 'unknown';
  }
};

/** Builds the record for the tarballs in `dist`. Exported for the tests. */
export function buildRecord(dist, { created = new Date().toISOString() } = {}) {
  const artifacts = readdirSync(dist)
    .filter((f) => f.endsWith('.tgz'))
    .sort()
    .map((file) => ({ file, sha256: sha256(join(dist, file)), bytes: statSync(join(dist, file)).size }));
  const versions = {};
  for (const name of ['quantum-safe-ts', 'quantum-safe-audit', 'quantum-safe-mcp']) {
    const p = join(repo, 'packages', name, 'package.json');
    if (existsSync(p)) versions[name] = JSON.parse(readFileSync(p, 'utf8')).version;
  }
  const wasm = join(repo, 'packages', 'quantum-safe-ts', 'dist', 'quantum_safe_wasm_bg.wasm');
  const toolchain = join(repo, 'rust-toolchain.toml');
  const channel = existsSync(toolchain) ? (readFileSync(toolchain, 'utf8').match(/channel\s*=\s*"([^"]+)"/)?.[1] ?? 'unknown') : 'unknown';
  return {
    schema: 1,
    repository: 'quantum-safe-ts',
    versions,
    git_commit: git('rev-parse', 'HEAD'),
    git_tag: git('describe', '--tags', '--exact-match'),
    created,
    rust_toolchain: channel,
    cargo_lock_sha256: existsSync(join(repo, 'Cargo.lock')) ? sha256(join(repo, 'Cargo.lock')) : null,
    wasm_sha256: existsSync(wasm) ? sha256(wasm) : null,
    artifacts,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const dist = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--out');
  const outIdx = args.indexOf('--out');
  const out = outIdx === -1 ? null : args[outIdx + 1];
  if (!dist || !existsSync(dist) || !statSync(dist).isDirectory()) {
    console.error('usage: node scripts/artifact-record.mjs <directory with .tgz files> [--out file.json]');
    process.exit(2);
  }
  const record = buildRecord(dist);
  if (record.artifacts.length === 0) {
    console.error('no .tgz files found');
    process.exit(1);
  }
  const text = `${JSON.stringify(record, null, 2)}\n`;
  if (out) {
    writeFileSync(out, text);
    console.log(`wrote ${out}: ${record.artifacts.length} artifacts`);
  } else {
    process.stdout.write(text);
  }
}
