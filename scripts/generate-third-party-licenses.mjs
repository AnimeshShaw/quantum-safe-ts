#!/usr/bin/env node
// Generates THIRD_PARTY_LICENSES.md for every published npm package.
//
//   packages/quantum-safe-ts/THIRD_PARTY_LICENSES.md   the Rust crates compiled into the WebAssembly (same crate set as sbom/quantum-safe-ts.cdx.json:
//                                                      reachable from the bindings crate by normal dependencies), each with its licence expression,
//                                                      repository and the licence/notice files shipped in its source
//   packages/<other>/THIRD_PARTY_LICENSES.md           a short statement: no third-party code is bundled; runtime dependencies are installed by npm
//                                                      under their own licences
//
//   node scripts/generate-third-party-licenses.mjs           writes the files
//   node scripts/generate-third-party-licenses.mjs --check   fails if a file is missing or out of date (CI)
//
// Uses only `cargo metadata` (already used by scripts/generate-sboms.mjs); no extra tool. Requires the crates to be downloaded (cargo fetch / a build).
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const NL = String.fromCharCode(10);
const norm = (s) => s.split(String.fromCharCode(13) + NL).join(NL).trimEnd() + NL;

const meta = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--locked', '--filter-platform', 'wasm32-unknown-unknown'], { cwd: repo, maxBuffer: 1 << 28 }).toString('utf8'),
);
const byId = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const root = meta.packages.find((p) => p.name === 'quantum-safe-wasm');
if (!root) throw new Error('quantum-safe-wasm not found in cargo metadata');
const reach = new Set();
const stack = [root.id];
while (stack.length) {
  const id = stack.pop();
  if (reach.has(id)) continue;
  reach.add(id);
  for (const d of nodes.get(id)?.deps ?? []) if (d.dep_kinds.some((k) => k.kind === null)) stack.push(d.pkg);
}
const crates = [...reach]
  .map((id) => byId.get(id))
  .filter((p) => p.source) // registry crates only; the two workspace crates are this project (Apache-2.0)
  .sort((a, b) => (a.name + a.version).localeCompare(b.name + b.version));

const LICENSE_FILE = /^(licen[sc]e|copying|unlicense|notice)/i;
const entries = crates.map((p) => {
  const dir = dirname(p.manifest_path);
  const files = readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile() && LICENSE_FILE.test(e.name))
    .map((e) => e.name)
    .sort();
  return { p, files: files.map((name) => ({ name, text: norm(readFileSync(join(dir, name), 'utf8')) })) };
});

const missing = entries.filter((e) => e.files.length === 0).map((e) => `${e.p.name} ${e.p.version}`);

// Identical texts are printed once, with the list of crates that ship them.
const texts = new Map();
for (const e of entries) for (const f of e.files) {
  const t = texts.get(f.text) ?? { name: f.name, users: [] };
  t.users.push(`${e.p.name} ${e.p.version}`);
  texts.set(f.text, t);
}

const out = [];
out.push('# Third-party licenses', '');
out.push(`quantum-safe-ts is licensed under the Apache License 2.0 (see LICENSE and NOTICE). The WebAssembly module in this package is compiled from this`);
out.push(`project's Rust code together with the third-party Rust crates below, which are used under their own licenses. The Rust standard library`);
out.push(`(MIT OR Apache-2.0) is also linked into the module. The list is generated from Cargo.lock by scripts/generate-third-party-licenses.mjs and matches`);
out.push(`the CycloneDX SBOM in the repository (crates reachable from the WebAssembly bindings through normal dependencies).`, '');
out.push(`## Crates (${entries.length})`, '');
out.push('| Crate | Version | License | Repository |', '|---|---|---|---|');
for (const { p } of entries) out.push(`| ${p.name} | ${p.version} | ${p.license ?? 'see its license files'} | ${p.repository ?? ''} |`);
out.push('', '## License and notice texts', '');
out.push('Each distinct text is printed once, followed by the crates whose source ships it.', '');
for (const [text, t] of [...texts.entries()].sort((a, b) => a[1].users[0].localeCompare(b[1].users[0]))) {
  out.push('---', '', `### ${t.name}`, '', `Shipped by: ${t.users.join(', ')}`, '', '```text', text.trimEnd(), '```', '');
}
if (missing.length) {
  out.push('---', '', '## Crates that ship no license file in their source', '');
  out.push('These crates declare their license in Cargo.toml only (see the table above); the license text is the standard text of that license.', '');
  for (const m of missing) out.push(`- ${m}`);
  out.push('');
}
const rust = out.join(NL);

const statement = (name, deps) =>
  [
    '# Third-party licenses',
    '',
    `${name} is licensed under the Apache License 2.0 (see LICENSE and NOTICE). This package does not bundle or embed any third-party code.`,
    deps.length
      ? `Its runtime dependencies (${deps.join(', ')}) are installed separately by npm and are used under their own licenses; see each package for its license.`
      : 'It has no runtime dependencies.',
    '',
  ].join(NL);

const targets = [['packages/quantum-safe-ts', rust]];
for (const dir of ['quantum-safe-audit', 'quantum-safe-mcp', 'pqc-audit', 'pqc-mcp']) {
  const pkg = JSON.parse(readFileSync(join(repo, 'packages', dir, 'package.json'), 'utf8'));
  targets.push([`packages/${dir}`, statement(pkg.name, Object.keys(pkg.dependencies ?? {}))]);
}

let stale = 0;
for (const [dir, content] of targets) {
  const file = join(repo, dir, 'THIRD_PARTY_LICENSES.md');
  const want = norm(content);
  if (check) {
    const have = existsSync(file) ? norm(readFileSync(file, 'utf8')) : null;
    if (have !== want) {
      console.error(`${dir}/THIRD_PARTY_LICENSES.md is ${have === null ? 'missing' : 'out of date'}; run: node scripts/generate-third-party-licenses.mjs`);
      stale++;
    }
  } else {
    writeFileSync(file, want);
    console.log(`wrote ${dir}/THIRD_PARTY_LICENSES.md`);
  }
}
console.log(`${entries.length} crates; ${missing.length} without a license file in their source${missing.length ? ': ' + missing.join(', ') : ''}`);
if (stale) process.exit(1);
