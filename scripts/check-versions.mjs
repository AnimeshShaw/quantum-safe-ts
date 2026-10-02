#!/usr/bin/env node
// Fails if values that must agree have drifted apart: the audit tool version (package.json, cli.ts, action.yml default) and the Rust
// toolchain (rust-toolchain.toml versus the toolchain named anywhere else in the workflows).
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');
const problems = [];

const auditVersion = JSON.parse(read('packages/quantum-safe-audit/package.json')).version;
const cliVersion = /const VERSION = '([^']+)'/.exec(read('packages/quantum-safe-audit/src/cli.ts'))?.[1];
const actionDefault = /version:\n\s+description: [^\n]*\n\s+default: '([^']+)'/.exec(read('action.yml'))?.[1];
if (cliVersion !== auditVersion) problems.push(`cli.ts VERSION ${cliVersion} != audit package.json ${auditVersion}`);
if (actionDefault !== auditVersion) problems.push(`action.yml default version ${actionDefault} != audit package.json ${auditVersion}`);

const channel = /channel = "([^"]+)"/.exec(read('rust-toolchain.toml'))?.[1];
for (const f of ['.github/workflows/ci.yml', '.github/workflows/release.yml', '.github/workflows/docs.yml']) {
  for (const m of read(f).matchAll(/rust-toolchain@([0-9][^\s]*)/g)) if (m[1] !== channel) problems.push(`${f} names toolchain ${m[1]} but rust-toolchain.toml pins ${channel}`);
}
for (const pkg of ['quantum-safe-ts', 'quantum-safe-audit', 'quantum-safe-mcp']) {
  const v = JSON.parse(read(`packages/${pkg}/package.json`)).version;
  if (v !== '0.1.0') problems.push(`${pkg} is ${v}; update this script, CHANGELOG and action.yml together when versions move`);
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`versions agree (audit ${auditVersion}, rust ${channel})`);
