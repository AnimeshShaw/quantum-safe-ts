#!/usr/bin/env node
// Release helper. Run before publishing.
//
//   node scripts/prepare-release.mjs            checks versions and rewrites quantum-safe-mcp's dependency on
//                                                quantum-safe-audit from `file:../quantum-safe-audit` to `^<version>`
//   node scripts/prepare-release.mjs --restore  puts the `file:` path back for local development
//
// The MCP package must never be published with a `file:` dependency (npm would ship a path that does not exist).
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => JSON.parse(readFileSync(resolve(root, p), 'utf8'));
const write = (p, v) => writeFileSync(resolve(root, p), JSON.stringify(v, null, 2) + '\n');

const core = read('packages/quantum-safe-ts/package.json');
const audit = read('packages/quantum-safe-audit/package.json');
const mcp = read('packages/quantum-safe-mcp/package.json');
const alias = read('packages/pqc-audit/package.json');
const restore = process.argv.includes('--restore');

if (restore) {
  mcp.dependencies['quantum-safe-audit'] = 'file:../quantum-safe-audit';
  write('packages/quantum-safe-mcp/package.json', mcp);
  console.log('restored the local file: dependency in quantum-safe-mcp');
  process.exit(0);
}

const problems = [];
for (const [name, pkg] of [['quantum-safe-ts', core], ['quantum-safe-audit', audit], ['quantum-safe-mcp', mcp], ['pqc-audit', alias]]) {
  if (!/^\d+\.\d+\.\d+$/.test(pkg.version)) problems.push(`${name}: version '${pkg.version}' is not a plain x.y.z (no prerelease tags in a release)`);
  if (pkg.license !== 'Apache-2.0') problems.push(`${name}: license must be Apache-2.0`);
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}

mcp.dependencies['quantum-safe-audit'] = `^${audit.version}`;
write('packages/quantum-safe-mcp/package.json', mcp);
console.log(`quantum-safe-mcp now depends on quantum-safe-audit@^${audit.version}`);
console.log('\nPublish order: audit -> quantum-safe-ts -> mcp -> pqc-audit');
console.log(`  quantum-safe-audit  ${audit.version}\n  quantum-safe-ts     ${core.version}\n  pqc-audit           ${alias.version}
  quantum-safe-mcp    ${mcp.version}`);
console.log('\nAfter publishing, run:  node scripts/prepare-release.mjs --restore');
