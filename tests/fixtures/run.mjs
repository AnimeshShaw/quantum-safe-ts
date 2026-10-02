#!/usr/bin/env node
// Fixture matrix driver. For each fixture: pack the package once, install the tarball into a fresh
// copy of the fixture, build it with the real toolchain, run the shared smoke test.
//
//   node tests/fixtures/run.mjs [fixture ...]     (default: all)
//
// A runtime/framework appears in the README support table ONLY if its fixture is green in CI.
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');
const pkgDir = join(repo, 'packages', 'quantum-safe-ts');
const work = join(here, '.work');
const isWin = process.platform === 'win32';

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: isWin, ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed (${r.status})`);
}

const all = readdirSync(here, { withFileTypes: true })
  .filter((d) => d.isDirectory() && d.name !== 'shared' && !d.name.startsWith('.'))
  .map((d) => d.name)
  .sort();
const wanted = process.argv.slice(2);
const names = wanted.length ? wanted : all;

rmSync(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 500 });
mkdirSync(work, { recursive: true });
console.log('Packing quantum-safe-ts ...');
const packOut = execFileSync('npm', ['pack', '--pack-destination', work, '--silent'], { cwd: pkgDir, shell: isWin }).toString().trim().split('\n').pop();
const tarball = join(work, packOut);
console.log('tarball:', tarball);

const results = [];
for (const name of names) {
  const src = join(here, name);
  if (!existsSync(join(src, 'fixture.json'))) { results.push([name, 'SKIP (no fixture.json)']); continue; }
  const meta = JSON.parse(readFileSync(join(src, 'fixture.json'), 'utf8'));
  const dir = join(work, name);
  cpSync(src, dir, { recursive: true });
  cpSync(join(here, 'shared'), join(dir, 'shared'), { recursive: true });
  // Point the fixture at the packed tarball.
  const pj = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  pj.dependencies = { ...(pj.dependencies ?? {}), 'quantum-safe-ts': `file:${tarball.split(String.fromCharCode(92)).join('/')}` };
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pj, null, 2));
  console.log(`\n===== ${name}: ${meta.description} =====`);
  try {
    sh('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: dir });
    for (const step of meta.steps ?? []) sh(step[0], step.slice(1), { cwd: dir });
    results.push([name, 'PASS']);
  } catch (e) {
    results.push([name, `FAIL: ${e.message}`]);
  }
}
console.log('\n===== fixture matrix =====');
for (const [n, r] of results) console.log(`${r.startsWith('PASS') ? 'PASS' : r.startsWith('SKIP') ? 'SKIP' : 'FAIL'}  ${n}${r.startsWith('FAIL') ? '  -> ' + r : ''}`);
process.exit(results.some(([, r]) => r.startsWith('FAIL')) ? 1 : 0);
