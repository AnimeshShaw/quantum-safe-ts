#!/usr/bin/env node
// Reproducible-build check for the WASM artifact.
//
//   node scripts/repro-check.mjs [--keep]
//
// Copies the working tree (tracked and untracked-but-not-ignored files) into two directories with DIFFERENT paths, builds the WASM in
// each with the same pinned toolchain, and compares SHA-256 of the outputs: the raw cargo .wasm, the final
// wasm-bindgen/wasm-opt .wasm, and the JS glue. Identical hashes mean the artifact does not depend on the checkout path or build time.
//
// What this proves and does not prove: same source + same toolchain + same flags -> same bytes, on this machine type. It does not
// prove the toolchain itself is trustworthy, nor that a different OS gives the same bytes (path separators are embedded, so build the release artifact on one designated platform;
// CI runs this check on that platform).
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir, userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const keep = process.argv.includes('--keep');
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const sh = (cmd, args, cwd, env = {}) =>
  execFileSync(cmd, args, { cwd, stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, ...env }, shell: process.platform === 'win32' });

const files = execFileSync('git', ['ls-files', '-co', '--exclude-standard', '-z'], { cwd: repo, maxBuffer: 1 << 28 })
  .toString('utf8')
  .split('\0')
  .filter(Boolean);

const base = mkdtempSync(join(tmpdir(), 'qs-repro-'));
const dirs = [join(base, 'a', 'one'), join(base, 'bb', 'deeper', 'two')];
const results = [];
for (const dir of dirs) {
  mkdirSync(dir, { recursive: true });
  for (const f of files) {
    const src = join(repo, f);
    if (!existsSync(src)) continue;
    const dst = join(dir, f);
    mkdirSync(dirname(dst), { recursive: true });
    cpSync(src, dst);
  }
  console.log(`\n=== building in ${dir}`);
  // The ordinary build script (the same one `npm run build` runs) remaps the checkout and Cargo home, so the only thing set here is a
  // separate target directory inside each copy.
  const env = { CARGO_TARGET_DIR: join(dir, 'target'), SOURCE_DATE_EPOCH: '1700000000' };
  sh('node', ['packages/quantum-safe-ts/scripts/build-wasm.mjs'], dir, env);
  // The artifact must not contain the checkout path, the Cargo home or the user name.
  const wasmBytes = readFileSync(join(dir, 'packages', 'quantum-safe-ts', 'wasm', 'quantum_safe_wasm_bg.wasm'));
  const needles = [dir, process.env.CARGO_HOME ?? join(homedir(), '.cargo'), userInfo().username].filter((x) => x && x.length > 3);
  const leaked = needles.filter((n) => wasmBytes.includes(Buffer.from(n)));
  if (leaked.length) {
    console.log(`LEAK: the WebAssembly contains host-specific strings: ${leaked.join(', ')}`);
    process.exitCode = 1;
  }
  results.push({
    dir,
    rawWasm: sha(join(dir, 'target', 'wasm32-unknown-unknown', 'release', 'quantum_safe_wasm.wasm')),
    finalWasm: sha(join(dir, 'packages', 'quantum-safe-ts', 'wasm', 'quantum_safe_wasm_bg.wasm')),
    glue: sha(join(dir, 'packages', 'quantum-safe-ts', 'wasm', 'quantum_safe_wasm.js')),
  });
}

console.log('\n=== results');
let same = true;
for (const key of ['rawWasm', 'finalWasm', 'glue']) {
  const a = results[0][key];
  const b = results[1][key];
  const ok = a === b;
  same &&= ok;
  console.log(`${ok ? 'IDENTICAL' : 'DIFFERENT'}  ${key.padEnd(10)} ${a}${ok ? '' : `\n                      ${b}`}`);
}
if (!keep) rmSync(base, { recursive: true, force: true });
else console.log(`kept ${base}`);
console.log(same ? '\nReproducible: both builds are byte-identical.' : '\nNOT reproducible: see DIFFERENT rows.');
process.exit(same && !process.exitCode ? 0 : 1);
