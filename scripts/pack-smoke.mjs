#!/usr/bin/env node
// Packs each package as `npm publish` would, installs the TARBALLS into an empty project (no workspace, no dev dependencies, no
// hoisting luck) and runs them. Catches what the unit tests cannot: a dependency that is only a devDependency, a file missing from `files`,
// a broken `exports` map, a `file:` dependency that cannot resolve from the registry.
//
//   node scripts/pack-smoke.mjs
//
// Requires the three packages to be built already (npm run build in each). Network access is needed for their npm dependencies.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const work = mkdtempSync(join(tmpdir(), 'qs-pack-smoke-'));
const shell = process.platform === 'win32';
const run = (cmd, args, cwd, extra = {}) => execFileSync(cmd, args, { cwd, encoding: 'utf8', shell, stdio: ['ignore', 'pipe', 'pipe'], ...extra });

function pack(name) {
  const dir = join(repo, 'packages', name);
  if (!existsSync(join(dir, 'dist'))) throw new Error(`${name} is not built (run npm run build in packages/${name})`);
  const out = run('npm', ['pack', '--ignore-scripts', '--pack-destination', work, '--json'], dir);
  const file = JSON.parse(out)[0].filename;
  console.log(`packed ${name}: ${file}`);
  return join(work, file);
}

let failures = 0;
const check = (label, ok, detail = '') => {
  console.log(`${ok ? 'ok   ' : 'FAIL '}${label}${ok ? '' : `  ${detail}`}`);
  if (!ok) failures++;
};

const tarballs = { ts: pack('quantum-safe-ts'), audit: pack('quantum-safe-audit'), mcp: pack('quantum-safe-mcp') };

// 1. The library: ESM, CJS, the file-store subpath, and a round trip, installed with nothing else around.
{
  const dir = join(work, 'lib');
  mkdirSync(dir);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'smoke-lib', version: '1.0.0', private: true }));
  run('npm', ['install', '--no-audit', '--no-fund', tarballs.ts], dir);
  writeFileSync(join(dir, 'esm.mjs'), "import { easy, QuantumSafeError } from 'quantum-safe-ts';\nimport { FileMigrationStore } from 'quantum-safe-ts/file-store';\nconst k = easy.generateEncryptionKeys();\nconsole.log(easy.decryptText(k.secretKey, easy.encrypt(k.publicKey, 'esm ok')), typeof FileMigrationStore, typeof QuantumSafeError);\n");
  writeFileSync(join(dir, 'cjs.cjs'), "const { easy } = require('quantum-safe-ts');\nconst { FileMigrationStore } = require('quantum-safe-ts/file-store');\nconst k = easy.generateEncryptionKeys();\nconsole.log(easy.decryptText(k.secretKey, easy.encrypt(k.publicKey, 'cjs ok')), typeof FileMigrationStore);\n");
  let out = run('node', ['esm.mjs'], dir);
  check('quantum-safe-ts: ESM import, round trip and file-store subpath', out.startsWith('esm ok function function'), out);
  out = run('node', ['cjs.cjs'], dir);
  check('quantum-safe-ts: CommonJS require, round trip and file-store subpath', out.startsWith('cjs ok function'), out);
  const files = readdirSync(join(dir, 'node_modules', 'quantum-safe-ts'));
  for (const f of ['README.md', 'LICENSE', 'NOTICE', 'llms.txt', 'llms-full.txt', 'dist']) check(`quantum-safe-ts tarball contains ${f}`, files.includes(f));
}

// 2. The scanner: must run from an empty project (typescript has to be a real dependency), and must find a real RSA call.
{
  const dir = join(work, 'audit');
  mkdirSync(join(dir, 'sample'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'smoke-audit', version: '1.0.0', private: true }));
  run('npm', ['install', '--no-audit', '--no-fund', tarballs.audit], dir);
  writeFileSync(join(dir, 'sample', 'a.js'), "const c = require('node:crypto');\nc.generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
  const cli = join(dir, 'node_modules', 'quantum-safe-audit', 'dist', 'cli.js');
  const help = run('node', [cli, '--help'], dir);
  check('quantum-safe-audit: --help runs from an empty project', help.includes('quantum-safe-audit'), help.slice(0, 80));
  let code = 0;
  let out = '';
  try {
    out = run('node', [cli, 'scan', 'sample', '--no-config'], dir);
  } catch (e) {
    code = e.status;
    out = String(e.stdout);
  }
  check('quantum-safe-audit: finds RSA key generation and exits 1', code === 1 && /QSJ001/.test(out), `exit ${code}: ${out.slice(0, 200)}`);
}

// 3. The MCP server: its dependency on the audit package is `file:` in the repository; a registry install would resolve a version range,
// so here the dependency is pointed at the audit tarball. Then speak MCP to it over stdio.
{
  const dir = join(work, 'mcp');
  mkdirSync(dir);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'smoke-mcp', version: '1.0.0', private: true, dependencies: { 'quantum-safe-audit': `file:${tarballs.audit}` } }));
  const extracted = join(work, 'mcp-extracted');
  mkdirSync(extracted);
  run('tar', ['-xzf', basename(tarballs.mcp), '-C', 'mcp-extracted'], work); // relative names: GNU tar reads 'C:' as a remote host
  const pkgPath = join(extracted, 'package', 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  pkg.dependencies['quantum-safe-audit'] = `file:${tarballs.audit}`;
  writeFileSync(pkgPath, JSON.stringify(pkg));
  // Repack the patched manifest (installing a directory would symlink it and skip its own dependencies).
  const repacked = join(work, JSON.parse(run('npm', ['pack', '--ignore-scripts', '--pack-destination', work, '--json'], join(extracted, 'package')))[0].filename);
  run('npm', ['install', '--no-audit', '--no-fund', repacked], dir);
  const server = spawn(process.execPath, [join(dir, 'node_modules', 'quantum-safe-mcp', 'dist', 'server.js')], { cwd: dir, stdio: ['pipe', 'pipe', 'pipe'] });
  const reply = await new Promise((res) => {
    let buf = '';
    const t = setTimeout(() => res(buf), 15000);
    server.stdout.on('data', (d) => {
      buf += d;
      if (buf.includes('\n')) {
        clearTimeout(t);
        res(buf);
      }
    });
    server.on('exit', () => res(buf));
    server.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } } }) + '\n');
  });
  server.kill();
  check('quantum-safe-mcp: starts from its tarball and answers initialize', String(reply).includes('"serverInfo"'), String(reply).slice(0, 200));
}

console.log(failures ? `\n${failures} check(s) failed` : '\nAll packed-tarball smoke checks passed.');
process.exit(failures ? 1 : 0);
