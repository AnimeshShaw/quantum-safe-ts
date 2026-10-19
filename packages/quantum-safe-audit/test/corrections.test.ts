/** Corrections found while documenting the scanner and its command line. */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanSource } from '../src/scanner.js';

const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const RSA = "const c = require('node:crypto');\nc.generateKeyPairSync('rsa', { modulusLength: 2048 });\n";

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'qs-fix-'));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}
const run = (cwd: string, ...args: string[]) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });

describe('package.json that is not JSON', () => {
  it('is an analysis error, not a clean file', () => {
    expect(() => scanSource('package.json', '{ "dependencies": ')).toThrow(/not valid JSON/);
  });
  it('a valid manifest still reports its dependencies', () => {
    const found = scanSource('package.json', JSON.stringify({ dependencies: { 'node-forge': '^1' } }));
    expect(found.map((f) => f.ruleId)).toEqual(['QSJ050']);
  });
});

describe.skipIf(!existsSync(cli))('command line (built dist/cli.js)', () => {
  it('a broken package.json makes the scan incomplete (exit 2), unless that is allowed', () => {
    const dir = project({ 'a.js': 'const x = 1;\n', 'package.json': '{ "name": ' });
    const r = run(dir, 'scan', '.', '--no-config');
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('incomplete');
    expect(run(dir, 'scan', '.', '--no-config', '--allow-incomplete').status).toBe(0);
  });

  it('an unknown option is a usage error and does not swallow the next argument', () => {
    const dir = project({ 'a.js': RSA });
    const r = run(dir, 'scan', '--cnsa', '.', '--no-config');
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Unknown option --cnsa');
  });

  it('a policy of the wrong shape is reported as an error (2), not as findings (1)', () => {
    const dir = project({ 'a.js': 'const x = 1;\n', 'policy.json': JSON.stringify({ exclude: 'x', ignoreRules: 5 }) });
    const r = run(dir, 'scan', '.', '--policy', 'policy.json');
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/Error|policy/i);
  });

  it('an unwritable --output is an error (2), not findings (1)', () => {
    const dir = project({ 'a.js': RSA });
    const r = run(dir, 'scan', '.', '--no-config', '--output', join(dir, 'missing-dir', 'out.txt'));
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Error');
  });

  it('findings still exit 1 and a clean scan 0', () => {
    expect(run(project({ 'a.js': RSA }), 'scan', '.', '--no-config').status).toBe(1);
    expect(run(project({ 'a.js': 'const x = 1;\n' }), 'scan', '.', '--no-config').status).toBe(0);
  });

  it('the help names every policy key and says an incomplete scan wins over findings', () => {
    const help = run(project({}), '--help').stdout;
    expect(help).toContain('noInlineIgnore');
    expect(help).toContain('noDefaultExcludes');
    expect(help).toContain('incomplete scan');
  });
});
