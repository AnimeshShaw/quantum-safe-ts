/**
 * The CI gate must not be bypassable by the code it checks: an incomplete scan is an error, auto-loaded config can be disabled, and the
 * SARIF output says when a scan was incomplete.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const RSA = "const c = require('node:crypto');\nc.generateKeyPairSync('rsa', { modulusLength: 2048 });\n";

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'qs-gate-'));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}
const run = (cwd: string, ...args: string[]) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });

describe.skipIf(!existsSync(cli))('scan gate', () => {
  it('padding a file past the size limit cannot make the scan pass', () => {
    const dir = project({ 'a.js': RSA + '//' + 'x'.repeat(1_100_000), 'b.js': 'const x = 1;\n' });
    const r = run(dir, 'scan', '.', '--fail-on', 'low');
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('incomplete');
    expect(run(dir, 'scan', '.', '--fail-on', 'low', '--allow-incomplete').status).toBe(0);
  });

  it('a scan that covers no files is an error, not a pass', () => {
    const dir = project({ 'a.js': RSA });
    const r = run(dir, 'scan', '.', '--exclude', '**');
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('No files were scanned');
  });

  it('a policy file in the scanned tree can be ignored with --no-config', () => {
    const dir = project({ 'a.js': RSA, '.qs-audit.json': JSON.stringify({ ignoreRules: ['QSJ001', 'QSJ010'], failOn: 'none' }) });
    expect(run(dir, 'scan', '.').status).toBe(0); // auto-loaded policy silences the finding (documented)
    expect(run(dir, 'scan', '.', '--no-config').status).toBe(1); // the gate cannot be edited away by the checked code
  });

  it('SARIF reports an incomplete scan in invocations', () => {
    const dir = project({ 'a.js': RSA + '//' + 'x'.repeat(1_100_000) });
    const r = run(dir, 'scan', '.', '--format', 'sarif', '--allow-incomplete');
    const sarif = JSON.parse(r.stdout);
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(false);
    expect(sarif.runs[0].invocations[0].toolExecutionNotifications.length).toBe(1);
  });

  it('hidden-by-default places are scanned or reported: .github, node shebang scripts, html, inline ignores', () => {
    const dir = project({
      '.github/scripts/release.js': RSA,
      'bin/tool': '#!/usr/bin/env node\n' + RSA,
      'page.html': '<script>' + RSA + '</script>',
      'ok.js': 'export const x = 1;\n',
    });
    const r = run(dir, 'scan', '.', '--no-config', '--format', 'json');
    const files = new Set(JSON.parse(r.stdout).findings.map((f: { file: string }) => f.file));
    expect(files).toContain('.github/scripts/release.js');
    expect(files).toContain('bin/tool');
    expect(files).toContain('page.html');
  });

  it('inline ignores can be disabled for untrusted code, and suppressions are counted', () => {
    const dir = project({ 'a.js': '// qs-audit-ignore-file QSJ001 QSJ010\n' + RSA });
    expect(run(dir, 'scan', '.', '--no-config').status).toBe(0);
    expect(run(dir, 'scan', '.', '--no-config').stdout).toContain('suppressed');
    expect(run(dir, 'scan', '.', '--no-config', '--no-inline-ignore').status).toBe(1);
  });

  it('default exclusions and minified files are listed as notes, and --no-default-excludes scans them', () => {
    const dir = project({ 'ok.js': 'export const x = 1;\n', 'vendor/lib.js': RSA, 'x.min.js': RSA });
    const r = run(dir, 'scan', '.', '--no-config');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('not scanned (default exclusion): vendor/');
    expect(r.stdout).toContain('not scanned (minified): x.min.js');
    expect(run(dir, 'scan', '.', '--no-config', '--no-default-excludes').status).toBe(1);
  });

  it('prototype-key severities do not disable the gate, and scan --format cbom is gated', () => {
    const dir = project({ 'a.js': RSA });
    expect(run(dir, 'scan', '.', '--no-config', '--fail-on', 'constructor').status).toBe(2);
    expect(run(dir, 'scan', '.', '--no-config', '--format', 'cbom').status).toBe(1);
    expect(run(dir, 'cbom', '.', '--no-config').status).toBe(0);
  });

  it('a clean complete scan still exits 0', () => {
    const dir = project({ 'a.js': 'export const x = 1;\n' });
    expect(run(dir, 'scan', '.', '--fail-on', 'low').status).toBe(0);
  });
});
