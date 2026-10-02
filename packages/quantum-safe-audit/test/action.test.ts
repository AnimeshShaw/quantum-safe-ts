/**
 * Tests the GitHub Action's runner script (action/run.sh) end to end against a built CLI, including that hostile input values
 * (which a pull request could control) are treated as data and never executed.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, '..');
const script = join(here, '..', '..', '..', 'action', 'run.sh');
const hasBash = spawnSync('bash', ['--version']).status === 0;
const built = existsSync(join(pkg, 'dist', 'cli.js'));

function run(env: Partial<Record<string, string>>) {
  const work = mkdtempSync(join(tmpdir(), 'qs-action-'));
  mkdirSync(join(work, 'src'));
  writeFileSync(join(work, 'src', 'a.js'), "const c = require('node:crypto');\nc.generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
  const out = join(work, 'gh_output');
  const sum = join(work, 'gh_summary');
  writeFileSync(out, '');
  const r = spawnSync('bash', [script], {
    cwd: work,
    encoding: 'utf8',
    env: { ...process.env, QS_PACKAGE_PATH: pkg.split(sep).join('/'), QS_PATH: 'src', GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: sum, ...env },
  });
  const outputs = Object.fromEntries(readFileSync(out, 'utf8').split('\n').filter(Boolean).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  return { work, status: r.status, stdout: r.stdout, stderr: r.stderr, outputs, summary: existsSync(sum) ? readFileSync(sum, 'utf8') : '' };
}

describe.skipIf(!hasBash || !built)('GitHub Action runner', () => {
  it('reports findings, writes SARIF and publishes outputs (exit code is deferred to the gate step)', () => {
    const r = run({});
    expect(r.status).toBe(0);
    expect(r.outputs['exit-code']).toBe('1');
    expect(Number(r.outputs.findings)).toBeGreaterThan(0);
    const sarif = JSON.parse(readFileSync(join(r.work, r.outputs['report-file']!), 'utf8'));
    expect(sarif.version).toBe('2.1.0');
    expect(r.summary).toContain('not a compliance verdict');
    expect(r.stdout).toContain('::warning');
  });

  it('fail-on none passes; cbom output is produced on request', () => {
    const r = run({ QS_FAIL_ON: 'none', QS_CBOM: 'true' });
    expect(r.outputs['exit-code']).toBe('0');
    const cbom = JSON.parse(readFileSync(join(r.work, 'quantum-safe-cbom.json'), 'utf8'));
    expect(cbom.bomFormat).toBe('CycloneDX');
  });

  it('rejects invalid inputs with exit 2', () => {
    for (const env of [
      { QS_FAIL_ON: 'whenever' },
      { QS_FORMAT: 'xml' },
      { QS_VERSION: '1.0.0; touch pwned' },
      { QS_VERSION: '$(touch pwned)' },
      { QS_OUTPUT: '../escape.sarif' },
      { QS_OUTPUT: '/abs/out.sarif' },
      { QS_PATH: '../..' },
      { QS_PATH: '/etc' },
    ]) {
      const r = run(env);
      expect(r.status, JSON.stringify(env)).toBe(2);
      expect(r.stdout).toContain('::error');
    }
  });

  it('rejects control characters in inputs (a newline would forge extra output lines)', () => {
    for (const env of [{ QS_OUTPUT: 'r.json' + String.fromCharCode(10) + 'exit-code=0' }, { QS_PATH: 'src' + String.fromCharCode(10) }, { QS_POLICY: 'p' + String.fromCharCode(13) }]) {
      const r = run(env);
      expect(r.status, JSON.stringify(env)).toBe(2);
    }
  });

  it('ignores inline suppression comments by default (a PR could add one to pass its own check)', () => {
    const ignored = { 'QS_PATH': 'src' };
    const r = run(ignored);
    expect(r.outputs['exit-code']).toBe('1');
    const dir = r.work;
    writeFileSync(join(dir, 'src', 'a.js'), '// qs-audit-ignore-file' + String.fromCharCode(10) + "require('node:crypto').generateKeyPairSync('rsa', { modulusLength: 2048 });" + String.fromCharCode(10));
    const out = join(dir, 'o2');
    writeFileSync(out, '');
    const again = spawnSync('bash', [script], { cwd: dir, encoding: 'utf8', env: { ...process.env, QS_PACKAGE_PATH: pkg.split(sep).join('/'), QS_PATH: 'src', GITHUB_OUTPUT: out } });
    expect(again.status).toBe(0);
    expect(readFileSync(out, 'utf8')).toContain('exit-code=1');
    const opted = spawnSync('bash', [script], { cwd: dir, encoding: 'utf8', env: { ...process.env, QS_PACKAGE_PATH: pkg.split(sep).join('/'), QS_PATH: 'src', QS_INLINE_IGNORES: 'true', GITHUB_OUTPUT: out } });
    expect(opted.status).toBe(0);
    expect(readFileSync(out, 'utf8')).toContain('exit-code=0');
  });

  it('fails the step (70) if it cannot write its outputs, instead of letting the gate be skipped', () => {
    const r = run({ GITHUB_OUTPUT: '/nonexistent-dir-for-test/out' });
    expect(r.status).toBe(70);
  });

  it('never executes shell metacharacters supplied in free-text inputs', () => {
    const r = run({ QS_EXCLUDE: '$(touch pwned)\n`touch pwned2`\n; touch pwned3', QS_POLICY: '' });
    expect(existsSync(join(r.work, 'pwned'))).toBe(false);
    expect(existsSync(join(r.work, 'pwned2'))).toBe(false);
    expect(existsSync(join(r.work, 'pwned3'))).toBe(false);
    expect(r.outputs['exit-code']).toBe('1');
  });
});
