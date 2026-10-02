/**
 * Cross-process behaviour of FileMigrationStore and of MigrationStateManager on top of it, tested with real concurrent child processes.
 * The store is transpiled on the fly so this test does not depend on a build; the manager-level test uses the built package (dist/)
 * and is skipped when it has not been built.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const root = mkdtempSync(join(tmpdir(), 'qs-file-store-'));
const storeJs = join(root, 'file-store.mjs');
const dist = join(here, '..', 'dist');

function run(script: string, args: string[]): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out: out.trim(), err: err.trim() }));
  });
}

beforeAll(() => {
  const src = readFileSync(join(here, '..', 'src', 'file-store.ts'), 'utf8');
  const js = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
  writeFileSync(storeJs, js);
  writeFileSync(
    join(root, 'counter.mjs'),
    `import { FileMigrationStore } from ${JSON.stringify(pathToFileURL(storeJs).href)};
const [, , dir, n] = process.argv;
const s = new FileMigrationStore(dir);
for (let i = 0; i < Number(n); i++) {
  for (;;) {
    const v = await s.get('counter');
    if (await s.compareAndSet('counter', v, String(Number(v ?? '0') + 1))) break;
  }
}
`,
  );
  writeFileSync(
    join(root, 'transition.mjs'),
    `import { MigrationStateManager } from ${JSON.stringify(pathToFileURL(join(dist, 'node.js')).href)};
import { FileMigrationStore } from ${JSON.stringify(pathToFileURL(join(dist, 'file-store.js')).href)};
const [, , dir, who] = process.argv;
const m = new MigrationStateManager(new FileMigrationStore(dir));
try {
  await m.transition({ keyId: 'shared-key', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'X25519+ML-KEM-768', actor: who });
  console.log('won');
} catch (e) {
  console.log('lost:' + (e && e.name));
}
`,
  );
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('FileMigrationStore', () => {
  it('stores, reads and lists keys with awkward names; absent keys are undefined', async () => {
    const { FileMigrationStore } = (await import(pathToFileURL(storeJs).href)) as typeof import('../src/file-store.js');
    const dir = join(root, 'basic');
    const s = new FileMigrationStore(dir);
    expect(await s.get('missing')).toBeUndefined();
    expect(await s.keys()).toEqual([]);
    await s.set('a/b ünï', 'one');
    await s.set('../../escape', 'two'); // must stay inside the directory
    expect(await s.get('a/b ünï')).toBe('one');
    expect([...(await s.keys())].sort()).toEqual(['../../escape', 'a/b ünï']);
    expect(existsSync(join(root, 'escape'))).toBe(false);
    expect(await s.compareAndSet('a/b ünï', 'wrong', 'x')).toBe(false);
    expect(await s.compareAndSet('a/b ünï', 'one', 'three')).toBe(true);
    expect(await s.compareAndSet('fresh', undefined, 'v')).toBe(true);
    expect(await s.compareAndSet('fresh', undefined, 'v2')).toBe(false);
    expect(await s.get('a/b ünï')).toBe('three');
  });

  it('6 concurrent processes x 40 increments through compareAndSet: no lost update', async () => {
    const dir = join(root, 'counter');
    const results = await Promise.all(Array.from({ length: 6 }, () => run(join(root, 'counter.mjs'), [dir, '40'])));
    for (const r of results) expect(r, r.err).toMatchObject({ code: 0 });
    const { FileMigrationStore } = (await import(pathToFileURL(storeJs).href)) as typeof import('../src/file-store.js');
    expect(await new FileMigrationStore(dir).get('counter')).toBe('240');
  }, 120_000);

  it('breaks a stale lock left by a crashed process, and times out on a live one', async () => {
    const { FileMigrationStore } = (await import(pathToFileURL(storeJs).href)) as typeof import('../src/file-store.js');
    const dir = join(root, 'stale');
    const fast = new FileMigrationStore(dir, { staleLockMs: 200, lockTimeoutMs: 1500 });
    await fast.set('k', 'v0');
    const file = (await import('node:fs')).readdirSync(dir).find((n) => n.endsWith('.json'))!;
    const lock = join(dir, `${file}.lock`);
    mkdirSync(lock);
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);
    expect(await fast.compareAndSet('k', 'v0', 'v1')).toBe(true); // stale lock was broken
    // a fresh lock that is never released: must time out rather than hang or corrupt
    mkdirSync(lock);
    const patient = new FileMigrationStore(dir, { staleLockMs: 60_000, lockTimeoutMs: 300 });
    await expect(patient.compareAndSet('k', 'v1', 'v2')).rejects.toThrow(/timed out/);
    expect(await patient.get('k')).toBe('v1');
  });
});

describe('FileMigrationStore lock safety', () => {
  const load = async () => (await import(pathToFileURL(storeJs).href)) as typeof import('../src/file-store.js');

  it('a holder whose lock was taken over fails with "lock lost" instead of overwriting the new holder', async () => {
    const { FileMigrationStore } = await load();
    const dir = join(root, 'stolen');
    // A stalls inside the critical section (its read of the current value is slow)...
    class SlowStore extends FileMigrationStore {
      override async get(key: string): Promise<string | undefined> {
        const v = await super.get(key);
        await new Promise((r) => setTimeout(r, 400));
        return v;
      }
    }
    const slow = new SlowStore(dir, { lockTimeoutMs: 5000 });
    const other = new FileMigrationStore(dir, { lockTimeoutMs: 5000 });
    const fs = await import('node:fs');
    const pending = slow.compareAndSet('k', undefined, 'A');
    pending.catch(() => undefined);
    // ...and meanwhile its lock is broken (as a stale-lock breaker would) and another process takes over and writes.
    await new Promise((r) => setTimeout(r, 150));
    for (const n of fs.readdirSync(dir)) if (n.endsWith('.lock')) fs.rmSync(join(dir, n), { recursive: true, force: true });
    expect(await other.compareAndSet('k', undefined, 'B')).toBe(true);
    await expect(pending).rejects.toThrow(/lock was lost/);
    expect(await other.get('k')).toBe('B');
  });

  it('a slow but live holder keeps its lock (heartbeat), so two racers still produce exactly one winner', async () => {
    const { FileMigrationStore } = await load();
    const dir = join(root, 'slow-live');
    class SlowStore extends FileMigrationStore {
      override async get(key: string): Promise<string | undefined> {
        const v = await super.get(key);
        await new Promise((r) => setTimeout(r, 300));
        return v;
      }
    }
    const a = new SlowStore(dir, { staleLockMs: 90, lockTimeoutMs: 8000 });
    const b = new SlowStore(dir, { staleLockMs: 90, lockTimeoutMs: 8000 });
    const results = await Promise.all([a.compareAndSet('k', undefined, 'A'), b.compareAndSet('k', undefined, 'B')]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('keys that differ only by case never share a file (case-insensitive filesystems)', async () => {
    const { FileMigrationStore } = await load();
    const s = new FileMigrationStore(join(root, 'case'));
    await s.set('user@', 'one');
    await s.set('userZ', 'two');
    expect(await s.get('user@')).toBe('one');
    expect(await s.get('userZ')).toBe('two');
    expect([...(await s.keys())].sort()).toEqual(['user@', 'userZ']);
  });

  it('rejects over-long keys with a generic error, and keeps files and the directory private', async () => {
    const { FileMigrationStore } = await load();
    const dir = join(root, 'private');
    const s = new FileMigrationStore(dir);
    await expect(s.set('x'.repeat(500), 'v')).rejects.toThrow(/at most 120 bytes/);
    await s.set('k', 'v');
    if (process.platform !== 'win32') {
      const fs = await import('node:fs');
      expect(fs.statSync(dir).mode & 0o077).toBe(0);
      for (const n of fs.readdirSync(dir)) expect(fs.statSync(join(dir, n)).mode & 0o077).toBe(0);
    }
  });
});

describe.skipIf(!existsSync(join(dist, 'node.js')) || !existsSync(join(dist, 'file-store.js')))('MigrationStateManager over FileMigrationStore (built package)', () => {
  it('8 processes race the same transition: exactly one wins, history has one record', async () => {
    const dir = join(root, 'manager');
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => run(join(root, 'transition.mjs'), [dir, `p${i}`])));
    for (const r of results) expect(r, r.err).toMatchObject({ code: 0 });
    expect(results.filter((r) => r.out === 'won')).toHaveLength(1);
    expect(results.filter((r) => r.out.startsWith('lost:'))).toHaveLength(7);
    const { MigrationStateManager } = await import(pathToFileURL(join(dist, 'node.js')).href);
    const { FileMigrationStore } = await import(pathToFileURL(join(dist, 'file-store.js')).href);
    const m = new MigrationStateManager(new FileMigrationStore(dir));
    expect(m.crossProcessSafe).toBe(true);
    const hist = await m.getHistory('shared-key');
    expect(hist).toHaveLength(1);
    expect(hist[0].toState).toBe('hybrid_transition');
  }, 120_000);
});
