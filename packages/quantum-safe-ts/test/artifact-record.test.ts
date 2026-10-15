/** scripts/artifact-record.mjs: the per-release record of what was built and from what. */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const script = pathToFileURL(join(here, '..', '..', '..', 'scripts', 'artifact-record.mjs')).href;
const dir = mkdtempSync(join(tmpdir(), 'qs-record-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('artifact record', () => {
  it('lists each tarball with its SHA-256, and the versions and pins', async () => {
    writeFileSync(join(dir, 'quantum-safe-ts-0.2.0.tgz'), 'tarball bytes');
    writeFileSync(join(dir, 'notes.txt'), 'ignored');
    const { buildRecord } = (await import(script)) as { buildRecord: (d: string, o?: { created?: string }) => Record<string, unknown> };
    const record = buildRecord(dir, { created: '2026-10-15T00:00:00.000Z' }) as {
      artifacts: Array<{ file: string; sha256: string; bytes: number }>;
      versions: Record<string, string>;
      schema: number;
      created: string;
      rust_toolchain: string;
    };
    expect(record.artifacts).toHaveLength(1);
    expect(record.artifacts[0]).toEqual({
      file: 'quantum-safe-ts-0.2.0.tgz',
      sha256: createHash('sha256').update('tarball bytes').digest('hex'),
      bytes: 'tarball bytes'.length,
    });
    expect(record.schema).toBe(1);
    expect(Object.keys(record.versions)).toContain('quantum-safe-ts');
    expect(record.created).toBe('2026-10-15T00:00:00.000Z');
    expect(record.rust_toolchain).not.toBe('unknown');
  });
});
