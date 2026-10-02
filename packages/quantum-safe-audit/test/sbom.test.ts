import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assessComponent, enrichSbom, npmNameOf } from '../src/sbom.js';

const bom = () => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  components: [
    { type: 'library', name: 'node-forge', version: '1.3.1', purl: 'pkg:npm/node-forge@1.3.1' },
    { type: 'library', group: '@noble', name: 'post-quantum', version: '0.7.1', purl: 'pkg:npm/%40noble/post-quantum@0.7.1' },
    { type: 'library', name: 'openpgp', version: '5.11.0' },
    { type: 'library', name: 'openpgp', version: '6.1.0', properties: [{ name: 'keep', value: 'me' }] },
    { type: 'library', name: 'left-pad', version: '1.3.0' },
    { type: 'library', name: 'cryptography', version: '44.0.0', purl: 'pkg:pypi/cryptography@44.0.0' },
    { type: 'library', name: 'crypto-js', version: '4.2.0', components: [{ type: 'library', name: 'elliptic', version: '6.5.0' }] },
    { type: 'library', name: '__proto__', version: '1.0.0' },
  ],
});

describe('SBOM enrichment', () => {
  it('assesses known libraries by name, scoped names and version', () => {
    const r = enrichSbom(bom());
    const by = (n: string, v?: string) => r.assessments.find((a) => a.name === n && (v === undefined || a.version === v))!;
    expect(by('node-forge').readiness).toBe('NOT_READY');
    expect(by('@noble/post-quantum').readiness).toBe('READY');
    expect(by('openpgp', '5.11.0').readiness).toBe('NOT_READY');
    expect(by('openpgp', '6.1.0').readiness).toBe('PARTIAL');
    expect(by('crypto-js').readiness).toBe('NOT_APPLICABLE');
    expect(by('elliptic').readiness).toBe('NOT_READY'); // nested component
    expect(by('left-pad').readiness).toBe('UNKNOWN'); // no record is never READY
    expect(by('__proto__').readiness).toBe('UNKNOWN'); // prototype keys are not records
  });

  it('skips non-npm components and keeps existing properties; the input is not modified', () => {
    const input = bom();
    const snapshot = JSON.stringify(input);
    const r = enrichSbom(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(r.assessments.some((a) => a.name === 'cryptography')).toBe(false);
    const comps = (r.bom.components as Array<{ name: string; version: string; properties?: Array<{ name: string; value: string }> }>);
    const o6 = comps.find((c) => c.name === 'openpgp' && c.version === '6.1.0')!;
    expect(o6.properties![0]).toEqual({ name: 'keep', value: 'me' });
    expect(o6.properties!.map((p) => p.name)).toContain('quantum-safe:pqc-readiness');
    const py = comps.find((c) => c.name === 'cryptography')!;
    expect(py.properties).toBeUndefined();
    expect(JSON.stringify((r.bom.metadata as { properties: unknown }).properties)).toContain('not a compliance verdict'.replace('not', 'Not'));
  });

  it('summary counts add up; purl parsing handles scopes and garbage', () => {
    const r = enrichSbom(bom());
    expect(Object.values(r.summary).reduce((a, b) => a + b, 0)).toBe(r.assessments.length);
    expect(npmNameOf({ purl: 'pkg:npm/%40a/b@1.0.0?x=y' })).toBe('@a/b');
    expect(npmNameOf({ purl: 'pkg:npm/%E0%A4%A@1' })).toBeUndefined();
    expect(npmNameOf({ name: 'x', group: '@g' })).toBe('@g/x');
    expect(npmNameOf({})).toBeUndefined();
    expect(assessComponent('constructor').readiness).toBe('UNKNOWN');
  });

  it('rejects non-CycloneDX input', () => {
    for (const bad of [null, 5, 'x', {}, { bomFormat: 'SPDX' }]) expect(() => enrichSbom(bad)).toThrow(/CycloneDX/);
  });

  it('CLI: reads a file, writes enriched JSON, exits 2 on bad input', () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const cli = join(here, '..', 'dist', 'cli.js');
    if (!existsSync(cli)) return; // dist not built: the library-level tests above cover the logic
    const dir = mkdtempSync(join(tmpdir(), 'qs-sbom-'));
    const inFile = join(dir, 'bom.json');
    const outFile = join(dir, 'out.json');
    writeFileSync(inFile, JSON.stringify(bom()));
    const ok = spawnSync(process.execPath, [cli, 'sbom', inFile, '--output', outFile], { encoding: 'utf8' });
    expect(ok.status, ok.stderr).toBe(0);
    expect(JSON.parse(readFileSync(outFile, 'utf8')).components[0].properties.length).toBe(3);
    writeFileSync(inFile, 'not json');
    expect(spawnSync(process.execPath, [cli, 'sbom', inFile], { encoding: 'utf8' }).status).toBe(2);
    expect(spawnSync(process.execPath, [cli, 'sbom'], { encoding: 'utf8' }).status).toBe(2);
  });
});
