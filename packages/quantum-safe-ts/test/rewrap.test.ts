/**
 * Envelope re-wrap (open under the old key, seal to the new key, keep the AAD) and the directory driver: resumable, verified, atomic, with a
 * JSON report and a CycloneDX document. quantum-safe-py has the same API and the same report shape (`quantum_safe.migrate.rewrap`).
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DecryptionAuthenticationError, Envelope, HybridKEM, SealedMessage, utf8, warnings } from '../src/index.js';
import type { QuantumSafeWarning } from '../src/index.js';
import { rewrapDirectory } from '../src/rewrap-files.js';

const root = mkdtempSync(join(tmpdir(), 'qs-rewrap-'));
let n = 0;
const fresh = (): string => join(root, `case-${n++}`);
afterAll(() => rmSync(root, { recursive: true, force: true }));

const oldKem = new HybridKEM('X25519+ML-KEM-768');
const newKem = new HybridKEM('X25519+ML-KEM-1024');
const oldPair = oldKem.generateKeyPair();
const newPair = newKem.generateKeyPair();

let seen: QuantumSafeWarning[] = [];
beforeEach(() => {
  seen = [];
  warnings.reset();
  warnings.onWarning((w) => seen.push(w));
});
afterEach(() => warnings.reset());

describe('Envelope.rewrap', () => {
  it('moves a message to the new key and keeps plaintext and AAD', () => {
    const sealed = Envelope.seal(utf8('the plaintext'), oldPair.publicKey, { aad: utf8('record-7') });
    const moved = Envelope.rewrap(sealed, oldPair.secretKey, newPair.publicKey, { expectedAad: utf8('record-7') });
    expect(moved.algorithm).toBe('X25519+ML-KEM-1024');
    expect(moved.aad).toEqual(utf8('record-7'));
    expect(Envelope.open(moved, newPair.secretKey, { expectedAad: utf8('record-7') })).toEqual(utf8('the plaintext'));
    expect(() => Envelope.open(moved, oldPair.secretKey, { expectedAad: utf8('record-7') })).toThrow();
  });

  it('leaves the original message alone', () => {
    const sealed = Envelope.seal(utf8('keep me'), oldPair.publicKey);
    const before = sealed.toBytes();
    Envelope.rewrap(sealed, oldPair.secretKey, newPair.publicKey);
    expect(sealed.toBytes()).toEqual(before);
  });

  it('refuses a different expectedAad and warns when it is omitted for a message with AAD', () => {
    const sealed = Envelope.seal(utf8('x'), oldPair.publicKey, { aad: utf8('tenant-a') });
    expect(() => Envelope.rewrap(sealed, oldPair.secretKey, newPair.publicKey, { expectedAad: utf8('tenant-b') })).toThrow(
      DecryptionAuthenticationError,
    );
    expect(seen).toHaveLength(0);
    const moved = Envelope.rewrap(sealed, oldPair.secretKey, newPair.publicKey);
    expect(moved.aad).toEqual(utf8('tenant-a'));
    expect(seen.map((w) => w.code)).toEqual(['QS_AAD_OMITTED']);
  });

  it('can replace the AAD', () => {
    const sealed = Envelope.seal(utf8('x'), oldPair.publicKey, { aad: utf8('old') });
    const moved = Envelope.rewrap(sealed, oldPair.secretKey, newPair.publicKey, { expectedAad: utf8('old'), aad: utf8('new') });
    expect(Envelope.open(moved, newPair.secretKey, { expectedAad: utf8('new') })).toEqual(utf8('x'));
  });

  it('a stranger key fails and returns nothing', () => {
    const stranger = oldKem.generateKeyPair();
    const sealed = Envelope.seal(utf8('x'), oldPair.publicKey);
    expect(() => Envelope.rewrap(sealed, stranger.secretKey, newPair.publicKey, { expectedAad: new Uint8Array(0) })).toThrow();
  });
});

describe('rewrapDirectory', () => {
  const make = (): { src: string; files: Record<string, string> } => {
    const src = fresh();
    mkdirSync(join(src, 'sub'), { recursive: true });
    const files: Record<string, string> = { 'a.sealed': 'alpha', 'sub/b.sealed': 'bravo', 'sub/c.hex': 'charlie' };
    for (const [name, text] of Object.entries(files)) {
      const sealed = Envelope.seal(utf8(text), oldPair.publicKey, { aad: utf8(name) });
      writeFileSync(join(src, name), name.endsWith('.hex') ? sealed.toHex() : sealed.toBytes());
    }
    writeFileSync(join(src, 'notes.txt'), 'not an envelope');
    return { src, files };
  };
  const base = { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, newSecretKey: newPair.secretKey, expectedAad: (rel: string) => utf8(rel) };

  it('converts every envelope, verifies, and leaves the source alone', async () => {
    const { src, files } = make();
    const dst = fresh();
    const report = await rewrapDirectory(src, dst, base);
    expect(report.counts).toEqual({ rewrapped: 3, skipped: 1, failed: 0 });
    expect(report.items.filter((i) => i.status === 'rewrapped').every((i) => i.verified === true)).toBe(true);
    for (const [name, text] of Object.entries(files)) {
      const raw = readFileSync(join(dst, name));
      const sealed = name.endsWith('.hex') ? SealedMessage.fromHex(raw.toString('ascii')) : SealedMessage.fromBytes(new Uint8Array(raw));
      expect(sealed.algorithm).toBe('X25519+ML-KEM-1024');
      expect(Envelope.open(sealed, newPair.secretKey, { expectedAad: utf8(name) })).toEqual(utf8(text));
    }
    expect(existsSync(join(dst, 'notes.txt'))).toBe(false);
    expect(readFileSync(join(src, 'a.sealed')).equals(readFileSync(join(dst, 'a.sealed')))).toBe(false);
    expect(report.ok).toBe(true);
  });

  it('a second run changes nothing, and an interrupted run resumes', async () => {
    const { src } = make();
    const dst = fresh();
    await rewrapDirectory(src, dst, base);
    const snapshot = readFileSync(join(dst, 'sub', 'c.hex'));
    const again = await rewrapDirectory(src, dst, base);
    expect(again.counts.rewrapped).toBe(0);
    expect(again.items.every((i) => ['already_migrated', 'skipped'].includes(i.status))).toBe(true);
    expect(readFileSync(join(dst, 'sub', 'c.hex')).equals(snapshot)).toBe(true);
    unlinkSync(join(dst, 'sub', 'b.sealed'));
    const resumed = await rewrapDirectory(src, dst, base);
    expect(resumed.counts.rewrapped).toBe(1);
    expect(existsSync(join(dst, 'sub', 'b.sealed'))).toBe(true);
  });

  it('reports a failure by name and carries on with the rest', async () => {
    const { src } = make();
    const stranger = oldKem.generateKeyPair();
    writeFileSync(join(src, 'z.sealed'), Envelope.seal(utf8('not yours'), stranger.publicKey).toBytes());
    const dst = fresh();
    const report = await rewrapDirectory(src, dst, { ...base, expectedAad: (rel) => (rel === 'z.sealed' ? new Uint8Array(0) : utf8(rel)) });
    const z = report.items.find((i) => i.name === 'z.sealed')!;
    expect(z.status).toBe('failed');
    expect(z.error).toBeTruthy();
    expect(report.counts.rewrapped).toBe(3);
    expect(report.counts.failed).toBe(1);
    expect(existsSync(join(dst, 'z.sealed'))).toBe(false);
    expect(report.ok).toBe(false);
  });

  it('a dry run writes nothing', async () => {
    const { src } = make();
    const dst = fresh();
    const report = await rewrapDirectory(src, dst, { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, expectedAad: base.expectedAad, dryRun: true });
    expect(report.counts.rewrapped).toBe(0);
    expect(report.items.some((i) => i.status === 'would_rewrap')).toBe(true);
    expect(existsSync(dst)).toBe(false);
  });

  it('in place replaces atomically, and only when asked', async () => {
    const { src } = make();
    await expect(rewrapDirectory(src, src, { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey })).rejects.toThrow(/inPlace/);
    await expect(rewrapDirectory(src, null, { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey })).rejects.toThrow(/destination/);
    const report = await rewrapDirectory(src, null, { ...base, inPlace: true });
    expect(report.counts.rewrapped).toBe(3);
    expect(SealedMessage.fromBytes(new Uint8Array(readFileSync(join(src, 'a.sealed')))).algorithm).toBe('X25519+ML-KEM-1024');
    expect(readdirSync(src).filter((f) => f.endsWith('.tmp'))).toEqual([]);
    const second = await rewrapDirectory(src, null, { ...base, inPlace: true });
    expect(second.counts.rewrapped).toBe(0);
  });

  it('the report never contains plaintext, and the CycloneDX document lists the algorithms before and after', async () => {
    const { src, files } = make();
    const report = await rewrapDirectory(src, fresh(), base);
    const text = JSON.stringify(report.toJSON());
    for (const plain of Object.values(files)) expect(text).not.toContain(plain);
    const cbom = report.toCbom() as { bomFormat: string; specVersion: string; components: Array<{ name: string; properties: Array<{ name: string; value: string }> }> };
    expect(cbom.bomFormat).toBe('CycloneDX');
    expect(cbom.specVersion).toBe('1.6');
    expect(cbom.components.map((c) => c.name).sort()).toEqual(['X25519+ML-KEM-1024', 'X25519+ML-KEM-768']);
    const statuses = cbom.components.flatMap((c) => c.properties.filter((p) => p.name === 'quantum-safe:migration-status').map((p) => p.value));
    expect(statuses.sort()).toEqual(['migrated-from', 'migrated-to']);
  });
});
