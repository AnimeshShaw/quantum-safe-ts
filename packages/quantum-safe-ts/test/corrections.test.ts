/** Corrections found while documenting the library: each of these failed before the fix. */
import { existsSync, mkdtempSync, readdirSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  Envelope,
  HybridKEM,
  InvalidArgumentError,
  MemoryMigrationStore,
  MigrationStateManager,
  SealedMessage,
  fromBase64Url,
  openStream,
  sealBytes,
  utf8,
} from '../src/core.js';
import { FileMigrationStore } from '../src/file-store.js';
import { LmsSigner } from '../src/lms-signer.js';
import { fromBase64UrlStrict } from '../src/utils.js';
import { rewrapDirectory } from '../src/rewrap-files.js';

describe('base64url of an impossible length', () => {
  it('is an InvalidArgumentError, not a DOMException', () => {
    for (const bad of ['A', 'AAAAA', 'AAAAAAAAA']) {
      expect(() => fromBase64Url(bad), bad).toThrow(InvalidArgumentError);
      expect(() => fromBase64UrlStrict(bad), bad).toThrow(InvalidArgumentError);
    }
  });
  it('valid lengths still decode', () => {
    expect(fromBase64Url('AA')).toEqual(new Uint8Array([0]));
    expect(fromBase64Url('AAA')).toEqual(new Uint8Array([0, 0]));
    expect(fromBase64Url('AAAA')).toEqual(new Uint8Array([0, 0, 0]));
    expect(fromBase64Url('')).toEqual(new Uint8Array());
  });
});

describe('file store key listing', () => {
  it('lists the keys it wrote and ignores other .json files', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'qs-fs-'));
    const store = new FileMigrationStore(dir);
    await store.set('alpha', 'one');
    await store.set('beta/gamma', 'two');
    writeFileSync(join(dir, 'notes.json'), '{}');
    writeFileSync(join(dir, 'zz.json'), '{}');
    writeFileSync(join(dir, 'abc.json'), '{}'); // odd number of hex digits
    expect((await store.keys()).sort()).toEqual(['alpha', 'beta/gamma']);
  });
});

describe('importHistory limit', () => {
  it('refuses a history longer than reading accepts', async () => {
    const manager = new MigrationStateManager(new MemoryMigrationStore());
    const record = {
      keyId: 'k',
      fromState: 'classical_only',
      toState: 'hybrid_transition',
      algorithm: 'X25519+ML-KEM-768',
      timestamp: 1,
      actor: 'a',
      reason: '',
    } as never;
    const many = Array.from({ length: 10_001 }, () => record);
    await expect(manager.importHistory('k', many)).rejects.toThrow(/at most 10000/);
  });
});

describe('openStream releases its source', () => {
  it('closes the source iterator when the consumer stops early', async () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = await sealBytes(pair.publicKey, new Uint8Array(200_000), { chunkSize: 1024 });
    let closed = false;
    async function* source() {
      try {
        for (let i = 0; i < sealed.length; i += 700) yield sealed.subarray(i, i + 700);
      } finally {
        closed = true;
      }
    }
    for await (const chunk of openStream(pair.secretKey, source())) {
      expect(chunk.length).toBeGreaterThan(0);
      break; // stop after the first chunk
    }
    expect(closed).toBe(true);
  });

  it('closes the source when a chunk fails authentication', async () => {
    using pair = new HybridKEM().generateKeyPair();
    const sealed = await sealBytes(pair.publicKey, new Uint8Array(20_000), { chunkSize: 1024 });
    sealed[sealed.length - 3]! ^= 1;
    let closed = false;
    async function* source() {
      try {
        for (let i = 0; i < sealed.length; i += 700) yield sealed.subarray(i, i + 700);
      } finally {
        closed = true;
      }
    }
    await expect(
      (async () => {
        for await (const _ of openStream(pair.secretKey, source())) void _;
      })(),
    ).rejects.toThrow();
    expect(closed).toBe(true);
  });
});

describe('LmsSigner scrypt cost', () => {
  it('a cost the memory limit cannot run is refused before the slow tree is built', () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'lms-')), 'k');
    const t = Date.now();
    expect(() => LmsSigner.create({ directory: dir, height: 15, protection: { passphrase: 'x', scryptLog2N: 19 } })).toThrow(/scryptLog2N/);
    expect(Date.now() - t).toBeLessThan(2000);
    expect(existsSync(dir)).toBe(false);
  });
});

describe('rewrapDirectory', () => {
  it('refuses a destination inside the source', async () => {
    using oldPair = new HybridKEM().generateKeyPair();
    using newPair = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    const src = mkdtempSync(join(tmpdir(), 'rw-src-'));
    await mkdir(join(src, 'out'));
    await expect(
      rewrapDirectory(src, join(src, 'out'), { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, newSecretKey: newPair.secretKey }),
    ).rejects.toThrow(/inside the source/);
  });

  it.skipIf(process.platform !== 'win32')('refuses a destination inside the source when the paths differ only in case (Windows)', async () => {
    using oldPair = new HybridKEM().generateKeyPair();
    using newPair = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    const src = mkdtempSync(join(tmpdir(), 'rw-case-'));
    await mkdir(join(src, 'out'));
    await expect(
      rewrapDirectory(src, join(src.toUpperCase(), 'out'), { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, newSecretKey: newPair.secretKey }),
    ).rejects.toThrow(/inside the source/);
    await expect(
      rewrapDirectory(src, src.toUpperCase(), { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, newSecretKey: newPair.secretKey }),
    ).rejects.toThrow(/is the source directory/);
  });

  it.skipIf(process.platform === 'win32')('an in-place rewrite keeps the file permissions', async () => {
    using oldPair = new HybridKEM().generateKeyPair();
    using newPair = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    const src = mkdtempSync(join(tmpdir(), 'rw-mode-'));
    const file = join(src, 'a.sealed');
    writeFileSync(file, Envelope.seal(utf8('hello'), oldPair.publicKey).toBytes());
    chmodSync(file, 0o600);
    await rewrapDirectory(src, null, { inPlace: true, oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, newSecretKey: newPair.secretKey });
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(src)).toEqual(['a.sealed']);
  });

  it('the CBOM does not call a post-quantum source vulnerable, and gives the real security level', async () => {
    using oldPair = new HybridKEM().generateKeyPair();
    using newPair = new HybridKEM('X25519+ML-KEM-1024').generateKeyPair();
    const src = mkdtempSync(join(tmpdir(), 'rw-cbom-src-'));
    const dst = mkdtempSync(join(tmpdir(), 'rw-cbom-dst-'));
    writeFileSync(join(src, 'a.sealed'), Envelope.seal(utf8('hello'), oldPair.publicKey).toBytes());
    const report = await rewrapDirectory(src, dst, { oldSecretKey: oldPair.secretKey, newPublicKey: newPair.publicKey, newSecretKey: newPair.secretKey });
    expect(report.ok).toBe(true);
    const cbom = report.toCbom() as { components: Array<{ name: string; cryptoProperties: { algorithmProperties: { nistQuantumSecurityLevel: number } }; properties: Array<{ name: string; value: string }> }> };
    const from = cbom.components.find((c) => c.name === 'X25519+ML-KEM-768')!;
    expect(from.properties.find((p) => p.name === 'quantum-safe:quantum-vulnerable')!.value).toBe('false');
    expect(from.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(3);
    const to = cbom.components.find((c) => c.name === 'X25519+ML-KEM-1024')!;
    expect(to.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(5);
    // unrelated: a sealed message can be read back from the destination
    const written = SealedMessage.fromBytes(new Uint8Array(readFileSyncBytes(join(dst, 'a.sealed'))));
    expect(written.algorithm).toBe('X25519+ML-KEM-1024');
  });
});

import { readFileSync } from 'node:fs';
function readFileSyncBytes(path: string): Buffer {
  return readFileSync(path);
}
