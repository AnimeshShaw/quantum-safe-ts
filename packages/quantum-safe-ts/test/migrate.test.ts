import { describe, expect, it } from 'vitest';
import {
  HybridKEM,
  HybridSign,
  InvalidArgumentError,
  KEM,
  MemoryMigrationStore,
  MigrationStateManager,
  Upgrader,
  utf8,
} from '../src/core.js';
import type { MigrationStore } from '../src/core.js';

function split(raw: Uint8Array): [Uint8Array, Uint8Array] {
  const n = (raw[0]! << 8) | raw[1]!;
  return [raw.slice(2, 2 + n), raw.slice(2 + n)];
}

describe('Upgrader', () => {
  it('upgrades an X25519 KEM key: classical half is preserved and the hybrid key works', () => {
    using classical = new HybridKEM('X25519+ML-KEM-768').generateKeyPair();
    // Take a genuine X25519 keypair out of an existing hybrid key (the same bytes py would hold).
    const [cPub] = split(classical.publicKey.toBytes());
    const secRaw = classical.secretKey.exportBytes();
    const [cSec] = split(secRaw);
    using up = Upgrader.upgradeKemKey({ classicalSecret: cSec, classicalPublic: cPub }).keyPair;
    expect(up.algorithm).toBe('X25519+ML-KEM-768');
    expect(split(up.publicKey.toBytes())[0]).toEqual(cPub);
    expect(split(up.secretKey.exportBytes())[0]).toEqual(cSec);
    const kem = new HybridKEM('X25519+ML-KEM-768');
    const { ciphertext, sharedSecret } = kem.encapsulate(up.publicKey);
    using rec = kem.decapsulate(up.secretKey, ciphertext);
    using ss = sharedSecret;
    expect(rec.exportBytes()).toEqual(ss.exportBytes());
    secRaw.fill(0);
  });

  it('reports the result metadata and honest notes', () => {
    using c = new HybridKEM().generateKeyPair();
    const [cPub] = split(c.publicKey.toBytes());
    const [cSec] = split(c.secretKey.exportBytes());
    const r = Upgrader.upgradeKemKey({ classicalSecret: cSec, classicalPublic: cPub, targetPqc: 'ML-KEM-1024' });
    using _kp = r.keyPair;
    expect(r.oldAlgorithm).toBe('X25519');
    expect(r.newAlgorithm).toBe('X25519+ML-KEM-1024');
    expect(r.migrationState).toBe('hybrid_transition');
    expect(r.notes.toLowerCase()).not.toMatch(/quantum-proof|audited|compliant/);
  });

  it('upgrades an Ed25519 signing key and the hybrid signature verifies', () => {
    using base = new HybridSign('Ed25519+ML-DSA-65').generateKeyPair();
    const [cPub] = split(base.publicKey.toBytes());
    const [cSec] = split(base.secretKey.exportBytes());
    using up = Upgrader.upgradeSigningKey({ classicalSecret: cSec, classicalPublic: cPub }).keyPair;
    expect(up.algorithm).toBe('Ed25519+ML-DSA-65');
    const signer = new HybridSign('Ed25519+ML-DSA-65');
    const msg = utf8('upgrade me');
    const signed = signer.sign(msg, up.secretKey);
    expect(() => signer.verify(signed, up.publicKey)).not.toThrow();
    expect(() => signer.verify(signed, base.publicKey)).toThrow();
    expect(split(up.publicKey.toBytes())[0]).toEqual(cPub);
  });

  it('rejects bad key sizes and unapproved pairings', () => {
    expect(() => Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(31), classicalPublic: new Uint8Array(32) })).toThrow(InvalidArgumentError);
    expect(() => Upgrader.upgradeSigningKey({ classicalSecret: new Uint8Array(32), classicalPublic: new Uint8Array(31) })).toThrow(InvalidArgumentError);
    expect(() =>
      Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(32), classicalPublic: new Uint8Array(32), classicalAlgorithm: 'X25519', targetPqc: 'ML-KEM-999' as never }),
    ).toThrow();
    expect(() => Upgrader.upgradeKemKey({ classicalSecret: 'x' as never, classicalPublic: new Uint8Array(32) })).toThrow(InvalidArgumentError);
  });

  it('stripClassicalComponent yields a PQC-only key pair; refuses non-hybrid keys', () => {
    using hybrid = new HybridKEM('X25519+ML-KEM-768').generateKeyPair();
    using pqcOnly = Upgrader.stripClassicalComponent(hybrid);
    expect(pqcOnly.algorithm).toBe('ML-KEM-768');
    const kem = new KEM('ML-KEM-768');
    const { ciphertext, sharedSecret } = kem.encapsulate(pqcOnly.publicKey);
    using ss = sharedSecret;
    using rec = kem.decapsulate(pqcOnly.secretKey, ciphertext);
    expect(rec.exportBytes()).toEqual(ss.exportBytes());
    expect(() => Upgrader.stripClassicalComponent(pqcOnly)).toThrow(InvalidArgumentError);
  });

  it('checkNeedsUpgrade is true only for classical_only', () => {
    expect(Upgrader.checkNeedsUpgrade('classical_only')).toBe(true);
    for (const s of ['hybrid_transition', 'pqc_preferred', 'pqc_only'] as const) expect(Upgrader.checkNeedsUpgrade(s)).toBe(false);
  });
});

describe('MigrationStateManager', () => {
  const t = (m: MigrationStateManager, keyId: string, from: any, to: any, extra: object = {}) =>
    m.transition({ keyId, fromState: from, toState: to, algorithm: 'X25519+ML-KEM-768', ...extra });

  it('walks the forward path and records history', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await t(m, 'k1', 'classical_only', 'hybrid_transition', { actor: 'alice' });
    await t(m, 'k1', 'hybrid_transition', 'pqc_preferred');
    const last = await t(m, 'k1', 'pqc_preferred', 'pqc_only');
    expect(last.isForward).toBe(true);
    expect(await m.getCurrentState('k1')).toBe('pqc_only');
    const hist = await m.getHistory('k1');
    expect(hist.map((r) => r.toState)).toEqual(['hybrid_transition', 'pqc_preferred', 'pqc_only']);
    expect(hist[0]!.actor).toBe('alice');
  });

  it('rejects skipping states, and pqc_only is terminal', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await expect(t(m, 'k', 'classical_only', 'pqc_only')).rejects.toThrow(InvalidArgumentError);
    await expect(t(m, 'k', 'pqc_only', 'pqc_preferred', { allowBackward: true, reason: 'x' })).rejects.toThrow(InvalidArgumentError);
  });

  it('backward transitions need allowBackward and a reason', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await t(m, 'k', 'classical_only', 'hybrid_transition');
    await expect(t(m, 'k', 'hybrid_transition', 'classical_only')).rejects.toThrow(/allowBackward/);
    await expect(t(m, 'k', 'hybrid_transition', 'classical_only', { allowBackward: true })).rejects.toThrow(/reason/);
    const r = await t(m, 'k', 'hybrid_transition', 'classical_only', { allowBackward: true, reason: 'rollback: interop bug' });
    expect(r.isForward).toBe(false);
    expect(await m.getCurrentState('k')).toBe('classical_only');
  });

  it('detects stale expected state', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await t(m, 'k', 'classical_only', 'hybrid_transition');
    await expect(t(m, 'k', 'classical_only', 'hybrid_transition')).rejects.toThrow(/expected|Invalid/);
  });

  it('serialises concurrent transitions on the same key: exactly one wins', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await t(m, 'k', 'classical_only', 'hybrid_transition');
    const results = await Promise.allSettled(Array.from({ length: 10 }, () => t(m, 'k', 'hybrid_transition', 'pqc_preferred')));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect((await m.getHistory('k')).length).toBe(2);
  });

  it('works with an async store without compareAndSet, and reports progress', async () => {
    const mem = new Map<string, string>();
    const store: MigrationStore = {
      get: async (k) => mem.get(k),
      set: async (k, v) => void mem.set(k, v),
      keys: async () => [...mem.keys()],
    };
    const m = new MigrationStateManager(store);
    await t(m, 'a', 'classical_only', 'hybrid_transition');
    await t(m, 'b', 'classical_only', 'hybrid_transition');
    await t(m, 'b', 'hybrid_transition', 'pqc_preferred');
    expect(await m.keysByState('hybrid_transition')).toEqual(['a']);
    expect(await m.migrationProgress()).toEqual({ classical_only: 0, hybrid_transition: 1, pqc_preferred: 1, pqc_only: 0 });
    expect(await m.getCurrentState('nope')).toBeUndefined();
  });

  it('a store whose compareAndSet fails surfaces a concurrency error', async () => {
    const mem = new MemoryMigrationStore();
    const store: MigrationStore = { get: (k) => mem.get(k), set: (k, v) => mem.set(k, v), keys: () => mem.keys(), compareAndSet: () => false };
    const m = new MigrationStateManager(store);
    await expect(t(m, 'k', 'classical_only', 'hybrid_transition')).rejects.toThrow(/concurrently/);
    expect(await m.getHistory('k')).toEqual([]);
  });
});
