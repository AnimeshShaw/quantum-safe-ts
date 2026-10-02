import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  HybridKEM,
  HybridSign,
  InvalidArgumentError,
  KEM,
  KeyPair,
  MemoryMigrationStore,
  MigrationStateManager,
  PublicKey,
  SecretKey,
  Sign,
  SignedMessage,
  Upgrader,
  exportToPyStore,
  importFromPyStore,
  recordFromPyBytes,
  recordToPyBytes,
  toHex,
  utf8,
} from '../src/core.js';
import type { KemAlgorithm, MigrationState, MigrationStore} from '../src/core.js';
import { cborDecode, cborEncode, CborFloat } from '../src/cbor.js';
import { h, vectors } from './helpers.js';

function split(raw: Uint8Array): [Uint8Array, Uint8Array] {
  const n = (raw[0]! << 8) | raw[1]!;
  return [raw.slice(2, 2 + n), raw.slice(2 + n)];
}

describe('Upgrader', () => {
  it('upgrades an X25519 KEM key: classical half is preserved and the hybrid key works', () => {
    using classical = new HybridKEM('X25519+ML-KEM-768').generateKeyPair();
    const [cPub] = split(classical.publicKey.toBytes());
    const secRaw = classical.secretKey.exportBytes();
    const [cSec] = split(secRaw);
    using up = Upgrader.upgradeKemKey({ classicalSecret: cSec, classicalPublic: cPub }).keyPair;
    expect(up.algorithm).toBe('X25519+ML-KEM-768');
    expect(up.publicKey.migrationState).toBe('hybrid_transition');
    expect(split(up.publicKey.toBytes())[0]).toEqual(cPub);
    expect(split(up.secretKey.exportBytes())[0]).toEqual(cSec);
    const kem = new HybridKEM('X25519+ML-KEM-768');
    const { ciphertext, sharedSecret } = kem.encapsulate(up.publicKey);
    using rec = kem.decapsulate(up.secretKey, ciphertext);
    using ss = sharedSecret;
    expect(rec.exportBytes()).toEqual(ss.exportBytes());
    secRaw.fill(0);
  });

  it('upgrades a P-256 KEM key (PKCS#8 PEM secret, 65-byte public point) and the hybrid key works', () => {
    using base = new HybridKEM('P-256+ML-KEM-768').generateKeyPair();
    const [cPub] = split(base.publicKey.toBytes());
    const [cSec] = split(base.secretKey.exportBytes());
    expect(cPub.length).toBe(65);
    expect(new TextDecoder().decode(cSec)).toContain('BEGIN PRIVATE KEY');
    const r = Upgrader.upgradeKemKey({ classicalSecret: cSec, classicalPublic: cPub, classicalAlgorithm: 'P-256', targetPqc: 'ML-KEM-512' });
    using up = r.keyPair;
    expect(r.newAlgorithm).toBe('P-256+ML-KEM-512');
    const kem = new HybridKEM('P-256+ML-KEM-512');
    const { ciphertext, sharedSecret } = kem.encapsulate(up.publicKey);
    using rec = kem.decapsulate(up.secretKey, ciphertext);
    using ss = sharedSecret;
    expect(rec.exportBytes()).toEqual(ss.exportBytes());
  });

  it('upgrades a P-256 signing key (raw x||y public) and the hybrid signature verifies', () => {
    using base = new HybridSign('P-256+ML-DSA-65').generateKeyPair();
    const [cPub] = split(base.publicKey.toBytes());
    const [cSec] = split(base.secretKey.exportBytes());
    expect(cPub.length).toBe(64);
    const r = Upgrader.upgradeSigningKey({ classicalSecret: cSec, classicalPublic: cPub, classicalAlgorithm: 'P-256', targetPqc: 'ML-DSA-44' });
    using up = r.keyPair;
    const signer = new HybridSign('P-256+ML-DSA-44');
    const signed = signer.sign(utf8('p256 upgrade'), up.secretKey);
    expect(() => signer.verify(signed, up.publicKey)).not.toThrow();
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
    const signed = signer.sign(utf8('upgrade me'), up.secretKey);
    expect(() => signer.verify(signed, up.publicKey)).not.toThrow();
    expect(() => signer.verify(signed, base.publicKey)).toThrow();
    expect(split(up.publicKey.toBytes())[0]).toEqual(cPub);
  });

  it('rejects bad key sizes, bad types and unapproved pairings', () => {
    expect(() => Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(31), classicalPublic: new Uint8Array(32) })).toThrow(InvalidArgumentError);
    expect(() => Upgrader.upgradeSigningKey({ classicalSecret: new Uint8Array(32), classicalPublic: new Uint8Array(31) })).toThrow(InvalidArgumentError);
    expect(() =>
      Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(32), classicalPublic: new Uint8Array(32), targetPqc: 'ML-KEM-999' as never }),
    ).toThrow();
    expect(() => Upgrader.upgradeKemKey({ classicalSecret: 'x' as never, classicalPublic: new Uint8Array(32) })).toThrow(InvalidArgumentError);
    // P-256 + ML-KEM-1024 is not an approved pairing (py parity)
    expect(() =>
      Upgrader.upgradeKemKey({ classicalSecret: new Uint8Array(200), classicalPublic: new Uint8Array(65), classicalAlgorithm: 'P-256', targetPqc: 'ML-KEM-1024' }),
    ).toThrow();
  });

  it('stripClassicalComponent yields a PQC-only key pair; refuses non-hybrid keys', () => {
    using hybrid = new HybridKEM('X25519+ML-KEM-768').generateKeyPair();
    using pqcOnly = Upgrader.stripClassicalComponent(hybrid);
    expect(pqcOnly.algorithm).toBe('ML-KEM-768');
    expect(pqcOnly.publicKey.migrationState).toBe('pqc_only');
    const kem = new KEM('ML-KEM-768');
    const { ciphertext, sharedSecret } = kem.encapsulate(pqcOnly.publicKey);
    using ss = sharedSecret;
    using rec = kem.decapsulate(pqcOnly.secretKey, ciphertext);
    expect(rec.exportBytes()).toEqual(ss.exportBytes());
    expect(() => Upgrader.stripClassicalComponent(pqcOnly)).toThrow(InvalidArgumentError);
  });

  it('checkNeedsUpgrade and describeKey', () => {
    expect(Upgrader.checkNeedsUpgrade('classical_only')).toBe(true);
    for (const s of ['hybrid_transition', 'pqc_preferred', 'pqc_only'] as const) expect(Upgrader.checkNeedsUpgrade(s)).toBe(false);
    using kp = new HybridKEM().generateKeyPair();
    const d = Upgrader.describeKey(kp);
    expect(d).toMatchObject({ algorithm: 'X25519+ML-KEM-768', isHybrid: true });
    expect(JSON.stringify(d)).not.toMatch(/secret/i);
    using xw = new HybridKEM('X-Wing').generateKeyPair();
    expect(Upgrader.describeKey(xw).isHybrid).toBe(false);
  });
});

describe('Upgrader parity with the real quantum-safe-py', () => {
  const V = vectors('migrate_vectors.json');

  for (const v of V.upgrade_kem) {
    it(`KEM ${v.classical}+${v.pqc}: py-upgraded key decapsulates py's ciphertext; TS upgrade packs identical classical bytes`, () => {
      const kem = new HybridKEM(v.algorithm as KemAlgorithm);
      using sk = SecretKey.fromBytes(v.algorithm, h(v.secret_key), 'hybrid_transition');
      using ss = kem.decapsulate(sk, h(v.ciphertext));
      expect(toHex(ss.exportBytes())).toBe(v.shared_secret);
      // Same independently produced classical key bytes, upgraded by TS:
      const r = Upgrader.upgradeKemKey({
        classicalSecret: h(v.classical_secret),
        classicalPublic: h(v.classical_public),
        classicalAlgorithm: v.classical,
        targetPqc: v.pqc,
      });
      using up = r.keyPair;
      const pyPub = h(v.public_key);
      const tsPub = up.publicKey.toBytes();
      expect(tsPub.length).toBe(pyPub.length); // same layout and size
      expect(split(tsPub)[0]).toEqual(split(pyPub)[0]); // identical classical half
      expect(split(up.secretKey.exportBytes())[0]).toEqual(split(h(v.secret_key))[0]);
      // and the TS-upgraded key is a working hybrid key
      const enc = kem.encapsulate(up.publicKey);
      using back = kem.decapsulate(up.secretKey, enc.ciphertext);
      expect(back.exportBytes()).toEqual(enc.sharedSecret.exportBytes());
      enc.sharedSecret.free();
    });
  }

  for (const v of V.upgrade_sign) {
    it(`signing ${v.classical}+${v.pqc}: py's signature verifies in TS`, () => {
      const signer = new HybridSign(v.algorithm as ConstructorParameters<typeof HybridSign>[0]);
      using pub = PublicKey.fromBytes(v.algorithm, h(v.public_key), 'hybrid_transition');
      const signed = SignedMessage.fromCbor(h(v.signed_message));
      expect(() => signer.verify(signed, pub, { expectedContext: h(v.context) })).not.toThrow();
      const r = Upgrader.upgradeSigningKey({
        classicalSecret: h(v.classical_secret),
        classicalPublic: h(v.classical_public),
        classicalAlgorithm: v.classical,
        targetPqc: v.pqc,
      });
      using up = r.keyPair;
      expect(split(up.publicKey.toBytes())[0]).toEqual(split(h(v.public_key))[0]);
      const mine = signer.sign(utf8('ts after upgrade'), up.secretKey);
      expect(() => signer.verify(mine, up.publicKey)).not.toThrow();
    });
  }

  it('stripClassicalComponent produces byte-identical keys to py (the operation is deterministic)', () => {
    for (const v of V.strip) {
      using hpub = PublicKey.fromBytes('X25519+ML-KEM-768', h(v.hybrid_public));
      using hsec = SecretKey.fromBytes('X25519+ML-KEM-768', h(v.hybrid_secret));
      using hybrid = KeyPair.fromKeys(hpub, hsec);
      using stripped = Upgrader.stripClassicalComponent(hybrid);
      expect(stripped.algorithm).toBe(v.algorithm);
      expect(toHex(stripped.publicKey.toBytes())).toBe(v.public_key);
      expect(toHex(stripped.secretKey.exportBytes())).toBe(v.secret_key);
      const kem = new KEM(v.algorithm as 'ML-KEM-768');
      using sk = SecretKey.fromBytes(v.algorithm, h(v.secret_key), 'pqc_only');
      using ss = kem.decapsulate(sk, h(v.ciphertext));
      expect(toHex(ss.exportBytes())).toBe(v.shared_secret);
    }
    for (const v of V.strip_sign) {
      using pub = PublicKey.fromBytes(v.algorithm, h(v.public_key), 'pqc_only');
      expect(() => new Sign('ML-DSA-65').verify(SignedMessage.fromCbor(h(v.signed_message)), pub)).not.toThrow();
    }
  });
});

describe('MigrationStateManager', () => {
  const t = (m: MigrationStateManager, keyId: string, from: MigrationState, to: MigrationState, extra: object = {}) =>
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
    expect(hist[0]!.recordId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
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

  it('two managers sharing one CAS store (two "processes"): exactly one wins, history stays consistent', async () => {
    const store = new MemoryMigrationStore();
    const a = new MigrationStateManager(store);
    const b = new MigrationStateManager(store);
    await t(a, 'k', 'classical_only', 'hybrid_transition');
    expect(a.crossProcessSafe).toBe(true);
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, (_, i) => t(i % 2 ? a : b, 'k', 'hybrid_transition', 'pqc_preferred', { actor: `w${i}` })),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect((await a.getHistory('k')).map((r) => r.toState)).toEqual(['hybrid_transition', 'pqc_preferred']);
  });

  it('retries after losing a CAS race and then reports the stale state', async () => {
    const mem = new MemoryMigrationStore();
    let injected = false;
    const store: MigrationStore = {
      get: (k) => mem.get(k),
      set: (k, v) => mem.set(k, v),
      keys: () => mem.keys(),
      compareAndSet: async (k, exp, val) => {
        if (!injected) {
          injected = true;
          // another process wins between our read and our write
          const other = new MigrationStateManager(mem);
          await other.transition({ keyId: 'k', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'a' });
        }
        return mem.compareAndSet(k, exp, val);
      },
    };
    const m = new MigrationStateManager(store);
    await expect(m.transition({ keyId: 'k', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'a' })).rejects.toThrow(/expected/);
    expect((await m.getHistory('k')).length).toBe(1);
  });

  it('works with an async store without compareAndSet (and says it is not cross-process safe), and reports progress', async () => {
    const mem = new Map<string, string>();
    const store: MigrationStore = {
      get: async (k) => mem.get(k),
      set: async (k, v) => void mem.set(k, v),
      keys: async () => [...mem.keys()],
    };
    const m = new MigrationStateManager(store);
    expect(m.crossProcessSafe).toBe(false);
    await t(m, 'a', 'classical_only', 'hybrid_transition');
    await t(m, 'b', 'classical_only', 'hybrid_transition');
    await t(m, 'b', 'hybrid_transition', 'pqc_preferred');
    await m.importHistory('c', [
      { recordId: 'r', keyId: 'c', fromState: 'classical_only', toState: 'classical_only' as never, algorithm: 'x', timestamp: 1, actor: 'a', reason: '', metadata: {}, isForward: false },
    ]).catch(() => undefined);
    expect(await m.keysByState('hybrid_transition')).toEqual(['a']);
    expect(await m.migrationProgress()).toEqual({ classical_only: 0, hybrid_transition: 1, pqc_preferred: 1, pqc_only: 0 });
    expect(await m.getCurrentState('nope')).toBeUndefined();
    expect(await m.needsMigration()).toEqual([]);
  });

  it('fails closed on a corrupt stored document', async () => {
    const mem = new MemoryMigrationStore();
    const m = new MigrationStateManager(mem);
    for (const bad of ['not json', '{}', '{"v":2,"history":[]}', '{"v":1,"history":[{"keyId":"k"}]}', '{"v":1,"history":[null]}']) {
      mem.set('qs-migration/v1/k', bad);
      await expect(m.getHistory('k')).rejects.toThrow(InvalidArgumentError);
      await expect(t(m, 'k', 'classical_only', 'hybrid_transition')).rejects.toThrow(InvalidArgumentError);
    }
  });

  it('importHistory validates the chain and refuses to overwrite', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    const rec = (from: MigrationState, to: MigrationState, id: string) => ({
      recordId: id, keyId: 'k', fromState: from, toState: to, algorithm: 'x', timestamp: 1, actor: 'a', reason: '', metadata: {}, isForward: true,
    });
    await expect(m.importHistory('k', [rec('classical_only', 'pqc_only', '1')])).rejects.toThrow(/illegal/);
    await expect(m.importHistory('k', [rec('classical_only', 'hybrid_transition', '1'), rec('pqc_preferred', 'pqc_only', '2')])).rejects.toThrow(/continuous/);
    await m.importHistory('k', [rec('classical_only', 'hybrid_transition', '1')]);
    await expect(m.importHistory('k', [rec('classical_only', 'hybrid_transition', '9')])).rejects.toThrow(/already/);
  });
});

describe('quantum-safe-py migration store interoperability', () => {
  const V = vectors('migrate_vectors.json');
  const pyEntries = (): [string, Uint8Array][] => Object.entries(V.store.entries as Record<string, string>).map(([k, v]) => [k, h(v)]);

  it('imports a real py store: states, progress and full histories match py', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    const ids = await importFromPyStore(pyEntries(), m);
    expect(ids).toEqual(['key/with/slashes', 'svc-ünï', 'user-1']);
    for (const [id, state] of Object.entries(V.store.current_states)) expect(await m.getCurrentState(id)).toBe(state);
    expect(await m.migrationProgress()).toMatchObject({
      classical_only: V.store.progress.classical_only,
      hybrid_transition: V.store.progress.hybrid_transition,
      pqc_preferred: V.store.progress.pqc_preferred,
      pqc_only: V.store.progress.pqc_only,
    });
    for (const [id, hist] of Object.entries(V.store.histories as Record<string, Array<Record<string, unknown>>>)) {
      const mine = await m.getHistory(id);
      expect(mine.map((r) => [r.recordId, r.keyId, r.fromState, r.toState, r.algorithm, r.timestamp, r.actor, r.reason, r.metadata, r.isForward])).toEqual(
        hist.map((r) => [r.record_id, r.key_id, r.from_state, r.to_state, r.algorithm, r.timestamp, r.actor, r.reason, r.metadata, r.is_forward]),
      );
    }
    // the imported history can be continued from TS
    await m.transition({ keyId: 'user-1', fromState: 'hybrid_transition', toState: 'pqc_preferred', algorithm: 'X25519+ML-KEM-768', actor: 'ts' });
    expect((await m.getHistory('user-1')).length).toBe(4);
  });

  it('export reproduces py\'s store byte for byte', async () => {
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await importFromPyStore(pyEntries(), m);
    const out = await exportToPyStore(m);
    expect([...out.keys()].sort()).toEqual(Object.keys(V.store.entries).sort());
    for (const [k, hexv] of Object.entries(V.store.entries as Record<string, string>)) expect(toHex(out.get(k)!)).toBe(hexv);
  });

  it('record bytes round-trip and reject garbage', () => {
    const cur = pyEntries().find(([k]) => k === 'user-1_current')![1];
    const r = recordFromPyBytes(cur);
    expect(toHex(recordToPyBytes(r))).toBe(toHex(cur));
    for (const bad of [new Uint8Array(0), Uint8Array.of(0xa1), Uint8Array.of(0xf6), utf8('{"json":true}')]) {
      expect(() => recordFromPyBytes(bad)).toThrow(InvalidArgumentError);
    }
  });

  it('refuses an inconsistent py store (current does not match history tail) and never overwrites', async () => {
    const entries = new Map(pyEntries());
    entries.set('user-1_current', entries.get('svc-ünï_current')!);
    const m = new MigrationStateManager(new MemoryMigrationStore());
    await expect(importFromPyStore(entries, m)).rejects.toThrow(InvalidArgumentError);
    const m2 = new MigrationStateManager(new MemoryMigrationStore());
    await importFromPyStore(pyEntries(), m2);
    await expect(importFromPyStore(pyEntries(), m2)).rejects.toThrow(/already/);
  });
});

describe('internal CBOR codec', () => {
  const val: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
    leaf: fc.oneof(fc.constant(null), fc.boolean(), fc.integer({ min: -(2 ** 40), max: 2 ** 40 }), fc.string(), fc.uint8Array({ maxLength: 20 })),
    node: fc.oneof(
      { depthSize: 'small' },
      tie('leaf'),
      fc.array(tie('node'), { maxLength: 4 }),
      fc.dictionary(fc.string({ maxLength: 6 }).filter((s) => s !== '__proto__'), tie('node'), { maxKeys: 4 }),
    ),
  })).node;

  it('round-trips arbitrary values', () => {
    fc.assert(
      fc.property(val, (v) => {
        const back = cborDecode(cborEncode(v as never));
        expect(JSON.stringify(normalise(back))).toBe(JSON.stringify(normalise(v)));
      }),
      { numRuns: 300 },
    );
  });

  it('writes floats as 64-bit floats and ints as shortest ints (cbor2-compatible)', () => {
    expect(toHex(cborEncode(new CborFloat(1)))).toBe('fb3ff0000000000000');
    expect(toHex(cborEncode(1))).toBe('01');
    expect(toHex(cborEncode(-1))).toBe('20');
    expect(toHex(cborEncode(500))).toBe('1901f4');
    expect(cborDecode(Uint8Array.of(0xf9, 0x3c, 0x00))).toBe(1); // half-precision 1.0
  });

  it('only ever throws InvalidArgumentError on hostile input', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        try {
          cborDecode(bytes);
        } catch (e) {
          expect(e).toBeInstanceOf(InvalidArgumentError);
        }
      }),
      { numRuns: 2000 },
    );
    for (const bad of [[0xc0, 0x00], [0x5f, 0xff], [0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02], [0xa1, 0x01, 0x01], [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]]) {
      expect(() => cborDecode(Uint8Array.from(bad))).toThrow(InvalidArgumentError);
    }
    // deep nesting
    expect(() => cborDecode(new Uint8Array(1000).fill(0x81))).toThrow(InvalidArgumentError);
  });
});

function normalise(v: unknown): unknown {
  if (v instanceof Uint8Array) return { b: Array.from(v) };
  if (Array.isArray(v)) return v.map(normalise);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)).map(([k, x]) => [k, normalise(x)]));
  return v;
}
