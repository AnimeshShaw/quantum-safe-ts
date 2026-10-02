/**
 * Migration helpers, mirroring `quantum_safe.migrate` in quantum-safe-py: upgrade an existing classical key to a hybrid key, and track
 * migration progress with an audited state machine over a storage backend you provide.
 *
 * What these do **not** do: find classical cryptography in your code (use `quantum-safe-audit`), re-encrypt stored data, or provide
 * distributed locking. The state manager serialises transitions per key **within one process**; across processes you must either supply a
 * store with atomic compare-and-set ({@link MigrationStore.compareAndSet}) or hold an external lock (Redis SETNX, a database row lock).
 */
import type { MigrationState } from './algorithms.js';
import { kemSuites, sigSuites } from './algorithms.js';
import { InvalidArgumentError, UnsupportedAlgorithmError } from './errors.js';
import { KeyPair, PublicKey, SecretKey } from './keys.js';
import { KEM } from './kem.js';
import { Sign } from './signatures.js';
import { bytes } from './utils.js';

// ---------------------------------------------------------------------------------------------
// Upgrader
// ---------------------------------------------------------------------------------------------

/** Result of {@link Upgrader.upgradeKemKey} / {@link Upgrader.upgradeSigningKey}. */
export interface UpgradeResult {
  /** The new hybrid key pair (free it, or use `using`). */
  readonly keyPair: KeyPair;
  readonly oldAlgorithm: string;
  readonly newAlgorithm: string;
  /** Always `hybrid_transition`. */
  readonly migrationState: MigrationState;
  /** Human-readable notes, including what the upgrade does not give you. */
  readonly notes: string;
}

export interface UpgradeKemKeyInput {
  /** Raw classical secret. X25519: 32 bytes. P-256: the PKCS#8 **PEM text** bytes (quantum-safe-py's layout). */
  classicalSecret: Uint8Array;
  /** Raw classical public key. X25519: 32 bytes. P-256: 65-byte uncompressed SEC1 point. */
  classicalPublic: Uint8Array;
  classicalAlgorithm?: 'X25519' | 'P-256';
  /** Post-quantum KEM to add. Default `ML-KEM-768`. */
  targetPqc?: 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
}

export interface UpgradeSigningKeyInput {
  /** Raw classical secret. Ed25519: 32 bytes. P-256: the PKCS#8 PEM text bytes. */
  classicalSecret: Uint8Array;
  /** Raw classical public key. Ed25519: 32 bytes. P-256: 64-byte raw `x ‖ y` (no 0x04 tag). */
  classicalPublic: Uint8Array;
  classicalAlgorithm?: 'Ed25519' | 'P-256';
  /** Post-quantum signature algorithm to add. Default `ML-DSA-65`. */
  targetPqc?: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
}

function pack(classical: Uint8Array, pqc: Uint8Array): Uint8Array {
  if (classical.length > 0xffff) throw new InvalidArgumentError('classical component is too large to pack.');
  const out = new Uint8Array(2 + classical.length + pqc.length);
  out[0] = classical.length >> 8;
  out[1] = classical.length & 0xff;
  out.set(classical, 2);
  out.set(pqc, 2 + classical.length);
  return out;
}

function unpack(raw: Uint8Array): [Uint8Array, Uint8Array] {
  if (raw.length < 2) throw new InvalidArgumentError('Not a packed hybrid key.');
  const n = (raw[0]! << 8) | raw[1]!;
  if (raw.length < 2 + n) throw new InvalidArgumentError('Not a packed hybrid key.');
  return [raw.slice(2, 2 + n), raw.slice(2 + n)];
}

/** Upgrades classical keys to hybrid post-quantum keys. */
export const Upgrader = {
  /**
   * Adds a fresh post-quantum KEM key to an existing classical KEM key. The classical key bytes are kept **unchanged** inside the
   * hybrid key, so the same X25519/P-256 identity continues. Both halves are required by this library's own `HybridKEM`.
   * @throws {InvalidArgumentError} for wrong key lengths. @throws {UnsupportedAlgorithmError} for an unapproved pairing.
   */
  upgradeKemKey(input: UpgradeKemKeyInput): UpgradeResult {
    const classical = input.classicalAlgorithm ?? 'X25519';
    const pqc = input.targetPqc ?? 'ML-KEM-768';
    const secret = bytes(input.classicalSecret, 'classicalSecret');
    const pub = bytes(input.classicalPublic, 'classicalPublic');
    const name = `${classical}+${pqc}`;
    if (!kemSuites().some((s) => s.name === name && s.hybrid)) {
      throw new UnsupportedAlgorithmError(`'${name}' is not an approved hybrid KEM.`);
    }
    if (classical === 'X25519' && (secret.length !== 32 || pub.length !== 32)) {
      throw new InvalidArgumentError('X25519 keys must be 32 bytes each.');
    }
    if (classical === 'P-256' && (pub.length !== 65 || pub[0] !== 0x04 || secret.length < 100)) {
      throw new InvalidArgumentError('P-256 needs a 65-byte uncompressed public key and the PKCS#8 PEM text bytes as the secret.');
    }
    using pqcPair = new KEM(pqc).generateKeyPair();
    const pqcSecret = pqcPair.secretKey.exportBytes();
    try {
      const keyPair = assemble(name, pack(pub, pqcPair.publicKey.toBytes()), pack(secret, pqcSecret));
      return {
        keyPair,
        oldAlgorithm: classical,
        newAlgorithm: name,
        migrationState: 'hybrid_transition',
        notes:
          `The original ${classical} key is retained unchanged inside the ${name} key. This library's HybridKEM needs both halves; ` +
          'senders that only know the classical key cannot use the hybrid key through this library, so keep a classical-only decryption path ' +
          'for the transition period if you must serve them, and plan its removal.',
      };
    } finally {
      pqcSecret.fill(0);
    }
  },

  /**
   * Adds a fresh post-quantum signing key to an existing classical signing key. The classical key is retained unchanged. New signatures
   * carry both sub-signatures and verifiers must accept both; existing classical-only signatures do **not** verify as hybrid signatures.
   */
  upgradeSigningKey(input: UpgradeSigningKeyInput): UpgradeResult {
    const classical = input.classicalAlgorithm ?? 'Ed25519';
    const pqc = input.targetPqc ?? 'ML-DSA-65';
    const secret = bytes(input.classicalSecret, 'classicalSecret');
    const pub = bytes(input.classicalPublic, 'classicalPublic');
    const name = `${classical}+${pqc}`;
    if (!sigSuites().some((s) => s.name === name && s.hybrid)) {
      throw new UnsupportedAlgorithmError(`'${name}' is not an approved hybrid signature algorithm.`);
    }
    if (classical === 'Ed25519' && (secret.length !== 32 || pub.length !== 32)) {
      throw new InvalidArgumentError('Ed25519 keys must be 32 bytes each.');
    }
    if (classical === 'P-256' && (pub.length !== 64 || secret.length < 100)) {
      throw new InvalidArgumentError('P-256 signing needs a 64-byte raw x||y public key and the PKCS#8 PEM text bytes as the secret.');
    }
    using pqcPair = new Sign(pqc).generateKeyPair();
    const pqcSecret = pqcPair.secretKey.exportBytes();
    try {
      const keyPair = assemble(name, pack(pub, pqcPair.publicKey.toBytes()), pack(secret, pqcSecret));
      return {
        keyPair,
        oldAlgorithm: classical,
        newAlgorithm: name,
        migrationState: 'hybrid_transition',
        notes:
          `The original ${classical} signing key is retained. New signatures contain both an ${classical} and an ${pqc} signature and verifiers ` +
          'require both; signatures made before the upgrade remain classical-only and must be verified with the classical key.',
      };
    } finally {
      pqcSecret.fill(0);
    }
  },

  /**
   * Removes the classical half of a hybrid key pair, producing a PQC-only pair in `pqc_only` state. **One-way**: classical clients can no
   * longer use the result. Log the action in your migration audit trail.
   * @throws {InvalidArgumentError} if the key pair is not hybrid.
   */
  stripClassicalComponent(keyPair: KeyPair): KeyPair {
    const algorithm = keyPair.algorithm;
    if (!algorithm.includes('+') || algorithm === 'X-Wing') {
      throw new InvalidArgumentError(`'${algorithm}' is not a packed hybrid key; there is nothing to strip.`);
    }
    const pqcName = algorithm.split('+')[1]!;
    const [, pqcPublic] = unpack(keyPair.publicKey.toBytes());
    const secretRaw = keyPair.secretKey.exportBytes();
    try {
      const [, pqcSecret] = unpack(secretRaw);
      const pub = PublicKey.fromBytes(pqcName, pqcPublic, 'pqc_only');
      const sec = SecretKey.fromBytes(pqcName, pqcSecret, 'pqc_only');
      pqcSecret.fill(0);
      return assembleFrom(pub, sec);
    } finally {
      secretRaw.fill(0);
    }
  },

  /** True if the key is still `classical_only` and should be upgraded. */
  checkNeedsUpgrade(migrationState: MigrationState): boolean {
    return migrationState === 'classical_only';
  },
} as const;

/** Builds a KeyPair from raw packed bytes via the CBOR bundle path (keeps all secret handling inside WASM). */
function assemble(algorithm: string, publicRaw: Uint8Array, secretRaw: Uint8Array): KeyPair {
  const pub = PublicKey.fromBytes(algorithm, publicRaw, 'hybrid_transition');
  const sec = SecretKey.fromBytes(algorithm, secretRaw, 'hybrid_transition');
  secretRaw.fill(0);
  return assembleFrom(pub, sec);
}

function assembleFrom(pub: PublicKey, sec: SecretKey): KeyPair {
  // The WASM KeyPair class is built from a bundle; round-trip through CBOR bundle bytes.
  const bundle = bundleBytes(pub, sec);
  try {
    return KeyPair.fromCborBundle(bundle);
  } finally {
    bundle.fill(0);
    pub.free();
    sec.free();
  }
}

/** quantum-safe-py `KeyPair.to_cbor_bundle()` layout: `{v, bundle: "keypair", pub: {...}, sec: {...}}`. */
function bundleBytes(pub: PublicKey, sec: SecretKey): Uint8Array {
  const pubCbor = pub.toCbor();
  const secCbor = sec.toCbor();
  try {
    // Map(3 header) + "v":1 + "bundle":"keypair" + "pub": <map> + "sec": <map>; all CBOR-in-CBOR items are embedded verbatim.
    const head = Uint8Array.from([
      0xa4, // map(4)
      0x61, 0x76, 0x01, // "v": 1
      0x66, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, // "bundle"
      0x67, 0x6b, 0x65, 0x79, 0x70, 0x61, 0x69, 0x72, // "keypair"
      0x63, 0x70, 0x75, 0x62, // "pub"
    ]);
    const mid = Uint8Array.from([0x63, 0x73, 0x65, 0x63]); // "sec"
    const out = new Uint8Array(head.length + pubCbor.length + mid.length + secCbor.length);
    out.set(head, 0);
    out.set(pubCbor, head.length);
    out.set(mid, head.length + pubCbor.length);
    out.set(secCbor, head.length + pubCbor.length + mid.length);
    return out;
  } finally {
    secCbor.fill(0);
  }
}

// ---------------------------------------------------------------------------------------------
// Migration state machine
// ---------------------------------------------------------------------------------------------

const FORWARD: Record<MigrationState, readonly MigrationState[]> = {
  classical_only: ['hybrid_transition'],
  hybrid_transition: ['pqc_preferred'],
  pqc_preferred: ['pqc_only'],
  pqc_only: [],
};
const BACKWARD: Partial<Record<MigrationState, readonly MigrationState[]>> = {
  hybrid_transition: ['classical_only'],
  pqc_preferred: ['hybrid_transition'],
  // pqc_only -> anything is intentionally not allowed without a manual override
};

/** An immutable record of one migration transition. */
export interface MigrationRecord {
  readonly recordId: string;
  readonly keyId: string;
  readonly fromState: MigrationState;
  readonly toState: MigrationState;
  readonly algorithm: string;
  /** Unix seconds. */
  readonly timestamp: number;
  readonly actor: string;
  readonly reason: string;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly isForward: boolean;
}

/**
 * Storage you provide (Redis, Postgres, DynamoDB, a Map in tests). Values are JSON strings. Methods may be sync or async.
 * Implement {@link MigrationStore.compareAndSet} to make transitions atomic across processes.
 */
export interface MigrationStore {
  get(key: string): string | undefined | Promise<string | undefined>;
  set(key: string, value: string): void | Promise<void>;
  keys(): Iterable<string> | Promise<Iterable<string>>;
  /** Optional. Sets `key` to `value` only if its current value equals `expected` (`undefined` = absent). Returns whether it was set. */
  compareAndSet?(key: string, expected: string | undefined, value: string): boolean | Promise<boolean>;
}

/** In-memory store, for tests and single-process tools. */
export class MemoryMigrationStore implements MigrationStore {
  readonly #m = new Map<string, string>();
  get(key: string): string | undefined {
    return this.#m.get(key);
  }
  set(key: string, value: string): void {
    this.#m.set(key, value);
  }
  keys(): string[] {
    return [...this.#m.keys()];
  }
  compareAndSet(key: string, expected: string | undefined, value: string): boolean {
    if (this.#m.get(key) !== expected) return false;
    this.#m.set(key, value);
    return true;
  }
}

/** Options for {@link MigrationStateManager.transition}. */
export interface TransitionOptions {
  keyId: string;
  /** Expected current state: an optimistic-concurrency check against stale callers. */
  fromState: MigrationState;
  toState: MigrationState;
  /** Key algorithm after the transition. */
  algorithm: string;
  actor?: string;
  /** Required (non-empty) for backward transitions. */
  reason?: string;
  metadata?: Record<string, unknown>;
  /** Must be true to permit a backward transition. */
  allowBackward?: boolean;
}

const randomId = (): string =>
  Array.from(globalThis.crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Tracks PQC migration state for a collection of keys, with validation, history and an audit trail.
 * Storage-agnostic: you provide the {@link MigrationStore}. Records are JSON, not interchangeable with quantum-safe-py's CBOR store.
 *
 * Valid forward transitions: classical_only → hybrid_transition → pqc_preferred → pqc_only. Backward transitions
 * (hybrid_transition → classical_only, pqc_preferred → hybrid_transition) need `allowBackward: true` and a reason; `pqc_only` is terminal.
 */
export class MigrationStateManager {
  readonly #store: MigrationStore;
  readonly #tails = new Map<string, Promise<unknown>>();

  constructor(store: MigrationStore) {
    this.#store = store;
  }

  /** Records a transition. Serialised per key within this process. @throws {InvalidArgumentError} for invalid or stale transitions. */
  async transition(opts: TransitionOptions): Promise<MigrationRecord> {
    const forwardTargets = FORWARD[opts.fromState] ?? [];
    const backwardTargets = BACKWARD[opts.fromState] ?? [];
    if (!forwardTargets.includes(opts.toState) && !backwardTargets.includes(opts.toState)) {
      throw new InvalidArgumentError(
        `Invalid transition from '${opts.fromState}' to '${opts.toState}'. Valid targets: ${[...forwardTargets, ...backwardTargets].join(', ') || '(none)'}.`,
      );
    }
    const backward = backwardTargets.includes(opts.toState);
    if (backward) {
      if (!opts.allowBackward) throw new InvalidArgumentError(`Backward transition '${opts.fromState}' → '${opts.toState}' requires allowBackward: true.`);
      if (!opts.reason) throw new InvalidArgumentError('A backward transition requires a non-empty reason.');
    }
    return this.#serialise(opts.keyId, async () => {
      const currentRaw = await this.#store.get(`${opts.keyId}_current`);
      const current = currentRaw === undefined ? undefined : (JSON.parse(currentRaw) as MigrationRecord).toState;
      if (current !== undefined && current !== opts.fromState) {
        throw new InvalidArgumentError(`Key '${opts.keyId}' is in state '${current}', but the transition expected '${opts.fromState}'. Concurrent modification or stale state?`);
      }
      const record: MigrationRecord = {
        recordId: randomId(),
        keyId: opts.keyId,
        fromState: opts.fromState,
        toState: opts.toState,
        algorithm: opts.algorithm,
        timestamp: Date.now() / 1000,
        actor: opts.actor ?? 'system',
        reason: opts.reason ?? '',
        metadata: opts.metadata ?? {},
        isForward: forwardTargets.includes(opts.toState),
      };
      const historyRaw = await this.#store.get(`${opts.keyId}_history`);
      const history = historyRaw === undefined ? [] : (JSON.parse(historyRaw) as MigrationRecord[]);
      history.push(record);
      const recordJson = JSON.stringify(record);
      if (this.#store.compareAndSet) {
        const ok = await this.#store.compareAndSet(`${opts.keyId}_current`, currentRaw, recordJson);
        if (!ok) throw new InvalidArgumentError(`Key '${opts.keyId}' was modified concurrently; retry.`);
      } else {
        await this.#store.set(`${opts.keyId}_current`, recordJson);
      }
      await this.#store.set(`${opts.keyId}_history`, JSON.stringify(history));
      return record;
    });
  }

  async getCurrentRecord(keyId: string): Promise<MigrationRecord | undefined> {
    const raw = await this.#store.get(`${keyId}_current`);
    return raw === undefined ? undefined : (JSON.parse(raw) as MigrationRecord);
  }

  async getCurrentState(keyId: string): Promise<MigrationState | undefined> {
    return (await this.getCurrentRecord(keyId))?.toState;
  }

  /** Full history, oldest first. */
  async getHistory(keyId: string): Promise<MigrationRecord[]> {
    const raw = await this.#store.get(`${keyId}_history`);
    return raw === undefined ? [] : (JSON.parse(raw) as MigrationRecord[]);
  }

  /** Key ids currently in `state`. A full scan: keep a secondary index in production. */
  async keysByState(state: MigrationState): Promise<string[]> {
    const out: string[] = [];
    for (const k of await this.#store.keys()) {
      if (!k.endsWith('_current')) continue;
      const raw = await this.#store.get(k);
      if (raw !== undefined && (JSON.parse(raw) as MigrationRecord).toState === state) out.push(k.slice(0, -'_current'.length));
    }
    return out;
  }

  /** Counts of keys per state. */
  async migrationProgress(): Promise<Record<MigrationState, number>> {
    const counts: Record<MigrationState, number> = { classical_only: 0, hybrid_transition: 0, pqc_preferred: 0, pqc_only: 0 };
    for (const s of Object.keys(counts) as MigrationState[]) counts[s] = (await this.keysByState(s)).length;
    return counts;
  }

  /** Runs `fn` after every earlier operation on the same key finishes (in-process mutex). */
  #serialise<T>(keyId: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.#tails.get(keyId) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => undefined);
    this.#tails.set(keyId, tail);
    void tail.then(() => {
      if (this.#tails.get(keyId) === tail) this.#tails.delete(keyId);
    });
    return run;
  }
}
