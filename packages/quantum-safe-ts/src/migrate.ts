/**
 * Migration helpers, mirroring `quantum_safe.migrate` in quantum-safe-py: upgrade an existing classical key to a hybrid key, and track
 * migration progress with a tested state machine over a storage backend you provide.
 *
 * What these do **not** do: find classical cryptography in your code (use `quantum-safe-audit`), re-encrypt stored data, or provide
 * distributed locking. The state manager serialises transitions per key **within one process**; across processes you must either supply a
 * store with atomic compare-and-set ({@link MigrationStore.compareAndSet}) or hold an external lock (Redis SETNX, a database row lock).
 */
import type { MigrationState } from './algorithms.js';
import { kemSuites, sigSuites } from './algorithms.js';
import { InvalidArgumentError, UnsupportedAlgorithmError } from './errors.js';
import { KeyPair, PublicKey, SecretKey } from './keys.js';
import { HybridKEM, KEM } from './kem.js';
import { HybridSign, Sign } from './signatures.js';
import { bytes } from './utils.js';

// ---------------------------------------------------------------------------------------------
// Upgrader
// ---------------------------------------------------------------------------------------------

/** Result of {@link Upgrader.upgradeKemKey} / {@link Upgrader.upgradeSigningKey}. */
export interface UpgradeResult {
  /** The new hybrid key pair (free it, or use `using`). */
  readonly keyPair: KeyPair;
  /** The classical algorithm the key had, for example `X25519`. */
  readonly oldAlgorithm: string;
  /** The hybrid algorithm of the new key, for example `X25519+ML-KEM-768`. */
  readonly newAlgorithm: string;
  /** Always `hybrid_transition`. */
  readonly migrationState: MigrationState;
  /** Human-readable notes, including what the upgrade does not give you. */
  readonly notes: string;
}

/** Input to {@link Upgrader.upgradeKemKey}: an existing classical KEM key pair and the post-quantum KEM to add. */
export interface UpgradeKemKeyInput {
  /** Raw classical secret. X25519: 32 bytes. P-256 and P-384: the PKCS#8 **PEM text** bytes (quantum-safe-py's layout). */
  classicalSecret: Uint8Array;
  /** Raw classical public key. X25519: 32 bytes. P-256: 65-byte, P-384: 97-byte uncompressed SEC1 point. */
  classicalPublic: Uint8Array;
  /** The classical algorithm of the key. Default `X25519`. */
  classicalAlgorithm?: 'X25519' | 'P-256' | 'P-384';
  /** Post-quantum KEM to add. Default `ML-KEM-768`. */
  targetPqc?: 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
}

/** Input to {@link Upgrader.upgradeSigningKey}: an existing classical signing key pair and the post-quantum signature algorithm to add. */
export interface UpgradeSigningKeyInput {
  /** Raw classical secret. Ed25519: 32 bytes. P-256 and P-384: the PKCS#8 PEM text bytes. */
  classicalSecret: Uint8Array;
  /** Raw classical public key. Ed25519: 32 bytes. P-256: 64-byte, P-384: 96-byte raw `x ‖ y` (no 0x04 tag). */
  classicalPublic: Uint8Array;
  /** The classical algorithm of the key. Default `Ed25519`. */
  classicalAlgorithm?: 'Ed25519' | 'P-256' | 'P-384';
  /** Post-quantum signature algorithm to add. Default `ML-DSA-65`. */
  targetPqc?: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
}

/** Message of the {@link InvalidArgumentError} raised when the classical halves of an upgrade do not work together. */
const MISMATCH =
  'The classical public key does not belong to the classical secret (or the pair is not a valid key). An upgrade with a mismatched pair would produce a hybrid key that can never decrypt or sign correctly, so it was refused.';

/**
 * Round-trips the new key; frees it and throws if it does not work. Catches a swapped, wrong or garbage classical half at upgrade time.
 * On success the key pair is left intact and open; on any failure it is freed and an {@link InvalidArgumentError} is thrown.
 */
function selfTestKem(keyPair: KeyPair, algorithm: string): void {
  try {
    const kem = new HybridKEM(algorithm as never);
    const { ciphertext, sharedSecret } = kem.encapsulate(keyPair.publicKey);
    using recovered = kem.decapsulate(keyPair.secretKey, ciphertext);
    using expected = sharedSecret;
    const a = recovered.exportBytes();
    const b = expected.exportBytes();
    let diff = a.length ^ b.length;
    for (let i = 0; i < a.length && i < b.length; i++) diff |= a[i]! ^ b[i]!;
    const same = diff === 0;
    a.fill(0);
    b.fill(0);
    if (!same) throw new InvalidArgumentError(MISMATCH);
  } catch (e) {
    keyPair.free();
    throw e instanceof InvalidArgumentError ? e : new InvalidArgumentError(MISMATCH);
  }
}

/**
 * Signs one byte with the new hybrid key and verifies it. On success the key pair is left intact and open; on any failure it is freed and an
 * {@link InvalidArgumentError} with the mismatch message is thrown.
 */
function selfTestSigning(keyPair: KeyPair, algorithm: string): void {
  try {
    const signer = new HybridSign(algorithm as never);
    signer.verify(signer.sign(new Uint8Array([1]), keyPair.secretKey), keyPair.publicKey);
  } catch {
    keyPair.free();
    throw new InvalidArgumentError(MISMATCH);
  }
}

/** Packs a hybrid key as `u16 length of classical || classical || pqc` (big endian); `classical` may be at most 65,535 bytes. */
function pack(classical: Uint8Array, pqc: Uint8Array): Uint8Array {
  if (classical.length > 0xffff) throw new InvalidArgumentError('classical component is too large to pack.');
  const out = new Uint8Array(2 + classical.length + pqc.length);
  out[0] = classical.length >> 8;
  out[1] = classical.length & 0xff;
  out.set(classical, 2);
  out.set(pqc, 2 + classical.length);
  return out;
}

/** Splits bytes made by {@link pack} into copies of the classical and the post-quantum parts; too-short input throws {@link InvalidArgumentError}. */
function unpack(raw: Uint8Array): [Uint8Array, Uint8Array] {
  if (raw.length < 2) throw new InvalidArgumentError('Not a packed hybrid key.');
  const n = (raw[0]! << 8) | raw[1]!;
  if (raw.length < 2 + n) throw new InvalidArgumentError('Not a packed hybrid key.');
  return [raw.slice(2, 2 + n), raw.slice(2 + n)];
}

/**
 * Upgrades classical keys to hybrid post-quantum keys.
 *
 * @example
 * ```ts
 * const result = Upgrader.upgradeKemKey({ classicalSecret, classicalPublic }); // X25519 + ML-KEM-768
 * using pair = result.keyPair;
 * console.log(result.newAlgorithm, result.migrationState); // "X25519+ML-KEM-768" "hybrid_transition"
 * ```
 */
export const Upgrader = {
  /**
   * Adds a fresh post-quantum KEM key to an existing classical KEM key. The classical key bytes are kept **unchanged** inside the
   * hybrid key, so the same X25519/P-256 identity continues. Both halves are required by this library's own `HybridKEM`.
   *
   * The new key is round-tripped (encapsulate, then decapsulate) before it is returned, which catches a classical public key that does not
   * belong to the secret.
   * @param input - The classical key bytes, the classical algorithm (default `X25519`) and the post-quantum KEM (default `ML-KEM-768`).
   * @returns The hybrid key pair (free it, or use `using`), the old and new algorithm names, the state `hybrid_transition` and notes.
   * @throws {InvalidArgumentError} for wrong key lengths, for a classical key pair that fails the round trip, or for input that is not bytes.
   * @throws {UnsupportedAlgorithmError} for an unapproved pairing.
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
    if (classical === 'P-384' && (pub.length !== 97 || pub[0] !== 0x04 || secret.length < 100)) {
      throw new InvalidArgumentError('P-384 needs a 97-byte uncompressed public key and the PKCS#8 PEM text bytes as the secret.');
    }
    using pqcPair = new KEM(pqc).generateKeyPair();
    const pqcSecret = pqcPair.secretKey.exportBytes();
    try {
      const keyPair = assemble(name, pack(pub, pqcPair.publicKey.toBytes()), pack(secret, pqcSecret));
      selfTestKem(keyPair, name);
      return {
        keyPair,
        oldAlgorithm: classical,
        newAlgorithm: name,
        migrationState: 'hybrid_transition',
        notes:
          `The original ${classical} key is retained unchanged inside the ${name} key. HybridKEM needs both halves. The packed hybrid key ` +
          'is not a plain X25519/P-256 key on the wire, so a sender that only speaks the classical algorithm cannot use it (quantum-safe-py ' +
          'documents otherwise, but its code does not support that either). Keep the original classical key and a classical decryption path ' +
          'for any such sender during the transition, and plan to retire it. Reusing one classical key in two protocols (its old use and this hybrid) ' +
          'means a signature or key agreement made in one context must never be acceptable in the other; use distinct contexts and plan to retire the classical key.',
      };
    } finally {
      pqcSecret.fill(0);
    }
  },

  /**
   * Adds a fresh post-quantum signing key to an existing classical signing key. The classical key is retained unchanged. New signatures
   * carry both sub-signatures and verifiers must accept both; existing classical-only signatures do **not** verify as hybrid signatures.
   *
   * The new key signs and verifies one byte before it is returned, which catches a classical public key that does not belong to the secret.
   * @param input - The classical key bytes, the classical algorithm (default `Ed25519`) and the post-quantum algorithm (default `ML-DSA-65`).
   * @returns The hybrid key pair (free it, or use `using`), the old and new algorithm names, the state `hybrid_transition` and notes.
   * @throws {InvalidArgumentError} for wrong key lengths, for a classical key pair that fails the self-test, or for input that is not bytes.
   * @throws {UnsupportedAlgorithmError} for an unapproved pairing.
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
    if (classical === 'P-384' && (pub.length !== 96 || secret.length < 100)) {
      throw new InvalidArgumentError('P-384 signing needs a 96-byte raw x||y public key and the PKCS#8 PEM text bytes as the secret.');
    }
    using pqcPair = new Sign(pqc).generateKeyPair();
    const pqcSecret = pqcPair.secretKey.exportBytes();
    try {
      const keyPair = assemble(name, pack(pub, pqcPair.publicKey.toBytes()), pack(secret, pqcSecret));
      selfTestSigning(keyPair, name);
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
   *
   * The classical secret bytes are wiped from the temporary copies made here. The input key pair is not modified or freed; free it
   * separately.
   * @param keyPair - A packed hybrid key pair (a name of the form `<classical>+<pqc>`, not `X-Wing`).
   * @returns A new key pair holding only the post-quantum keys, with the algorithm name of the post-quantum half and the state `pqc_only`.
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
      const [classicalSecret, pqcSecret] = unpack(secretRaw);
      classicalSecret.fill(0);
      const pub = PublicKey.fromBytes(pqcName, pqcPublic, 'pqc_only');
      const sec = SecretKey.fromBytes(pqcName, pqcSecret, 'pqc_only');
      pqcSecret.fill(0);
      return assembleFrom(pub, sec);
    } finally {
      secretRaw.fill(0);
    }
  },

  /**
   * True if the key is still `classical_only` and should be upgraded. Accepts a key pair or a state.
   * @param keyOrState - A key pair (its public key's migration state is used) or a {@link MigrationState}.
   * @returns Whether the state is `classical_only`.
   */
  checkNeedsUpgrade(keyOrState: KeyPair | MigrationState): boolean {
    const state = typeof keyOrState === 'string' ? keyOrState : keyOrState.publicKey.migrationState;
    return state === 'classical_only';
  },

  /**
   * Describes a key's migration status for reports and dashboards. Never includes secret material.
   * @param keyPair - The key pair to describe; only its public key is read.
   * @returns The algorithm, state, whether it is a packed hybrid, whether it needs an upgrade, the public-key fingerprint and size in bytes,
   * and a recommendation for the next step.
   */
  describeKey(keyPair: KeyPair): {
    algorithm: string;
    migrationState: MigrationState;
    isHybrid: boolean;
    needsUpgrade: boolean;
    fingerprint: string;
    publicKeySize: number;
    recommendation: string;
  } {
    const pub = keyPair.publicKey;
    const state = pub.migrationState;
    const recommendations: Record<MigrationState, string> = {
      classical_only: 'Upgrade to hybrid_transition with Upgrader.upgradeKemKey() or upgradeSigningKey().',
      hybrid_transition: 'Advance to pqc_preferred when all clients support the hybrid construction.',
      pqc_preferred: 'Consider pqc_only once classical clients are retired. That step cannot be undone for the key.',
      pqc_only: 'Fully migrated. Keep monitoring standards guidance.',
    };
    return {
      algorithm: keyPair.algorithm,
      migrationState: state,
      isHybrid: keyPair.algorithm.includes('+') && keyPair.algorithm !== 'X-Wing',
      needsUpgrade: state === 'classical_only',
      fingerprint: pub.fingerprint(),
      publicKeySize: pub.toBytes().length,
      recommendation: recommendations[state],
    };
  },
} as const;

/** Builds a KeyPair from raw packed bytes; the temporary key objects are freed here. */
function assemble(algorithm: string, publicRaw: Uint8Array, secretRaw: Uint8Array): KeyPair {
  const pub = PublicKey.fromBytes(algorithm, publicRaw, 'hybrid_transition');
  const sec = SecretKey.fromBytes(algorithm, secretRaw, 'hybrid_transition');
  secretRaw.fill(0);
  return assembleFrom(pub, sec);
}

/** Builds a KeyPair from a public and a secret key and frees both inputs, whether or not the build succeeds. */
function assembleFrom(pub: PublicKey, sec: SecretKey): KeyPair {
  try {
    return KeyPair.fromKeys(pub, sec);
  } finally {
    pub.free();
    sec.free();
  }
}

// ---------------------------------------------------------------------------------------------
// Migration state machine
// ---------------------------------------------------------------------------------------------

/** The states reachable by a forward transition from each state. */
const FORWARD: Record<MigrationState, readonly MigrationState[]> = {
  classical_only: ['hybrid_transition'],
  hybrid_transition: ['pqc_preferred'],
  pqc_preferred: ['pqc_only'],
  pqc_only: [],
};
/** The states reachable by a backward transition from each state (these need `allowBackward` and a reason). */
const BACKWARD: Partial<Record<MigrationState, readonly MigrationState[]>> = {
  hybrid_transition: ['classical_only'],
  pqc_preferred: ['hybrid_transition'],
  // pqc_only -> anything is intentionally not allowed without a manual override
};
/** Every migration state, in order of progress. */
const STATES: readonly MigrationState[] = ['classical_only', 'hybrid_transition', 'pqc_preferred', 'pqc_only'];
/** Type guard: true when `v` is one of the four migration state names. */
const isState =(v: unknown): v is MigrationState => typeof v === 'string' && (STATES as readonly string[]).includes(v);

/** An immutable record of one migration transition. */
export interface MigrationRecord {
  /** A random UUID (version 4 layout) identifying this record. */
  readonly recordId: string;
  /** The key this transition belongs to. */
  readonly keyId: string;
  /** The state before the transition. */
  readonly fromState: MigrationState;
  /** The state after the transition. */
  readonly toState: MigrationState;
  /** The key algorithm after the transition. */
  readonly algorithm: string;
  /** Unix seconds. */
  readonly timestamp: number;
  /** Who made the change (default `system`). */
  readonly actor: string;
  /** Why the change was made; non-empty for a backward transition. */
  readonly reason: string;
  /** Free-form JSON-serializable details supplied by the caller. */
  readonly metadata: Readonly<Record<string, unknown>>;
  /** True when `toState` is a forward step from `fromState`. */
  readonly isForward: boolean;
}

/**
 * Storage you provide (Redis, Postgres, DynamoDB, a file, a Map in tests). Values are JSON strings. Methods may be sync or async.
 *
 * **Cross-process safety depends on {@link MigrationStore.compareAndSet}.** If it is implemented atomically, every transition is atomic
 * across processes and machines that share the store. If it is absent, transitions are only serialised inside one process.
 */
export interface MigrationStore {
  /** Returns the value stored under `key`, or `undefined` when there is none. */
  get(key: string): string | undefined | Promise<string | undefined>;
  /** Stores `value` under `key`, replacing any existing value. */
  set(key: string, value: string): void | Promise<void>;
  /** Lists every key in the store. */
  keys(): Iterable<string> | Promise<Iterable<string>>;
  /**
   * Optional but strongly recommended. Atomically sets `key` to `value` only if its current value is exactly `expected`
   * (`undefined` means "the key must not exist"). Returns whether the write happened.
   * Recipes: Redis `WATCH`/`MULTI` or a Lua script; Postgres `UPDATE ... WHERE value = $expected` (and `INSERT ... ON CONFLICT DO NOTHING`
   * for absent); DynamoDB `ConditionExpression`; SQLite `BEGIN IMMEDIATE`. `FileMigrationStore` (subpath `quantum-safe-ts/file-store`)
   * is a tested single-host implementation.
   */
  compareAndSet?(key: string, expected: string | undefined, value: string): boolean | Promise<boolean>;
}

/** In-memory store, for tests and single-process tools. Atomic within the process. */
export class MemoryMigrationStore implements MigrationStore {
  readonly #m = new Map<string, string>();
  /** Returns the value stored under `key`, or `undefined` when there is none. */
  get(key: string): string | undefined {
    return this.#m.get(key);
  }
  /** Stores `value` under `key`, replacing any existing value. */
  set(key: string, value: string): void {
    this.#m.set(key, value);
  }
  /** Returns a snapshot array of every key. */
  keys(): string[] {
    return [...this.#m.keys()];
  }
  /**
   * Sets `key` to `value` only if its current value is exactly `expected` (`undefined` meaning the key must not exist).
   * @returns Whether the write happened.
   */
  compareAndSet(key: string, expected: string | undefined, value: string): boolean {
    if (this.#m.get(key) !== expected) return false;
    this.#m.set(key, value);
    return true;
  }
}

/** Options for {@link MigrationStateManager.transition}. */
export interface TransitionOptions {
  /** The key to move; a non-empty string. */
  keyId: string;
  /** Expected current state: an optimistic-concurrency check against stale callers. */
  fromState: MigrationState;
  /** The state to move to. */
  toState: MigrationState;
  /** Key algorithm after the transition. */
  algorithm: string;
  /** Who made the change. Default `system`. */
  actor?: string;
  /** Required (non-empty) for backward transitions. */
  reason?: string;
  /** Free-form JSON-serializable details stored in the record. Default empty. */
  metadata?: Record<string, unknown>;
  /** Must be true to permit a backward transition. */
  allowBackward?: boolean;
}

/** A random UUID in the version 4 layout, from the platform's secure random source. */
const randomId = (): string => {
  const b = globalThis.crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6]! & 0x0f) | 0x40; // UUID v4, same shape as quantum-safe-py's record ids
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};

/** Store-key prefix of one key's history document. Exported for store implementations and tooling. */
export const MIGRATION_DOC_PREFIX = 'qs-migration/v1/';
/** How many times `transition` re-reads and retries after losing a compare-and-set race. */
const MAX_ATTEMPTS = 32;
/** Most records one key's history may hold, for writes through `transition` and for reading a stored document. */
const MAX_HISTORY = 10_000;

/**
 * @internal Validates an untrusted value as a migration record (used for stored documents and imports).
 *
 * Requires string `recordId`, `keyId`, `algorithm`, `actor` and `reason`, known `fromState` and `toState`, a finite `timestamp`, a `metadata`
 * object, and (when `expectKey` is given) a matching `keyId`. `isForward` is recomputed from the two states, whatever the input says.
 * @param v - The value to validate.
 * @param expectKey - The key id the record must belong to.
 * @returns A new record object built from the validated fields.
 * @throws {InvalidArgumentError} naming the first invalid field.
 */
export function parseMigrationRecord(v: unknown, expectKey?: string): MigrationRecord {
  const r = v as Record<string, unknown> | null;
  const bad = (why: string): never => {
    throw new InvalidArgumentError(`Corrupt migration record (${why}).`);
  };
  if (typeof r !== 'object' || r === null || Array.isArray(r)) return bad('not an object');
  for (const f of ['recordId', 'keyId', 'algorithm', 'actor', 'reason'] as const) if (typeof r[f] !== 'string') bad(f);
  if (!isState(r.fromState) || !isState(r.toState)) bad('state');
  if (typeof r.timestamp !== 'number' || !Number.isFinite(r.timestamp)) bad('timestamp');
  if (typeof r.metadata !== 'object' || r.metadata === null || Array.isArray(r.metadata)) bad('metadata');
  if (expectKey !== undefined && r.keyId !== expectKey) bad('key id mismatch');
  const fromState = r.fromState as MigrationState;
  const toState = r.toState as MigrationState;
  return {
    recordId: r.recordId as string,
    keyId: r.keyId as string,
    fromState,
    toState,
    algorithm: r.algorithm as string,
    timestamp: r.timestamp as number,
    actor: r.actor as string,
    reason: r.reason as string,
    metadata: r.metadata as Record<string, unknown>,
    isForward: FORWARD[fromState].includes(toState),
  };
}

/**
 * Parses a stored history document `{ v: 1, history: [...] }` for `keyId` into validated records. Invalid JSON, another version, a
 * non-array history, a history over 10,000 records or an invalid record throws {@link InvalidArgumentError}.
 */
function parseDoc(raw: string, keyId: string): MigrationRecord[] {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw new InvalidArgumentError(`Corrupt migration document for key '${keyId}' (not JSON).`);
  }
  const d = doc as { v?: unknown; history?: unknown } | null;
  if (typeof d !== 'object' || d === null || d.v !== 1 || !Array.isArray(d.history) || d.history.length > MAX_HISTORY) {
    throw new InvalidArgumentError(`Corrupt migration document for key '${keyId}'.`);
  }
  return d.history.map((x) => parseMigrationRecord(x, keyId));
}

/** The JSON text of a history document, `{ "v": 1, "history": [...] }`, the inverse of `parseDoc`. */
const serialiseDoc = (history: readonly MigrationRecord[]): string => JSON.stringify({ v: 1, history });

/**
 * Tracks PQC migration state for a collection of keys, with validation, history and an audit trail.
 * Storage-agnostic: you provide the {@link MigrationStore}. Convert to and from quantum-safe-py's store layout with
 * `exportToPyStore` / `importFromPyStore`.
 *
 * Valid forward transitions: classical_only → hybrid_transition → pqc_preferred → pqc_only. Backward transitions
 * (hybrid_transition → classical_only, pqc_preferred → hybrid_transition) need `allowBackward: true` and a reason; `pqc_only` is terminal.
 *
 * **Concurrency.** Each key's whole history is one document, written with a single compare-and-set. With a store that implements
 * `compareAndSet` atomically, concurrent transitions from any number of processes are safe: exactly one wins and the others get a
 * stale-state error. Without it, the manager only serialises inside this process (see {@link MigrationStateManager.crossProcessSafe}).
 *
 * Each key's history is stored under `MIGRATION_DOC_PREFIX + keyId` as JSON, at most 10,000 records per key.
 *
 * @example
 * ```ts
 * const manager = new MigrationStateManager(new MemoryMigrationStore());
 * await manager.transition({ keyId: 'orders', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'X25519+ML-KEM-768' });
 * await manager.getCurrentState('orders'); // "hybrid_transition"
 * ```
 */
export class MigrationStateManager {
  readonly #store: MigrationStore;
  readonly #tails = new Map<string, Promise<unknown>>();

  /** @param store - The storage backend. Give it an atomic `compareAndSet` for safety across processes. */
  constructor(store: MigrationStore) {
    this.#store = store;
  }

  /** True if the store provides compare-and-set, so transitions are atomic across processes (given a correct store). */
  get crossProcessSafe(): boolean {
    return typeof this.#store.compareAndSet === 'function';
  }

  /**
   * Records a transition.
   *
   * The transition must be a legal step from `fromState`. A key with no history accepts any `fromState` as its starting point; a key with
   * history must currently be in `fromState`. A backward step needs `allowBackward: true` and a non-empty `reason`. With
   * `compareAndSet` the write is retried up to 32 times after losing a race; without it the write is a plain `set`.
   * @param opts - The key, the expected and new states, the key's algorithm after the change, and optional actor, reason and metadata.
   * @returns The record that was stored.
   * @throws {InvalidArgumentError} for invalid, stale or contended transitions: an empty `keyId`, an unknown state, an illegal step, a backward
   * step without `allowBackward` or a reason, a current state other than `fromState`, a corrupt stored history, a history that already holds
   * 10,000 records, or 32 lost compare-and-set races in a row.
   */
  async transition(opts: TransitionOptions): Promise<MigrationRecord> {
    if (typeof opts.keyId !== 'string' || opts.keyId.length === 0) throw new InvalidArgumentError('keyId must be a non-empty string.');
    if (!isState(opts.fromState) || !isState(opts.toState)) throw new InvalidArgumentError('Unknown migration state.');
    const forwardTargets = FORWARD[opts.fromState];
    const backwardTargets = BACKWARD[opts.fromState] ?? [];
    if (!forwardTargets.includes(opts.toState) && !backwardTargets.includes(opts.toState)) {
      throw new InvalidArgumentError(
        `Invalid transition from '${opts.fromState}' to '${opts.toState}'. Valid targets: ${[...forwardTargets, ...backwardTargets].join(', ') || '(none)'}.`,
      );
    }
    if (backwardTargets.includes(opts.toState)) {
      if (!opts.allowBackward) throw new InvalidArgumentError(`Backward transition '${opts.fromState}' → '${opts.toState}' requires allowBackward: true.`);
      if (!opts.reason) throw new InvalidArgumentError('A backward transition requires a non-empty reason.');
    }
    return this.#serialise(opts.keyId, async () => {
      const storeKey = MIGRATION_DOC_PREFIX + opts.keyId;
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        const raw = await this.#store.get(storeKey);
        const history = raw === undefined ? [] : parseDoc(raw, opts.keyId);
        const current = history.at(-1)?.toState;
        if (current !== undefined && current !== opts.fromState) {
          throw new InvalidArgumentError(
            `Key '${opts.keyId}' is in state '${current}', but the transition expected '${opts.fromState}'. Concurrent modification or stale state?`,
          );
        }
        if (history.length >= MAX_HISTORY) throw new InvalidArgumentError(`History for '${opts.keyId}' is full.`);
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
        const next = serialiseDoc([...history, record]);
        if (!this.#store.compareAndSet) {
          await this.#store.set(storeKey, next);
          return record;
        }
        if (await this.#store.compareAndSet(storeKey, raw, next)) return record;
        // Lost a race: re-read and re-validate (the next pass reports a stale state if the other writer moved the key on).
      }
      throw new InvalidArgumentError(`Key '${opts.keyId}' is too contended; giving up after ${MAX_ATTEMPTS} attempts.`);
    });
  }

  /**
   * Imports a complete, previously exported history for a key that has no records yet (used by `importFromPyStore`).
   * The chain is validated: each record's `fromState` must equal the previous `toState` and every step must be a legal transition.
   * Without `compareAndSet` the check for existing history and the write are two separate store calls.
   * @param keyId - The key the records belong to; every record's `keyId` must equal it.
   * @param records - The history, oldest first.
   * @throws {InvalidArgumentError} for an empty list, an invalid record, an illegal step, a broken chain, or a key that already has history
   * (including one created concurrently).
   */
  async importHistory(keyId: string, records: readonly MigrationRecord[]): Promise<void> {
    if (records.length === 0) throw new InvalidArgumentError('Nothing to import.');
    if (records.length > MAX_HISTORY) throw new InvalidArgumentError(`A history holds at most ${MAX_HISTORY} records; got ${records.length}.`);
    let prev: MigrationState | undefined;
    for (const r of records) {
      parseMigrationRecord(r, keyId);
      const legal = FORWARD[r.fromState].includes(r.toState) || (BACKWARD[r.fromState] ?? []).includes(r.toState);
      if (!legal) throw new InvalidArgumentError(`Imported history has an illegal transition '${r.fromState}' → '${r.toState}'.`);
      if (prev !== undefined && prev !== r.fromState) throw new InvalidArgumentError('Imported history is not a continuous chain.');
      prev = r.toState;
    }
    await this.#serialise(keyId, async () => {
      const storeKey = MIGRATION_DOC_PREFIX + keyId;
      if ((await this.#store.get(storeKey)) !== undefined) throw new InvalidArgumentError(`Key '${keyId}' already has history; refusing to overwrite.`);
      const doc = serialiseDoc(records);
      if (this.#store.compareAndSet) {
        if (!(await this.#store.compareAndSet(storeKey, undefined, doc))) throw new InvalidArgumentError(`Key '${keyId}' was created concurrently.`);
      } else {
        await this.#store.set(storeKey, doc);
      }
    });
  }

  /**
   * The latest record of `keyId`, or `undefined` when the key has no history.
   * @throws {InvalidArgumentError} if the stored document is corrupt.
   */
  async getCurrentRecord(keyId: string): Promise<MigrationRecord | undefined> {
    return (await this.getHistory(keyId)).at(-1);
  }

  /**
   * The current state of `keyId` (the `toState` of its latest record), or `undefined` when the key has no history.
   * @throws {InvalidArgumentError} if the stored document is corrupt.
   */
  async getCurrentState(keyId: string): Promise<MigrationState | undefined> {
    return (await this.getCurrentRecord(keyId))?.toState;
  }

  /**
   * Full history, oldest first.
   * @throws {InvalidArgumentError} if the stored document is corrupt.
   */
  async getHistory(keyId: string): Promise<MigrationRecord[]> {
    const raw = await this.#store.get(MIGRATION_DOC_PREFIX + keyId);
    return raw === undefined ? [] : parseDoc(raw, keyId);
  }

  /** All key ids that have any history, sorted. A full scan: keep a secondary index in production. */
  async keyIds(): Promise<string[]> {
    const out: string[] = [];
    for (const k of await this.#store.keys()) if (k.startsWith(MIGRATION_DOC_PREFIX)) out.push(k.slice(MIGRATION_DOC_PREFIX.length));
    return out.sort();
  }

  /**
   * Key ids currently in `state`, sorted. A full scan.
   * @throws {InvalidArgumentError} if a stored document is corrupt.
   */
  async keysByState(state: MigrationState): Promise<string[]> {
    const out: string[] = [];
    for (const id of await this.keyIds()) if ((await this.getCurrentState(id)) === state) out.push(id);
    return out;
  }

  /**
   * Key ids that are still `classical_only`.
   * @throws {InvalidArgumentError} if a stored document is corrupt.
   */
  async needsMigration(): Promise<string[]> {
    return this.keysByState('classical_only');
  }

  /**
   * Counts of keys per state; every state is present, with 0 when no key is in it.
   * @throws {InvalidArgumentError} if a stored document is corrupt.
   */
  async migrationProgress(): Promise<Record<MigrationState, number>> {
    const counts: Record<MigrationState, number> = { classical_only: 0, hybrid_transition: 0, pqc_preferred: 0, pqc_only: 0 };
    for (const id of await this.keyIds()) {
      const s = await this.getCurrentState(id);
      if (s !== undefined) counts[s]++;
    }
    return counts;
  }

  /**
   * Runs `fn` after every earlier operation on the same key finishes (in-process mutex). A failed earlier operation does not block later
   * ones, and the key's queue entry is removed once it drains.
   */
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
