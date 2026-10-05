# Migrating to post-quantum

Migration is gradual: you cannot swap every key and every client at once. This toolkit covers the parts a library can: finding what
needs to change, upgrading keys without discarding the classical identity, and tracking progress with an audit trail.

| Step | Tool |
|---|---|
| 1. Find classical cryptography | [`quantum-safe-audit`](/tools/audit) and the [GitHub Action](/tools/github-action) |
| 2. Upgrade keys to hybrid | `Upgrader` |
| 3. Track and gate each key's progress | `MigrationStateManager` with a store you provide |
| 4. Retire the classical half | `Upgrader.stripClassicalComponent`, once all clients are ready |

It does **not** re-encrypt your stored data, and it does not decide when your clients are ready.

## A plan, end to end

1. **Inventory.** Run `npx quantum-safe-audit scan .` and `cbom .`; read the [audit page](/tools/audit). Decide which findings are exposed to
   harvest-now-decrypt-later (anything whose confidentiality must outlive about a decade: encrypted data at rest, recorded traffic, long-lived
   secrets) and fix those first. Signatures matter once a quantum computer exists, so they can follow.
2. **Pick suites** ([Choosing what to use](/guide/choosing)): hybrid `X25519+ML-KEM-768` and `Ed25519+ML-DSA-65` (or `-v2`) in most cases.
3. **Upgrade keys** with `Upgrader`, one population at a time, recording each key as `hybrid_transition` in a `MigrationStateManager`.
4. **Dual-run.** Servers accept both the old and the new; clients move when ready. Watch `migrationProgress()` and `needsMigration()`.
5. **Prefer post-quantum** (`pqc_preferred`) once nearly every client can use the new key, then **retire the classical half** (`pqc_only`) with
   `Upgrader.stripClassicalComponent`. Going back is possible but explicit and recorded.
6. **Gate CI** with the [GitHub Action](/tools/github-action) so new classical cryptography cannot slip back in.

| State | Meaning | Typical action |
|---|---|---|
| `classical_only` | Only the classical key exists | Upgrade it |
| `hybrid_transition` | A hybrid key exists; clients are moving | Run both; track progress |
| `pqc_preferred` | Nearly everyone uses the new key; classical is a fallback | Prepare to retire the classical half |
| `pqc_only` | Classical half removed (terminal) | Done |

## Upgrade a key

`Upgrader` adds a fresh post-quantum key to an existing classical key and keeps the classical bytes unchanged, so the same X25519 or
Ed25519 identity continues inside the new hybrid key.

```ts test
import { HybridKEM, Upgrader, utf8 } from 'quantum-safe-ts';

// Pretend these are your existing X25519 key bytes (32 + 32 bytes). Here we lift them out of a throwaway key.
using old = new HybridKEM().generateKeyPair();
const pubRaw = old.publicKey.toBytes();
const secRaw = old.secretKey.exportBytes();
const len = (raw: Uint8Array) => (raw[0]! << 8) | raw[1]!;
const classicalPublic = pubRaw.slice(2, 2 + len(pubRaw));
const classicalSecret = secRaw.slice(2, 2 + len(secRaw));

const result = Upgrader.upgradeKemKey({ classicalSecret, classicalPublic, classicalAlgorithm: 'X25519', targetPqc: 'ML-KEM-768' });
using upgraded = result.keyPair;
if (result.newAlgorithm !== 'X25519+ML-KEM-768' || result.migrationState !== 'hybrid_transition') throw new Error('unexpected');

// The upgraded key is a working hybrid key.
const kem = new HybridKEM('X25519+ML-KEM-768');
const { ciphertext, sharedSecret } = kem.encapsulate(upgraded.publicKey);
using back = kem.decapsulate(upgraded.secretKey, ciphertext);
sharedSecret.free();
if (back.exportBytes().length !== 32) throw new Error('unexpected');
secRaw.fill(0);
```

The upgrader round-trips the new key (encapsulate and decapsulate, or sign and verify) before returning it, so a classical public key that does not belong to the secret, or a swapped pair, is refused at upgrade time instead of producing a hybrid key that can never decrypt.

Supported: X25519 and P-256 (KEM, with ML-KEM-512/768/1024 where approved), Ed25519 and P-256 (signing, with ML-DSA-44/65/87 where
approved). Raw key layouts follow quantum-safe-py: X25519 and Ed25519 are 32 raw bytes; a P-256 secret is its PKCS#8 PEM text as bytes;
a P-256 KEM public key is the 65-byte uncompressed point; a P-256 signing public key is the 64-byte raw `x ‖ y`.

::: warning The old classical key is not a drop-in for the new one
The hybrid key is packed as `u16 length ‖ classical ‖ post-quantum`. A sender that only speaks plain X25519 cannot use it. Keep the
original classical key (and a classical decryption path) for any such sender during the transition, and plan to retire it. (quantum-safe-py's
documentation says old senders can still use the classical component; its code does not support that either.)
:::

## Track progress

```ts test
import { MemoryMigrationStore, MigrationStateManager } from 'quantum-safe-ts';

const manager = new MigrationStateManager(new MemoryMigrationStore());
await manager.transition({
  keyId: 'user-1', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'X25519+ML-KEM-768', actor: 'rotation-job',
});
await manager.transition({ keyId: 'user-1', fromState: 'hybrid_transition', toState: 'pqc_preferred', algorithm: 'X25519+ML-KEM-768' });

// Going backwards needs an explicit flag and a reason, and is recorded.
await manager.transition({
  keyId: 'user-1', fromState: 'pqc_preferred', toState: 'hybrid_transition', algorithm: 'X25519+ML-KEM-768',
  allowBackward: true, reason: 'client rollback: interop bug',
});

const progress = await manager.migrationProgress();
if (progress.hybrid_transition !== 1 || (await manager.getHistory('user-1')).length !== 3) throw new Error('unexpected');
```

The states are `classical_only → hybrid_transition → pqc_preferred → pqc_only`. `pqc_only` is terminal. A transition names the state
it expects the key to be in; if another writer moved the key first, you get an error instead of a silent overwrite.

## Concurrency: what is and is not safe

Each key's history is stored as one document and written with a single **compare-and-set**. That gives you:

| Setup | Guarantee |
|---|---|
| One process, any store | Transitions on a key are serialised. |
| Several processes, one machine | Use `FileMigrationStore` (below). Tested with concurrent child processes: exactly one writer wins a race. |
| Several machines | Provide a store with an atomic `compareAndSet` (Redis, Postgres, DynamoDB, SQLite recipes in the interface docs). The manager is safe if your store is. We have not tested those backends here. |
| A store without `compareAndSet` | Only in-process safety. `manager.crossProcessSafe` is `false`. Use an external lock. |

```ts no-run
// Node.js only; a complete, running example with two racing workers is in the Cookbook (recipe 6).
import { MigrationStateManager } from 'quantum-safe-ts';
import { FileMigrationStore } from 'quantum-safe-ts/file-store';

const manager = new MigrationStateManager(new FileMigrationStore('./migration-state'));
```

`FileMigrationStore` uses a per-key lock directory stamped with an owner token and kept fresh by a heartbeat, re-checks ownership before each write, and finishes with an fsynced atomic rename. A process frozen for longer than `staleLockMs` can lose its lock; it then fails with "lock lost" instead of writing. It is for **one host**: network filesystems (NFS, SMB) and
some container volume drivers do not give atomic `mkdir` or `rename`, so do not share one directory across machines.

## Moving state to or from quantum-safe-py

Records are JSON in this library and CBOR in quantum-safe-py's store, so they are not interchangeable as stored. Converters read and
write py's exact layout (`<id>_current`, `<id>_history`, CBOR):

```ts test
import { MemoryMigrationStore, MigrationStateManager, exportToPyStore, importFromPyStore } from 'quantum-safe-ts';

const manager = new MigrationStateManager(new MemoryMigrationStore());
await manager.transition({ keyId: 'user-1', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'X25519+ML-KEM-768', actor: 'job' });

const entries = await exportToPyStore(manager);            // Map<string, Uint8Array>: '<id>_current' and '<id>_history' as CBOR, load into a py store dict
console.log([...entries.keys()]);

const other = new MigrationStateManager(new MemoryMigrationStore());
const imported = await importFromPyStore(entries, other);  // validates the history chain; refuses to overwrite existing keys
if (imported.length !== 1 || (await other.getCurrentState('user-1')) !== 'hybrid_transition') throw new Error('round trip failed');
```

Both directions are verified against the real Python library, and the exported bytes are identical to what py writes.
