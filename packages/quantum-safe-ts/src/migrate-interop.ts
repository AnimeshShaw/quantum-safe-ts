/**
 * Converters between this library's migration records and quantum-safe-py's migration store layout, so a deployment can move state
 * between the two ecosystems.
 *
 * quantum-safe-py keeps a dict-like store with, per key id, `"<id>_current"` (CBOR of the latest record as a dict) and
 * `"<id>_history"` (CBOR of a list of record dicts). Dict field names are snake_case. These helpers read and write exactly that.
 * They require py to have used its `cbor2` serialiser (the default); py's JSON fallback serialiser is not supported and is rejected.
 */
import { InvalidArgumentError } from './errors.js';
import { CborFloat, cborDecode, cborEncode } from './cbor.js';
import type { CborValue } from './cbor.js';
import { MigrationStateManager, parseMigrationRecord } from './migrate.js';
import type { MigrationRecord } from './migrate.js';

/** A record as quantum-safe-py's `MigrationRecord.to_dict()` writes it. */
function toPyDict(r: MigrationRecord): CborValue {
  return {
    record_id: r.recordId,
    key_id: r.keyId,
    from_state: r.fromState,
    to_state: r.toState,
    algorithm: r.algorithm,
    timestamp: new CborFloat(r.timestamp),
    actor: r.actor,
    reason: r.reason,
    metadata: r.metadata as CborValue,
    is_forward: r.isForward,
  };
}

function fromPyDict(v: CborValue): MigrationRecord {
  if (typeof v !== 'object' || v === null || Array.isArray(v) || v instanceof Uint8Array || v instanceof CborFloat) {
    throw new InvalidArgumentError('quantum-safe-py migration record is not a map.');
  }
  const d = v as Record<string, CborValue>;
  return parseMigrationRecord({
    recordId: d.record_id,
    keyId: d.key_id,
    fromState: d.from_state,
    toState: d.to_state,
    algorithm: d.algorithm,
    timestamp: d.timestamp,
    actor: d.actor ?? 'system',
    reason: d.reason ?? '',
    metadata: d.metadata ?? {},
  });
}

/** Parses one py `"<id>_current"` value. */
export function recordFromPyBytes(data: Uint8Array): MigrationRecord {
  return fromPyDict(cborDecode(data));
}

/** Serialises a record exactly as py's `MigrationRecord.to_bytes()` does. */
export function recordToPyBytes(record: MigrationRecord): Uint8Array {
  return cborEncode(toPyDict(record));
}

/**
 * Exports every key in `manager` into py's layout. The result can be loaded into a py `MigrationStateManager` store dict
 * (`store[key] = value`) and py will continue the history.
 */
export async function exportToPyStore(manager: MigrationStateManager): Promise<Map<string, Uint8Array>> {
  const out = new Map<string, Uint8Array>();
  for (const id of await manager.keyIds()) {
    const history = await manager.getHistory(id);
    const last = history.at(-1);
    if (!last) continue;
    out.set(`${id}_current`, recordToPyBytes(last));
    out.set(`${id}_history`, cborEncode(history.map(toPyDict)));
  }
  return out;
}

/**
 * Imports a py store (`"<id>_current"` and `"<id>_history"` entries) into `manager`. Each key's history is validated as a continuous chain
 * of legal transitions; keys that already have history in `manager` are refused (an error, nothing is overwritten).
 * Keys with a `_current` but no readable `_history` are imported from the single current record.
 * @returns the imported key ids.
 */
export async function importFromPyStore(
  entries: Iterable<readonly [string, Uint8Array]>,
  manager: MigrationStateManager,
): Promise<string[]> {
  const map = new Map<string, Uint8Array>(entries);
  const ids = new Set<string>();
  for (const k of map.keys()) {
    if (k.endsWith('_current')) ids.add(k.slice(0, -'_current'.length));
    else if (k.endsWith('_history')) ids.add(k.slice(0, -'_history'.length));
  }
  const imported: string[] = [];
  for (const id of [...ids].sort()) {
    let records: MigrationRecord[] = [];
    const h = map.get(`${id}_history`);
    if (h) {
      const list = cborDecode(h);
      if (!Array.isArray(list)) throw new InvalidArgumentError(`History for '${id}' is not a list.`);
      records = list.map(fromPyDict);
    }
    if (records.length === 0) {
      const c = map.get(`${id}_current`);
      if (!c) continue;
      records = [recordFromPyBytes(c)];
    }
    // py does not enforce that `_current` matches the tail of `_history` after external edits: require it, or refuse.
    const cur = map.get(`${id}_current`);
    if (cur && recordFromPyBytes(cur).recordId !== records.at(-1)!.recordId) {
      throw new InvalidArgumentError(`'${id}_current' does not match the last history record; refusing to import an inconsistent store.`);
    }
    await manager.importHistory(id, records);
    imported.push(id);
  }
  return imported;
}
