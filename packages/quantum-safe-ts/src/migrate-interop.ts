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

/**
 * A record as quantum-safe-py's `MigrationRecord.to_dict()` writes it: snake_case field names, with the timestamp as a CBOR float so that an
 * integral Unix time is still a float on the wire.
 */
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

/**
 * Reads a decoded py record dict. A missing `actor` becomes `system`, a missing `reason` becomes an empty string and a missing `metadata`
 * becomes `{}`; the other fields are validated by `parseMigrationRecord`, and `is_forward` is recomputed from the states rather than trusted.
 * A value that is not a map, or an invalid record, throws {@link InvalidArgumentError}.
 */
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

/**
 * Parses one py `"<id>_current"` value.
 * @param data - The CBOR bytes of one record dict.
 * @returns The record.
 * @throws {InvalidArgumentError} if the bytes are not valid CBOR in the accepted subset, are not a map, or are not a valid record.
 */
export function recordFromPyBytes(data: Uint8Array): MigrationRecord {
  return fromPyDict(cborDecode(data));
}

/**
 * Serialises a record exactly as py's `MigrationRecord.to_bytes()` does.
 * @param record - The record to write.
 * @returns The CBOR bytes of the record dict.
 * @throws {InvalidArgumentError} if the record's `metadata` holds a value the CBOR codec cannot encode (for example a non-finite number).
 */
export function recordToPyBytes(record: MigrationRecord): Uint8Array {
  return cborEncode(toPyDict(record));
}

/**
 * Exports every key in `manager` into py's layout. The result can be loaded into a py `MigrationStateManager` store dict
 * (`store[key] = value`) and py will continue the history.
 * @param manager - The manager whose keys are exported.
 * @returns A map from `"<id>_current"` (the latest record) and `"<id>_history"` (all records, oldest first) to CBOR bytes.
 * @throws {InvalidArgumentError} if a stored history is corrupt.
 * @example
 * ```ts
 * const entries = await exportToPyStore(manager);
 * const latest = entries.get('orders_current'); // CBOR of the latest record of the key "orders"
 * ```
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
 * Keys with a `_current` but no `_history` (or an empty one) are imported from the single current record. When both are present, `_current` must
 * be the last record of `_history`. Keys are imported one at a time in sorted order; a failure stops the run, and keys imported before it
 * stay imported.
 * @param entries - The py store as `[key, value]` pairs of CBOR bytes.
 * @param manager - The manager to import into.
 * @returns the imported key ids.
 * @throws {InvalidArgumentError} for invalid CBOR, a `_history` that is not a list, an invalid record or illegal transition, a `_current` that
 * does not match the end of `_history`, or a key that already has history in `manager`.
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
