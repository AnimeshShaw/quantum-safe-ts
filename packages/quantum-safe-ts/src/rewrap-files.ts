/**
 * `rewrapDirectory`: move a directory of sealed envelopes from one recipient key to another, safely and verifiably. Node.js only: import it
 * from `quantum-safe-ts/rewrap` (the main `quantum-safe-ts` entry must be imported first, as it initialises the WebAssembly).
 *
 * For every file that is a `SealedMessage` (raw CBOR or hex) it opens the envelope under the old secret key, seals the plaintext to the new
 * public key keeping the AAD, and writes the result. Around that it adds what a real migration needs, the same as quantum-safe-py's
 * `quantum_safe.migrate.rewrap`:
 *
 * - **Never destructive by default.** Output goes to a separate destination directory; the source is not touched. `inPlace: true` replaces
 *   files one at a time through a temporary file and an atomic rename.
 * - **Resumable and idempotent.** A file whose output already exists and is a valid migrated copy is `already_migrated` and left alone, so a
 *   second run does nothing and an interrupted run continues.
 * - **Verified.** With `newSecretKey`, every written file is opened again and its plaintext compared (SHA-256) with the original.
 *   Without it the item's `verified` is `null`: nothing was checked.
 * - **One failure does not stop the run.** Each file ends in `rewrapped`, `skipped` (not an envelope), `already_migrated`, `would_rewrap`
 *   (dry run) or `failed`, with a reason that contains no secret.
 * - **A report** as JSON (`toJSON()`) and as a CycloneDX 1.6 document (`toCbom()`).
 *
 * Only envelopes are handled; a streaming envelope is a different container.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { Envelope, SealedMessage } from './envelope.js';
import { InvalidArgumentError } from './errors.js';
import type { PublicKey, SecretKey } from './keys.js';

/**
 * The outcome for one file: `rewrapped` (written), `skipped` (not an envelope), `already_migrated` (already under the new key),
 * `would_rewrap` (dry run: it would be written) or `failed`.
 */
export type RewrapStatus = 'rewrapped' | 'skipped' | 'already_migrated' | 'would_rewrap' | 'failed';

/** What happened to one file. */
export interface RewrapItem {
  /** Path relative to the source directory, with `/` separators. */
  name: string;
  /** What happened to the file. */
  status: RewrapStatus;
  /** The envelope's KEM algorithm before the run, or `null` if the file is not an envelope. */
  fromAlgorithm: string | null;
  /** The envelope's KEM algorithm after the run (or in the existing copy), or `null` when none was produced. */
  toAlgorithm: string | null;
  /** `true` or `false` when `newSecretKey` was given and the copy was compared; otherwise `null`. */
  verified: boolean | null;
  /** A short reason for `failed` and `skipped` items, never containing key or plaintext data; otherwise `null`. */
  error: string | null;
}

/** Options for {@link rewrapDirectory}. */
export interface RewrapOptions {
  /** The secret key the envelopes are sealed to today. */
  oldSecretKey: SecretKey;
  /** The public key to seal them to. */
  newPublicKey: PublicKey;
  /** The matching new secret key: results are opened again and compared, and files already under the new key are recognised. */
  newSecretKey?: SecretKey;
  /**
   * The AAD each envelope must carry: bytes for all, or a function of the relative path. Omitted: whatever AAD the message carries is
   * accepted (it is authenticated) and kept, and the report's `aadChecked` is false.
   */
  expectedAad?: Uint8Array | ((relativePath: string) => Uint8Array);
  /** Replace files in the source directory (each through a temporary file and an atomic rename). */
  inPlace?: boolean;
  /** Decrypt and check; write nothing. Items are `would_rewrap`. */
  dryRun?: boolean;
  /** Only files whose relative path satisfies this are considered. Default: every file. */
  filter?: (relativePath: string) => boolean;
}

/** The outcome of a run: names, algorithms and counts; never a key or a plaintext. */
export class RewrapReport {
  /** One entry per file considered, in the order they were visited (sorted by name within each directory). */
  readonly items: RewrapItem[] = [];
  /** When the report was created, as an ISO 8601 timestamp. */
  readonly startedAt = new Date().toISOString();
  /**
   * @param newAlgorithm - The KEM algorithm of the new public key.
   * @param dryRun - Whether the run wrote nothing.
   * @param inPlace - Whether files were replaced in the source directory.
   * @param aadChecked - Whether the caller supplied the AAD to expect (`expectedAad`).
   */
  constructor(
    readonly newAlgorithm: string,
    readonly dryRun: boolean,
    readonly inPlace: boolean,
    readonly aadChecked: boolean,
  ) {}

  /**
   * Counts of items by outcome: `rewrapped`, `skipped` and `failed` (always present), and `would_rewrap` (present only when some item has
   * that status). An `already_migrated` item is counted under `skipped`.
   */
  get counts(): Record<string, number> {
    const out: Record<string, number> = { rewrapped: 0, skipped: 0, failed: 0 };
    for (const item of this.items) {
      if (item.status === 'rewrapped') out.rewrapped = (out.rewrapped ?? 0) + 1;
      else if (item.status === 'failed') out.failed = (out.failed ?? 0) + 1;
      else if (item.status === 'would_rewrap') out.would_rewrap = (out.would_rewrap ?? 0) + 1;
      else out.skipped = (out.skipped ?? 0) + 1;
    }
    return out;
  }

  /** True when nothing failed and every rewrapped item that could be verified was. */
  get ok(): boolean {
    return (this.counts.failed ?? 0) === 0 && this.items.every((i) => !(i.status === 'rewrapped' && i.verified === false));
  }

  /**
   * The report as a plain object with snake_case keys (`started_at`, `new_algorithm`, `dry_run`, `in_place`, `aad_checked`, `counts`, `items`),
   * which `JSON.stringify` uses. It contains names, algorithms, statuses and error reasons, never keys or plaintext.
   */
  toJSON(): Record<string, unknown> {
    return {
      started_at: this.startedAt,
      new_algorithm: this.newAlgorithm,
      dry_run: this.dryRun,
      in_place: this.inPlace,
      aad_checked: this.aadChecked,
      counts: this.counts,
      items: this.items.map((i) => ({
        name: i.name,
        status: i.status,
        from_algorithm: i.fromAlgorithm,
        to_algorithm: i.toAlgorithm,
        verified: i.verified,
        error: i.error,
      })),
    };
  }

  /**
   * A CycloneDX 1.6 document: the algorithms migrated from and to, with counts and status.
   *
   * It has one `migrated-from` component per source algorithm of the `rewrapped` and `would_rewrap` items (with the number of items), and one
   * `migrated-to` component for the new algorithm (with the number of `rewrapped` items). Source algorithms other than the new algorithm are
   * marked quantum-vulnerable. A fresh serial number and timestamp are generated on each call.
   * @param applicationName - The name of the subject application in the document (default `envelope-store`).
   * @returns The document as a plain object, ready for `JSON.stringify`.
   */
  toCbom(applicationName = 'envelope-store'): Record<string, unknown> {
    const counts = this.counts;
    const fromCounts = new Map<string, number>();
    for (const i of this.items) {
      if ((i.status === 'rewrapped' || i.status === 'would_rewrap') && i.fromAlgorithm !== null) {
        fromCounts.set(i.fromAlgorithm, (fromCounts.get(i.fromAlgorithm) ?? 0) + 1);
      }
    }
    const slug = (n: string): string => n.toLowerCase().replace(/\+/g, '-');
    const component = (name: string, ref: string, vulnerable: boolean, status: string, items: number): Record<string, unknown> => ({
      type: 'cryptographic-asset',
      'bom-ref': ref,
      name,
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'kem',
          executionEnvironment: 'software-plain-ram',
          implementationPlatform: 'generic',
          nistQuantumSecurityLevel: vulnerable ? 0 : 3,
        },
      },
      properties: [
        { name: 'quantum-safe:quantum-vulnerable', value: vulnerable ? 'true' : 'false' },
        { name: 'quantum-safe:migration-status', value: status },
        { name: 'quantum-safe:items', value: String(items) },
      ],
    });
    const components = [...fromCounts.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, n]) => component(name, `migrated-from/${slug(name)}`, name !== this.newAlgorithm, 'migrated-from', n));
    components.push(component(this.newAlgorithm, `migrated-to/${slug(this.newAlgorithm)}`, false, 'migrated-to', counts.rewrapped ?? 0));
    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: { components: [{ type: 'application', name: 'quantum-safe-ts rewrapDirectory', description: 'Envelope re-wrap migration report' }] },
        component: { type: 'application', 'bom-ref': 'subject', name: applicationName },
        properties: [
          { name: 'quantum-safe:items-rewrapped', value: String(counts.rewrapped ?? 0) },
          { name: 'quantum-safe:items-skipped', value: String(counts.skipped ?? 0) },
          { name: 'quantum-safe:items-failed', value: String(counts.failed ?? 0) },
          { name: 'quantum-safe:new-algorithm', value: this.newAlgorithm },
          { name: 'quantum-safe:verified-items', value: String(this.items.filter((i) => i.verified === true).length) },
        ],
      },
      components,
    };
  }
}

/** The SHA-256 of `b` as lowercase hex; used to compare plaintexts without keeping both. */
const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

/** The envelope in `raw` and how it was encoded, or `null`. Anything that is not an envelope is skipped, not fatal. */
function parse(raw: Uint8Array): { sealed: SealedMessage; encoding: 'bytes' | 'hex' } | null {
  try {
    return { sealed: SealedMessage.fromBytes(raw), encoding: 'bytes' };
  } catch {
    // not CBOR: try hex below
  }
  try {
    const text = Buffer.from(raw).toString('ascii').trim();
    if (!/^[0-9a-fA-F]+$/.test(text) || text.length % 2 !== 0) return null;
    return { sealed: SealedMessage.fromHex(text), encoding: 'hex' };
  } catch {
    return null;
  }
}

/** Serialises `sealed` in the encoding the input file used: raw CBOR bytes, or the hex text as ASCII bytes. */
function encode(sealed: SealedMessage, encoding: 'bytes' | 'hex'): Uint8Array {
  return encoding === 'hex' ? new Uint8Array(Buffer.from(sealed.toHex(), 'ascii')) : sealed.toBytes();
}

/**
 * Writes `data` to `path` so readers see the old or the new file, never a partial one: creates the parent directories, writes a
 * `.<uuid>.tmp` file in the same directory, fsyncs it, renames it over `path`, and removes the temporary file if anything fails.
 * Filesystem errors propagate.
 */
async function writeAtomic(path: string, data: Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = join(dirname(path), `.${randomUUID()}.tmp`);
  try {
    const fh = await open(tmp, 'w');
    try {
      await fh.writeFile(data);
      await fh.sync();
    } finally {
      await fh.close();
    }
    await rename(tmp, path);
  } finally {
    await rm(tmp, { force: true });
  }
}

/**
 * Yields the path of every regular file under `dir`, relative to `base` and with `/` separators. Each directory is read in name order
 * and subdirectories are visited where they appear; symbolic links and other non-regular entries are not yielded.
 */
async function* walk(dir: string, base = dir): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p, base);
    else if (e.isFile()) yield relative(base, p).split(sep).join('/');
  }
}

/**
 * Re-wraps every envelope under `source` from `options.oldSecretKey` to `options.newPublicKey`.
 *
 * Files are visited recursively. Temporary files named `.<anything>.tmp` (left by an interrupted run) are ignored. A file that is not a
 * `SealedMessage` as raw CBOR or as hex text is reported as `skipped`. A written file keeps its input encoding (raw or hex) and its AAD.
 * Resuming: with a destination, an existing output is `already_migrated` when it is an envelope of the new algorithm (and, with
 * `newSecretKey`, opens under it), otherwise the item `failed` and the output is left alone; in place, a file is recognised as already
 * migrated only when `newSecretKey` is given and opens it.
 *
 * @param source - Directory to read.
 * @param destination - Directory to write, mirroring relative paths. Required unless `options.inPlace`.
 * @param options - Keys, AAD policy, `inPlace`, `dryRun` and a path `filter` (see {@link RewrapOptions}).
 * @returns A report with one item per file considered.
 * @throws {InvalidArgumentError} for an unusable argument combination. A bad file never throws: it is reported.
 * @example
 * ```ts
 * import { rewrapDirectory } from 'quantum-safe-ts/rewrap';
 *
 * const report = await rewrapDirectory('./vault', './vault-v2', { oldSecretKey, newPublicKey, newSecretKey });
 * if (!report.ok) console.error(JSON.stringify(report));
 * ```
 */
export async function rewrapDirectory(source: string, destination: string | null, options: RewrapOptions): Promise<RewrapReport> {
  const src = resolve(source);
  if (!(await stat(src).catch(() => null))?.isDirectory()) throw new InvalidArgumentError(`source is not a directory: ${src}`);
  const inPlace = options.inPlace === true;
  let dst = src;
  if (inPlace) {
    if (destination !== null && resolve(destination) !== src) {
      throw new InvalidArgumentError('inPlace rewrites the source directory; do not pass another destination.');
    }
  } else {
    if (destination === null) throw new InvalidArgumentError('destination is required unless inPlace is true.');
    dst = resolve(destination);
    if (dst === src) throw new InvalidArgumentError('destination is the source directory; pass inPlace: true to replace files there.');
  }
  const report = new RewrapReport(options.newPublicKey.algorithm, options.dryRun === true, inPlace, options.expectedAad !== undefined);
  /** The AAD to require for a file: the caller's value (or function of the relative path), else the AAD the message already carries. */
  const aadFor = (rel: string, sealed: SealedMessage): Uint8Array => {
    const e = options.expectedAad;
    if (e === undefined) return sealed.aad;
    return typeof e === 'function' ? e(rel) : e;
  };

  for await (const rel of walk(src)) {
    if (options.filter !== undefined && !options.filter(rel)) continue;
    if (/^\.[^/]*\.tmp$/.test(rel.split('/').pop() ?? '')) continue;
    const item: RewrapItem = { name: rel, status: 'skipped', fromAlgorithm: null, toAlgorithm: null, verified: null, error: null };
    report.items.push(item);
    try {
      const raw = new Uint8Array(await readFile(join(src, ...rel.split('/'))));
      const parsed = parse(raw);
      if (parsed === null) {
        item.error = 'not an envelope';
        continue;
      }
      const { sealed, encoding } = parsed;
      item.fromAlgorithm = sealed.algorithm;
      const aad = aadFor(rel, sealed);
      const target = inPlace ? join(src, ...rel.split('/')) : join(dst, ...rel.split('/'));

      if (inPlace && options.newSecretKey !== undefined) {
        let underNewKey = true;
        try {
          Envelope.open(sealed, options.newSecretKey, { expectedAad: aad });
        } catch {
          underNewKey = false;
        }
        if (underNewKey) {
          item.status = 'already_migrated';
          item.toAlgorithm = sealed.algorithm;
          continue;
        }
      }
      if (!inPlace && (await stat(target).catch(() => null)) !== null) {
        const existing = parse(new Uint8Array(await readFile(target)));
        let ok = existing !== null && existing.sealed.algorithm === options.newPublicKey.algorithm;
        if (ok && existing !== null && options.newSecretKey !== undefined) {
          try {
            Envelope.open(existing.sealed, options.newSecretKey, { expectedAad: aad });
          } catch {
            ok = false;
          }
        }
        if (ok) {
          item.status = 'already_migrated';
          item.toAlgorithm = options.newPublicKey.algorithm;
        } else {
          item.status = 'failed';
          item.error = 'the destination file exists and is not a copy migrated to the new key';
        }
        continue;
      }

      const moved = Envelope.rewrap(sealed, options.oldSecretKey, options.newPublicKey, { expectedAad: aad });
      item.toAlgorithm = moved.algorithm;
      if (options.newSecretKey !== undefined) {
        const original = Envelope.open(sealed, options.oldSecretKey, { expectedAad: aad });
        const again = Envelope.open(moved, options.newSecretKey, { expectedAad: moved.aad });
        item.verified = sha256(original) === sha256(again);
        if (!item.verified) {
          item.status = 'failed';
          item.error = 'the re-wrapped copy did not match the original';
          continue;
        }
      }
      if (options.dryRun === true) {
        item.status = 'would_rewrap';
        continue;
      }
      await writeAtomic(target, encode(moved, encoding));
      item.status = 'rewrapped';
    } catch (e) {
      item.status = 'failed';
      item.error = `${(e as Error).name}: could not open under the old key or write`;
    }
  }
  return report;
}
