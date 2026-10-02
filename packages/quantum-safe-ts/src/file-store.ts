/**
 * `FileMigrationStore`: a {@link MigrationStore} backed by a directory, with an atomic `compareAndSet` that is safe across **processes on
 * one host** (tested with concurrent child processes). Node.js only: import from `quantum-safe-ts/file-store`.
 *
 * How it works: each store key is one file. A per-key lock is taken with `mkdir` (atomic on local filesystems) and stamped with an owner
 * token; while held it is kept fresh by a heartbeat. The value is compared, then written to a temporary file, fsynced and renamed over the old
 * one, so readers never see a partial value. Ownership is re-checked immediately before the rename, and a lock is only released by its owner.
 * A lock left by a crashed process (no heartbeat for `staleLockMs`) is broken by atomically renaming it away.
 *
 * Limits, stated plainly: this is not distributed. Network filesystems (NFS, SMB, some container volume drivers) may not give atomic
 * `mkdir`/`rename`, so do not share one directory across machines; use a database or Redis store with real compare-and-set there. If a
 * process is frozen for longer than `staleLockMs` (a suspended VM, a long stop-the-world pause) another process may legitimately take its lock;
 * the frozen one then fails with "lock lost" instead of writing, except in a window of a few microseconds between the final ownership check and
 * the rename. Files are written with mode 0600 in a 0700 directory, but the history has no integrity protection: anyone who can write the
 * directory can rewrite it.
 */
import { mkdir, open, readFile, readdir, rename, rm, stat, unlink, utimes, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { MigrationStore } from './migrate.js';

export interface FileMigrationStoreOptions {
  /** Consider a lock abandoned if it has not been refreshed for this many milliseconds. Default 30 000. */
  staleLockMs?: number;
  /** Give up acquiring a lock after this many milliseconds. Default 10 000. */
  lockTimeoutMs?: number;
}

const MAX_KEY_BYTES = 120;
// Lowercase hex, not base64url: file names that differ only by case would be the SAME file on case-insensitive filesystems (Windows, macOS default).
const enc = (key: string): string => Buffer.from(key, 'utf8').toString('hex');
const dec = (name: string): string => Buffer.from(name, 'hex').toString('utf8');
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const TRANSIENT = new Set(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY']);
const code = (e: unknown): string => (e as NodeJS.ErrnoException).code ?? '';

export class FileMigrationStore implements MigrationStore {
  readonly #dir: string;
  readonly #stale: number;
  readonly #timeout: number;

  constructor(directory: string, options: FileMigrationStoreOptions = {}) {
    if (typeof directory !== 'string' || directory === '') throw new TypeError('directory must be a non-empty string');
    this.#dir = directory;
    this.#stale = options.staleLockMs ?? 30_000;
    this.#timeout = options.lockTimeoutMs ?? 10_000;
  }

  #file(key: string): string {
    if (typeof key !== 'string' || Buffer.byteLength(key, 'utf8') > MAX_KEY_BYTES) {
      throw new RangeError(`FileMigrationStore keys must be strings of at most ${MAX_KEY_BYTES} bytes.`);
    }
    return join(this.#dir, `${enc(key)}.json`);
  }

  async get(key: string): Promise<string | undefined> {
    const file = this.#file(key);
    for (let attempt = 0; ; attempt++) {
      try {
        return await readFile(file, 'utf8');
      } catch (e) {
        if (code(e) === 'ENOENT') return undefined;
        // A concurrent atomic rename on Windows can briefly deny reads; a permanently unreadable file must throw, not hang.
        if (TRANSIENT.has(code(e)) && attempt < 100) {
          await sleep(5);
          continue;
        }
        throw e;
      }
    }
  }

  async set(key: string, value: string): Promise<void> {
    await this.#withLock(key, (owns) => this.#write(key, value, owns));
  }

  async keys(): Promise<string[]> {
    try {
      return (await readdir(this.#dir)).filter((n) => n.endsWith('.json')).map((n) => dec(n.slice(0, -'.json'.length)));
    } catch (e) {
      if (code(e) === 'ENOENT') return [];
      throw e;
    }
  }

  async compareAndSet(key: string, expected: string | undefined, value: string): Promise<boolean> {
    return this.#withLock(key, async (owns) => {
      if ((await this.get(key)) !== expected) return false;
      await this.#write(key, value, owns);
      return true;
    });
  }

  async #write(key: string, value: string, owns: () => Promise<void>): Promise<void> {
    const target = this.#file(key);
    const tmp = `${target}.${randomBytes(6).toString('hex')}.tmp`;
    try {
      const fh = await open(tmp, 'w', 0o600);
      try {
        await fh.writeFile(value, 'utf8');
        await fh.sync();
      } finally {
        await fh.close();
      }
      for (let attempt = 0; ; attempt++) {
        await owns(); // ownership is re-checked before EVERY rename attempt, including retries
        try {
          await rename(tmp, target);
          break;
        } catch (e) {
          if (attempt >= 50 || !TRANSIENT.has(code(e))) throw e;
          await sleep(5 + attempt);
        }
      }
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      throw e;
    }
    // Make the rename durable; not supported on every platform (Windows), so best effort.
    try {
      const dh = await open(this.#dir, 'r');
      try {
        await dh.sync();
      } finally {
        await dh.close();
      }
    } catch {
      /* best effort */
    }
  }

  async #withLock<T>(key: string, fn: (owns: () => Promise<void>) => Promise<T>): Promise<T> {
    await mkdir(this.#dir, { recursive: true, mode: 0o700 });
    const lock = `${this.#file(key)}.lock`;
    const token = randomBytes(12).toString('hex');
    const ownerFile = join(lock, 'owner');
    const deadline = Date.now() + this.#timeout;
    for (let attempt = 0; ; attempt++) {
      try {
        await mkdir(lock, { mode: 0o700 });
        try {
          await writeFile(ownerFile, token, { mode: 0o600 });
        } catch (writeError) {
          await rm(lock, { recursive: true, force: true }).catch(() => undefined); // never leave our own ownerless lock behind
          throw writeError;
        }
        break;
      } catch (e) {
        const c = code(e);
        if (c !== 'EEXIST' && !TRANSIENT.has(c) && c !== 'ENOENT') throw e;
        if (c === 'EEXIST') await this.#breakIfStale(lock);
        if (Date.now() > deadline) throw new Error('FileMigrationStore: timed out waiting for a lock.');
        await sleep(Math.min(2 + attempt, 25) + Math.random() * 3);
      }
    }
    // Heartbeat: a lock that is being worked on is never "stale", however long the operation takes.
    const beat = setInterval(() => {
      const now = new Date();
      utimes(lock, now, now).catch(() => undefined);
    }, Math.max(5, Math.floor(this.#stale / 3)));
    beat.unref?.();
    const owns = async (): Promise<void> => {
      let current: string;
      try {
        current = await readFile(ownerFile, 'utf8');
      } catch {
        current = '';
      }
      if (current !== token) throw new Error('FileMigrationStore: the lock was lost (it was broken as stale); nothing was written.');
    };
    try {
      return await fn(owns);
    } finally {
      clearInterval(beat);
      // Release only a lock we still own, so a stalled holder can never delete the lock of whoever took over.
      try {
        if ((await readFile(ownerFile, 'utf8')) === token) await rm(lock, { recursive: true, force: true });
      } catch {
        /* already gone */
      }
    }
  }

  /** Removes a lock that has not been refreshed for `staleLockMs`. The removal is a rename to a unique name, so only one waiter wins it. */
  async #breakIfStale(lock: string): Promise<void> {
    try {
      if (Date.now() - (await stat(lock)).mtimeMs <= this.#stale) return;
      const graveyard = `${lock}.stale.${randomBytes(6).toString('hex')}`;
      await rename(lock, graveyard);
      await rm(graveyard, { recursive: true, force: true });
    } catch {
      /* the holder released it, or another waiter broke it first: just retry */
    }
  }
}
