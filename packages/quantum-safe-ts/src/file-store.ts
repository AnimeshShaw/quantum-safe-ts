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

/** Options for {@link FileMigrationStore}. */
export interface FileMigrationStoreOptions {
  /** Consider a lock abandoned if it has not been refreshed for this many milliseconds. Default 30 000. */
  staleLockMs?: number;
  /** Give up acquiring a lock after this many milliseconds. Default 10 000. */
  lockTimeoutMs?: number;
}

// Hex doubles the length, and the temporary-file and lock suffixes are added to the file name, which must stay under 255 characters.
/** Longest store key accepted, in UTF-8 bytes. */
const MAX_KEY_BYTES = 100;
// Lowercase hex, not base64url: file names that differ only by case would be the SAME file on case-insensitive filesystems (Windows, macOS default).
/** Maps a store key to the lowercase hex of its UTF-8 bytes, used as the file name. */
const enc = (key: string): string => Buffer.from(key, 'utf8').toString('hex');
/** Inverse of {@link enc}: the store key for a hex file name. */
const dec = (name: string): string => Buffer.from(name, 'hex').toString('utf8');
/** Resolves after `ms` milliseconds. */
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
/** Error codes that can occur briefly while another process renames or removes a file (mainly on Windows); the store retries on them. */
const TRANSIENT = new Set(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY']);
/** The Node.js error code of `e` (such as `ENOENT`), or an empty string. */
const code = (e: unknown): string => (e as NodeJS.ErrnoException).code ?? '';

/**
 * A {@link MigrationStore} that keeps each key as a file in one directory, with an atomic `compareAndSet` across processes on one host.
 * See the module notes for how locking works and what it does not cover.
 *
 * Keys are limited to 100 UTF-8 bytes. The directory is created (mode 0700) on the first write, and each file is named by the hex of its key
 * plus `.json`.
 *
 * @example
 * ```ts
 * import { FileMigrationStore } from 'quantum-safe-ts/file-store';
 * import { MigrationStateManager } from 'quantum-safe-ts';
 *
 * const manager = new MigrationStateManager(new FileMigrationStore('./migration-state'));
 * manager.crossProcessSafe; // true: the store provides compareAndSet
 * ```
 */
export class FileMigrationStore implements MigrationStore {
  readonly #dir: string;
  readonly #stale: number;
  readonly #timeout: number;

  /**
   * @param directory - The directory that holds the store's files.
   * @param options - `staleLockMs` (default 30,000) and `lockTimeoutMs` (default 10,000).
   * @throws {TypeError} if `directory` is not a non-empty string.
   */
  constructor(directory: string, options: FileMigrationStoreOptions = {}) {
    if (typeof directory !== 'string' || directory === '') throw new TypeError('directory must be a non-empty string');
    this.#dir = directory;
    this.#stale = options.staleLockMs ?? 30_000;
    this.#timeout = options.lockTimeoutMs ?? 10_000;
  }

  /** The path of the file for `key`; a non-string key or one over 100 UTF-8 bytes throws {@link RangeError}. */
  #file(key: string): string {
    if (typeof key !== 'string' || Buffer.byteLength(key, 'utf8') > MAX_KEY_BYTES) {
      throw new RangeError(`FileMigrationStore keys must be strings of at most ${MAX_KEY_BYTES} bytes.`);
    }
    return join(this.#dir, `${enc(key)}.json`);
  }

  /**
   * Returns the value stored under `key`, or `undefined` when there is none. It takes no lock; a write replaces the file atomically, so a
   * reader sees the old or the new value, never a partial one. A read denied by a concurrent rename is retried (up to 100 times, 5 ms apart).
   * @param key - The store key, at most 100 UTF-8 bytes.
   * @throws {RangeError} for an invalid key.
   * @throws {Error} the Node.js error for a file that stays unreadable for a reason other than absence.
   */
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

  /**
   * Stores `value` under `key`, replacing any existing value, while holding the key's lock. The write goes through a temporary file that is
   * fsynced and renamed into place.
   * @param key - The store key, at most 100 UTF-8 bytes.
   * @param value - The text to store (written as UTF-8).
   * @throws {RangeError} for an invalid key.
   * @throws {Error} `FileMigrationStore: timed out waiting for a lock.` after `lockTimeoutMs`, or `the lock was lost` (nothing is written) if
   * another process took over the lock as stale before the rename; or the Node.js error for a failed filesystem operation.
   */
  async set(key: string, value: string): Promise<void> {
    await this.#withLock(key, (owns) => this.#write(key, value, owns));
  }

  /**
   * Lists every key in the store, in directory order. Returns an empty list when the directory does not exist yet. The names are read from
   * the file names; lock directories and temporary files are not listed.
   * @throws {Error} the Node.js error if the directory cannot be read for a reason other than absence.
   */
  async keys(): Promise<string[]> {
    try {
      return (await readdir(this.#dir)).filter((n) => /^(?:[0-9a-f]{2})+\.json$/.test(n)).map((n) => dec(n.slice(0, -'.json'.length)));
    } catch (e) {
      if (code(e) === 'ENOENT') return [];
      throw e;
    }
  }

  /**
   * Atomically sets `key` to `value` only if its current value is exactly `expected` (`undefined` means "the key must not exist"). The compare
   * and the write both happen while holding the key's lock, which is safe across processes on one host.
   * @param key - The store key, at most 100 UTF-8 bytes.
   * @param expected - The value the key must currently hold, or `undefined` for absent.
   * @param value - The text to store.
   * @returns `true` if the value was written, `false` if the current value differed from `expected`.
   * @throws {RangeError} for an invalid key.
   * @throws {Error} on a lock timeout or a lost lock (see {@link FileMigrationStore.set}), or a failed filesystem operation.
   */
  async compareAndSet(key: string, expected: string | undefined, value: string): Promise<boolean> {
    return this.#withLock(key, async (owns) => {
      if ((await this.get(key)) !== expected) return false;
      await this.#write(key, value, owns);
      return true;
    });
  }

  /**
   * Writes `value` to a temporary file next to the target (mode 0600), fsyncs it, then renames it over the target, calling `owns()` before every
   * rename attempt so a holder that lost its lock writes nothing. Rename failures with a transient code are retried up to 50 times. The
   * temporary file is removed on failure, and the directory is fsynced afterwards where the platform allows. The caller holds the lock.
   */
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

  /**
   * Runs `fn` while holding the lock of `key`: a `<file>.lock` directory made with `mkdir` that contains an `owner` file holding a random
   * token. Waits, with a short randomised backoff, until the lock is free or `lockTimeoutMs` passes, breaking a lock that has not been
   * refreshed for `staleLockMs`. While `fn` runs, a timer refreshes the lock's modification time. `fn` receives `owns()`, which throws if the
   * token in the owner file is no longer ours. The lock is released only if it is still ours.
   * @throws {Error} `FileMigrationStore: timed out waiting for a lock.` when the lock cannot be taken in time.
   */
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
    await breakIfStale(lock, this.#stale);
  }
}

/** The time in milliseconds since `path` was last modified; rejects if it does not exist. */
const ageMs = async (path: string): Promise<number> => Date.now() - (await stat(path)).mtimeMs;

/**
 * Breaks `lock` if it has not been refreshed for `staleMs`.
 *
 * Checking the age and renaming are two steps. Between them another waiter may have broken the stale lock and a third process taken a fresh
 * one at the same path, which our rename would then move away. So the age is checked again on what was actually moved: a lock that turns out
 * to be live is put back (if its path is still free). If it cannot be, its holder fails with "lock lost" before writing, never with a corrupt
 * write.
 *
 * It never throws: a lock that vanished, or that another waiter broke first, is not an error, and the caller simply retries.
 * @param lock - Path of the lock directory.
 * @param staleMs - The age in milliseconds above which a lock counts as abandoned.
 * @param ageOf - Returns the age of a path in milliseconds (default: time since last modification).
 * @internal `ageOf` is injectable for tests.
 */
export async function breakIfStale(lock: string, staleMs: number, ageOf: (path: string) => Promise<number> = ageMs): Promise<void> {
  try {
    if ((await ageOf(lock)) <= staleMs) return;
    const graveyard = `${lock}.stale.${randomBytes(6).toString('hex')}`;
    await rename(lock, graveyard);
    let movedLive = false;
    try {
      movedLive = (await ageOf(graveyard)) <= staleMs;
    } catch {
      movedLive = false;
    }
    if (movedLive) {
      try {
        await rename(graveyard, lock);
        return;
      } catch {
        /* the path is taken again: the holder will notice and fail safely */
      }
    }
    await rm(graveyard, { recursive: true, force: true });
  } catch {
    /* the holder released it, or another waiter broke it first: just retry */
  }
}
