/**
 * `LmsSigner`: LMS signing (RFC 8554, SHA-256, n = m = 32) with **write-ahead durable state**, for Node.js only. Import it from
 * `quantum-safe-ts/lms-signer`; verification of what it signs is `Lms.verify` from the main entry, in any runtime.
 *
 * LMS is stateful: every signature uses one one-time key, and signing two messages with the same one breaks the scheme. So the signer
 * never releases a signature before the index it used is durable:
 *
 * 1. take the key's lock file (exclusive create), read the state, check the tree is not exhausted;
 * 2. write the *next* index to a temporary file, `fsync` it, rename it over the state file, `fsync` the directory;
 * 3. release the lock; only then compute the signature with the index reserved in step 2.
 *
 * A crash anywhere in between can waste an index; it can never reuse one. Any error in the state (missing, unreadable, inconsistent, a
 * lock held by someone else) makes the signer refuse; it does not guess. Before a signature is returned it is checked against the public
 * key's root, so a fault during computation does not produce a bad signature.
 *
 * Scope, stated plainly: one LMS tree (an HSS key with one level), SHA-256 with 32-byte hashes, height 5, 10, 15 or 20, Winternitz 1, 2, 4
 * or 8. The key is generated here from the operating system's random source and kept in a directory on a **local** filesystem (mode
 * 0600 in a 0700 directory); it is not generated inside a hardware module, and the directory must not be restored from a backup while
 * the key is in use (that would reuse indices). Network filesystems may not provide the atomic rename this relies on. The signer refuses
 * to load in browsers and Workers.
 *
 * Key generation computes every leaf of the tree, so it takes time that grows with the tree: seconds for height 10 and w = 8, much longer
 * for height 15 and above (run it in a worker thread or a separate process).
 */
import crypto, { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import { join } from 'node:path';
import { InvalidArgumentError, SigningError, UnsupportedAlgorithmError } from './errors.js';

/** Tree heights this signer builds. Height 25 (33 million leaves) needs HSS with several levels, which is not provided. */
export type LmsSignerHeight = 5 | 10 | 15 | 20;
/** Winternitz parameter: larger is slower and gives shorter signatures. */
export type LmsSignerWinternitz = 1 | 2 | 4 | 8;

export interface LmsSignerCreateOptions {
  /** Directory that will hold the key (`key.json`, `tree.bin`). Created if missing; must not already hold a key. */
  directory: string;
  /** Default 10 (1,024 signatures). */
  height?: LmsSignerHeight;
  /** Default 8. */
  winternitz?: LmsSignerWinternitz;
  /** How long `sign` waits for the key's lock before refusing, in milliseconds. Default 5,000. */
  lockTimeoutMs?: number;
}

export interface LmsSignerOpenOptions {
  /** How long `sign` waits for the key's lock before refusing, in milliseconds. Default 5,000. */
  lockTimeoutMs?: number;
}

const LMS_TYPE: Readonly<Record<number, number>> = { 5: 5, 10: 6, 15: 7, 20: 8 };
const OTS_TYPE: Readonly<Record<number, number>> = { 1: 1, 2: 2, 4: 3, 8: 4 };
const OTS_P: Readonly<Record<number, number>> = { 1: 265, 2: 133, 4: 67, 8: 34 };
const OTS_LS: Readonly<Record<number, number>> = { 1: 7, 2: 6, 4: 4, 8: 0 };
const N = 32;
const D_MESG = 0x8181;
const D_PBLC = 0x8080;
const D_LEAF = 0x8282;
const D_INTR = 0x8383;
const FORMAT = 'quantum-safe-ts-lms-key';

// ---------------------------------------------------------------------------------------------------------------------------------
// Runtime guard
// ---------------------------------------------------------------------------------------------------------------------------------

/** @internal Throws unless this is Node.js (or a runtime that reports itself as such) and not a browser or Worker global scope. */
export function assertNodeRuntime(g: Record<string, unknown> = globalThis as Record<string, unknown>): void {
  const proc = g.process as { versions?: { node?: string } } | undefined;
  const isNode = typeof proc?.versions?.node === 'string';
  const isBrowserLike = typeof g.window !== 'undefined' || typeof g.WorkerGlobalScope !== 'undefined' || typeof g.document !== 'undefined';
  if (!isNode || isBrowserLike) {
    throw new UnsupportedAlgorithmError(
      'LmsSigner signs only in Node.js, where its durable state can be written safely. Browsers and Workers can verify LMS signatures (Lms.verify) but not sign.',
    );
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// LMS / LM-OTS primitives (RFC 8554)
// ---------------------------------------------------------------------------------------------------------------------------------

const sha = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const u32 = (v: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v >>> 0, false);
  return b;
};
const u16 = (v: number): Uint8Array => Uint8Array.of((v >> 8) & 0xff, v & 0xff);
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const fromHex = (s: string, len: number, what: string): Uint8Array => {
  if (typeof s !== 'string' || !/^[0-9a-f]*$/.test(s) || s.length !== len * 2) throw new SigningError(`The LMS key file is damaged (${what}).`);
  return new Uint8Array(Buffer.from(s, 'hex'));
};
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);

/** The `i`-th w-bit coefficient of a byte string (RFC 8554 Algorithm 2). */
function coef(s: Uint8Array, i: number, w: number): number {
  return ((s[(i * w) >> 3] ?? 0) >> (8 - w * ((i % (8 / w)) + 1))) & ((1 << w) - 1);
}

function checksum(q: Uint8Array, w: number): number {
  const ls = OTS_LS[w] as number;
  let sum = 0;
  for (let i = 0; i < (N * 8) / w; i++) sum += (1 << w) - 1 - coef(q, i, w);
  return (sum << ls) & 0xffff;
}

/** One chain step `H(I || u32(q) || u16(i) || u8(j) || tmp)` on a reusable 55-byte buffer. */
class Chain {
  readonly #buf = Buffer.alloc(16 + 4 + 2 + 1 + N);
  constructor(i16: Uint8Array, q: number, index: number) {
    this.#buf.set(i16, 0);
    this.#buf.writeUInt32BE(q >>> 0, 16);
    this.#buf.writeUInt16BE(index, 20);
  }
  /** Advances `tmp` from step `from` to step `to` (exclusive). */
  run(tmp: Uint8Array, from: number, to: number): Uint8Array {
    let cur = tmp;
    for (let j = from; j < to; j++) {
      this.#buf[22] = j;
      this.#buf.set(cur, 23);
      cur = new Uint8Array(createHash('sha256').update(this.#buf).digest());
    }
    return cur;
  }
}

const secretX = (i16: Uint8Array, q: number, i: number, seed: Uint8Array): Uint8Array =>
  sha(i16, u32(q), u16(i), Uint8Array.of(0xff), seed);

/** LM-OTS public key `K` for leaf `q` (RFC 8554 Algorithm 1). */
function otsPublicKey(i16: Uint8Array, seed: Uint8Array, q: number, w: number): Uint8Array {
  const p = OTS_P[w] as number;
  const top = (1 << w) - 1;
  const h = createHash('sha256').update(i16).update(u32(q)).update(u16(D_PBLC));
  for (let i = 0; i < p; i++) h.update(new Chain(i16, q, i).run(secretX(i16, q, i, seed), 0, top));
  return new Uint8Array(h.digest());
}

const leafHash = (i16: Uint8Array, r: number, k: Uint8Array): Uint8Array => sha(i16, u32(r), u16(D_LEAF), k);
const nodeHash = (i16: Uint8Array, r: number, l: Uint8Array, rt: Uint8Array): Uint8Array => sha(i16, u32(r), u16(D_INTR), l, rt);

/** Nodes of the Merkle tree, 1-based: node `r` is at `[r * 32, r * 32 + 32)`; slot 0 is unused. */
function buildTree(i16: Uint8Array, seed: Uint8Array, height: number, w: number): Uint8Array {
  const leaves = 1 << height;
  const t = new Uint8Array(2 * leaves * N);
  for (let q = 0; q < leaves; q++) t.set(leafHash(i16, leaves + q, otsPublicKey(i16, seed, q, w)), (leaves + q) * N);
  for (let r = leaves - 1; r >= 1; r--) {
    t.set(nodeHash(i16, r, t.subarray(2 * r * N, (2 * r + 1) * N), t.subarray((2 * r + 1) * N, (2 * r + 2) * N)), r * N);
  }
  return t;
}

/** Signs with leaf `q` and returns the LMS signature `u32(q) || lmots || u32(lmsType) || path`. */
function lmsSign(
  i16: Uint8Array,
  seed: Uint8Array,
  q: number,
  height: number,
  w: number,
  tree: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const p = OTS_P[w] as number;
  const c = new Uint8Array(crypto.randomBytes(N));
  const qd = sha(i16, u32(q), u16(D_MESG), c, message);
  const qc = concat(qd, u16(checksum(qd, w)));
  const parts: Uint8Array[] = [u32(q), u32(OTS_TYPE[w] as number), c];
  for (let i = 0; i < p; i++) {
    parts.push(new Chain(i16, q, i).run(secretX(i16, q, i, seed), 0, coef(qc, i, w)));
  }
  parts.push(u32(LMS_TYPE[height] as number));
  let r = (1 << height) + q;
  for (let level = 0; level < height; level++) {
    parts.push(tree.slice((r ^ 1) * N, ((r ^ 1) + 1) * N));
    r >>= 1;
  }
  return concat(...parts);
}

/** Recomputes the root from a signature (RFC 8554 Algorithms 4b and 6a); used to check a signature before it is released. */
function lmsRoot(i16: Uint8Array, height: number, w: number, message: Uint8Array, sig: Uint8Array): Uint8Array {
  const p = OTS_P[w] as number;
  const top = (1 << w) - 1;
  const q = new DataView(sig.buffer, sig.byteOffset, sig.byteLength).getUint32(0, false);
  const c = sig.subarray(8, 8 + N);
  const qd = sha(i16, u32(q), u16(D_MESG), c, message);
  const qc = concat(qd, u16(checksum(qd, w)));
  const h = createHash('sha256').update(i16).update(u32(q)).update(u16(D_PBLC));
  for (let i = 0; i < p; i++) {
    const y = sig.subarray(8 + N + i * N, 8 + N + (i + 1) * N);
    h.update(new Chain(i16, q, i).run(new Uint8Array(y), coef(qc, i, w), top));
  }
  const k = new Uint8Array(h.digest());
  let r = (1 << height) + q;
  let node = leafHash(i16, r, k);
  const pathOffset = 8 + N + p * N + 4;
  for (let level = 0; level < height; level++) {
    const sib = sig.subarray(pathOffset + level * N, pathOffset + (level + 1) * N);
    node = r & 1 ? nodeHash(i16, r >> 1, sib, node) : nodeHash(i16, r >> 1, node, sib);
    r >>= 1;
  }
  return node;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Durable state
// ---------------------------------------------------------------------------------------------------------------------------------

interface KeyFile {
  format: string;
  version: number;
  height: number;
  winternitz: number;
  I: string;
  seed: string;
  next: number;
  publicKey: string;
  treeSha256: string;
}

const sleepSync = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

function fsyncDirectory(dir: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch {
    // Directories cannot be opened for fsync on Windows; the rename is already durable there once the file is.
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function writeFileDurable(path: string, data: Uint8Array | string, mode: number): void {
  const tmp = `${path}.tmp`;
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeSync(fd, typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, path);
  fsyncDirectory(join(path, '..'));
}

/**
 * An LMS signing key whose state is kept in a directory. Create it once with {@link LmsSigner.create}; reopen it later with
 * {@link LmsSigner.open}. Several processes may sign with the same directory on one host: each takes the lock to reserve an index.
 */
export class LmsSigner {
  readonly #dir: string;
  readonly #height: number;
  readonly #w: number;
  readonly #i: Uint8Array;
  readonly #seed: Uint8Array;
  readonly #tree: Uint8Array;
  readonly #publicKey: Uint8Array;
  readonly #lockTimeout: number;
  #disposed = false;

  private constructor(
    dir: string,
    key: KeyFile,
    seed: Uint8Array,
    i16: Uint8Array,
    tree: Uint8Array,
    publicKey: Uint8Array,
    lockTimeout: number,
  ) {
    this.#dir = dir;
    this.#height = key.height;
    this.#w = key.winternitz;
    this.#seed = seed;
    this.#i = i16;
    this.#tree = tree;
    this.#publicKey = publicKey;
    this.#lockTimeout = lockTimeout;
  }

  /** Generates a new key in `options.directory`. Refuses if a key is already there. */
  static create(options: LmsSignerCreateOptions): LmsSigner {
    assertNodeRuntime();
    const { directory } = options;
    if (typeof directory !== 'string' || directory === '') throw new InvalidArgumentError('directory must be a non-empty string');
    const height = options.height ?? 10;
    const w = options.winternitz ?? 8;
    if ((height as number) === 25) {
      throw new UnsupportedAlgorithmError('LmsSigner builds one tree of height 5, 10, 15 or 20; height 25 needs a multi-level HSS key, which is not provided.');
    }
    if (!(height in LMS_TYPE)) throw new InvalidArgumentError('height must be 5, 10, 15 or 20');
    if (!(w in OTS_TYPE)) throw new InvalidArgumentError('winternitz must be 1, 2, 4 or 8');
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (fs.existsSync(join(directory, 'key.json')) || fs.existsSync(join(directory, 'tree.bin'))) {
      throw new SigningError('A signing key already exists in this directory; refusing to overwrite it.');
    }
    const i16 = new Uint8Array(crypto.randomBytes(16));
    const seed = new Uint8Array(crypto.randomBytes(N));
    const tree = buildTree(i16, seed, height, w);
    const root = tree.slice(N, 2 * N);
    const publicKey = concat(u32(1), u32(LMS_TYPE[height] as number), u32(OTS_TYPE[w] as number), i16, root);
    const key: KeyFile = {
      format: FORMAT,
      version: 1,
      height,
      winternitz: w,
      I: hex(i16),
      seed: hex(seed),
      next: 0,
      publicKey: hex(publicKey),
      treeSha256: hex(sha(tree)),
    };
    // The tree first: a key file without its tree is refused on open; a tree without a key file is simply unused.
    writeFileDurable(join(directory, 'tree.bin'), tree, 0o600);
    writeFileDurable(join(directory, 'key.json'), JSON.stringify(key), 0o600);
    return new LmsSigner(directory, key, seed, i16, tree, publicKey, options.lockTimeoutMs ?? 5_000);
  }

  /** Opens an existing key. Refuses a damaged or inconsistent directory. */
  static open(directory: string, options: LmsSignerOpenOptions = {}): LmsSigner {
    assertNodeRuntime();
    if (typeof directory !== 'string' || directory === '') throw new InvalidArgumentError('directory must be a non-empty string');
    const key = LmsSigner.#readKey(directory);
    const seed = fromHex(key.seed, N, 'seed');
    const i16 = fromHex(key.I, 16, 'identifier');
    const publicKey = fromHex(key.publicKey, 60, 'public key');
    let tree: Uint8Array;
    try {
      tree = new Uint8Array(fs.readFileSync(join(directory, 'tree.bin')));
    } catch (e) {
      throw new SigningError(`The LMS tree file cannot be read: ${(e as Error).message}`);
    }
    if (tree.length !== 2 * (1 << key.height) * N || !same(sha(tree), fromHex(key.treeSha256, N, 'tree digest'))) {
      throw new SigningError('The LMS tree file does not match the key; refusing to sign.');
    }
    if (!same(tree.subarray(N, 2 * N), publicKey.subarray(28, 60))) {
      throw new SigningError('The LMS tree root does not match the public key; refusing to sign.');
    }
    return new LmsSigner(directory, key, seed, i16, tree, publicKey, options.lockTimeoutMs ?? 5_000);
  }

  static #readKey(directory: string): KeyFile {
    let key: KeyFile;
    try {
      key = JSON.parse(fs.readFileSync(join(directory, 'key.json'), 'utf8')) as KeyFile;
    } catch (e) {
      throw new SigningError(`The LMS key state cannot be read: ${(e as Error).message}`);
    }
    const ok =
      key !== null &&
      typeof key === 'object' &&
      key.format === FORMAT &&
      key.version === 1 &&
      key.height in LMS_TYPE &&
      key.winternitz in OTS_TYPE &&
      Number.isInteger(key.next) &&
      key.next >= 0 &&
      key.next <= 1 << key.height;
    if (!ok) throw new SigningError('The LMS key state is damaged or from an unknown format; refusing to sign.');
    return key;
  }

  /** The HSS public key (`u32(1) || LMS public key`, 60 bytes), the form {@link Lms.verify} takes. */
  get publicKey(): Uint8Array {
    return this.#publicKey.slice();
  }

  /** `LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8`, for example. */
  get parameterSet(): string {
    return `LMS_SHA256_M32_H${this.#height}/LMOTS_SHA256_N32_W${this.#w}`;
  }

  /** The number of signatures this key can make in total. */
  get capacity(): number {
    return 1 << this.#height;
  }

  /** Signatures still available, read from the durable state. */
  get remaining(): number {
    return this.capacity - LmsSigner.#readKey(this.#dir).next;
  }

  /** Reserves the next index durably and returns it. */
  #reserve(): number {
    const lock = join(this.#dir, 'key.json.lock');
    const keyFile = join(this.#dir, 'key.json');
    const deadline = Date.now() + this.#lockTimeout;
    let fd: number | undefined;
    for (;;) {
      try {
        fd = fs.openSync(lock, 'wx', 0o600);
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw new SigningError(`The LMS key lock cannot be taken: ${(e as Error).message}`);
        if (Date.now() > deadline) {
          throw new SigningError(
            'The LMS key is locked by another signer, or a signer stopped while holding the lock. Refusing to sign. If you are sure no signer is running, delete key.json.lock.',
          );
        }
        sleepSync(5);
      }
    }
    try {
      fs.closeSync(fd);
      fd = undefined;
      const key = LmsSigner.#readKey(this.#dir);
      // The file must still describe the key this object holds.
      if (key.publicKey !== hex(this.#publicKey) || key.I !== hex(this.#i)) {
        throw new SigningError('The LMS key state belongs to a different key; refusing to sign.');
      }
      if (key.next >= 1 << this.#height) {
        throw new SigningError('This LMS key has used all of its one-time keys; it cannot sign again. Generate a new key.');
      }
      const reserved = key.next;
      try {
        writeFileDurable(keyFile, JSON.stringify({ ...key, next: reserved + 1 }), 0o600);
      } catch (e) {
        try {
          fs.unlinkSync(`${keyFile}.tmp`);
        } catch {
          // Nothing to clean up.
        }
        throw new SigningError(`The LMS key state could not be written, so nothing was signed: ${(e as Error).message}`);
      }
      return reserved;
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
      try {
        fs.unlinkSync(lock);
      } catch {
        // Nothing more can be done; the next signer reports a held lock rather than reusing an index.
      }
    }
  }

  /**
   * Signs `message` and returns an HSS signature (`u32(0) || LMS signature`) that `Lms.verify(publicKey, message, signature)` accepts.
   * Consumes one one-time key, durably, before the signature exists.
   *
   * @throws {SigningError} if the state cannot be read or written, the key is exhausted, or the signature fails its own check.
   */
  sign(message: Uint8Array): Uint8Array {
    assertNodeRuntime();
    if (!(message instanceof Uint8Array)) throw new InvalidArgumentError('message must be a Uint8Array');
    if (this.#disposed) throw new SigningError('This LmsSigner was disposed; open the key again to sign.');
    const q = this.#reserve();
    const lmsSig = lmsSign(this.#i, this.#seed, q, this.#height, this.#w, this.#tree, message);
    const root = lmsRoot(this.#i, this.#height, this.#w, message, lmsSig);
    if (!same(root, this.#tree.subarray(N, 2 * N))) {
      throw new SigningError('The computed signature did not verify against the key; it was not released.');
    }
    return concat(u32(0), lmsSig);
  }

  /** Overwrites the secret seed held in memory. The key on disk is untouched; use `open` to sign again. */
  dispose(): void {
    this.#disposed = true;
    this.#seed.fill(0);
  }
}
