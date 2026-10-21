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
 * The seed is **encrypted at rest** (AES-256-GCM) under a key you supply or derive from a passphrase (scrypt), and the counter carries an
 * HMAC keyed from the seed, so a file edited without the key is refused. Plain storage is possible only by saying so
 * (`{ unprotected: true }`). Encryption protects a copy of the directory taken without the key; it does not protect a process that is running
 * with the key.
 *
 * Scope, stated plainly: one LMS tree (an HSS key with one level), SHA-256 with 32-byte hashes, height 5, 10, 15 or 20, Winternitz 1, 2, 4
 * or 8. The key is generated here from the operating system's random source and kept in a directory on a **local** filesystem (mode
 * 0600 in a 0700 directory); it is not generated inside a hardware module, and the directory must not be restored from a backup while
 * the key is in use (an older, valid state file rewinds the counter and would reuse indices; nothing local can detect that). Network
 * filesystems may not provide the atomic rename this relies on. The signer refuses to load in browsers and Workers.
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

/**
 * How the signing seed is kept in `key.json`.
 * - `{ passphrase }`: the seed is encrypted under a key derived with scrypt (default cost 2^17, 128 MiB). The salt and cost are stored.
 * - `{ key }`: the seed is encrypted under a 32-byte key you supply (from a KMS, a secrets manager or the environment).
 * - `{ unprotected: true }`: the seed is stored in clear. Only for keys whose directory is itself protected (an encrypted volume, an
 *   ephemeral build runner).
 */
export type LmsKeyProtection =
  | { passphrase: string | Uint8Array; scryptLog2N?: number }
  | { key: Uint8Array }
  | { unprotected: true };

/** Options for {@link LmsSigner.create}. */
export interface LmsSignerCreateOptions {
  /** Directory that will hold the key (`key.json`, `tree.bin`). Created if missing; must not already hold a key. */
  directory: string;
  /** Required: how the seed is stored. There is no default, so nobody ends up with a plain seed by accident. */
  protection: LmsKeyProtection;
  /** Default 10 (1,024 signatures). */
  height?: LmsSignerHeight;
  /** Default 8. */
  winternitz?: LmsSignerWinternitz;
  /** How long `sign` waits for the key's lock before refusing, in milliseconds. Default 5,000. */
  lockTimeoutMs?: number;
}

/** Options for {@link LmsSigner.open}. */
export interface LmsSignerOpenOptions {
  /** The passphrase, for a key created with `{ passphrase }`. */
  passphrase?: string | Uint8Array;
  /** The 32-byte key, for a key created with `{ key }`. */
  key?: Uint8Array;
  /** How long `sign` waits for the key's lock before refusing, in milliseconds. Default 5,000. */
  lockTimeoutMs?: number;
}

/** RFC 8554 LMS type code for each tree height. */
const LMS_TYPE: Readonly<Record<number, number>> = { 5: 5, 10: 6, 15: 7, 20: 8 };
/** RFC 8554 LM-OTS type code for each Winternitz parameter. */
const OTS_TYPE: Readonly<Record<number, number>> = { 1: 1, 2: 2, 4: 3, 8: 4 };
/** Number of hash chains `p` in an LM-OTS key for each Winternitz parameter (RFC 8554 Table 1). */
const OTS_P: Readonly<Record<number, number>> = { 1: 265, 2: 133, 4: 67, 8: 34 };
/** Left shift `ls` applied to the LM-OTS checksum for each Winternitz parameter (RFC 8554 Table 1). */
const OTS_LS: Readonly<Record<number, number>> = { 1: 7, 2: 6, 4: 4, 8: 0 };
/** Hash output and seed length in bytes. */
const N = 32;
/** RFC 8554 domain-separation constants: message hash, one-time public key, tree leaf, tree interior node. */
const D_MESG = 0x8181;
const D_PBLC = 0x8080;
const D_LEAF = 0x8282;
const D_INTR = 0x8383;
/** Value of the `format` field of `key.json`. */
const FORMAT = 'quantum-safe-ts-lms-key';

// ---------------------------------------------------------------------------------------------------------------------------------
// Runtime guard
// ---------------------------------------------------------------------------------------------------------------------------------

/**
 * @internal Throws unless this is Node.js (or a runtime that reports itself as such) and not a browser or Worker global scope.
 * @param g - The global object to inspect (default `globalThis`); a parameter so tests can pass a stand-in.
 * @throws {UnsupportedAlgorithmError} if `process.versions.node` is missing, or `window`, `WorkerGlobalScope` or `document` is defined.
 */
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

/** SHA-256 of the concatenation of `parts`. */
const sha = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
/** `v` as four big-endian bytes (RFC 8554 `u32str`). */
const u32 = (v: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v >>> 0, false);
  return b;
};
/** `v` as two big-endian bytes (RFC 8554 `u16str`). */
const u16 = (v: number): Uint8Array => Uint8Array.of((v >> 8) & 0xff, v & 0xff);
/** Joins `parts` into one new array, in order. */
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
/** Lowercase hexadecimal text of `b`. */
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
/** Decodes lowercase hex `s` that must be exactly `len` bytes long; any other input throws {@link SigningError} naming `what` as damaged. */
const fromHex = (s: string, len: number, what: string): Uint8Array => {
  if (typeof s !== 'string' || !/^[0-9a-f]*$/.test(s) || s.length !== len * 2) throw new SigningError(`The LMS key file is damaged (${what}).`);
  return new Uint8Array(Buffer.from(s, 'hex'));
};
/** Constant-time equality; false when the lengths differ. */
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);

/** The `i`-th w-bit coefficient of a byte string (RFC 8554 Algorithm 2). */
function coef(s: Uint8Array, i: number, w: number): number {
  return ((s[(i * w) >> 3] ?? 0) >> (8 - w * ((i % (8 / w)) + 1))) & ((1 << w) - 1);
}

/** The LM-OTS checksum of the 256-bit digest `q` for Winternitz parameter `w`, shifted left by `ls` and cut to 16 bits (RFC 8554 Algorithm 2). */
function checksum(q: Uint8Array, w: number): number {
  const ls = OTS_LS[w] as number;
  let sum = 0;
  for (let i = 0; i < (N * 8) / w; i++) sum += (1 << w) - 1 - coef(q, i, w);
  return (sum << ls) & 0xffff;
}

/** One chain step `H(I || u32(q) || u16(i) || u8(j) || tmp)` on a reusable 55-byte buffer. */
class Chain {
  readonly #buf = Buffer.alloc(16 + 4 + 2 + 1 + N);
  /**
   * @param i16 - The 16-byte key identifier `I`.
   * @param q - The leaf number.
   * @param index - The chain number `i` within the one-time key.
   */
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

/** The start of chain `i` of leaf `q`: `SHA-256(I || u32(q) || u16(i) || 0xff || seed)`, the seed-derived value of RFC 8554 Appendix A. */
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

/** Hash of the leaf at node number `r` from its LM-OTS public key `k`. */
const leafHash = (i16: Uint8Array, r: number, k: Uint8Array): Uint8Array => sha(i16, u32(r), u16(D_LEAF), k);
/** Hash of the interior node number `r` from its left child `l` and right child `rt`. */
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

/**
 * Signs with leaf `q` and returns the LMS signature `u32(q) || lmots || u32(lmsType) || path`, where `lmots` is `u32(otsType) || C || y[0..p-1]`
 * with a fresh random 32-byte `C`, and `path` holds the `height` sibling nodes from the leaf upward. It reads `tree` and never changes it.
 * The caller has already made leaf `q` durable as used.
 */
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

/** How the seed is stored in `key.json`: in clear (`none`), under a scrypt-derived key (`passphrase`) or under a supplied key (`key`). */
type Protection = 'none' | 'passphrase' | 'key';

/**
 * The contents of `key.json`. After creation only `next` changes, and `mac` changes with it; the fields listed in `headerBytes` are
 * authenticated by `mac` and are the associated data of the sealed seed. Byte values are lowercase hex.
 */
interface KeyFile {
  /** Always {@link FORMAT}. */
  format: string;
  /** File format version (2). */
  version: number;
  /** Tree height. */
  height: number;
  /** Winternitz parameter. */
  winternitz: number;
  /** The 16-byte key identifier `I`. */
  I: string;
  /** The 60-byte HSS public key (`u32(1) || LMS public key`). */
  publicKey: string;
  /** SHA-256 of `tree.bin`. */
  treeSha256: string;
  /** How the seed is stored. */
  protection: Protection;
  /** protection 'none': the seed in hex. */
  seed?: string;
  /** protection 'passphrase' or 'key': AES-256-GCM of the seed (ciphertext || tag), bound to the header. */
  sealed?: { nonce: string; ciphertext: string };
  /** protection 'passphrase': the scrypt parameters. */
  kdf?: { name: 'scrypt'; salt: string; log2N: number; r: number; p: number };
  /** The index of the next one-time key to use (0 for a new key; `2^height` when exhausted). */
  next: number;
  /** HMAC-SHA256 over the header and `next`, keyed from the seed. */
  mac: string;
}

/** scrypt block size `r` and parallelism `p` written to and required of every passphrase-protected key. */
const KDF_R = 8;
const KDF_P = 1;
/** Default, smallest and largest scrypt cost exponent (`N = 2^log2N`) accepted for a passphrase. */
const KDF_DEFAULT_LOG2N = 17;
const KDF_MIN_LOG2N = 14;
const KDF_MAX_LOG2N = 18; // 2^18 * 1 KiB = 256 MiB, within KDF_MAXMEM; larger costs would fail after the tree is built
/** Memory limit passed to scrypt, in bytes. */
const KDF_MAXMEM = 512 * 1024 * 1024;
/** Empty HKDF salt. */
const NO_SALT = new Uint8Array(0);
/** UTF-8 bytes of `s`. */
const utf8 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'utf8'));

/** The fields that never change after creation, as the authenticated header (also the AES-GCM associated data). */
function headerBytes(k: KeyFile): Uint8Array {
  return utf8(JSON.stringify([k.format, k.version, k.height, k.winternitz, k.I, k.publicKey, k.treeSha256, k.protection, k.kdf ?? null]));
}

/** HKDF-SHA-256 with an empty salt: derives 32 bytes from `ikm` for the purpose named by `info`. */
const hkdf = (ikm: Uint8Array, info: string): Uint8Array => new Uint8Array(crypto.hkdfSync('sha256', ikm, NO_SALT, info, 32));

/** The hex HMAC-SHA-256 under `macKey` of the header of `k` and the counter value `next`. */
function stateMac(macKey: Uint8Array, k: KeyFile, next: number): string {
  return crypto.createHmac('sha256', macKey).update(headerBytes(k)).update(utf8(`:${next}`)).digest('hex');
}

/**
 * Encrypts `seed` with AES-256-GCM under a key derived from `master`, using a fresh random 12-byte nonce and the header of `k` as associated
 * data. Returns the nonce and `ciphertext || tag` as hex.
 */
function sealSeed(master: Uint8Array, k: KeyFile, seed: Uint8Array): { nonce: string; ciphertext: string } {
  const nonce = new Uint8Array(crypto.randomBytes(12));
  const cipher = crypto.createCipheriv('aes-256-gcm', hkdf(master, 'qs-lms-seed-v1'), nonce);
  cipher.setAAD(headerBytes(k));
  const ct = concat(new Uint8Array(cipher.update(seed)), new Uint8Array(cipher.final()), new Uint8Array(cipher.getAuthTag()));
  return { nonce: hex(nonce), ciphertext: hex(ct) };
}

/** Decrypts the seed of `k` under `master`. A wrong key or passphrase, or any change to the sealed data or the header, throws {@link SigningError}. */
function unsealSeed(master: Uint8Array, k: KeyFile): Uint8Array {
  const wrong = 'The key could not be unsealed: the passphrase or key is wrong, or the key file was modified.';
  try {
    const nonce = fromHex(k.sealed!.nonce, 12, 'nonce');
    const all = fromHex(k.sealed!.ciphertext, N + 16, 'sealed seed');
    const decipher = crypto.createDecipheriv('aes-256-gcm', hkdf(master, 'qs-lms-seed-v1'), nonce);
    decipher.setAAD(headerBytes(k));
    decipher.setAuthTag(all.subarray(N));
    return concat(new Uint8Array(decipher.update(all.subarray(0, N))), new Uint8Array(decipher.final()));
  } catch {
    throw new SigningError(wrong);
  }
}

/**
 * Returns the master secret for the key file `k`: the supplied 32-byte key itself (not a copy) for `key` protection, or the scrypt output for
 * `passphrase` protection (a string passphrase is NFC-normalised and UTF-8 encoded first). Missing or malformed credentials throw
 * {@link InvalidArgumentError}.
 */
function deriveMaster(k: KeyFile, creds: { passphrase?: string | Uint8Array; key?: Uint8Array }): Uint8Array {
  if (k.protection === 'key') {
    if (!(creds.key instanceof Uint8Array) || creds.key.length !== 32) {
      throw new InvalidArgumentError('This key is sealed under a 32-byte key: pass { key } (a 32-byte Uint8Array) to open().');
    }
    return creds.key;
  }
  if (creds.passphrase === undefined || creds.passphrase.length === 0) {
    throw new InvalidArgumentError('This key is sealed under a passphrase: pass { passphrase } to open().');
  }
  const kdf = k.kdf!;
  const pass = typeof creds.passphrase === 'string' ? utf8(creds.passphrase.normalize('NFC')) : creds.passphrase;
  return new Uint8Array(
    crypto.scryptSync(pass, fromHex(kdf.salt, 16, 'salt'), 32, { N: 2 ** kdf.log2N, r: kdf.r, p: kdf.p, maxmem: KDF_MAXMEM }),
  );
}

/** Blocks the calling thread for `ms` milliseconds. */
const sleepSync = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

/** Flushes the directory entry of `dir` to disk. On Windows directories cannot be opened for fsync, so errors are ignored there; elsewhere they propagate. */
function fsyncDirectory(dir: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch (error) {
    // Directories cannot be opened for fsync on Windows; the rename is already durable there once the file is.
    if (process.platform !== 'win32') throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/**
 * Replaces `path` with `data` so that a crash leaves either the old or the new content: writes `<path>.tmp` with `mode`, fsyncs it, renames
 * it over `path`, then fsyncs the directory. Filesystem errors propagate.
 */
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
 *
 * The directory holds `key.json` (parameters, public key, sealed seed, counter and its HMAC), `tree.bin` (every node of the Merkle tree, so
 * a signature needs no recomputation of the tree) and, briefly during `sign`, `key.json.lock`. The tree and the seed stay in memory while
 * the object is in use; call {@link LmsSigner.dispose} to wipe the seed.
 *
 * @example
 * ```ts
 * import { LmsSigner } from 'quantum-safe-ts/lms-signer';
 * import { Lms } from 'quantum-safe-ts';
 *
 * const signer = LmsSigner.create({ directory: './lms-key', protection: { passphrase: 'correct horse' }, height: 10 });
 * const signature = signer.sign(firmwareDigest);
 * Lms.verify(signer.publicKey, firmwareDigest, signature);
 * signer.dispose();
 * // later: LmsSigner.open('./lms-key', { passphrase: 'correct horse' })
 * ```
 */
export class LmsSigner {
  readonly #dir: string;
  readonly #height: number;
  readonly #w: number;
  readonly #i: Uint8Array;
  readonly #seed: Uint8Array;
  readonly #macKey: Uint8Array;
  readonly #tree: Uint8Array;
  readonly #publicKey: Uint8Array;
  readonly #lockTimeout: number;
  #disposed = false;

  /** Holds a verified key: the directory, the parsed key file, the seed, the identifier, the tree, the public key and the lock timeout. */
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
    this.#macKey = hkdf(seed, 'qs-lms-state-v1');
    this.#i = i16;
    this.#tree = tree;
    this.#publicKey = publicKey;
    this.#lockTimeout = lockTimeout;
  }

  /**
   * Generates a new key in `options.directory`. Refuses if a key is already there.
   *
   * Builds the whole Merkle tree (slow for large heights), writes `tree.bin` and then `key.json`, each durably with mode 0600, and returns a
   * signer holding the new key. Filesystem errors from creating the directory or writing the files propagate unchanged.
   * @param options - Directory, protection (required), `height` (default 10), `winternitz` (default 8) and `lockTimeoutMs` (default 5,000).
   * @returns The signer for the new key; read {@link LmsSigner.publicKey} to publish it.
   * @throws {UnsupportedAlgorithmError} when not running in Node.js, or for `height` 25.
   * @throws {InvalidArgumentError} for an empty `directory`, a `height` or `winternitz` outside the supported values, a `protection` that does
   * not name exactly one of `passphrase` (non-empty), `key` (32 bytes) or `unprotected: true`, or a `scryptLog2N` that is not an integer from
   * 14 to 18.
   * @throws {SigningError} if `key.json` or `tree.bin` already exists in the directory.
   */
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
    const prot = options.protection as Record<string, unknown> | undefined;
    const hasPass = prot !== undefined && (typeof prot.passphrase === 'string' || prot.passphrase instanceof Uint8Array) && (prot.passphrase as string | Uint8Array).length > 0;
    const hasKey = prot !== undefined && prot.key instanceof Uint8Array;
    const plain = prot !== undefined && prot.unprotected === true;
    if ([hasPass, hasKey, plain].filter(Boolean).length !== 1) {
      throw new InvalidArgumentError('protection is required: { passphrase }, { key } (32 bytes) or { unprotected: true }.');
    }
    if (hasKey && (prot!.key as Uint8Array).length !== 32) throw new InvalidArgumentError('protection.key must be 32 bytes.');
    const log2N = hasPass ? ((prot!.scryptLog2N as number | undefined) ?? KDF_DEFAULT_LOG2N) : 0;
    if (hasPass && (!Number.isInteger(log2N) || log2N < KDF_MIN_LOG2N || log2N > KDF_MAX_LOG2N)) {
      throw new InvalidArgumentError(`protection.scryptLog2N must be an integer from ${KDF_MIN_LOG2N} to ${KDF_MAX_LOG2N}.`);
    }
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
      version: 2,
      height,
      winternitz: w,
      I: hex(i16),
      publicKey: hex(publicKey),
      treeSha256: hex(sha(tree)),
      protection: plain ? 'none' : hasKey ? 'key' : 'passphrase',
      next: 0,
      mac: '',
    };
    if (hasPass) key.kdf = { name: 'scrypt', salt: hex(new Uint8Array(crypto.randomBytes(16))), log2N, r: KDF_R, p: KDF_P };
    if (plain) {
      key.seed = hex(seed);
    } else {
      const master = deriveMaster(key, { passphrase: prot!.passphrase as string | Uint8Array | undefined, key: prot!.key as Uint8Array | undefined });
      key.sealed = sealSeed(master, key, seed);
      if (hasPass) master.fill(0);
    }
    key.mac = stateMac(hkdf(seed, 'qs-lms-state-v1'), key, 0);
    // The tree first: a key file without its tree is refused on open; a tree without a key file is simply unused.
    writeFileDurable(join(directory, 'tree.bin'), tree, 0o600);
    writeFileDurable(join(directory, 'key.json'), JSON.stringify(key), 0o600);
    return new LmsSigner(directory, key, seed, i16, tree, publicKey, options.lockTimeoutMs ?? 5_000);
  }

  /**
   * Opens an existing key. Refuses a damaged or inconsistent directory.
   *
   * Reads `key.json`, unseals the seed, checks the counter's HMAC, then loads `tree.bin` and checks it against the recorded digest and the
   * public key's root.
   * @param directory - The directory given to {@link LmsSigner.create}.
   * @param options - `passphrase` or `key`, matching the protection the key was created with, and `lockTimeoutMs` (default 5,000).
   * @returns The signer for the stored key.
   * @throws {UnsupportedAlgorithmError} when not running in Node.js.
   * @throws {InvalidArgumentError} for an empty `directory`, or a missing or malformed passphrase or key for the stored protection.
   * @throws {SigningError} if the state cannot be read, is damaged, was modified outside the signer, cannot be unsealed (wrong passphrase or
   * key), or does not match `tree.bin`.
   */
  static open(directory: string, options: LmsSignerOpenOptions = {}): LmsSigner {
    assertNodeRuntime();
    if (typeof directory !== 'string' || directory === '') throw new InvalidArgumentError('directory must be a non-empty string');
    const key = LmsSigner.#readKey(directory);
    let seed: Uint8Array;
    if (key.protection === 'none') {
      seed = fromHex(key.seed!, N, 'seed');
    } else {
      const master = deriveMaster(key, { passphrase: options.passphrase, key: options.key });
      seed = unsealSeed(master, key);
      if (key.protection === 'passphrase') master.fill(0);
    }
    if (!same(new Uint8Array(Buffer.from(key.mac, 'hex')), new Uint8Array(Buffer.from(stateMac(hkdf(seed, 'qs-lms-state-v1'), key, key.next), 'hex')))) {
      throw new SigningError('The LMS key state was modified outside the signer (its authentication code does not match); refusing to sign.');
    }
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

  /**
   * Reads and structurally validates `key.json` in `directory`: known format and version, supported parameters, well-typed fields, a counter in
   * range, and a complete protection record. Throws {@link SigningError} for an unreadable, damaged or unknown-format file. It does not
   * check the MAC.
   */
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
      key.version === 2 &&
      key.height in LMS_TYPE &&
      key.winternitz in OTS_TYPE &&
      typeof key.I === 'string' &&
      typeof key.publicKey === 'string' &&
      typeof key.treeSha256 === 'string' &&
      typeof key.mac === 'string' &&
      Number.isInteger(key.next) &&
      key.next >= 0 &&
      key.next <= 1 << key.height &&
      (key.protection === 'none'
        ? typeof key.seed === 'string'
        : (key.protection === 'key' || key.protection === 'passphrase') &&
          typeof key.sealed?.nonce === 'string' &&
          typeof key.sealed?.ciphertext === 'string' &&
          (key.protection === 'key' ||
            (key.kdf?.name === 'scrypt' &&
              typeof key.kdf.salt === 'string' &&
              Number.isInteger(key.kdf.log2N) &&
              key.kdf.log2N >= KDF_MIN_LOG2N &&
              key.kdf.log2N <= KDF_MAX_LOG2N &&
              key.kdf.r === KDF_R &&
              key.kdf.p === KDF_P)));
    if (!ok) throw new SigningError('The LMS key state is damaged or from an unknown format; refusing to sign.');
    return key;
  }

  /** The HSS public key (`u32(1) || LMS public key`, 60 bytes), the form {@link Lms.verify} takes. Each read returns a new copy. */
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

  /**
   * Signatures still available, read from the durable state.
   * @throws {SigningError} if the signer was disposed, or the state file cannot be read, is damaged, belongs to another key, or was modified
   * outside the signer.
   */
  get remaining(): number {
    if (this.#disposed) throw new SigningError('This LmsSigner was disposed; open the key again.');
    return this.capacity - this.#readVerified().next;
  }

  /**
   * The state file, checked: same key as this object, and its authentication code matches. Throws {@link SigningError} otherwise.
   * It takes no lock; `#reserve` calls it while holding the lock.
   */
  #readVerified(): KeyFile {
    const key = LmsSigner.#readKey(this.#dir);
    if (key.publicKey !== hex(this.#publicKey) || key.I !== hex(this.#i)) {
      throw new SigningError('The LMS key state belongs to a different key; refusing to sign.');
    }
    if (!same(new Uint8Array(Buffer.from(key.mac, 'hex')), new Uint8Array(Buffer.from(stateMac(this.#macKey, key, key.next), 'hex')))) {
      throw new SigningError('The LMS key state was modified outside the signer (its authentication code does not match); refusing to sign.');
    }
    return key;
  }

  /**
   * Reserves the next index durably and returns it. Takes `key.json.lock` (exclusive create, retrying every 5 ms until `lockTimeoutMs`),
   * re-reads and verifies the state, writes the incremented counter and its MAC through `writeFileDurable`, and removes the lock in all cases.
   * The index is recorded as used before it is returned, so a failure after this point can waste an index but never repeat one.
   * Throws {@link SigningError} if the lock cannot be taken in time, the state is invalid, the key is exhausted, or the write fails.
   */
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
        const code = (e as NodeJS.ErrnoException).code;
        // On Windows a lock file that another process has just removed is briefly "delete pending", and creating it fails with EPERM, EACCES
        // or EBUSY: that is contention, like EEXIST. Anywhere else those codes are real permission problems and fail at once.
        const contended = code === 'EEXIST' || (process.platform === 'win32' && (code === 'EPERM' || code === 'EACCES' || code === 'EBUSY'));
        if (!contended) throw new SigningError(`The LMS key lock cannot be taken: ${(e as Error).message}`);
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
      // The file must still describe the key this object holds, and must not have been edited without the key.
      const key = this.#readVerified();
      if (key.next >= 1 << this.#height) {
        throw new SigningError('This LMS key has used all of its one-time keys; it cannot sign again. Generate a new key.');
      }
      const reserved = key.next;
      try {
        const updated: KeyFile = { ...key, next: reserved + 1 };
        updated.mac = stateMac(this.#macKey, updated, updated.next);
        writeFileDurable(keyFile, JSON.stringify(updated), 0o600);
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
   * The signature is checked against the tree root before it is returned. A failure after the index was reserved (for example the self-check)
   * still counts that index as used.
   * @param message - The bytes to sign (any length).
   * @returns The HSS signature, 48 + 32 * (p + height) bytes, with `p` = 265, 133, 67 or 34 for Winternitz 1, 2, 4 or 8.
   * @throws {SigningError} if the state cannot be read or written, the key is exhausted, or the signature fails its own check.
   * @throws {InvalidArgumentError} if `message` is not a `Uint8Array`.
   * @throws {UnsupportedAlgorithmError} when not running in Node.js.
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

  /**
   * Overwrites the secret seed held in memory. The key on disk is untouched; use `open` to sign again.
   * After this call `sign` and `remaining` throw {@link SigningError}; the public key stays readable.
   */
  dispose(): void {
    this.#disposed = true;
    this.#seed.fill(0);
    this.#macKey.fill(0);
  }
}
