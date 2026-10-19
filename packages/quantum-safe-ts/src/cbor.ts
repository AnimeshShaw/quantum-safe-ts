/**
 * A deliberately small CBOR (RFC 8949) codec for the data-model subset quantum-safe-py's migration store uses
 * (maps with text keys, arrays, text, integers, floats, booleans, null, byte strings). Internal: the cryptographic wire formats are
 * parsed in the Rust core, not here. Decoding is defensive: bounded depth and size, no tags, no indefinite lengths, no duplicate keys.
 */
import { InvalidArgumentError } from './errors.js';

/**
 * Marks a number that must be written as a CBOR float even when it is integral (for example a Unix timestamp).
 * The encoder writes it as an 8-byte double (initial byte `0xfb`).
 */
export class CborFloat {
  /** @param value - The number to write as a double. */
  constructor(readonly value: number) {}
}

/** Deepest nesting of arrays and maps, for both encoding and decoding. */
const MAX_DEPTH = 32;
/** Most data items one decode may read, and the largest array or map length it accepts. */
const MAX_ITEMS = 100_000;

/**
 * A value this codec can encode or decode: `null`, booleans, numbers, text, byte strings, arrays, maps with text keys, and {@link CborFloat}.
 * A decoded float comes back as a plain `number`.
 */
export type CborValue = null | boolean | number | string | Uint8Array | CborValue[] | { [key: string]: CborValue } | CborFloat;

/** Throws {@link InvalidArgumentError} with the message `Malformed CBOR (<why>).`; used for every encoding and decoding failure. */
const bad = (why: string): never => {
  throw new InvalidArgumentError(`Malformed CBOR (${why}).`);
};

/**
 * Encodes `value` as CBOR.
 *
 * Safe integers are written as CBOR integers in the shortest form, other finite numbers and {@link CborFloat} values as 8-byte doubles,
 * text as UTF-8, and maps with their keys in `Object.keys` order.
 * @param value - The value to encode.
 * @returns The CBOR bytes.
 * @throws {InvalidArgumentError} if a number is not finite or the value is nested more than 32 levels deep.
 * @example
 * ```ts
 * const bytes = cborEncode({ id: 'k1', created: new CborFloat(1_700_000_000), tags: ['a', 'b'] });
 * const value = cborDecode(bytes);
 * ```
 */
export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encode(value, out, 0);
  return Uint8Array.from(out);
}

/** Appends the initial byte and argument for major type `major` and length or value `n` to `out`, in the shortest form (up to 8 argument bytes). */
function head(major: number, n: number, out: number[]): void {
  if (n < 24) out.push((major << 5) | n);
  else if (n < 0x100) out.push((major << 5) | 24, n);
  else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
  else if (n < 0x100000000) out.push((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  else {
    const hi = Math.floor(n / 0x100000000);
    const lo = n >>> 0;
    out.push((major << 5) | 27, (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
    out.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
  }
}

/** Appends the encoding of `v` to `out`; `depth` counts the nesting so far and is limited to {@link MAX_DEPTH}. */
function encode(v: CborValue, out: number[], depth: number): void {
  if (depth > MAX_DEPTH) bad('too deeply nested');
  if (v === null) out.push(0xf6);
  else if (typeof v === 'boolean') out.push(v ? 0xf5 : 0xf4);
  else if (v instanceof CborFloat) {
    const b = new DataView(new ArrayBuffer(8));
    b.setFloat64(0, v.value);
    out.push(0xfb, ...new Uint8Array(b.buffer));
  } else if (typeof v === 'number') {
    if (!Number.isFinite(v)) bad('non-finite number');
    if (Number.isSafeInteger(v)) {
      if (v >= 0) head(0, v, out);
      else head(1, -1 - v, out);
    } else {
      const b = new DataView(new ArrayBuffer(8));
      b.setFloat64(0, v);
      out.push(0xfb, ...new Uint8Array(b.buffer));
    }
  } else if (typeof v === 'string') {
    const t = new TextEncoder().encode(v);
    head(3, t.length, out);
    for (const x of t) out.push(x);
  } else if (v instanceof Uint8Array) {
    head(2, v.length, out);
    for (const x of v) out.push(x);
  } else if (Array.isArray(v)) {
    head(4, v.length, out);
    for (const x of v) encode(x, out, depth + 1);
  } else {
    const keys = Object.keys(v);
    head(5, keys.length, out);
    for (const k of keys) {
      encode(k, out, depth + 1);
      encode((v as { [key: string]: CborValue })[k]!, out, depth + 1);
    }
  }
}

/**
 * Decodes exactly one CBOR item from `data`.
 *
 * Integers (any width, up to the safe-integer range), half, single and double floats, text, byte strings, arrays, maps with text keys,
 * booleans and `null` are accepted. Maps come back as objects without a prototype. Tags, indefinite lengths, simple values other than
 * false, true and null, non-text map keys, duplicate keys, non-finite floats, invalid UTF-8 and trailing bytes are refused. Integers are
 * not required to be in their shortest form.
 * @param data - The CBOR bytes.
 * @param maxBytes - Largest accepted input length in bytes (default 16 MiB).
 * @returns The decoded value.
 * @throws {InvalidArgumentError} for input that is not bytes, is too large, truncated, nested more than 32 levels, holds more than 100,000
 * items, or is otherwise outside the accepted subset.
 */
export function cborDecode(data: Uint8Array, maxBytes = 16 * 1024 * 1024): CborValue {
  if (!(data instanceof Uint8Array)) bad('input is not bytes');
  if (data.length > maxBytes) bad('input too large');
  const r = { d: data, i: 0, items: 0 };
  const v = decode(r, 0);
  if (r.i !== data.length) bad('trailing bytes');
  return v;
}

/** Decoder state: the input `d`, the read offset `i`, and the number of items read so far (`items`). */
type Reader = { d: Uint8Array; i: number; items: number };

/** Fails with a "truncated" error unless `n` more bytes are available at the read offset. */
function need(r: Reader, n: number): void {
  if (n < 0 || r.i + n > r.d.length) bad('truncated');
}

/** Reads the argument for additional information `info` (the value itself below 24, else 1, 2, 4 or 8 big-endian bytes) and returns it as a safe integer. */
function readUint(r: Reader, info: number): number {
  if (info < 24) return info;
  const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : -1;
  if (size < 0) return bad('unsupported length encoding');
  need(r, size);
  let n = 0;
  for (let k = 0; k < size; k++) n = n * 256 + r.d[r.i++]!;
  if (!Number.isSafeInteger(n)) bad('integer out of range');
  return n;
}

/** Reads one item at the current offset. Each call counts against the 100,000-item budget; `depth` is limited to {@link MAX_DEPTH}. */
function decode(r: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) bad('too deeply nested');
  if (++r.items > MAX_ITEMS) bad('too many items');
  need(r, 1);
  const ib = r.d[r.i++]!;
  const major = ib >> 5;
  const info = ib & 0x1f;
  switch (major) {
    case 0:
      return readUint(r, info);
    case 1:
      return -1 - readUint(r, info);
    case 2: {
      const n = readUint(r, info);
      need(r, n);
      const s = r.d.slice(r.i, r.i + n);
      r.i += n;
      return s;
    }
    case 3: {
      const n = readUint(r, info);
      need(r, n);
      let s: string;
      try {
        s = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(r.d.subarray(r.i, r.i + n));
      } catch {
        return bad('invalid UTF-8 in text string');
      }
      r.i += n;
      return s;
    }
    case 4: {
      const n = readUint(r, info);
      if (n > MAX_ITEMS) bad('array too long');
      const a: CborValue[] = [];
      for (let k = 0; k < n; k++) a.push(decode(r, depth + 1));
      return a;
    }
    case 5: {
      const n = readUint(r, info);
      if (n > MAX_ITEMS) bad('map too large');
      const m: { [key: string]: CborValue } = Object.create(null) as { [key: string]: CborValue };
      for (let k = 0; k < n; k++) {
        const key = decode(r, depth + 1);
        if (typeof key !== 'string') bad('non-text map key');
        if ((key as string) in m) bad('duplicate map key');
        m[key as string] = decode(r, depth + 1);
      }
      return m;
    }
    case 7: {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 25) {
        need(r, 2);
        const h = (r.d[r.i]! << 8) | r.d[r.i + 1]!;
        r.i += 2;
        const e = (h >> 10) & 0x1f;
        const f = h & 0x3ff;
        const sign = h & 0x8000 ? -1 : 1;
        if (e === 0) return sign * f * 2 ** -24;
        if (e === 31) return bad('non-finite float');
        return sign * (1 + f / 1024) * 2 ** (e - 15);
      }
      if (info === 26 || info === 27) {
        const n = info === 26 ? 4 : 8;
        need(r, n);
        const dv = new DataView(r.d.buffer, r.d.byteOffset + r.i, n);
        const x = n === 4 ? dv.getFloat32(0) : dv.getFloat64(0);
        r.i += n;
        if (!Number.isFinite(x)) bad('non-finite float');
        return x;
      }
      return bad('unsupported simple value');
    }
    default:
      return bad('unsupported major type (tags are not accepted)');
  }
}
