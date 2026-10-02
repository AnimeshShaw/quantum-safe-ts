/**
 * A deliberately small CBOR (RFC 8949) codec for the data-model subset quantum-safe-py's migration store uses
 * (maps with text keys, arrays, text, integers, floats, booleans, null, byte strings). Internal: the cryptographic wire formats are
 * parsed in the Rust core, not here. Decoding is defensive: bounded depth and size, no tags, no indefinite lengths, no duplicate keys.
 */
import { InvalidArgumentError } from './errors.js';

/** Marks a number that must be written as a CBOR float even when it is integral (for example a Unix timestamp). */
export class CborFloat {
  constructor(readonly value: number) {}
}

const MAX_DEPTH = 32;
const MAX_ITEMS = 100_000;

export type CborValue = null | boolean | number | string | Uint8Array | CborValue[] | { [key: string]: CborValue } | CborFloat;

const bad = (why: string): never => {
  throw new InvalidArgumentError(`Malformed CBOR (${why}).`);
};

export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encode(value, out, 0);
  return Uint8Array.from(out);
}

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

export function cborDecode(data: Uint8Array, maxBytes = 16 * 1024 * 1024): CborValue {
  if (!(data instanceof Uint8Array)) bad('input is not bytes');
  if (data.length > maxBytes) bad('input too large');
  const r = { d: data, i: 0, items: 0 };
  const v = decode(r, 0);
  if (r.i !== data.length) bad('trailing bytes');
  return v;
}

type Reader = { d: Uint8Array; i: number; items: number };

function need(r: Reader, n: number): void {
  if (n < 0 || r.i + n > r.d.length) bad('truncated');
}

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
