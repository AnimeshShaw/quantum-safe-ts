import { InvalidArgumentError } from './errors.js';

/** Returns `value` if it is a `Uint8Array` (Node `Buffer` included); throws a typed error otherwise. */
export function bytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new InvalidArgumentError(`${name} must be a Uint8Array (got ${describe(value)}).`);
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'Array';
  return typeof v === 'object' ? ((v as object).constructor?.name ?? 'object') : typeof v;
}

export function str(value: unknown, name: string): string {
  if (typeof value === 'string') return value;
  throw new InvalidArgumentError(`${name} must be a string (got ${describe(value)}).`);
}

const HEX = '0123456789abcdef';

/** Lowercase hex encoding. */
export function toHex(data: Uint8Array): string {
  let out = '';
  for (const b of data) out += HEX[b >> 4]! + HEX[b & 15]!;
  return out;
}

/** Decodes hex (either case). Throws {@link InvalidArgumentError} on malformed input. */
export function fromHex(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new InvalidArgumentError('Invalid hex string.');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const enc = new TextEncoder();
/** UTF-8 encodes a string. */
export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

/** Overwrites a byte array with zeros. Use on copies you extracted from a secret. */
export function wipe(data: Uint8Array): void {
  data.fill(0);
}

/** Base64url without padding. */
export function toBase64Url(data: Uint8Array): string {
  let bin = '';
  for (const b of data) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url (padding optional). */
export function fromBase64Url(s: string): Uint8Array {
  if (typeof s !== 'string' || /[^A-Za-z0-9_-]/.test(s.replace(/=+$/, ''))) {
    throw new InvalidArgumentError('Invalid base64url string.');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Constant-time-ish equality for equal-length arrays (best effort in JS; not a guarantee). */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Symbol used for `using` declarations; falls back for runtimes without `Symbol.dispose`. */
export const DISPOSE: symbol =
  (Symbol as unknown as { dispose?: symbol }).dispose ?? Symbol.for('Symbol.dispose');
