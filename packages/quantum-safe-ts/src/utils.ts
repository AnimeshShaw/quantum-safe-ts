import { InvalidArgumentError } from './errors.js';

/** Returns `value` if it is a `Uint8Array` (Node `Buffer` included); throws a typed error otherwise. */
export function bytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  // Cross-realm values (vm contexts, iframes, jsdom, Electron preloads) fail `instanceof`; accept them by tag and normalise views and buffers.
  const tag = Object.prototype.toString.call(value);
  if (tag === '[object Uint8Array]') return value as Uint8Array;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') return new Uint8Array(value as ArrayBufferLike);
  throw new InvalidArgumentError(`${name} must be a Uint8Array, ArrayBuffer or typed-array view (got ${describe(value)}).`);
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

/** Decodes canonical, unpadded base64url only: rejects padding and non-canonical trailing bits, so a value has exactly one accepted spelling. */
export function fromBase64UrlStrict(s: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new InvalidArgumentError('Invalid base64url string.');
  const out = fromBase64Url(s);
  if (toBase64Url(out) !== s) throw new InvalidArgumentError('Non-canonical base64url string.');
  return out;
}

/** Equality for equal-length arrays that does not exit at the first difference. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// `using key = ...` needs Symbol.dispose, which older runtimes (Node < 20.5, some browsers) lack. Define it
// with the same registry key other polyfills (tslib, core-js) use, so objects stay disposable everywhere.
const sym = Symbol as unknown as { dispose?: symbol };
if (typeof sym.dispose !== 'symbol') {
  // Configurable and writable so that a later polyfill (core-js, tslib, test setup) can still define it without throwing.
  Object.defineProperty(Symbol, 'dispose', { value: Symbol.for('Symbol.dispose'), configurable: true, writable: true });
}
