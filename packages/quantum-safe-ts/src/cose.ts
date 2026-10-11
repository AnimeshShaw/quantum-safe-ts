/**
 * COSE_Sign1 with ML-DSA, and AKP COSE keys: the COSE half of RFC 9964 (the JOSE half is {@link StandardJwt}). A COSE_Sign1 is the CBOR
 * counterpart of a compact JWS: it is what CBOR Web Tokens, WebAuthn and many IoT and attestation formats carry.
 *
 * What is signed: `Sig_structure = ["Signature1", protected, external_aad, payload]` (RFC 9052 section 4.4), signed with plain FIPS 204
 * `ML-DSA.Sign` and the **empty** context (RFC 9964 section 5), that is exactly {@link Sign.signRaw}. Any compliant COSE library verifies
 * the result, and this module verifies theirs; quantum-safe-py 0.4.0 (`quantum_safe.protocols.cose`) produces and accepts the same bytes.
 *
 * Identifiers (RFC 9964 section 8.1): ML-DSA-44 = -48, ML-DSA-65 = -49, ML-DSA-87 = -50; key type `AKP` = 7, `pub` = -1, `priv` = -2 (the
 * 32-byte seed).
 *
 * Verification is strict: the algorithm must be in the protected header and known, `crit` is refused, the CBOR must be minimally encoded
 * with definite lengths, map labels must be unique, and trailing bytes are rejected.
 *
 * @example
 * ```ts
 * import { Sign, cose, utf8 } from 'quantum-safe-ts';
 * using pair = new Sign('ML-DSA-65').generateStandardKeyPair();
 * const message = cose.sign1(utf8('hello'), pair, { kid: utf8('key-1') });
 * const payload = cose.verify1(message, pair.publicKey);
 * ```
 */
import { InvalidArgumentError, UnsupportedAlgorithmError, VerificationError } from './errors.js';
import { PublicKey } from './keys.js';
import { Sign } from './signatures.js';
import { StandardKeyPair, STANDARD_SEED_LENGTH } from './standard.js';
import type { StandardAlgorithm } from './standard.js';
import { bytes, equalBytes } from './utils.js';

/** COSE algorithm identifiers for ML-DSA (RFC 9964 section 8.1.1). */
export const COSE_ALGORITHMS: Readonly<Record<StandardAlgorithm, number>> = { 'ML-DSA-44': -48, 'ML-DSA-65': -49, 'ML-DSA-87': -50 };
/** COSE key type for algorithm key pairs (RFC 9964 section 8.1.2). */
export const KTY_AKP = 7;

const BY_ID = new Map<number, StandardAlgorithm>(
  (Object.entries(COSE_ALGORITHMS) as Array<[StandardAlgorithm, number]>).map(([name, id]) => [id, name]),
);
const PUBLIC_KEY_BYTES: Readonly<Record<StandardAlgorithm, number>> = { 'ML-DSA-44': 1312, 'ML-DSA-65': 1952, 'ML-DSA-87': 2592 };
const TAG_SIGN1 = 18;
const TAG_SIGN = 98;
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 16;

// ---- a small, strict CBOR codec for exactly what COSE needs -----------------------------------------------------------------------------

type Item = number | string | Uint8Array | null | boolean | Item[] | CMap | { readonly tag: number; readonly value: Item };

/** A decoded CBOR map, keys kept as decoded (integers or text). */
class CMap {
  readonly entries: Array<[Item, Item]> = [];
  get(key: number | string): Item | undefined {
    for (const [k, v] of this.entries) if (k === key) return v;
    return undefined;
  }
  has(key: number | string): boolean {
    return this.get(key) !== undefined;
  }
}

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [(major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  throw new InvalidArgumentError('CBOR length too large.');
}
const encInt = (n: number): number[] => (n >= 0 ? head(0, n) : head(1, -1 - n));
const encBytes = (b: Uint8Array): number[] => [...head(2, b.length), ...b];
const encText = (s: string): number[] => {
  const t = new TextEncoder().encode(s);
  return [...head(3, t.length), ...t];
};
const NIL = [0xf6];

class Reader {
  pos = 0;
  constructor(readonly data: Uint8Array) {}

  private byte(): number {
    if (this.pos >= this.data.length) throw malformed('unexpected end of data');
    return this.data[this.pos++]!;
  }

  private argument(info: number): number {
    if (info < 24) return info;
    let n: number;
    let min: number;
    if (info === 24) {
      n = this.byte();
      min = 24;
    } else if (info === 25) {
      n = (this.byte() << 8) | this.byte();
      min = 0x100;
    } else if (info === 26) {
      n = ((this.byte() << 24) | (this.byte() << 16) | (this.byte() << 8) | this.byte()) >>> 0;
      min = 0x10000;
    } else if (info === 27) {
      const hi = ((this.byte() << 24) | (this.byte() << 16) | (this.byte() << 8) | this.byte()) >>> 0;
      const lo = ((this.byte() << 24) | (this.byte() << 16) | (this.byte() << 8) | this.byte()) >>> 0;
      if (hi > 0x1fffff) throw malformed('integer too large');
      n = hi * 0x100000000 + lo;
      min = 0x100000000;
    } else {
      throw malformed('indefinite length or reserved additional information');
    }
    if (n < min) throw malformed('non-minimal integer encoding');
    return n;
  }

  item(depth = 0): Item {
    if (depth > MAX_DEPTH) throw malformed('nested too deeply');
    const ib = this.byte();
    const major = ib >> 5;
    const info = ib & 0x1f;
    if (major === 7) {
      if (info === 22) return null;
      if (info === 20) return false;
      if (info === 21) return true;
      throw malformed('unsupported simple value or float');
    }
    const n = this.argument(info);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
      case 3: {
        if (this.pos + n > this.data.length) throw malformed('byte string runs past the end');
        const slice = this.data.slice(this.pos, this.pos + n);
        this.pos += n;
        if (major === 2) return slice;
        try {
          return new TextDecoder('utf-8', { fatal: true }).decode(slice);
        } catch {
          throw malformed('text is not valid UTF-8');
        }
      }
      case 4: {
        if (n > this.data.length) throw malformed('array longer than the data');
        const out: Item[] = [];
        for (let i = 0; i < n; i++) out.push(this.item(depth + 1));
        return out;
      }
      case 5: {
        if (n > this.data.length) throw malformed('map larger than the data');
        const map = new CMap();
        const seen = new Set<string>();
        for (let i = 0; i < n; i++) {
          const k = this.item(depth + 1);
          if (typeof k !== 'number' && typeof k !== 'string') throw malformed('map keys must be integers or text');
          const spelled = `${typeof k}:${String(k)}`;
          if (seen.has(spelled)) throw malformed('duplicate map label');
          seen.add(spelled);
          map.entries.push([k, this.item(depth + 1)]);
        }
        return map;
      }
      case 6:
        return { tag: n, value: this.item(depth + 1) };
      default:
        throw malformed('unsupported CBOR type');
    }
  }
}

const malformed = (why: string): InvalidArgumentError => new InvalidArgumentError(`Malformed COSE data (${why}).`);

function decodeOne(data: Uint8Array): Item {
  if (!(data instanceof Uint8Array) || data.length === 0) throw malformed('empty or not bytes');
  if (data.length > MAX_BYTES) throw malformed('too large');
  const r = new Reader(data);
  const item = r.item();
  if (r.pos !== data.length) throw malformed('trailing bytes');
  return item;
}

// ---- COSE_Sign1 -------------------------------------------------------------------------------------------------------------------------

/** The bytes COSE_Sign1 signs: `["Signature1", protected, external_aad, payload]` as CBOR. */
export function sigStructure(protectedHeader: Uint8Array, payload: Uint8Array, externalAad: Uint8Array = new Uint8Array()): Uint8Array {
  return Uint8Array.from([
    ...head(4, 4),
    ...encText('Signature1'),
    ...encBytes(bytes(protectedHeader, 'protectedHeader')),
    ...encBytes(bytes(externalAad, 'externalAad')),
    ...encBytes(bytes(payload, 'payload')),
  ]);
}

/** Options for {@link sign1}. */
export interface Sign1Options {
  /** Key identifier, placed in the protected header. */
  kid?: Uint8Array;
  /** Application data that is signed but not carried. Default empty. */
  externalAad?: Uint8Array;
  /** Wrap in CBOR tag 18 (default `true`). */
  tagged?: boolean;
  /** Leave the payload out of the message (it is still signed); the verifier must supply it. */
  detached?: boolean;
}

/** Options for {@link verify1}. */
export interface Verify1Options {
  externalAad?: Uint8Array;
  /** The payload, when the message has a detached one. */
  detachedPayload?: Uint8Array;
}

/** Non-secret facts about a COSE_Sign1. */
export interface Sign1Info {
  readonly algorithm: StandardAlgorithm;
  readonly coseAlg: number;
  readonly kid: Uint8Array | undefined;
  readonly tagged: boolean;
  readonly payloadLength: number | null;
  readonly detached: boolean;
  /** The serialized protected header, as signed. */
  readonly protectedHeader: Uint8Array;
}

/**
 * Creates a COSE_Sign1 over `payload` with a standards-mode ML-DSA key pair (see {@link Sign.generateStandardKeyPair}).
 * @throws {InvalidArgumentError} if `key` is not a {@link StandardKeyPair}.
 */
export function sign1(payload: Uint8Array, key: StandardKeyPair, options: Sign1Options = {}): Uint8Array {
  if (!(key instanceof StandardKeyPair)) throw new InvalidArgumentError('key must be a StandardKeyPair.');
  const alg = COSE_ALGORITHMS[key.algorithm];
  const kid = options.kid === undefined ? undefined : bytes(options.kid, 'kid');
  // {1: alg} or {1: alg, 4: kid}: minimal encoding, ascending labels
  const protectedHeader = Uint8Array.from([...head(5, kid === undefined ? 1 : 2), ...encInt(1), ...encInt(alg), ...(kid === undefined ? [] : [...encInt(4), ...encBytes(kid)])]);
  const body = bytes(payload, 'payload');
  const signature = new Sign(key.algorithm).signRaw(sigStructure(protectedHeader, body, options.externalAad), key);
  const array = [...head(4, 4), ...encBytes(protectedHeader), ...head(5, 0), ...(options.detached ? NIL : encBytes(body)), ...encBytes(signature)];
  return Uint8Array.from(options.tagged === false ? array : [...head(6, TAG_SIGN1), ...array]);
}

interface ParsedSign1 {
  protectedHeader: Uint8Array;
  header: CMap;
  unprotected: CMap;
  payload: Uint8Array | null;
  signature: Uint8Array;
  tagged: boolean;
  algorithm: StandardAlgorithm;
}

function parseSign1(data: Uint8Array): ParsedSign1 {
  let item = decodeOne(data);
  let tagged = false;
  if (item !== null && typeof item === 'object' && !(item instanceof Uint8Array) && !Array.isArray(item) && !(item instanceof CMap)) {
    if (item.tag === TAG_SIGN) throw malformed('this is a COSE_Sign (multiple signatures), not a COSE_Sign1');
    if (item.tag !== TAG_SIGN1) throw malformed(`unexpected CBOR tag ${item.tag}`);
    item = item.value;
    tagged = true;
  }
  if (!Array.isArray(item) || item.length !== 4) throw malformed('a COSE_Sign1 is an array of four elements');
  const [prot, unprot, payload, signature] = item;
  if (!(prot instanceof Uint8Array) || !(unprot instanceof CMap)) throw malformed('protected must be a byte string and unprotected a map');
  if (payload !== null && !(payload instanceof Uint8Array)) throw malformed('payload must be a byte string or nil');
  if (!(signature instanceof Uint8Array)) throw malformed('signature must be a byte string');
  if (prot.length === 0) throw malformed('the protected header is empty: the algorithm must be protected');
  const header = decodeOne(prot);
  if (!(header instanceof CMap)) throw malformed('the protected header is not a map');
  if (header.has(2) || unprot.has(2)) throw new UnsupportedAlgorithmError('A COSE "crit" header is present and no critical headers are understood.');
  const id = header.get(1);
  if (id === undefined) throw malformed('the protected header carries no algorithm');
  const algorithm = typeof id === 'number' ? BY_ID.get(id) : undefined;
  if (algorithm === undefined) throw new UnsupportedAlgorithmError(`COSE algorithm ${String(id)} is not an ML-DSA algorithm.`);
  return { protectedHeader: prot, header, unprotected: unprot, payload, signature, tagged, algorithm };
}

/** Facts about a COSE_Sign1 without any key. @throws {InvalidArgumentError} for anything malformed. */
export function inspectSign1(data: Uint8Array): Sign1Info {
  const p = parseSign1(data);
  const kid = p.header.get(4) ?? p.unprotected.get(4);
  return {
    algorithm: p.algorithm,
    coseAlg: COSE_ALGORITHMS[p.algorithm],
    kid: kid instanceof Uint8Array ? kid : undefined,
    tagged: p.tagged,
    payloadLength: p.payload === null ? null : p.payload.length,
    detached: p.payload === null,
    protectedHeader: p.protectedHeader,
  };
}

/**
 * Verifies a COSE_Sign1 and returns its payload. `publicKey` is the FIPS 204 public key as bytes, or a {@link PublicKey}.
 * @throws {VerificationError} if the signature, payload, protected header or external AAD is wrong (no detail on which, by design).
 * @throws {InvalidArgumentError} if the message is malformed or its algorithm differs from the key's.
 */
export function verify1(data: Uint8Array, publicKey: Uint8Array | PublicKey, options: Verify1Options = {}): Uint8Array {
  const p = parseSign1(data);
  const raw = publicKey instanceof PublicKey ? publicKey.toBytes() : bytes(publicKey, 'publicKey');
  if (publicKey instanceof PublicKey && publicKey.algorithm !== p.algorithm) {
    throw new InvalidArgumentError(`COSE algorithm ${p.algorithm} does not match the key's algorithm ${publicKey.algorithm}.`);
  }
  if (raw.length !== PUBLIC_KEY_BYTES[p.algorithm]) {
    throw new InvalidArgumentError(`COSE algorithm ${p.algorithm} needs a ${PUBLIC_KEY_BYTES[p.algorithm]}-byte public key.`);
  }
  let payload = p.payload;
  if (payload === null) {
    if (options.detachedPayload === undefined) throw new InvalidArgumentError('The payload is detached: pass detachedPayload.');
    payload = bytes(options.detachedPayload, 'detachedPayload');
  } else if (options.detachedPayload !== undefined && !equalBytes(options.detachedPayload, payload)) {
    throw new VerificationError();
  }
  new Sign(p.algorithm).verifyRaw(sigStructure(p.protectedHeader, payload, options.externalAad), p.signature, raw);
  return payload;
}

// ---- COSE keys (AKP) --------------------------------------------------------------------------------------------------------------------

/** A decoded AKP COSE_Key. */
export interface DecodedCoseKey {
  readonly algorithm: StandardAlgorithm;
  readonly publicKey: Uint8Array;
  readonly kid: Uint8Array | undefined;
  /** The 32-byte seed, for a private key. Wipe your copy after use. */
  readonly seed: Uint8Array | undefined;
}

function encodeMap(algorithm: StandardAlgorithm, pub: Uint8Array | undefined, kid: Uint8Array | undefined, seed: Uint8Array | undefined): Uint8Array {
  const entries: number[][] = [
    [...encInt(1), ...encInt(KTY_AKP)],
    [...encInt(3), ...encInt(COSE_ALGORITHMS[algorithm])],
  ];
  if (kid !== undefined) entries.push([...encInt(2), ...encBytes(kid)]);
  if (pub !== undefined) entries.push([...encInt(-1), ...encBytes(pub)]);
  if (seed !== undefined) entries.push([...encInt(-2), ...encBytes(seed)]);
  return Uint8Array.from([...head(5, entries.length), ...entries.flat()]);
}

/** Encodes an ML-DSA public key as an AKP COSE_Key. @throws {InvalidArgumentError} for a wrong-length key or an unknown algorithm. */
export function encodeKey(algorithm: StandardAlgorithm, publicKey: Uint8Array, options: { kid?: Uint8Array } = {}): Uint8Array {
  if (!(algorithm in COSE_ALGORITHMS)) throw new InvalidArgumentError(`COSE ML-DSA supports ${Object.keys(COSE_ALGORITHMS).join(', ')}.`);
  const pub = bytes(publicKey, 'publicKey');
  if (pub.length !== PUBLIC_KEY_BYTES[algorithm]) throw new InvalidArgumentError(`A ${algorithm} public key is ${PUBLIC_KEY_BYTES[algorithm]} bytes.`);
  return encodeMap(algorithm, pub, options.kid === undefined ? undefined : bytes(options.kid, 'kid'), undefined);
}

/** Encodes a standards-mode key pair as a private AKP COSE_Key: the public key and the 32-byte seed (`priv`). Store it as a secret. */
export function encodePrivateKey(pair: StandardKeyPair, options: { kid?: Uint8Array } = {}): Uint8Array {
  const seed = pair.exportSeed();
  try {
    return encodeMap(pair.algorithm, pair.publicKey, options.kid === undefined ? undefined : bytes(options.kid, 'kid'), seed);
  } finally {
    seed.fill(0);
  }
}

/** Decodes an AKP COSE_Key (public or private). @throws {InvalidArgumentError} for another key type, algorithm, or a wrong-length field. */
export function decodeKey(data: Uint8Array): DecodedCoseKey {
  const key = decodeOne(data);
  if (!(key instanceof CMap)) throw malformed('a COSE_Key is a map');
  if (key.get(1) !== KTY_AKP) throw new InvalidArgumentError('Not an AKP key (kty must be 7).');
  const id = key.get(3);
  if (id === undefined) throw new InvalidArgumentError('An AKP key must carry its algorithm (alg).');
  const algorithm = typeof id === 'number' ? BY_ID.get(id) : undefined;
  if (algorithm === undefined) throw new UnsupportedAlgorithmError(`COSE algorithm ${String(id)} is not an ML-DSA algorithm.`);
  const pub = key.get(-1);
  const priv = key.get(-2);
  const kid = key.get(2);
  if (priv !== undefined && (!(priv instanceof Uint8Array) || priv.length !== STANDARD_SEED_LENGTH)) {
    throw new InvalidArgumentError('The private key (seed) must be 32 bytes.');
  }
  if (pub === undefined && priv === undefined) throw new InvalidArgumentError('The key carries neither pub nor priv.');
  if (pub !== undefined && (!(pub instanceof Uint8Array) || pub.length !== PUBLIC_KEY_BYTES[algorithm])) {
    throw new InvalidArgumentError(`The public key must be ${PUBLIC_KEY_BYTES[algorithm]} bytes.`);
  }
  if (kid !== undefined && !(kid instanceof Uint8Array)) throw new InvalidArgumentError('kid must be a byte string.');
  let publicKey = pub as Uint8Array | undefined;
  if (publicKey === undefined) {
    using derived = new Sign(algorithm).standardKeyPairFromSeed(priv as Uint8Array);
    publicKey = derived.publicKey;
  }
  return { algorithm, publicKey, kid: kid as Uint8Array | undefined, seed: priv as Uint8Array | undefined };
}

/**
 * Builds a standards-mode key pair from a private AKP COSE_Key. If the key also carries `pub`, it must equal the key derived from the seed.
 * @throws {InvalidArgumentError} if the key has no seed or the public key does not match it.
 */
export function keyPairFromCoseKey(data: Uint8Array): StandardKeyPair {
  const k = decodeKey(data);
  if (k.seed === undefined) throw new InvalidArgumentError('This COSE_Key has no private key (seed).');
  const pair = new Sign(k.algorithm).standardKeyPairFromSeed(k.seed);
  if (!equalBytes(pair.publicKey, k.publicKey)) {
    pair.free();
    throw new InvalidArgumentError('The COSE_Key public key does not match its seed.');
  }
  return pair;
}
