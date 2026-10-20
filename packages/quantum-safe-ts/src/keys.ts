/// <reference lib="esnext.disposable" />
import type { MigrationState } from './algorithms.js';
import { AlgorithmMismatchError, InvalidArgumentError } from './errors.js';
import { call } from './runtime.js';
import type {
  KeyPair as WPair,
  PublicKey as WPublic,
  SecretBytes as WBytes,
  SecretKey as WSecret,
} from '../wasm/quantum_safe_wasm.js';
import { bytes, str } from './utils.js';

/** The accepted migration state values; `ms()` validates against this list. */
const MIGRATION: readonly MigrationState[] = ['classical_only', 'hybrid_transition', 'pqc_preferred', 'pqc_only'];

/** Returns `value` unchanged when it is `undefined` or a known migration state; otherwise throws {@link InvalidArgumentError}. */
function ms(value: MigrationState | undefined): string | undefined {
  if (value !== undefined && !MIGRATION.includes(value)) throw new InvalidArgumentError('Unknown migration state.');
  return value;
}

/**
 * Guards use-after-free with a clear typed error instead of a WASM null-pointer trap.
 * Invariant: `#inner` is non-null until the first `free()`, and `free()` can be called any number of times.
 */
class Handle<T extends { free(): void }> {
  #inner: T | null;
  /** Takes ownership of the WASM object `inner`. */
  constructor(inner: T) {
    this.#inner = inner;
  }
  /** Returns the wrapped object; throws {@link InvalidArgumentError} once the handle has been freed. */
  get(): T {
    if (this.#inner === null) throw new InvalidArgumentError('This object has been freed and can no longer be used.');
    return this.#inner;
  }
  /** True after `free()`. */
  get freed(): boolean {
    return this.#inner === null;
  }
  /** Frees the wrapped object (once) and drops the reference; later calls do nothing. */
  free(): void {
    this.#inner?.free();
    this.#inner = null;
  }
}

/**
 * A public key (KEM or signature). Safe to share, log and persist.
 */
export class PublicKey {
  #h: Handle<WPublic>;

  /** @internal Wraps a WASM object. Use the static factories instead. */
  constructor(inner: WPublic) {
    this.#h = new Handle(inner);
  }

  /**
   * Builds a key from its raw bytes (for example read from a quantum-safe-py key).
   * The raw length is checked against the algorithm.
   * @param algorithm - Canonical algorithm string, e.g. `X25519+ML-KEM-768`.
   * @param raw - Raw public key bytes in quantum-safe-py wire layout.
   * @param migrationState - State to record with the key. Default: `hybrid_transition` for hybrid names and `X-Wing`, `pqc_only` otherwise.
   * @returns The public key.
   * @throws {InvalidArgumentError} if `algorithm` is not a string, `raw` is empty or not bytes, or `migrationState` is unknown.
   * @throws {KeyParseError} if the length of `raw` is not the public key length of `algorithm`.
   */
  static fromBytes(algorithm: string, raw: Uint8Array, migrationState?: MigrationState): PublicKey {
    return new PublicKey(
      call((w) => w.PublicKey.fromBytes(str(algorithm, 'algorithm'), bytes(raw, 'raw'), ms(migrationState))),
    );
  }
  /**
   * Parses `to_cbor()` output of quantum-safe-py or this library.
   * @param data - CBOR-encoded public key.
   * @returns The public key.
   * @throws {KeyParseError} if `data` is not a valid CBOR public key (a secret key is rejected too).
   * @throws {IncompatibleKeyVersionError} if the key was written by a newer format version.
   * @throws {PayloadTooLargeError} if `data` exceeds the 10 MB limit.
   * @throws {InvalidArgumentError} if `data` is not bytes.
   */
  static fromCbor(data: Uint8Array): PublicKey {
    return new PublicKey(call((w) => w.PublicKey.fromCbor(bytes(data, 'data'))));
  }
  /**
   * Parses a `QUANTUM SAFE PUBLIC KEY` PEM.
   * @param pem - PEM text.
   * @returns The public key.
   * @throws {KeyParseError} if `pem` is not a valid PEM public key (a secret key PEM is rejected too).
   * @throws {IncompatibleKeyVersionError} if the key was written by a newer format version.
   * @throws {PayloadTooLargeError} if `pem` exceeds the 10 MB limit.
   * @throws {InvalidArgumentError} if `pem` is not a string.
   */
  static fromPem(pem: string): PublicKey {
    return new PublicKey(call((w) => w.PublicKey.fromPem(str(pem, 'pem'))));
  }
  /**
   * Parses a JWK (`kty: "AKP"`) given as a JSON string or object.
   * @param jwk - The JWK as a JSON string or a plain object.
   * @returns The public key.
   * @throws {KeyParseError} if the JWK is not a valid public key JWK.
   * @throws {PayloadTooLargeError} if the JWK text exceeds the 10 MB limit.
   */
  static fromJwk(jwk: string | Record<string, unknown>): PublicKey {
    const json = typeof jwk === 'string' ? jwk : JSON.stringify(jwk);
    return new PublicKey(call((w) => w.PublicKey.fromJwk(json)));
  }

  /**
   * Canonical algorithm string, e.g. `X25519+ML-KEM-768`.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  get algorithm(): string {
    return call(() => this.#h.get().algorithm);
  }
  /**
   * Migration state recorded with the key.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  get migrationState(): MigrationState {
    return call(() => this.#h.get().migrationState) as MigrationState;
  }
  /**
   * Raw key bytes in quantum-safe-py wire layout.
   * @returns A copy of the key bytes.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  toBytes(): Uint8Array {
    return call(() => this.#h.get().toBytes());
  }
  /**
   * `sha256(algorithm ‖ 0x00 ‖ key)` as lowercase hex (identical to quantum-safe-py).
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  fingerprint(): string {
    return call(() => this.#h.get().fingerprint());
  }
  /**
   * Fingerprint as colon-separated byte pairs.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  fingerprintColon(): string {
    return call(() => this.#h.get().fingerprintColon());
  }
  /**
   * CBOR serialization (`{v, algo, ms, ktype, key}`).
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  toCbor(): Uint8Array {
    return call(() => this.#h.get().toCbor());
  }
  /**
   * PEM serialization with `qs-*` headers.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  toPem(): string {
    return call(() => this.#h.get().toPem());
  }
  /**
   * JWK serialization as a JSON string (`kty: "AKP"`).
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  toJwk(): string {
    return call(() => this.#h.get().toJwk());
  }
  /**
   * The underlying WASM key object; throws {@link InvalidArgumentError} if the key has been freed.
   * @internal
   */
  get _wasm(): WPublic {
    return this.#h.get();
  }
  /** Releases WASM memory. The object is unusable afterwards. Calling it again does nothing. */
  free(): void {
    this.#h.free();
  }
  /** Supports `using key = ...`; calls {@link PublicKey.free}. */
  [Symbol.dispose](): void {
    this.free();
  }
  /** Short description with the algorithm and the first 12 hex characters of the fingerprint. */
  toString(): string {
    return `PublicKey(${this.algorithm}, fp=${this.fingerprint().slice(0, 12)}…)`;
  }
  /** JSON form used by `JSON.stringify`: the type tag, algorithm and full fingerprint (no key bytes). */
  toJSON(): { type: 'PublicKey'; algorithm: string; fingerprint: string } {
    return { type: 'PublicKey', algorithm: this.algorithm, fingerprint: this.fingerprint() };
  }
}

/**
 * A secret key (KEM or signature), held in WASM memory. Call {@link SecretKey.free} (or use
 * `using`) when finished: it wipes the key material. Never log or serialize it casually.
 *
 * Copies you extract with {@link SecretKey.exportBytes}, `toCbor()` or `toPem()` live in the
 * JavaScript heap, outside this library's control; wipe them with `wipe()` after use.
 */
export class SecretKey {
  #h: Handle<WSecret>;

  /** @internal Wraps a WASM object and takes ownership of it. Use the static factories instead. */
  constructor(inner: WSecret) {
    this.#h = new Handle(inner);
  }

  /**
   * Builds a secret key from its raw bytes (for example read from a quantum-safe-py key). The bytes are copied into WASM memory; wipe your copy.
   * The length is not checked here; a wrong length surfaces when the key is used.
   * @param algorithm - Canonical algorithm string.
   * @param raw - Raw secret key bytes in quantum-safe-py wire layout.
   * @param migrationState - State to record with the key. Default: `hybrid_transition` for hybrid names and `X-Wing`, `pqc_only` otherwise.
   * @returns The secret key.
   * @throws {InvalidArgumentError} if `algorithm` is not a string, `raw` is empty or not bytes, or `migrationState` is unknown.
   */
  static fromBytes(algorithm: string, raw: Uint8Array, migrationState?: MigrationState): SecretKey {
    return new SecretKey(
      call((w) => w.SecretKey.fromBytes(str(algorithm, 'algorithm'), bytes(raw, 'raw'), ms(migrationState))),
    );
  }
  /**
   * Parses `to_cbor()` output of quantum-safe-py or this library. The CBOR contains the secret.
   * @param data - CBOR-encoded secret key.
   * @returns The secret key.
   * @throws {KeyParseError} if `data` is not a valid CBOR secret key (a public key is rejected too).
   * @throws {IncompatibleKeyVersionError} if the key was written by a newer format version.
   * @throws {PayloadTooLargeError} if `data` exceeds the 10 MB limit.
   * @throws {InvalidArgumentError} if `data` is not bytes.
   */
  static fromCbor(data: Uint8Array): SecretKey {
    return new SecretKey(call((w) => w.SecretKey.fromCbor(bytes(data, 'data'))));
  }
  /**
   * Parses a `QUANTUM SAFE SECRET KEY` PEM. The PEM text itself contains the secret.
   * @param pem - PEM text.
   * @returns The secret key.
   * @throws {KeyParseError} if `pem` is not a valid PEM secret key (a public key PEM is rejected too).
   * @throws {IncompatibleKeyVersionError} if the key was written by a newer format version.
   * @throws {PayloadTooLargeError} if `pem` exceeds the 10 MB limit.
   * @throws {InvalidArgumentError} if `pem` is not a string.
   */
  static fromPem(pem: string): SecretKey {
    return new SecretKey(call((w) => w.SecretKey.fromPem(str(pem, 'pem'))));
  }

  /**
   * Canonical algorithm string, e.g. `X25519+ML-KEM-768`.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  get algorithm(): string {
    return call(() => this.#h.get().algorithm);
  }
  /**
   * Migration state recorded with the key.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  get migrationState(): MigrationState {
    return call(() => this.#h.get().migrationState) as MigrationState;
  }
  /**
   * Copies the raw secret key bytes out of WASM memory. **Wipe the copy after use.**
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  exportBytes(): Uint8Array {
    return call(() => this.#h.get().exportBytes());
  }
  /**
   * CBOR serialization. Contains the secret; handle accordingly.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  toCbor(): Uint8Array {
    return call(() => this.#h.get().toCbor());
  }
  /**
   * PEM serialization. Contains the secret; handle accordingly.
   * @throws {InvalidArgumentError} if the key has been freed.
   */
  toPem(): string {
    return call(() => this.#h.get().toPem());
  }
  /**
   * The underlying WASM key object; throws {@link InvalidArgumentError} if the key has been freed.
   * @internal
   */
  get _wasm(): WSecret {
    return this.#h.get();
  }
  /** Wipes and releases the key material in WASM memory. The object is unusable afterwards. Calling it again does nothing. */
  free(): void {
    this.#h.free();
  }
  /** Supports `using key = ...`; calls {@link SecretKey.free}. */
  [Symbol.dispose](): void {
    this.free();
  }
  /** Never reveals key material. Prints the algorithm, or `freed` after {@link SecretKey.free}. */
  toString(): string {
    return `SecretKey(${this.#h.freed ? 'freed' : this.algorithm}, <redacted>)`;
  }
  /** Never reveals key material. */
  toJSON(): { type: 'SecretKey'; redacted: true } {
    return { type: 'SecretKey', redacted: true };
  }
}

/** A matched public/secret key pair. */
export class KeyPair {
  #h: Handle<WPair>;
  #pub: PublicKey | null = null;
  #sec: SecretKey | null = null;

  /** @internal Wraps a WASM object and takes ownership of it. */
  constructor(inner: WPair) {
    this.#h = new Handle(inner);
  }

  /**
   * Parses a quantum-safe-py `KeyPair.to_cbor_bundle()` blob.
   * @param data - CBOR bundle holding both keys.
   * @returns The key pair.
   * @throws {KeyParseError} if `data` is not a valid key pair bundle.
   * @throws {IncompatibleKeyVersionError} if a key was written by a newer format version.
   * @throws {InvalidArgumentError} if `data` is not bytes.
   */
  static fromCborBundle(data: Uint8Array): KeyPair {
    return new KeyPair(call((w) => w.KeyPair.fromCborBundle(bytes(data, 'data'))));
  }

  /**
   * Assembles a pair from separately held keys (for example a public key from one place and a secret key from another).
   * The keys are copied; the caller still owns, and should free, the arguments.
   * The intermediate CBOR copies of the keys are zeroed before returning.
   * @param publicKey - The public half.
   * @param secretKey - The secret half; must have the same algorithm as `publicKey`.
   * @returns A new key pair.
   * @throws {AlgorithmMismatchError} if the algorithms differ.
   * @throws {InvalidArgumentError} if an argument has the wrong type or has been freed.
   */
  static fromKeys(publicKey: PublicKey, secretKey: SecretKey): KeyPair {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    if (publicKey.algorithm !== secretKey.algorithm) {
      throw new AlgorithmMismatchError(`Public key is ${publicKey.algorithm} but secret key is ${secretKey.algorithm}.`);
    }
    const pub = publicKey.toCbor();
    const sec = secretKey.toCbor();
    // quantum-safe-py KeyPair.to_cbor_bundle() layout: {v: 1, bundle: "keypair", pub: <key map>, sec: <key map>}
    const head = [0xa4, 0x61, 0x76, 0x01, 0x66, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x67, 0x6b, 0x65, 0x79, 0x70, 0x61, 0x69, 0x72, 0x63, 0x70, 0x75, 0x62];
    const mid = [0x63, 0x73, 0x65, 0x63];
    const out = new Uint8Array(head.length + pub.length + mid.length + sec.length);
    out.set(head, 0);
    out.set(pub, head.length);
    out.set(mid, head.length + pub.length);
    out.set(sec, head.length + pub.length + mid.length);
    try {
      return KeyPair.fromCborBundle(out);
    } finally {
      out.fill(0);
      sec.fill(0);
    }
  }

  /**
   * The public key. The same object is returned on every call; it is freed together with the pair.
   * @throws {InvalidArgumentError} if the pair has been freed.
   */
  get publicKey(): PublicKey {
    this.#pub ??= new PublicKey(call(() => this.#h.get().publicKey));
    return this.#pub;
  }
  /**
   * The secret key. The same object is returned on every call; it is freed together with the pair.
   * @throws {InvalidArgumentError} if the pair has been freed.
   */
  get secretKey(): SecretKey {
    this.#sec ??= new SecretKey(call(() => this.#h.get().secretKey));
    return this.#sec;
  }
  /**
   * Canonical algorithm string of the pair.
   * @throws {InvalidArgumentError} if the pair has been freed.
   */
  get algorithm(): string {
    return call(() => this.#h.get().algorithm);
  }
  /**
   * CBOR bundle of both keys (contains the secret).
   * @throws {InvalidArgumentError} if the pair has been freed.
   */
  toCborBundle(): Uint8Array {
    return call(() => this.#h.get().toCborBundle());
  }
  /** Frees the pair and any key objects obtained from it. Calling it again does nothing. */
  free(): void {
    this.#pub?.free();
    this.#sec?.free();
    this.#h.free();
  }
  /** Supports `using pair = ...`; calls {@link KeyPair.free}. */
  [Symbol.dispose](): void {
    this.free();
  }
  /** Short description with the algorithm; contains no key material. */
  toString(): string {
    return `KeyPair(${this.algorithm})`;
  }
}

/**
 * 32 bytes of secret material in WASM memory: a KEM shared secret or an Argon2id master key.
 * Also exported as `SharedSecret`.
 */
export class SecretBytes {
  #h: Handle<WBytes>;

  /** @internal Wraps a WASM object and takes ownership of it. */
  constructor(inner: WBytes) {
    this.#h = new Handle(inner);
  }

  /**
   * Moves a copy of `data` into WASM memory. Wipe your own copy afterwards.
   * @param data - The secret bytes; must not be empty.
   * @returns A new {@link SecretBytes}.
   * @throws {InvalidArgumentError} if `data` is empty or not bytes.
   */
  static from(data: Uint8Array): SecretBytes {
    return new SecretBytes(call((w) => w.SecretBytes.fromBytes(bytes(data, 'data'))));
  }

  /**
   * Number of secret bytes held.
   * @throws {InvalidArgumentError} if the object has been freed.
   */
  get length(): number {
    return call(() => this.#h.get().length);
  }
  /**
   * HKDF-SHA256 with no salt (identical to quantum-safe-py `SharedSecret.derive_key`).
   * @param length Output length in bytes, at most 8160.
   * @param info Domain-separation string, e.g. `utf8('myapp-encryption-v1')`.
   * @returns `length` derived bytes (a copy in the JavaScript heap; wipe it when sensitive).
   * @throws {HkdfOutputTooLongError} if `length` exceeds 8160.
   * @throws {InvalidArgumentError} if `length` is not a non-negative integer, `info` is not bytes, or the object has been freed.
   * @example
   * ```ts
   * const key = secret.deriveKey(32, utf8('myapp-encryption-v1'));
   * ```
   */
  deriveKey(length: number, info: Uint8Array): Uint8Array {
    if (!Number.isInteger(length) || length < 0) {
      throw new InvalidArgumentError('length must be a non-negative integer.');
    }
    return call(() => this.#h.get().deriveKey(length, bytes(info, 'info')));
  }
  /**
   * Copies the secret out of WASM memory. **Wipe the copy after use.**
   * @throws {InvalidArgumentError} if the object has been freed.
   */
  exportBytes(): Uint8Array {
    return call(() => this.#h.get().exportBytes());
  }
  /**
   * The underlying WASM object; throws {@link InvalidArgumentError} if the object has been freed.
   * @internal
   */
  get _wasm(): WBytes {
    return this.#h.get();
  }
  /** Wipes and releases the secret in WASM memory. The object is unusable afterwards. Calling it again does nothing. */
  free(): void {
    this.#h.free();
  }
  /** Supports `using secret = ...`; calls {@link SecretBytes.free}. */
  [Symbol.dispose](): void {
    this.free();
  }
  /** Never reveals the secret. */
  toString(): string {
    return 'SecretBytes(<redacted>)';
  }
  /** Never reveals the secret: returns a redaction marker. */
  toJSON(): { type: 'SecretBytes'; redacted: true } {
    return { type: 'SecretBytes', redacted: true };
  }
}

/** A KEM shared secret. Same class as {@link SecretBytes}. */
export { SecretBytes as SharedSecret };
