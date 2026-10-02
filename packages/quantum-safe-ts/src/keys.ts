import type { MigrationState } from './algorithms.js';
import { InvalidArgumentError } from './errors.js';
import { call } from './runtime.js';
import type {
  KeyPair as WPair,
  PublicKey as WPublic,
  SecretBytes as WBytes,
  SecretKey as WSecret,
} from '../wasm/quantum_safe_wasm.js';
import { DISPOSE, bytes, str } from './utils.js';

const MIGRATION: readonly MigrationState[] = ['classical_only', 'hybrid_transition', 'pqc_preferred', 'pqc_only'];

function ms(value: MigrationState | undefined): string | undefined {
  if (value !== undefined && !MIGRATION.includes(value)) throw new InvalidArgumentError('Unknown migration state.');
  return value;
}

/** Guards use-after-free with a clear typed error instead of a WASM null-pointer trap. */
class Handle<T extends { free(): void }> {
  #inner: T | null;
  constructor(inner: T) {
    this.#inner = inner;
  }
  get(): T {
    if (this.#inner === null) throw new InvalidArgumentError('This object has been freed and can no longer be used.');
    return this.#inner;
  }
  get freed(): boolean {
    return this.#inner === null;
  }
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

  /** Builds a key from its raw bytes (for example read from a quantum-safe-py key). */
  static fromBytes(algorithm: string, raw: Uint8Array, migrationState?: MigrationState): PublicKey {
    return new PublicKey(
      call((w) => w.PublicKey.fromBytes(str(algorithm, 'algorithm'), bytes(raw, 'raw'), ms(migrationState))),
    );
  }
  /** Parses `to_cbor()` output of quantum-safe-py or this library. */
  static fromCbor(data: Uint8Array): PublicKey {
    return new PublicKey(call((w) => w.PublicKey.fromCbor(bytes(data, 'data'))));
  }
  /** Parses a `QUANTUM SAFE PUBLIC KEY` PEM. */
  static fromPem(pem: string): PublicKey {
    return new PublicKey(call((w) => w.PublicKey.fromPem(str(pem, 'pem'))));
  }
  /** Parses a JWK (`kty: "AKP"`) given as a JSON string or object. */
  static fromJwk(jwk: string | Record<string, unknown>): PublicKey {
    const json = typeof jwk === 'string' ? jwk : JSON.stringify(jwk);
    return new PublicKey(call((w) => w.PublicKey.fromJwk(json)));
  }

  /** Canonical algorithm string, e.g. `X25519+ML-KEM-768`. */
  get algorithm(): string {
    return call(() => this.#h.get().algorithm);
  }
  /** Migration state recorded with the key. */
  get migrationState(): MigrationState {
    return call(() => this.#h.get().migrationState) as MigrationState;
  }
  /** Raw key bytes in quantum-safe-py wire layout. */
  toBytes(): Uint8Array {
    return call(() => this.#h.get().toBytes());
  }
  /** `sha256(algorithm ‖ 0x00 ‖ key)` as lowercase hex (identical to quantum-safe-py). */
  fingerprint(): string {
    return call(() => this.#h.get().fingerprint());
  }
  /** Fingerprint as colon-separated byte pairs. */
  fingerprintColon(): string {
    return call(() => this.#h.get().fingerprintColon());
  }
  /** CBOR serialization (`{v, algo, ms, ktype, key}`). */
  toCbor(): Uint8Array {
    return call(() => this.#h.get().toCbor());
  }
  /** PEM serialization with `qs-*` headers. */
  toPem(): string {
    return call(() => this.#h.get().toPem());
  }
  /** JWK serialization as a JSON string (`kty: "AKP"`). */
  toJwk(): string {
    return call(() => this.#h.get().toJwk());
  }
  /** @internal */
  get _wasm(): WPublic {
    return this.#h.get();
  }
  /** Releases WASM memory. The object is unusable afterwards. */
  free(): void {
    this.#h.free();
  }
  /** Supports `using key = ...`. */
  [DISPOSE](): void {
    this.free();
  }
  toString(): string {
    return `PublicKey(${this.algorithm}, fp=${this.fingerprint().slice(0, 12)}…)`;
  }
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

  /** @internal Wraps a WASM object. Use the static factories instead. */
  constructor(inner: WSecret) {
    this.#h = new Handle(inner);
  }

  static fromBytes(algorithm: string, raw: Uint8Array, migrationState?: MigrationState): SecretKey {
    return new SecretKey(
      call((w) => w.SecretKey.fromBytes(str(algorithm, 'algorithm'), bytes(raw, 'raw'), ms(migrationState))),
    );
  }
  static fromCbor(data: Uint8Array): SecretKey {
    return new SecretKey(call((w) => w.SecretKey.fromCbor(bytes(data, 'data'))));
  }
  /** Parses a `QUANTUM SAFE SECRET KEY` PEM. The PEM text itself contains the secret. */
  static fromPem(pem: string): SecretKey {
    return new SecretKey(call((w) => w.SecretKey.fromPem(str(pem, 'pem'))));
  }

  get algorithm(): string {
    return call(() => this.#h.get().algorithm);
  }
  get migrationState(): MigrationState {
    return call(() => this.#h.get().migrationState) as MigrationState;
  }
  /** Copies the raw secret key bytes out of WASM memory. **Wipe the copy after use.** */
  exportBytes(): Uint8Array {
    return call(() => this.#h.get().exportBytes());
  }
  /** CBOR serialization. Contains the secret; handle accordingly. */
  toCbor(): Uint8Array {
    return call(() => this.#h.get().toCbor());
  }
  /** PEM serialization. Contains the secret; handle accordingly. */
  toPem(): string {
    return call(() => this.#h.get().toPem());
  }
  /** @internal */
  get _wasm(): WSecret {
    return this.#h.get();
  }
  free(): void {
    this.#h.free();
  }
  [DISPOSE](): void {
    this.free();
  }
  /** Never reveals key material. */
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

  /** @internal */
  constructor(inner: WPair) {
    this.#h = new Handle(inner);
  }

  /** Parses a quantum-safe-py `KeyPair.to_cbor_bundle()` blob. */
  static fromCborBundle(data: Uint8Array): KeyPair {
    return new KeyPair(call((w) => w.KeyPair.fromCborBundle(bytes(data, 'data'))));
  }

  /** The public key. */
  get publicKey(): PublicKey {
    this.#pub ??= new PublicKey(call(() => this.#h.get().publicKey));
    return this.#pub;
  }
  /** The secret key. Freed together with the pair. */
  get secretKey(): SecretKey {
    this.#sec ??= new SecretKey(call(() => this.#h.get().secretKey));
    return this.#sec;
  }
  get algorithm(): string {
    return call(() => this.#h.get().algorithm);
  }
  /** CBOR bundle of both keys (contains the secret). */
  toCborBundle(): Uint8Array {
    return call(() => this.#h.get().toCborBundle());
  }
  /** Frees the pair and any key objects obtained from it. */
  free(): void {
    this.#pub?.free();
    this.#sec?.free();
    this.#h.free();
  }
  [DISPOSE](): void {
    this.free();
  }
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

  /** @internal */
  constructor(inner: WBytes) {
    this.#h = new Handle(inner);
  }

  /** Moves a copy of `data` into WASM memory. Wipe your own copy afterwards. */
  static from(data: Uint8Array): SecretBytes {
    return new SecretBytes(call((w) => w.SecretBytes.fromBytes(bytes(data, 'data'))));
  }

  get length(): number {
    return call(() => this.#h.get().length);
  }
  /**
   * HKDF-SHA256 with no salt (identical to quantum-safe-py `SharedSecret.derive_key`).
   * @param length Output length in bytes, at most 8160.
   * @param info Domain-separation string, e.g. `utf8('myapp-encryption-v1')`.
   * @throws {HkdfOutputTooLongError}
   */
  deriveKey(length: number, info: Uint8Array): Uint8Array {
    if (!Number.isInteger(length) || length < 0) {
      throw new InvalidArgumentError('length must be a non-negative integer.');
    }
    return call(() => this.#h.get().deriveKey(length, bytes(info, 'info')));
  }
  /** Copies the secret out of WASM memory. **Wipe the copy after use.** */
  exportBytes(): Uint8Array {
    return call(() => this.#h.get().exportBytes());
  }
  /** @internal */
  get _wasm(): WBytes {
    return this.#h.get();
  }
  free(): void {
    this.#h.free();
  }
  [DISPOSE](): void {
    this.free();
  }
  toString(): string {
    return 'SecretBytes(<redacted>)';
  }
  toJSON(): { type: 'SecretBytes'; redacted: true } {
    return { type: 'SecretBytes', redacted: true };
  }
}

/** A KEM shared secret. Same class as {@link SecretBytes}. */
export { SecretBytes as SharedSecret };
