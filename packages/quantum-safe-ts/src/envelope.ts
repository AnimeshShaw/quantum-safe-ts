import { DecryptionAuthenticationError, InvalidArgumentError } from './errors.js';
import { PublicKey, SecretKey } from './keys.js';
import { call } from './runtime.js';
import { bytes, equalBytes, fromHex, toHex } from './utils.js';

/** Non-secret metadata of a sealed message. */
export interface SealedInfo {
  readonly version: number;
  readonly algorithm: string;
  readonly kemCiphertextLength: number;
  readonly nonceLength: number;
  readonly ciphertextLength: number;
  readonly aadLength: number;
}

/** Options for {@link Envelope.seal}. */
export interface SealOptions {
  /**
   * Additional authenticated data: bound to the ciphertext but not encrypted. It is stored in
   * the clear inside the sealed message. The same value is verified automatically on open.
   */
  aad?: Uint8Array;
}

/**
 * A sealed (encrypted) message: KEM ciphertext + AES-256-GCM ciphertext + metadata, serialized as
 * CBOR identical to quantum-safe-py's `SealedMessage`.
 */
export class SealedMessage {
  /** Envelope format version (currently 1). */
  readonly version: number;
  /** KEM algorithm the message was sealed to, e.g. `X25519+ML-KEM-768`. */
  readonly algorithm: string;
  /** The hybrid KEM ciphertext (`HybridCipherText.to_bytes()`). */
  readonly kemCiphertext: Uint8Array;
  /** 12-byte AES-GCM nonce. */
  readonly nonce: Uint8Array;
  /** AES-256-GCM ciphertext followed by the 16-byte tag. */
  readonly ciphertext: Uint8Array;
  /** The caller's additional authenticated data (empty by default). */
  readonly aad: Uint8Array;
  readonly #cbor: Uint8Array;

  private constructor(cbor: Uint8Array) {
    this.#cbor = cbor;
    const parts = call((w) => w.sealedMessageParse(cbor));
    try {
      this.version = parts.version;
      this.algorithm = parts.algorithm;
      this.kemCiphertext = parts.kemCiphertext;
      this.nonce = parts.nonce;
      this.ciphertext = parts.ciphertext;
      this.aad = parts.aad;
    } finally {
      parts.free();
    }
  }

  /** Parses CBOR bytes (from `toBytes()` or quantum-safe-py `SealedMessage.to_bytes()`). */
  static fromBytes(data: Uint8Array): SealedMessage {
    return new SealedMessage(bytes(data, 'data').slice());
  }
  /** Parses a hex string produced by `toHex()` / quantum-safe-py `to_hex()`. */
  static fromHex(hex: string): SealedMessage {
    return SealedMessage.fromBytes(fromHex(hex));
  }
  /** Assembles a sealed message from its fields (for example data stored in separate columns). */
  static fromParts(parts: {
    algorithm: string;
    kemCiphertext: Uint8Array;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    aad?: Uint8Array;
    version?: number;
  }): SealedMessage {
    const cbor = call((w) =>
      w.sealedMessageEncode(
        parts.version ?? 1,
        parts.algorithm,
        bytes(parts.kemCiphertext, 'kemCiphertext'),
        bytes(parts.nonce, 'nonce'),
        bytes(parts.ciphertext, 'ciphertext'),
        bytes(parts.aad ?? new Uint8Array(), 'aad'),
      ),
    );
    return new SealedMessage(cbor);
  }

  /** CBOR serialization (copy). */
  toBytes(): Uint8Array {
    return this.#cbor.slice();
  }
  /** Lowercase hex of {@link SealedMessage.toBytes}. */
  toHex(): string {
    return toHex(this.#cbor);
  }
  /** Non-secret metadata. */
  inspect(): SealedInfo {
    return JSON.parse(call((w) => w.envelopeInspect(this.#cbor))) as SealedInfo;
  }
  toString(): string {
    return `SealedMessage(${this.algorithm}, ${this.ciphertext.length} B)`;
  }
}

/**
 * Authenticated public-key encryption: hybrid KEM + AES-256-GCM, interoperable with
 * quantum-safe-py's `Envelope`.
 *
 * @example
 * ```ts
 * const kem = new HybridKEM();
 * using pair = kem.generateKeyPair();
 * const sealed = Envelope.seal(utf8('secret'), pair.publicKey, { aad: utf8('item-42') });
 * const plain = Envelope.open(sealed, pair.secretKey); // Uint8Array
 * ```
 */
export const Envelope = {
  /**
   * Encrypts `plaintext` to `publicKey`.
   * @throws {UnsupportedAlgorithmError} if the key is a pure (non-hybrid) KEM key.
   */
  seal(plaintext: Uint8Array, publicKey: PublicKey, options: SealOptions = {}): SealedMessage {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    const cbor = call((w) =>
      w.envelopeSeal(bytes(plaintext, 'plaintext'), publicKey._wasm, bytes(options.aad ?? new Uint8Array(), 'aad')),
    );
    return SealedMessage.fromBytes(cbor);
  },

  /**
   * Decrypts a sealed message. The returned plaintext is a copy in the JS heap: wipe it with
   * `wipe()` when it is sensitive and no longer needed.
   *
   * The AAD travels inside the message and is checked for tampering, but anyone holding the recipient's public key can seal a message with
   * any AAD. To bind a message to a context (a user id, a record id) pass `options.expectedAad`: opening then fails unless the message's
   * AAD equals it. This is anonymous encryption: it does not tell you who sent the message (sign it separately for that).
   * @throws {DecryptionAuthenticationError} on a wrong key, wrong AAD, an AAD that differs from `expectedAad`, or any tampering.
   * @throws {MalformedCiphertextError} if the message is structurally invalid.
   */
  open(sealed: SealedMessage | Uint8Array, secretKey: SecretKey, options: { expectedAad?: Uint8Array } = {}): Uint8Array {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    const msg = sealed instanceof SealedMessage ? sealed : SealedMessage.fromBytes(bytes(sealed, 'sealed'));
    if (options.expectedAad !== undefined && !equalBytes(msg.aad, bytes(options.expectedAad, 'expectedAad'))) {
      throw new DecryptionAuthenticationError('The message AAD does not equal the expected AAD.');
    }
    return call((w) => w.envelopeOpen(msg.toBytes(), secretKey._wasm));
  },
} as const;
