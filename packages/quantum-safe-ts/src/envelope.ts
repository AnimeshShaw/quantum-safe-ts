import { warnOnce } from './warnings.js';
import { DecryptionAuthenticationError, InvalidArgumentError } from './errors.js';
import { PublicKey, SecretKey } from './keys.js';
import { NATIVE_AEAD_MIN_BYTES, nativeAead } from './native-aead.js';
import { call } from './runtime.js';
import { bytes, equalBytes, fromHex, toHex, wipe } from './utils.js';

/** Non-secret metadata of a sealed message. */
export interface SealedInfo {
  /** Envelope format version: 1 for hybrid KEMs, 2 for pure ML-KEM-1024. */
  readonly version: number;
  /** KEM algorithm the message was sealed to. */
  readonly algorithm: string;
  /** Length in bytes of the KEM ciphertext. */
  readonly kemCiphertextLength: number;
  /** Length in bytes of the AES-GCM nonce. */
  readonly nonceLength: number;
  /** Length in bytes of the AES-GCM ciphertext including the 16-byte tag. */
  readonly ciphertextLength: number;
  /** Length in bytes of the stored additional authenticated data. */
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
  /** Envelope format version: 1 for hybrid KEMs, 2 for pure ML-KEM-1024. */
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
  /** The CBOR encoding this object was parsed from; `toBytes()` and `toHex()` return it (a copy for `toBytes()`). */
  readonly #cbor: Uint8Array;

  /** Parses `cbor` through the core and copies the fields out; use the static factories. */
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

  /**
   * Parses CBOR bytes (from `toBytes()` or quantum-safe-py `SealedMessage.to_bytes()`). The input is copied.
   * @param data - CBOR-encoded sealed message.
   * @returns The parsed message.
   * @throws {InvalidArgumentError} if `data` is not a `Uint8Array`, `ArrayBuffer` or typed-array view.
   * @throws {MalformedCiphertextError} if `data` is not a valid sealed message.
   */
  static fromBytes(data: Uint8Array): SealedMessage {
    return new SealedMessage(bytes(data, 'data').slice());
  }
  /**
   * Parses a hex string produced by `toHex()` / quantum-safe-py `to_hex()`.
   * @param hex - Hex of the CBOR encoding, either case.
   * @returns The parsed message.
   * @throws {InvalidArgumentError} if `hex` is not valid hex.
   * @throws {MalformedCiphertextError} if the decoded bytes are not a valid sealed message.
   */
  static fromHex(hex: string): SealedMessage {
    return SealedMessage.fromBytes(fromHex(hex));
  }
  /**
   * Assembles a sealed message from its fields (for example data stored in separate columns).
   * @param parts - The fields: `algorithm`, `kemCiphertext`, `nonce` and `ciphertext` are required; `aad` defaults to empty and `version` to 1.
   * @returns The message re-parsed from its CBOR encoding.
   * @throws {InvalidArgumentError} if a byte field is not a `Uint8Array`, `ArrayBuffer` or typed-array view.
   * @throws {MalformedCiphertextError} if the fields do not form a valid sealed message.
   */
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

  /**
   * CBOR serialization (copy).
   * @returns A fresh copy of the CBOR bytes.
   */
  toBytes(): Uint8Array {
    return this.#cbor.slice();
  }
  /**
   * Lowercase hex of {@link SealedMessage.toBytes}.
   * @returns The hex string.
   */
  toHex(): string {
    return toHex(this.#cbor);
  }
  /**
   * Non-secret metadata.
   * @returns Version, algorithm and the lengths of the stored fields.
   * @throws {NotInitializedError} if the WASM module is not initialised.
   */
  inspect(): SealedInfo {
    return JSON.parse(call((w) => w.envelopeInspect(this.#cbor))) as SealedInfo;
  }
  /** Short description with the algorithm and ciphertext length; contains no message data. */
  toString(): string {
    return `SealedMessage(${this.algorithm}, ${this.ciphertext.length} B)`;
  }
}

/**
 * Seals `plaintext` to `publicKey` and returns the CBOR message. Payloads of {@link NATIVE_AEAD_MIN_BYTES} or more are encrypted by the
 * native AES-256-GCM when the entry point registered one (Node.js); the message is byte-for-byte what the WebAssembly core would build.
 * The one-time AES key copied out of WASM for the native call is wiped before returning, and the plan object is always freed.
 */
function sealToCbor(plaintext: Uint8Array, publicKey: PublicKey, aad: Uint8Array): Uint8Array {
  const native = nativeAead();
  if (native === null || plaintext.length < NATIVE_AEAD_MIN_BYTES) {
    return call((w) => w.envelopeSeal(plaintext, publicKey._wasm, aad));
  }
  return call((w) => {
    const plan = w.envelopeSealPlan(publicKey._wasm, aad);
    let key: Uint8Array | null = null;
    try {
      const secret = plan.takeKey();
      try {
        key = secret.exportBytes();
      } finally {
        secret.free();
      }
      return plan.finish(native.encrypt(key, plan.nonce, plan.builtAad, plaintext));
    } finally {
      if (key !== null) wipe(key);
      plan.free();
    }
  });
}

/**
 * Opens `msg` with `secretKey`. For large payloads the native AES-256-GCM does the decryption; on any authentication failure the
 * WebAssembly core runs the same message so the error is exactly the one it raises.
 * Relies on the native `decrypt` returning `null` (never throwing) for bad data; the one-time key copy is wiped before returning.
 */
function openSealed(msg: SealedMessage, secretKey: SecretKey): Uint8Array {
  const native = nativeAead();
  if (native !== null && msg.ciphertext.length >= NATIVE_AEAD_MIN_BYTES + 16) {  // the plaintext is the ciphertext without its 16-byte tag
    const plain = call((w) => {
      const plan = w.envelopeOpenPlan(msg.toBytes(), secretKey._wasm);
      let key: Uint8Array | null = null;
      try {
        const secret = plan.takeKey();
        try {
          key = secret.exportBytes();
        } finally {
          secret.free();
        }
        return native.decrypt(key, plan.nonce, plan.builtAad, msg.ciphertext);
      } finally {
        if (key !== null) wipe(key);
        plan.free();
      }
    });
    if (plain !== null) return plain;
  }
  return call((w) => w.envelopeOpen(msg.toBytes(), secretKey._wasm));
}

/**
 * Authenticated public-key encryption: hybrid KEM + AES-256-GCM, interoperable with
 * quantum-safe-py's `Envelope`. A pure ML-KEM-1024 key produces envelope version 2 (HKDF-SHA-384); hybrid keys produce version 1.
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
   * @param plaintext - The bytes to encrypt.
   * @param publicKey - Recipient KEM public key: a hybrid key, or a pure ML-KEM-1024 key.
   * @param options - See {@link SealOptions}; `aad` defaults to empty.
   * @returns The sealed message.
   * @throws {UnsupportedAlgorithmError} if the key is neither a hybrid KEM key nor a pure ML-KEM-1024 key.
   * @throws {InvalidArgumentError} if `publicKey` is not a {@link PublicKey} or `plaintext` / `aad` is not a byte array.
   * @throws {MalformedKeyError} if the key bytes are invalid.
   */
  seal(plaintext: Uint8Array, publicKey: PublicKey, options: SealOptions = {}): SealedMessage {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    const cbor = sealToCbor(bytes(plaintext, 'plaintext'), publicKey, bytes(options.aad ?? new Uint8Array(), 'aad'));
    return SealedMessage.fromBytes(cbor);
  },

  /**
   * Decrypts a sealed message. The returned plaintext is a copy in the JS heap: wipe it with
   * `wipe()` when it is sensitive and no longer needed.
   *
   * The AAD travels inside the message and is checked for tampering, but anyone holding the recipient's public key can seal a message with
   * any AAD. To bind a message to a context (a user id, a record id) pass `options.expectedAad`: opening then fails unless the message's
   * AAD equals it. This is anonymous encryption: it does not tell you who sent the message (sign it separately for that).
   * Without `expectedAad`, a message that carries AAD triggers a `QS_AAD_OMITTED` warning.
   * @param sealed - A {@link SealedMessage} or its CBOR bytes.
   * @param secretKey - The recipient's KEM secret key.
   * @param options.expectedAad - The AAD the message must carry. Default: not checked.
   * @returns The plaintext bytes.
   * @throws {DecryptionAuthenticationError} on a wrong key, wrong AAD, an AAD that differs from `expectedAad`, or any tampering.
   * @throws {MalformedCiphertextError} if the message is structurally invalid.
   * @throws {AlgorithmMismatchError} if the message algorithm differs from the secret key's.
   * @throws {UnsupportedAlgorithmError} if the message carries an unsupported suite or version.
   * @throws {InvalidArgumentError} if `secretKey` is not a {@link SecretKey} or an argument is not a byte array.
   */
  open(sealed: SealedMessage | Uint8Array, secretKey: SecretKey, options: { expectedAad?: Uint8Array } = {}): Uint8Array {
    if (!(secretKey instanceof SecretKey)) throw new InvalidArgumentError('secretKey must be a SecretKey.');
    const msg = sealed instanceof SealedMessage ? sealed : SealedMessage.fromBytes(bytes(sealed, 'sealed'));
    if (options.expectedAad !== undefined && !equalBytes(msg.aad, bytes(options.expectedAad, 'expectedAad'))) {
      throw new DecryptionAuthenticationError('The message AAD does not equal the expected AAD.');
    }
    if (options.expectedAad === undefined && msg.aad.length > 0) {
      warnOnce(
        'QS_AAD_OMITTED',
        'Envelope.open() was called without expectedAad for a message that carries AAD. The AAD travels inside the message and anyone with ' +
          "the recipient's public key can set it, so pass the AAD you expect.",
      );
    }
    return openSealed(msg, secretKey);
  },

  /**
   * Moves a message from one recipient key to another: opens `sealed` under `oldSecretKey` and seals the plaintext to `newPublicKey`,
   * keeping the AAD. The original message is not modified, and nothing is returned if opening fails. This is the single step of a migration
   * to a hybrid or stronger key; `rewrapDirectory` from `quantum-safe-ts/rewrap` applies it to a directory.
   *
   * @param options.expectedAad The AAD the message must carry, as for {@link Envelope.open}. Omitted: any AAD is accepted (it is
   * authenticated) and a `QS_AAD_OMITTED` warning is emitted when the message carries AAD.
   * @param options.aad AAD for the new message. Default: the message's own AAD, unchanged.
   * @param sealed - A {@link SealedMessage} or its CBOR bytes.
   * @param oldSecretKey - The secret key the message is currently sealed to.
   * @param newPublicKey - The public key to seal to: a hybrid key, or a pure ML-KEM-1024 key.
   * @returns A new sealed message; the decrypted plaintext is wiped before returning.
   * @throws {DecryptionAuthenticationError} on a wrong key, an AAD mismatch or any tampering.
   * @throws {MalformedCiphertextError} if the message is structurally invalid.
   * @throws {AlgorithmMismatchError} if the message algorithm differs from `oldSecretKey`'s.
   * @throws {UnsupportedAlgorithmError} if the old message or the new key uses an unsupported suite.
   * @throws {InvalidArgumentError} if a key argument has the wrong type.
   */
  rewrap(
    sealed: SealedMessage | Uint8Array,
    oldSecretKey: SecretKey,
    newPublicKey: PublicKey,
    options: { expectedAad?: Uint8Array; aad?: Uint8Array } = {},
  ): SealedMessage {
    if (!(oldSecretKey instanceof SecretKey)) throw new InvalidArgumentError('oldSecretKey must be a SecretKey.');
    if (!(newPublicKey instanceof PublicKey)) throw new InvalidArgumentError('newPublicKey must be a PublicKey.');
    const msg = sealed instanceof SealedMessage ? sealed : SealedMessage.fromBytes(bytes(sealed, 'sealed'));
    if (options.expectedAad === undefined && msg.aad.length > 0) {
      warnOnce(
        'QS_AAD_OMITTED',
        'Envelope.rewrap() was called without expectedAad for a message that carries AAD. The AAD travels inside the message and anyone ' +
          "with the recipient's public key can set it, so pass the AAD you expect.",
      );
    }
    const expected = options.expectedAad ?? msg.aad;
    if (!equalBytes(msg.aad, bytes(expected, 'expectedAad'))) {
      throw new DecryptionAuthenticationError('The message AAD does not equal the expected AAD.');
    }
    const plaintext = openSealed(msg, oldSecretKey);
    try {
      const cbor = sealToCbor(bytes(plaintext, 'plaintext'), newPublicKey, bytes(options.aad ?? msg.aad, 'aad'));
      return SealedMessage.fromBytes(cbor);
    } finally {
      wipe(plaintext);
    }
  },
} as const;
