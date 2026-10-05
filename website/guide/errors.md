# Errors

Every error this library throws extends `QuantumSafeError` and carries three things you can rely on:

- `code`: a stable machine-readable string such as `QS_DECRYPTION_FAILED`, safe to `switch` on;
- `hint`: a one-line static suggestion for the usual fix (never contains key material, plaintext or your input);
- `toJSON()`: a JSON-safe description for logs.

Match with `instanceof` or `code`. **Never parse `message`.** Messages may change between versions; codes and class names will not.

## Handling errors

```ts test
import { easy, QuantumSafeError, DecryptionAuthenticationError } from 'quantum-safe-ts';

const a = easy.generateEncryptionKeys();
const b = easy.generateEncryptionKeys();
const sealed = easy.encrypt(a.publicKey, 'x');

try {
  easy.decrypt(b.secretKey, sealed); // wrong key
  throw new Error('should have failed');
} catch (e) {
  if (!(e instanceof DecryptionAuthenticationError)) throw e;
  if (!QuantumSafeError.is(e) || e.code !== 'QS_DECRYPTION_FAILED' || e.hint.length === 0) throw new Error('error contract');
  console.log(JSON.stringify(e.toJSON()));
}
```

`QuantumSafeError.is(e)` works across copies of the library. Prefer it to `instanceof` if your application might load both the ESM and the
CommonJS build (each has its own classes, see [runtimes](/guide/runtimes#mixed-esm-and-commonjs)).

A typical service wraps untrusted input like this:

```ts test
import { easy, QuantumSafeError } from 'quantum-safe-ts';

function openInbound(secretKey: string, bytes: Uint8Array): { ok: true; text: string } | { ok: false; reason: string } {
  try {
    return { ok: true, text: easy.decryptText(secretKey, bytes, { aad: 'inbox-v1' }) };
  } catch (e) {
    if (!QuantumSafeError.is(e)) throw e;                       // a bug of ours, not bad input: let it surface
    switch (e.code) {
      case 'QS_DECRYPTION_FAILED':                              // wrong key, wrong AAD, or modified data
      case 'QS_MALFORMED_CIPHERTEXT':
      case 'QS_KEY_PARSE_ERROR':
        return { ok: false, reason: e.code };                   // do not tell the sender more than the code
      default:
        throw e;
    }
  }
}

const keys = easy.generateEncryptionKeys();
const good = openInbound(keys.secretKey, easy.encrypt(keys.publicKey, 'hi', { aad: 'inbox-v1' }));
const bad = openInbound(keys.secretKey, new Uint8Array([1, 2, 3]));
if (!good.ok || bad.ok) throw new Error('unexpected');
```

## Reference

| Class | `code` | Thrown when | Usual fix |
|---|---|---|---|
| `NotInitializedError` | `QS_NOT_INITIALIZED` | An API was used before the WebAssembly was loaded | `await init()` once (outside Node.js) |
| `DecryptionAuthenticationError` | `QS_DECRYPTION_FAILED` | Wrong key, wrong AAD, or the message was modified | Check the key and the `expectedAad`; the data may be corrupt |
| `VerificationError` | `QS_VERIFICATION_FAILED` | A signature, message, context, key or token claim does not match. No detail by design. | Verify with the signer's public key and the same context |
| `DecapsulationError` | `QS_DECAPSULATION_FAILED` | The classical part of a KEM ciphertext is invalid | The ciphertext was not made for this key, or is corrupt |
| `SigningError` | `QS_SIGNING_FAILED` | Signing could not complete | Check the secret key is intact and matches the algorithm |
| `MalformedKeyError` | `QS_MALFORMED_KEY` | A secret key has the wrong length or structure | Re-export the key; check it matches the algorithm |
| `MalformedCiphertextError` | `QS_MALFORMED_CIPHERTEXT` | A ciphertext, sealed message or stream frame is structurally invalid | The data is corrupt or for another algorithm |
| `MalformedSignatureError` | `QS_MALFORMED_SIGNATURE` | Signature bytes are structurally invalid | The data is corrupt |
| `AlgorithmMismatchError` | `QS_ALGORITHM_MISMATCH` | A key of one algorithm was used with another algorithm's API | Use the class that matches the key |
| `HkdfOutputTooLongError` | `QS_HKDF_OUTPUT_TOO_LONG` | `deriveKey` asked for more than 8,160 bytes | Ask for less |
| `KdfError` | `QS_KDF_FAILED` | Argon2id could not run (for example a salt under 8 bytes) | Fix the parameters |
| `KeyParseError` | `QS_KEY_PARSE_ERROR` | CBOR, PEM or JWK key input is invalid: wrong type (`pub` / `sec`), wrong length for the algorithm, missing field, bad base64 | Check the source of the key |
| `IncompatibleKeyVersionError` | `QS_INCOMPATIBLE_KEY_VERSION` | The key was written by a newer format version | Upgrade this library |
| `PayloadTooLargeError` | `QS_PAYLOAD_TOO_LARGE` | A key, signed message or sealed message exceeds 10 MB | The input is not what you think it is |
| `UnsupportedFormatError` | `QS_UNSUPPORTED_FORMAT` | A format that is not supported (for example a JWK for a secret key) | Use CBOR or PEM for secret keys |
| `UnsupportedAlgorithmError` | `QS_UNSUPPORTED_ALGORITHM` | A name that is not a supported suite, or a suite not valid for that operation | `kemSuites()` / `sigSuites()` list valid names |
| `InvalidArgumentError` | `QS_INVALID_ARGUMENT` | A wrong type or value, use after `free()`, a context over 255 bytes, a bad chunk size | Fix the call |
| `PolicyViolationError` | `QS_POLICY_VIOLATION` | `cnsa2.enforce` rejected a configuration | Choose the CNSA 2.0 parameter sets |
| `CryptoError` (base) / `QuantumSafeError` | `QS_INTERNAL_ERROR` / `QS_ERROR` | Something unexpected: a bug | Report it, without secret data |

Class tree: `QuantumSafeError` has the subclasses `NotInitializedError`, `CryptoError`, `SerializationError`, `UnsupportedAlgorithmError`,
`InvalidArgumentError` and `PolicyViolationError`. `CryptoError` covers the cryptographic failures; `SerializationError` covers
`KeyParseError`, `IncompatibleKeyVersionError`, `PayloadTooLargeError` and `UnsupportedFormatError`.

## Producing each common error on purpose

Useful for tests of your own error handling.

```ts test
import { HybridKEM, KEM, PublicKey, SecretBytes, Sign, cnsa2, utf8 } from 'quantum-safe-ts';
import type { QsErrorCode } from 'quantum-safe-ts';

function codeOf(fn: () => unknown): QsErrorCode | 'no error' {
  try {
    fn();
    return 'no error';
  } catch (e) {
    return (e as { code: QsErrorCode }).code;
  }
}

using pair = new HybridKEM().generateKeyPair();
const seen: Record<string, QsErrorCode | 'no error'> = {
  unknownSuite: codeOf(() => new Sign('NOT-A-SUITE' as never)),
  badPem: codeOf(() => PublicKey.fromPem('not a key')),
  wrongLengthPublicKey: codeOf(() => PublicKey.fromBytes('X25519+ML-KEM-768', new Uint8Array(10))),
  tooLarge: codeOf(() => PublicKey.fromCbor(new Uint8Array(10 * 1024 * 1024 + 1))),
  badCiphertext: codeOf(() => new HybridKEM().decapsulate(pair.secretKey, new Uint8Array(3))),
  algorithmMismatch: codeOf(() => new KEM('ML-KEM-768').decapsulate(pair.secretKey, new Uint8Array(1088))),
  hkdfTooLong: codeOf(() => SecretBytes.from(new Uint8Array(32)).deriveKey(8161, utf8('x'))),
  contextTooLong: codeOf(() => {
    const s = new Sign('ML-DSA-44');
    using k = s.generateKeyPair();
    s.sign(utf8('m'), k.secretKey, { context: new Uint8Array(256) });
  }),
  policy: codeOf(() => cnsa2.enforce({ kem: 'ML-KEM-768' })),
};
console.table(seen);
const expected: Record<string, QsErrorCode> = {
  unknownSuite: 'QS_UNSUPPORTED_ALGORITHM',
  badPem: 'QS_KEY_PARSE_ERROR',
  wrongLengthPublicKey: 'QS_KEY_PARSE_ERROR',
  tooLarge: 'QS_PAYLOAD_TOO_LARGE',
  badCiphertext: 'QS_MALFORMED_CIPHERTEXT',
  algorithmMismatch: 'QS_ALGORITHM_MISMATCH',
  hkdfTooLong: 'QS_HKDF_OUTPUT_TOO_LONG',
  contextTooLong: 'QS_INVALID_ARGUMENT',
  policy: 'QS_POLICY_VIOLATION',
};
for (const [name, code] of Object.entries(expected)) if (seen[name] !== code) throw new Error(`${name}: expected ${code}, got ${seen[name]}`);
```

## Errors you will not see

- **ML-KEM never throws for a wrong ciphertext** (implicit rejection, FIPS 203): decapsulation returns a pseudo-random secret and the failure
  appears later as `DecryptionAuthenticationError` from `Envelope.open`.
- **Signature failures give no reason.** `VerificationError` does not say whether the message, signature, context or key was wrong.
- **Hints never contain your data.** They are static strings, so they are safe to show to users and to put in logs.

For coding agents: the [MCP server](/tools/mcp) has an `explain_error` tool that looks up a code or class name.
