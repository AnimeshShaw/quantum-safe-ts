# Errors

Every error extends `QuantumSafeError` and carries a stable `code`, a static `hint`, and `toJSON()`. Match with `instanceof` or `code`.
Never parse `message`. Hints never contain key material.

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
  if (!(e instanceof QuantumSafeError) || e.code !== 'QS_DECRYPTION_FAILED' || e.hint.length === 0) throw new Error('error contract');
}
```

| Code | Meaning and usual fix |
|---|---|
| `QS_NOT_INITIALIZED` | Call `await init()` first (outside Node.js). |
| `QS_DECRYPTION_FAILED` | Wrong key, wrong AAD, or the message was modified. |
| `QS_VERIFICATION_FAILED` | The signature, message, context or key does not match. No detail by design. |
| `QS_DECAPSULATION_FAILED`, `QS_MALFORMED_CIPHERTEXT` | The ciphertext is structurally invalid for this algorithm. |
| `QS_MALFORMED_KEY`, `QS_KEY_PARSE_ERROR` | The key bytes, PEM, CBOR or JWK are invalid. |
| `QS_MALFORMED_SIGNATURE`, `QS_SIGNING_FAILED` | The signature bytes are invalid, or signing could not complete. |
| `QS_ALGORITHM_MISMATCH` | A key of one algorithm was used with another algorithm's API. |
| `QS_UNSUPPORTED_ALGORITHM`, `QS_UNSUPPORTED_FORMAT` | Not a supported suite or format. |
| `QS_INCOMPATIBLE_KEY_VERSION`, `QS_PAYLOAD_TOO_LARGE` | A newer key format, or input over the size cap. |
| `QS_INVALID_ARGUMENT` | A wrong type or value, or use after `free()`. |
| `QS_POLICY_VIOLATION` | `cnsa2.enforce` rejected a configuration. |
| `QS_HKDF_OUTPUT_TOO_LONG`, `QS_KDF_FAILED` | Key derivation limits or parameters. |
| `QS_INTERNAL_ERROR` | A bug. Please report it, without secret data. |

The error type is part of the API: ML-KEM never throws for a wrong ciphertext (implicit rejection), so a wrong key shows up as
`DecryptionAuthenticationError` from `Envelope.open`, not from decapsulation.
