# Keys and passwords

## Serialization

```ts test
import { PublicKey, KeyPair, HybridKEM } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();

const pem = pair.publicKey.toPem();   // QUANTUM SAFE PUBLIC KEY, identical to quantum-safe-py's to_pem()
const jwk = pair.publicKey.toJwk();   // kty "AKP"; public keys only
const back = PublicKey.fromPem(pem);
if (back.fingerprint() !== pair.publicKey.fingerprint()) throw new Error('fingerprint changed');

const bundle = pair.toCborBundle();   // contains the secret: protect it
using restored = KeyPair.fromCborBundle(bundle);
if (restored.algorithm !== 'X25519+ML-KEM-768' || jwk.length < 10) throw new Error('unexpected');
```

| Format | Methods | Notes |
|---|---|---|
| CBOR | `toCbor` / `fromCbor` | `{v, algo, ms, ktype, key}`, identical to quantum-safe-py |
| PEM | `toPem` / `fromPem` | `QUANTUM SAFE PUBLIC KEY` / `QUANTUM SAFE SECRET KEY` |
| JWK | `toJwk` / `fromJwk` | Public keys only. Secret keys are never exported as JWK. |
| Fingerprint | `fingerprint()` | `sha256(algorithm ‖ 0x00 ‖ key)` as hex |
| Bundle | `KeyPair.toCborBundle` / `fromCborBundle` | Public and secret key together |
| Assemble | `KeyPair.fromKeys(pub, sec)` | From separately held keys |

Parsing rejects public/secret type confusion, version rollback, and payloads over 10 MB. Every parser returns a typed error on bad input.

## Memory

`SecretKey`, `SecretBytes` and `KeyPair` hold their secrets in WebAssembly memory and wipe them on `.free()` or at the end of a `using`
scope. Anything you copy out (`exportBytes()`, `toPem()` of a secret, plaintext from `Envelope.open`) lives in the JavaScript heap, where
this library cannot wipe it: call `wipe()` on those copies when done. `toString()`, `toJSON()` and `util.inspect` never reveal key material.

## Passwords

```ts test
import { deriveMasterKey, utf8, toHex } from 'quantum-safe-ts';

using master = await deriveMasterKey('correct horse battery staple', utf8('0123456789abcdef')); // Argon2id
const authKey = master.deriveKey(32, utf8('myapp-auth-v1'));
const vaultKey = master.deriveKey(32, utf8('myapp-vault-v1'));
if (toHex(authKey) === toHex(vaultKey)) throw new Error('subkeys must differ');
```

`deriveMasterKey(password, salt)` is Argon2id with 19 MiB, 2 passes and 1 lane. The salt must be at least 8 bytes (use 16 or more random
bytes). No Unicode normalisation is applied: normalise passwords yourself (for example NFKC) so the same password always yields the same key.
Argon2id slows guessing; it cannot rescue a guessable password.
