# Keys and passwords

Keys are the one thing you must get right operationally. This page covers the key objects, how to store and move them, how memory is
handled, and how to derive keys from passwords.

## The key objects

| Class | Holds | Notes |
|---|---|---|
| `PublicKey` | Algorithm name and raw public bytes | Safe to share, log and store. `fingerprint()` gives a stable id. |
| `SecretKey` | The secret half | Stays in WebAssembly memory; `.free()` wipes the owned buffers. Never printed. |
| `KeyPair` | Both | From `generateKeyPair()`, `KeyPair.fromCborBundle` or `KeyPair.fromKeys(pub, sec)` |
| `SecretBytes` (alias `SharedSecret`) | A secret byte string | KEM shared secrets and Argon2id master keys; `deriveKey`, `exportBytes`, `.free()` |

Every key records its algorithm and a migration state, and every API checks them: a key of one algorithm cannot be used with another suite
(`AlgorithmMismatchError`).

## Serialization

```ts test
import { PublicKey, SecretKey, KeyPair, HybridKEM } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();

// Public keys: PEM, CBOR, JWK. All safe to publish.
const pem = pair.publicKey.toPem();       // QUANTUM SAFE PUBLIC KEY, identical to quantum-safe-py's to_pem()
const jwk = pair.publicKey.toJwk();       // kty "AKP"; public keys only
const cbor = pair.publicKey.toCbor();
for (const back of [PublicKey.fromPem(pem), PublicKey.fromJwk(jwk), PublicKey.fromCbor(cbor)]) {
  if (back.fingerprint() !== pair.publicKey.fingerprint()) throw new Error('fingerprint changed');
  back.free();
}

// Secret keys: PEM or CBOR. These contain the secret: protect them.
const secretPem = pair.secretKey.toPem();     // QUANTUM SAFE SECRET KEY
using restored = SecretKey.fromPem(secretPem);
if (restored.algorithm !== 'X25519+ML-KEM-768') throw new Error('unexpected algorithm');

// A pair travels as one CBOR bundle.
const bundle = pair.toCborBundle();
using again = KeyPair.fromCborBundle(bundle);
if (again.publicKey.fingerprint() !== pair.publicKey.fingerprint()) throw new Error('bundle changed the key');
```

| Format | Methods | Notes |
|---|---|---|
| CBOR | `toCbor` / `fromCbor` | `{v, algo, ms, ktype, key}`, identical to quantum-safe-py |
| PEM | `toPem` / `fromPem` | `QUANTUM SAFE PUBLIC KEY` / `QUANTUM SAFE SECRET KEY` |
| JWK | `toJwk` / `fromJwk` | Public keys only. Secret keys are never exported as JWK. (`StandardJwt` has its own private JWK for ML-DSA, see [JWT](/guide/jwt).) |
| Raw | `PublicKey.fromBytes(algorithm, bytes)`, `toBytes()`; `SecretKey.fromBytes`, `exportBytes()` | For wire formats you define. Check the algorithm and length. |
| Fingerprint | `fingerprint()`, `fingerprintColon()` | `sha256(algorithm ‖ 0x00 ‖ key)` as hex, or in `aa:bb:...` form |
| Bundle | `KeyPair.toCborBundle` / `fromCborBundle` | Public and secret key together |
| Assemble | `KeyPair.fromKeys(pub, sec)` | From separately held keys |

## What the parsers refuse

Parsing keys that come from outside is a security boundary, so the parsers are strict. They refuse (with a typed error, never a crash):

- a **secret key loaded as a public key** or the reverse (`ktype` must be present and must match);
- a **public key of the wrong length** for its algorithm, which is how a secret key pasted into a public-key field is caught;
- a JWK that is not `kty: "AKP"`;
- a **newer format version** than this library knows (`IncompatibleKeyVersionError`) and a version below 1;
- payloads over **10 MB**, nesting that is too deep, duplicate map keys, trailing bytes and non-minimal integer encodings.

```ts test
import { PublicKey, SecretKey, HybridKEM, KeyParseError } from 'quantum-safe-ts';

using pair = new HybridKEM().generateKeyPair();

let refused = 0;
const attempts: (() => unknown)[] = [
  () => PublicKey.fromCbor(pair.secretKey.toCbor()),             // secret key presented as a public key
  () => SecretKey.fromCbor(pair.publicKey.toCbor()),             // and the reverse
  () => PublicKey.fromPem(pair.secretKey.toPem()),
  () => PublicKey.fromBytes('X25519+ML-KEM-768', new Uint8Array(32)), // wrong length
  () => PublicKey.fromJwk('{"kty":"RSA","alg":"X25519+ML-KEM-768","pub":"AAAA"}'),
];
for (const attempt of attempts) {
  try { attempt(); } catch (e) { if (e instanceof KeyParseError) refused++; else throw e; }
}
if (refused !== attempts.length) throw new Error(`only ${refused} of ${attempts.length} were refused`);
```

## Memory

`SecretKey`, `SecretBytes` and `KeyPair` hold their secrets in WebAssembly memory and wipe the owned buffers on `.free()` or at the end of a
`using` scope. After `free()`, any use throws `InvalidArgumentError`. Anything you copy out (`exportBytes()`, `toPem()` of a secret, plaintext
from `Envelope.open`) lives in the JavaScript heap, where this library cannot wipe it: call `wipe()` on those copies when done. `toString()`,
`toJSON()` and `util.inspect` never reveal key material.

```ts test
import { HybridKEM, InvalidArgumentError, wipe } from 'quantum-safe-ts';

const pair = new HybridKEM().generateKeyPair();
const copy = pair.secretKey.exportBytes();       // a JS-heap copy: your responsibility now
wipe(copy);
if (copy.some((b) => b !== 0)) throw new Error('wipe must zero the copy');
pair.free();
try {
  pair.secretKey.exportBytes();                  // use after free
  throw new Error('should have failed');
} catch (e) {
  if (!(e instanceof InvalidArgumentError)) throw e;
}
using other = new HybridKEM().generateKeyPair();
if (JSON.stringify(other.secretKey) !== '{"type":"SecretKey","redacted":true}') throw new Error('secrets must not serialise');
```

Honest limits: copies made while arguments are passed to WebAssembly and while parsing may remain in WebAssembly linear memory after `free()`;
the JavaScript engine may keep copies of strings (the easy layer's PEM strings) you cannot wipe. See the [security model](/guide/security).

## Where to keep secret keys

| Option | When |
|---|---|
| A secrets manager or KMS, loaded at start-up | Servers. Load the PEM/CBOR into a `SecretKey`, free it when done. |
| Encrypted at rest with a key derived from a password | Desktop or CLI tools (see below) |
| `localStorage` / `IndexedDB` in a browser | Only if you accept that any script on the page can read it. Prefer not persisting secret keys. |
| In source control or an environment file | **Never.** `quantum-safe-audit` flags embedded private keys (`QSJ060`). |

## Passwords

```ts test
import { deriveMasterKey, utf8, toHex } from 'quantum-safe-ts';

using master = await deriveMasterKey('correct horse battery staple', utf8('0123456789abcdef')); // Argon2id
const authKey = master.deriveKey(32, utf8('myapp-auth-v1'));
const vaultKey = master.deriveKey(32, utf8('myapp-vault-v1'));
if (toHex(authKey) === toHex(vaultKey)) throw new Error('subkeys must differ');
```

`deriveMasterKey(password, salt)` is Argon2id with 19 MiB of memory, 2 passes and 1 lane, returning a 32-byte `SecretBytes`. The salt must
be at least 8 bytes: use 16 or more random bytes, store it next to the ciphertext, and never reuse one across users. Derive purpose-specific
subkeys with `deriveKey(length, info)` rather than using the master key directly. No Unicode normalisation is applied: normalise passwords
yourself (for example NFKC) so the same password always yields the same key. Argon2id slows guessing; it cannot rescue a guessable
password. In a browser, run it in a Web Worker: it takes tens of milliseconds on a desktop and blocks while it runs.

## Common mistakes

| Mistake | Fix |
|---|---|
| Logging a `SecretKey` or its PEM | `toString()`/`toJSON()` are safe, but `toPem()` of a secret is the secret itself |
| Forgetting `.free()` | Use `using`, or `try { ... } finally { key.free() }` |
| Using the same salt for every user | Random 16+ bytes per user |
| Using the master key directly as an encryption key | `deriveKey` with a distinct `info` |
| Storing the secret next to the data it protects | Keep keys in a separate trust domain |
