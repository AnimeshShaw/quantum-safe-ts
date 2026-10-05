# Key encapsulation and hybrids

A **KEM** (key encapsulation mechanism) lets two parties agree on a shared secret using only a public key. The sender runs `encapsulate`
with the recipient's public key and gets a *ciphertext* to send and a *shared secret* to keep; the recipient runs `decapsulate` with the
secret key and the ciphertext and gets the same shared secret. You then use that secret to derive keys. Most applications should use the
[`Envelope`](/guide/encryption), which does the derivation and the encryption for you; use a KEM directly when you need the secret itself, for
example to derive session keys in your own protocol.

**Use it when** you are building a protocol that needs a shared secret. **Do not use it** to encrypt data yourself with the raw secret: use
`Envelope.seal`, which derives a one-time key with HKDF and authenticates the message, version and your AAD.

## Two classes

| Class | Algorithms | Use |
|---|---|---|
| `HybridKEM` | `X25519+ML-KEM-512/768/1024`, `P-256+ML-KEM-512/768`, `X-Wing` | The default: classical and post-quantum together |
| `KEM` | `ML-KEM-512/768/1024` | Pure ML-KEM, for example the CNSA 2.0 profile (`ML-KEM-1024`) |

```ts test
import { HybridKEM, kemSuites } from 'quantum-safe-ts';

const kem = new HybridKEM();                      // X25519+ML-KEM-768
if (kem.algorithm !== 'X25519+ML-KEM-768') throw new Error('unexpected default');
console.table(kemSuites().map((s) => ({ name: s.name, hybrid: s.hybrid, nistCategory: s.nistLevel, cnsa2: s.meetsCnsa2, pyCompatible: s.pyCompatible })));
const names = kemSuites().map((s) => s.name);
for (const expected of ['X25519+ML-KEM-768', 'P-256+ML-KEM-768', 'X-Wing', 'ML-KEM-1024']) {
  if (!names.includes(expected)) throw new Error(`missing suite ${expected}`);
}
```

`kemSuites()` and `sigSuites()` list every suite this build supports, with its NIST category, whether it meets the CNSA 2.0 parameter set,
and whether quantum-safe-py 0.3.0 can read its data.

## A complete exchange

```ts test
import { HybridKEM, utf8, equalBytes } from 'quantum-safe-ts';

const kem = new HybridKEM('X25519+ML-KEM-768');

// Recipient: generates a key pair and publishes the public key.
using pair = kem.generateKeyPair();

// Sender: encapsulates to that public key.
const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
const senderKey = sharedSecret.deriveKey(32, utf8('myapp-session-v1')); // HKDF-SHA-256; 'info' separates purposes
sharedSecret.free();

// Recipient: decapsulates the ciphertext it received.
using recovered = kem.decapsulate(pair.secretKey, ciphertext);
const recipientKey = recovered.deriveKey(32, utf8('myapp-session-v1'));

if (!equalBytes(senderKey, recipientKey)) throw new Error('keys differ');
console.log('ciphertext bytes:', ciphertext.length);
```

`deriveKey(length, info)` is HKDF-SHA-256 with no salt. Give each purpose its own `info` string (`myapp-session-v1`, `myapp-mac-v1`) so the keys
differ. The maximum output is 8,160 bytes; asking for more throws `HkdfOutputTooLongError`.

## What the shared secret is, and what to do with it

- It is secret: it lives in WebAssembly memory as a `SecretBytes` (also exported as `SharedSecret`). `exportBytes()` copies it into the
  JavaScript heap; call `wipe()` on the copy when you are done.
- Do not use it as a key directly. Derive keys with `deriveKey` and a distinct `info` per use.
- A KEM alone does **not** authenticate anyone. Anyone can encapsulate to a public key. If you need to know who you are talking to, sign
  something, or use a protocol that authenticates the exchange.

## Implicit rejection: a wrong ciphertext does not throw

ML-KEM (FIPS 203) is designed so that decapsulating a modified ciphertext returns a pseudo-random secret instead of an error. This avoids
leaking information through error behaviour. The consequence: `decapsulate` succeeds, the secrets differ, and the failure appears later,
when authentication fails (`Envelope.open` throws `DecryptionAuthenticationError`).

```ts test
import { HybridKEM, equalBytes } from 'quantum-safe-ts';

const kem = new HybridKEM();
using pair = kem.generateKeyPair();
const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);

const tampered = ciphertext.slice();
tampered[tampered.length - 1] ^= 1;              // flip a bit in the ML-KEM part
using wrong = kem.decapsulate(pair.secretKey, tampered);
if (equalBytes(wrong.exportBytes(), sharedSecret.exportBytes())) throw new Error('should differ');
sharedSecret.free();
```

A ciphertext of the wrong *length* or structure is different: it throws `MalformedCiphertextError`.

## Sizes

Fixed by the algorithms. Hybrids add the classical half plus a 2-byte length field.

| Suite | Public key | Ciphertext |
|---|---|---|
| `ML-KEM-512` | 800 | 768 |
| `ML-KEM-768` | 1,184 | 1,088 |
| `ML-KEM-1024` | 1,568 | 1,568 |
| `X25519+ML-KEM-768` | 1,218 | 1,122 |
| `X-Wing` | 1,216 | 1,120 |

```ts test
import { HybridKEM, KEM } from 'quantum-safe-ts';

const cases: [string, number, number][] = [['ML-KEM-768', 1184, 1088], ['X25519+ML-KEM-768', 1218, 1122], ['X-Wing', 1216, 1120]];
for (const [name, pk, ct] of cases) {
  const kem = name.startsWith('ML-KEM') ? new KEM(name as 'ML-KEM-768') : new HybridKEM(name as 'X-Wing');
  using pair = kem.generateKeyPair();
  const enc = kem.encapsulate(pair.publicKey);
  if (pair.publicKey.toBytes().length !== pk || enc.ciphertext.length !== ct) throw new Error(`${name}: ${pair.publicKey.toBytes().length}/${enc.ciphertext.length}`);
  enc.sharedSecret.free();
}
```

## About `X-Wing`

`X-Wing` combines X25519 with ML-KEM-768 using the construction specified in `draft-connolly-cfrg-xwing-kem` (an individual Internet-Draft, not an
RFC) and is implemented by other libraries too. Use it when systems outside the quantum-safe family must read your data. It is never a CNSA
2.0 suite (it is ML-KEM-768 based) and quantum-safe-py cannot read it.

## Common mistakes

| Mistake | Fix |
|---|---|
| Using the raw shared secret as an AES key | `deriveKey` with a purpose-specific `info`, or use `Envelope` |
| Forgetting to free a key pair or shared secret | `using`, or `.free()` in a `finally` |
| Expecting `decapsulate` to fail on a bad ciphertext | It does not (implicit rejection); authenticate afterwards |
| Using a key of one algorithm with another suite's KEM | `AlgorithmMismatchError`; keep the key and the class in step |
| Passing a ciphertext from a different suite | `MalformedCiphertextError` (wrong length) or a mismatching secret |
