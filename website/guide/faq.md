# Troubleshooting and FAQ

## Getting it running

**`NotInitializedError`: "quantum-safe-ts has not been initialised."**
You are not on Node.js (browser, Deno, Bun, Worker) and have not awaited `init()`. Call `await init()` once at start-up. In a Worker pass the
precompiled module: `await init({ wasm })` ([Runtimes](/guide/runtimes)).

**My bundle got much bigger.**
The default entry embeds the WebAssembly (about 600 KiB gzipped of JavaScript). Use `quantum-safe-ts/slim` and serve the `.wasm` yourself
([Runtimes](/guide/runtimes#size)).

**`using` is a syntax error.**
Explicit resource management needs TypeScript 5.2 or newer and a runtime or build target that supports it. Otherwise call `.free()` in a
`finally`: `const pair = kem.generateKeyPair(); try { ... } finally { pair.free(); }`.

**Does it work in React Native?**
Not yet.

**Does it work in an old browser or without WebAssembly?**
No. WebAssembly is required. Every current Chromium, Firefox and WebKit has it; the CSP in a Chrome extension must allow `'wasm-unsafe-eval'`.

## Errors

**`DecryptionAuthenticationError` when opening an envelope that I just sealed.**
Wrong secret key, a different `expectedAad` than the `aad` used to seal, or the bytes changed in storage (a text column that re-encoded
binary data is the usual culprit: store `toBytes()` in a `BYTEA`/`BLOB` column, or `toHex()`/base64 in a text one).

**`VerificationError` and no explanation.**
By design: a signature failure does not say which part was wrong. Check, in this order: the same **context** on both ends (`expectedContext`);
the same message bytes; the right public key (compare `fingerprint()`); for default-format signatures made with `hedged: false`, a verifier
built with `hedged: false`; the same format on both ends (`-v2` versus not).

**`KeyParseError` loading a key.**
A secret key presented as public (or the reverse), a public key of the wrong length for its algorithm, a damaged PEM, or a JWK that is not
`kty: "AKP"`. Print `fingerprint()` and `algorithm` on both sides.

**`UnsupportedAlgorithmError`.**
The name is not a supported suite for that operation (for example pure `ML-KEM-768` for an envelope, or a `-v2` name for SLH-DSA).
`kemSuites()` and `sigSuites()` list valid names.

More in the [error reference](/guide/errors).

## Using it

**How do I put a sealed message in a JSON field?**

```ts test
import { easy, toBase64Url, fromBase64Url } from 'quantum-safe-ts';

const keys = easy.generateEncryptionKeys();
const sealed = easy.encrypt(keys.publicKey, 'hello');
const json = JSON.stringify({ v: 1, ct: toBase64Url(sealed) });          // base64url: URL- and JSON-safe
const back = easy.decryptText(keys.secretKey, fromBase64Url(JSON.parse(json).ct));
if (back !== 'hello') throw new Error('round trip failed');
```

**How big are the outputs?**
Fixed by the algorithms: an `X25519+ML-KEM-768` envelope adds about 1.2 KB of KEM ciphertext plus 12 bytes of nonce and 16 of tag to your data;
an `Ed25519+ML-DSA-65-v2` signature is 3,373 bytes. Post-quantum material is larger than classical, so plan for it in tokens, cookies and headers
(a hybrid-signed JWT does not fit in a cookie).

**Can I encrypt to several recipients?**
Seal separately to each recipient's public key (the message is the part you may share if it is large: encrypt the data once with a random key
and seal that key to each recipient).

**Is it fast enough?**
For key exchange and signing in a request path, yes: operations take tens to hundreds of microseconds to a few milliseconds on a desktop CPU,
slower on phones. It is slower than native code. Password hashing (`deriveMasterKey`, 19 MiB of memory) is deliberately heavy: run it in a Web
Worker. Measure on your target devices.

**How do I rotate a key?**
Generate a new key pair, publish the new public key (with a key id), keep the old secret key until everything encrypted to it has been
re-encrypted or has expired, then retire it. For signatures, accept both public keys during the overlap ([Cookbook: rotation](/guide/cookbook#_4-jwts-for-an-api-with-rotating-keys),
[Migration](/guide/migration)).

**Can I use the same key for encryption and signing?**
No. KEM keys and signature keys are different kinds; generate each separately, and one signing key per format (v1 or `-v2`), never both.

**Where should I store the secret key?**
In a secrets manager or KMS and load it at start-up, not in source control or an environment file ([Keys](/guide/keys#where-to-keep-secret-keys)).

## Choosing

**Hybrid or pure?** Hybrid for most uses during the transition; pure `ML-KEM-1024`/`ML-DSA-87` for the CNSA 2.0 parameter sets
([Choosing](/guide/choosing)).

**Why is the default signature `Ed25519+ML-DSA-65` and not `-v2`?**
So deployments that include an older Python verifier keep working. `-v2` is cleaner and safe to choose today if every verifier is quantum-safe-py
0.3.2+ or quantum-safe-ts; the default is planned to flip in the next minor release ([Upgrading](/guide/upgrading)).

**Do I need X-Wing?**
Only if systems that are not quantum-safe-py or quantum-safe-ts must decrypt your data. They are not compatible with the default hybrid.

**Why not use WebCrypto's ML-KEM/ML-DSA?**
If you only need a primitive and your runtimes all have it, you probably should: it is smaller and native. This library adds formats, key
handling, typed errors, JWT, migration tools and Python interop, and runs where WebCrypto does not have the algorithms yet ([Which library?](/compare)).

## Security and compliance

**Is it CNSA 2.0 compliant?**
It provides the CNSA 2.0 parameter sets (`ML-KEM-1024`, `ML-DSA-87`) and reports its own gaps; compliance for National Security Systems runs
through validated modules and is outside what a library can claim ([CNSA 2.0](/guide/standards)).

**Does an envelope prove who sent it?**
No. Anyone with your public key can seal. Sign it as well ([Cookbook 1](/guide/cookbook#_1-end-to-end-encrypted-messages-between-services)).

**Someone found a vulnerability. What do I do?**
Report it privately through GitHub Security Advisories ([Security model](/guide/security#reporting-a-vulnerability)).

## Python

**Can Python decrypt what TypeScript encrypts, and the reverse?**
Yes, for the shared formats, in both directions ([Interop](/guide/python-interop)). Formats marked "0.3.2+" need quantum-safe-py 0.3.2.

**Why does a Python signature fail here?**
Almost always a context or hedging mismatch ([When interop fails](/guide/python-interop#when-interop-fails)).

## Migration and tooling

**How do I find what needs migrating?**
Run `npx quantum-safe-audit scan .` ([Audit tool](/tools/audit)) and gate CI with the [GitHub Action](/tools/github-action).

**Can an AI coding agent use this library correctly?**
That is the point of `llms.txt`, `llms-full.txt` (every example in it is executed in CI), stable error codes with hints, and the
[MCP server](/tools/mcp).
