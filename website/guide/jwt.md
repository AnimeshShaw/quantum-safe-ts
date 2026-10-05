# JWT (JSON Web Tokens)

A JWT is a signed set of claims (who, what, until when) that one service issues and another verifies. There are two modes, for two audiences.

| Mode | Use when | Algorithms | Who can verify |
|---|---|---|---|
| `JWTSigner` / `JWTVerifier` | Every verifier is quantum-safe-py or quantum-safe-ts | `ML-DSA-*` and the hybrids, including `-v2` | Only those two libraries |
| `StandardJwt` | Other JOSE libraries, gateways or third parties must verify | `ML-DSA-44/65/87` as `AKP` JWKs (RFC 9964) | Any compliant implementation |

**Do not** put a `JWTSigner` token in front of a generic JWT gateway: it will be rejected. A token that other systems read should be a
`StandardJwt`. If you need both, issue the standard one.

## quantum-safe mode

```ts test
import { HybridSign, JWTSigner, JWTVerifier, VerificationError } from 'quantum-safe-ts';

using keys = new HybridSign().generateKeyPair();

const signer = new JWTSigner(keys, { issuer: 'https://auth.example' });     // a KeyPair or a SecretKey
const token = signer.sign({ sub: 'user-1', scope: 'read', aud: 'api' }, { expiresIn: 600 }); // seconds

const verifier = new JWTVerifier(keys.publicKey, { issuer: 'https://auth.example', audience: 'api' });
const claims = verifier.verify(token, { requireExp: true });
if (claims.sub !== 'user-1' || claims.scope !== 'read') throw new Error('unexpected claims');

// A token past its expiry is refused. `now` makes the check testable.
try {
  verifier.verify(token, { now: Math.floor(Date.now() / 1000) + 3600 });
  throw new Error('an expired token must be refused');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}
```

- `expiresIn` is seconds from now. **Always set it.** A negative or non-finite value throws `InvalidArgumentError` (it used to silently produce a
  token that never expires). `expiresIn: 0` is the only way to ask for a token without `exp`.
- `requireExp: true` on `verify` rejects tokens that carry no `exp`. Set it whenever you rely on expiry.
- `issuer` and `audience` are checked when you give them to the verifier (`iss` must equal, `aud` must contain). A mismatch is a bare
  `VerificationError`.
- `exp` and `nbf` are validated with 30 seconds of skew.
- A structurally malformed token throws `InvalidArgumentError`; every claim or signature failure throws `VerificationError`, with no detail.
- The algorithm is pinned to the key: the `alg` header must equal the key's algorithm, and `alg: "none"` is rejected.
- Signatures have **one accepted spelling** (no base64 padding, no non-canonical trailing bits), so a token's text is not malleable.
- Use `context` (in both `sign` options and `verify` options) to bind tokens to a purpose, as with [signatures](/guide/signatures).
- The tokens use the library's own signing construction (a hedging prefix and a `jwt` context in the signature blob), which is why no other
  JOSE library can verify them. A verifier must match the signer's `hedged` setting (default `true`); with a `-v2` key there is nothing to match.

### With the clean signature format

```ts test
import { HybridSign, JWTSigner, JWTVerifier } from 'quantum-safe-ts';

using keys = new HybridSign('Ed25519+ML-DSA-65-v2').generateKeyPair();
const token = new JWTSigner(keys).sign({ sub: 'svc-a' }, { expiresIn: 60 });
const claims = new JWTVerifier(keys.publicKey).verify(token, { requireExp: true });
if (claims.sub !== 'svc-a') throw new Error('unexpected');
const header = JSON.parse(new TextDecoder().decode(Uint8Array.from(Buffer.from(token.split('.')[0]!, 'base64url'))));
if (header.alg !== 'Ed25519+ML-DSA-65-v2') throw new Error('the header names the key algorithm');
```

## Standards mode (RFC 9964)

`StandardJwt` produces tokens signed with plain ML-DSA exactly as RFC 9964 specifies (JWS with `alg` `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`, and
keys as `AKP` JWKs). It has been checked against `@noble/post-quantum` and Node's WebCrypto, and against quantum-safe-py 0.3.2+.

```ts test
import { StandardJwt, QuantumSafeError } from 'quantum-safe-ts';

const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65', { kid: 'key-2026-10' });
const token = StandardJwt.sign({ sub: 'user-1', aud: 'api', iss: 'https://auth.example' }, privateJwk, { expiresIn: 600 });

const claims = StandardJwt.verify(token, publicJwk, { audience: 'api', issuer: 'https://auth.example', requireExp: true });
if (claims.sub !== 'user-1') throw new Error('unexpected claims');

// Publish only the public JWK. Derive it from the private one when needed:
const derived = StandardJwt.publicJwk(privateJwk);
if (derived.priv !== undefined || derived.pub !== publicJwk.pub) throw new Error('public JWK must not carry the seed');

try {
  StandardJwt.verify(token + 'A', publicJwk);            // a tampered token
  throw new Error('should have failed');
} catch (e) {
  if (!QuantumSafeError.is(e)) throw e;                  // refused with a typed error
}
```

::: warning A private AKP JWK holds the secret
The private JWK's `priv` member is the secret seed as a string, which is inherent to JWK. Store it like any secret key, never publish it, and
publish only `publicJwk` (for example at a `jwks.json` URL).
:::

- Tokens made by quantum-safe-py 0.3.2+ `StandardJwt` verify here, and the reverse. **Private** JWKs are TypeScript-only: liboqs cannot
  derive a Python key pair from a seed, so only public JWKs and tokens cross.
- `StandardJwt` supports pure ML-DSA only (no hybrids, no SLH-DSA). For a hybrid you control, use the quantum-safe mode.
- Both modes pin the algorithm to the key and reject `alg: "none"`.

## Common mistakes

| Mistake | Fix |
|---|---|
| Issuing tokens with no expiry | Always pass `expiresIn`; verify with `requireExp: true` |
| Not checking `iss` / `aud` | Give the verifier `issuer` and `audience` |
| Publishing a private JWK | Publish `StandardJwt.publicJwk(privateJwk)` only |
| Sending a `JWTSigner` token to third parties | Use `StandardJwt` |
| Verifying a `hedged: false` signer's tokens with the default verifier | Give the verifier the same `hedged` option, or use a `-v2` key |
| Trusting claims before verifying | `verify` first, then read claims |
