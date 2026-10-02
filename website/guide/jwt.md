# JWT

Two modes, for two audiences.

```ts test
import { JWTSigner, JWTVerifier, StandardJwt, HybridSign } from 'quantum-safe-ts';

// quantum-safe-py mode: only quantum-safe-py and quantum-safe-ts can verify these tokens.
using pair = new HybridSign().generateKeyPair();
const token = new JWTSigner(pair, { issuer: 'https://issuer.example' }).sign({ sub: 'user-1' }, { expiresIn: 600 });
const claims = new JWTVerifier(pair.publicKey, { issuer: 'https://issuer.example' }).verify(token);

// Standards mode, RFC 9964: any compliant JOSE implementation can verify these.
const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65', { kid: 'k1' });
const std = StandardJwt.sign({ sub: 'user-1', aud: 'api' }, privateJwk, { expiresIn: 600 });
const ok = StandardJwt.verify(std, publicJwk, { audience: 'api' });

if (claims.sub !== 'user-1' || ok.sub !== 'user-1') throw new Error('unexpected');
```

| Mode | Use when | Algorithms |
|---|---|---|
| `JWTSigner` / `JWTVerifier` | Both ends are quantum-safe-py or quantum-safe-ts | `ML-DSA-*` and hybrids |
| `StandardJwt` | Other JOSE libraries must verify | `ML-DSA-44/65/87` as `AKP` JWKs (RFC 9964) |

Both modes pin the algorithm to the key, reject `alg: "none"` and any mismatched `alg`, validate `exp` and `nbf` with 30 seconds of skew,
and check `iss` and `aud` when you ask. A claim failure throws a bare `VerificationError`; a structurally malformed token throws
`InvalidArgumentError`.

::: warning
A private AKP JWK contains the secret seed as a string, which is inherent to JWK. Store it like any secret key.
:::
