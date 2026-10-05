# Upgrading and compatibility

How versions are handled, what is stable, what is planned to change, and what to check when you move between versions of this library or of
quantum-safe-py.

## Version policy

Until 1.0:

- **Wire formats are never changed.** A key, a sealed message or a signature written by one version is read by every later version. New capability
  arrives as a **new, explicitly named suite** (for example `X-Wing`, the `-v2` signatures); an existing identifier never changes meaning. The
  [compatibility table](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/COMPATIBILITY.md) and the fixtures in `tests/vectors/` enforce this.
- **API changes can happen in a minor version** (0.1 → 0.2), with a note in the [changelog](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/CHANGELOG.md)
  and, where practical, a deprecated alias for one release.
- Only the latest minor version receives fixes ([security policy](/guide/security#supported-versions)).
- **Pin an exact version** in production (`"quantum-safe-ts": "0.1.1"`, not `^0.1.1`) and read the changelog before moving.

At 1.0 the API is frozen under semantic versioning, which is gated on an independent security review.

## Planned changes you can prepare for

| Planned | What to do now |
|---|---|
| The default signature suite of `easy` and `HybridSign()` moves from `Ed25519+ML-DSA-65` to `Ed25519+ML-DSA-65-v2` in a later minor release | Choose explicitly: `new HybridSign('Ed25519+ML-DSA-65-v2')` if every verifier is quantum-safe-py 0.3.2+ or quantum-safe-ts; `new HybridSign('Ed25519+ML-DSA-65')` to keep the current format. Explicit choices never change. |
| Argument order and naming of some calls may be made consistent before 1.0 (for example `sign(message, key)` versus `decapsulate(key, ciphertext)`), with deprecated aliases | Keep your calls in one place (a small wrapper) so a change is a one-line edit |
| The ESM and CommonJS builds may be reduced to ESM only | Import the library one way throughout; use `QuantumSafeError.is(e)` rather than `instanceof` |
| `Jwt*` and `JWT*` naming, subpath imports for migration/JWT/LMS | Same: wrap and keep imports central |

None of these is scheduled for the first release; each will be announced in the changelog.

## From quantum-safe-py to quantum-safe-ts

Keys, envelopes, signatures and tokens cross without conversion ([Interop](/guide/python-interop)). Differences to expect:

| Python | TypeScript |
|---|---|
| `verify(sm, pub, context=...)` and `Envelope.open(..., expected_aad=...)` (0.3.1+) | `verify(signed, pub, { expectedContext })` and `Envelope.open(..., { expectedAad })`: the same rule, required in spirit, with an empty default |
| `Sign(algo, hedged=...)` | `new Sign(algo, { hedged })` |
| Snake case | Camel case; classes `HybridKEM`, `KEM`, `Sign`, `HybridSign`, `Envelope`, `Upgrader`, `MigrationStateManager`, `cnsa2` mirror the names |
| Exceptions such as `VerificationError` | The same class names where there is an equivalent, plus stable `code` and `hint` |
| Exceptions raised from the cryptography layer, sometimes untyped | Always a `QuantumSafeError` subclass for parser input |
| Secrets zeroized with `ctypes.memset` | `.free()` / `using`; copies in the JavaScript heap are yours to `wipe()` |
| Stricter input in TypeScript: `ktype` required in key CBOR, JWK `kty` must be `AKP`, hybrid signature payloads exactly four entries, CBOR integers in shortest form | Every key and signature Python writes still loads; only input Python accepted by accident is refused |

## From quantum-safe-py 0.3.0 to 0.3.2 (for mixed deployments)

| Change in Python 0.3.1 and 0.3.2 | Effect on a mixed deployment |
|---|---|
| Verifiers pin the signature prefix length to the verifier's hedging mode | Signatures made with `hedged=False` verify only on a verifier built with `hedged=False` (same rule here). Default hedged signatures are unaffected. |
| `verify(..., context=...)`, `Envelope.open(..., expected_aad=...)` | State what you expect, on both sides |
| New formats: envelope v2, `-v2` signatures, `StandardJwt` | Readable by this library; **0.3.0 cannot read them** and fails closed |
| Stricter key loaders and typed errors | Nothing valid is refused |
| CNSA 2.0 helper reports every hybrid `partial` | Same verdicts as `cnsa2.report` here |
| 0.3.2: `Sign.sign_raw()` and a standard `Sign.verify_raw()` (before, `verify_raw` rejected every standard signature) | The path for standard FIPS 204 signatures from Python; see [Interop](/guide/python-interop#compatible-is-not-the-same-as-standard) |

Upgrade every Python verifier to 0.3.2 before you start issuing `-v2` signatures or envelope v2 to it.

## Moving from the easy layer to the class API

The easy layer is a convenience; you can move without changing stored data, because both use the same formats. Keys exported from the easy
layer are ordinary PEM strings:

```ts test
import { easy, Envelope, SecretKey, PublicKey } from 'quantum-safe-ts';

const keys = easy.generateEncryptionKeys();
const sealedByEasy = easy.encrypt(keys.publicKey, 'stored last year', { aad: 'doc-1' });

// Later: open the same bytes with the class API, keeping the secret key inside WebAssembly memory.
using secret = SecretKey.fromPem(keys.secretKey);
const plain = Envelope.open(sealedByEasy, secret, { expectedAad: new TextEncoder().encode('doc-1') });
if (new TextDecoder().decode(plain) !== 'stored last year') throw new Error('formats must be shared');
const pub = PublicKey.fromPem(keys.publicKey);
pub.free();
```

## Upgrade checklist

- [ ] Read the changelog entries between your version and the new one.
- [ ] Run your tests against the new version with `expectedContext` / `expectedAad` set everywhere.
- [ ] If you sign with the default format and unhedged, confirm every verifier is in the same hedging mode.
- [ ] If you mix with Python, confirm the Python version supports the formats you are about to emit (`-v2`, envelope v2, `StandardJwt`).
- [ ] Re-run the [audit tool](/tools/audit) on your code, and `cnsa2.enforce` if you have a policy.
- [ ] Keep the old version's package-lock entry until the new version has run in production for a full key-rotation cycle.
