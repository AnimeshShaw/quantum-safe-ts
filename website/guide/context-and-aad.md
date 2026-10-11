# Context and AAD: binding a message to its purpose

A signature or an encrypted message is only as useful as what it is bound to. The same key may sign a login challenge, a payment instruction and
a software release; one recipient key may receive messages about many users. **Context** (signatures) and **AAD** (envelopes) are how a message
says what it is *for*, and how the verifier says what it *expects*. This page explains both, with the situations where they matter and exactly
what happens when you leave the argument out. quantum-safe-py behaves identically, so a service in one language can verify what the other signed.

## The one-line rule

Pass `expectedContext` to `verify()` and `expectedAad` to `Envelope.open()`. Both are optional and do something sensible when omitted, but
passing them is what makes the check mean something.

## What each one is

- **`context`** (signatures): up to 255 bytes chosen by the signer, covered by the signature and stored in the `SignedMessage`. The verifier
  states the context it expects. A signature made for `payments` does not verify as `refunds`, even with the same key and the same message.
- **`aad`** (envelopes): *additional authenticated data*, bytes that are not encrypted but are authenticated with the ciphertext. Changing
  them makes `open()` fail. They travel with the message and are usually an identifier: a user id, a record id, a tenant.

Neither is secret, and neither says *who* sent the message; sign the payload when the sender matters.

## Why it matters: four situations

- **One key, several purposes.** A service signs login tokens and payment instructions with the same key. Without a context, a token signature
  whose bytes happen to be a valid payment instruction is a valid payment signature. With `auth-v1` and `payments-v1` the two can never be confused.
- **Multi-tenant records.** A database holds one envelope per customer, all sealed to the same recipient key. If an attacker can copy customer A's
  envelope into customer B's row, B's service opens it. Sealing with `aad: tenant-A` and opening with `expectedAad: tenant-B` makes the copy fail.
- **Replay across environments.** A message signed for staging must not be accepted by production: put the environment in the context.
- **File signing.** Signing a release artifact with `release-v1` means the same signature cannot be presented as another kind of approval by the
  same key.

Choose contexts that are stable, specific and versioned (`myapp-docs-v1`), and keep them in one constants module so signer and verifier cannot drift.

## What happens if you leave it out

| Call | Message carries a context / AAD | Message carries none |
|---|---|---|
| `verify(sm, pk)` (no `expectedContext`) | **Rejected** with `VerificationError`, and a `QS_CONTEXT_OMITTED` warning says why | Accepted, silently |
| `verify(sm, pk, { expectedContext: x })` | Accepted only if equal to `x`; otherwise `VerificationError` | Rejected unless `x` is empty |
| `Envelope.open(sealed, sk)` (no `expectedAad`) | **Accepted**, with a `QS_AAD_OMITTED` warning: the AAD was not checked | Accepted, silently |
| `Envelope.open(sealed, sk, { expectedAad: x })` | Accepted only if equal to `x`; otherwise `DecryptionAuthenticationError` | Rejected unless `x` is empty |

In words: omitting `expectedContext` means "I expect no context", so a message made for a purpose is refused rather than silently accepted for
the wrong one. Omitting `expectedAad` means "I do not check the AAD", which is accepted but flagged because the opener did not verify what the
message was bound to. The thrown error stays opaque: it does not say whether the context or the signature was wrong. The warning is local,
for the developer, and never contains the context or AAD value.

## Working example

```ts test
import { HybridKEM, HybridSign, Envelope, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign();
using keys = signer.generateKeyPair();

const sm = signer.sign(utf8('transfer 5'), keys.secretKey, { context: utf8('payments-v1') });
signer.verify(sm, keys.publicKey, { expectedContext: utf8('payments-v1') });          // accepted
try {
  signer.verify(sm, keys.publicKey, { expectedContext: utf8('auth-v1') });            // another purpose
  throw new Error('should have been refused');
} catch (e) {
  if (!(e instanceof VerificationError)) throw e;
}

const kem = new HybridKEM();
using recipient = kem.generateKeyPair();
const sealed = Envelope.seal(utf8('card on file'), recipient.publicKey, { aad: utf8('tenant-A') });
const plain = Envelope.open(sealed, recipient.secretKey, { expectedAad: utf8('tenant-A') });
if (new TextDecoder().decode(plain) !== 'card on file') throw new Error('unexpected');
```

## Controlling the warnings

Each warning is emitted once per call site, through Node's `process.emitWarning` (type `QuantumSafeWarning`, with the code) or `console.warn`
where there is no `process`. Silence a code where omission is deliberate, or take over delivery:

```ts no-run
import { warnings } from 'quantum-safe-ts';

warnings.silence('QS_AAD_OMITTED');             // a deliberate "any AAD" opener
warnings.onWarning((w) => logger.warn(w.code, w.message));   // route to your logger; pass null to restore the default
```

In CI you can make omissions fail the build by routing warnings to a handler that throws.
