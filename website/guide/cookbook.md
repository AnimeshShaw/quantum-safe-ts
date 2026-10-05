# Cookbook: real-world recipes

End-to-end solutions to problems people actually have. Each recipe says what problem it solves, shows complete code that runs in the test
suite, and ends with what to watch for. They use only the public API; the code uses Node.js built-ins where a file, a hash or a temporary
directory is needed, and works the same way in a browser with the equivalent Web APIs.

Contents: [1. Service-to-service messages](#_1-end-to-end-encrypted-messages-between-services) ·
[2. Signed releases](#_2-signed-software-releases) · [3. Signed audit log](#_3-a-tamper-evident-signed-audit-log) ·
[4. API tokens and key rotation](#_4-jwts-for-an-api-with-rotating-keys) · [5. Row-bound field encryption](#_5-encrypt-database-fields-and-bind-them-to-their-row) ·
[6. Key rotation with the state store](#_6-rotate-keys-through-the-migration-state-machine) · [7. Talking to a Python service](#_7-exchange-data-with-a-python-service) ·
[Patterns to avoid](#patterns-to-avoid)

## 1. End-to-end encrypted messages between services

**Problem.** Service A sends a message to service B over a channel you do not fully trust (a queue, a shared bucket, a third-party relay).
B must be sure the message is from A and was not altered; only B may read it.

**Design.** Sign, then encrypt. A signs the payload with its signing key and a context that names the direction. Then A seals the signed
message to B's public encryption key, with an AAD that names the direction too. B opens it (stating the AAD it expects) and verifies the
signature against A's public key (stating the context it expects).

```ts test
import { Envelope, HybridKEM, HybridSign, SignedMessage, utf8 } from 'quantum-safe-ts';

// One-time setup. A knows B's *encryption* public key and holds its own *signing* key; B knows A's *signing* public key.
const kem = new HybridKEM();
const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using bEncryption = kem.generateKeyPair();     // B's key pair (B keeps the secret)
using aSigning = signer.generateKeyPair();     // A's key pair (A keeps the secret)

const CONTEXT = utf8('orders-v1:A->B');         // names the protocol, its version and the direction
const AAD = utf8('orders-v1:A->B');

// Service A: sign, then encrypt.
function send(payload: Uint8Array): Uint8Array {
  const signed = signer.sign(payload, aSigning.secretKey, { context: CONTEXT });
  return Envelope.seal(signed.toBytes(), bEncryption.publicKey, { aad: AAD }).toBytes();
}

// Service B: decrypt, then verify, stating what it expects at each step.
function receive(wire: Uint8Array): Uint8Array {
  const signedBytes = Envelope.open(wire, bEncryption.secretKey, { expectedAad: AAD });
  const signed = SignedMessage.fromBytes(signedBytes);
  signer.verify(signed, aSigning.publicKey, { expectedContext: CONTEXT });
  return signed.message;
}

const wire = send(utf8('{"order":4711,"status":"shipped"}'));
if (new TextDecoder().decode(receive(wire)) !== '{"order":4711,"status":"shipped"}') throw new Error('round trip failed');

// Anyone holding B's public key can send B a validly encrypted message, but not one that verifies as A's:
const forgery = Envelope.seal(utf8('{"order":4711,"status":"refunded"}'), bEncryption.publicKey, { aad: AAD }).toBytes();
let refused = false;
try { receive(forgery); } catch { refused = true; }
if (!refused) throw new Error('an unsigned message must be refused');
```

**Watch for.** Encrypt-then-sign would let anyone strip A's signature and substitute theirs; sign-then-encrypt hides who signed from outsiders.
Replays are still possible: put a message id and a timestamp inside the payload and have B reject ones it has seen. Rotate keys with recipe 6.

## 2. Signed software releases

**Problem.** Users download an artifact and must be able to tell it is yours and unmodified, even if the download server is compromised.

**Design.** Sign a small manifest (name, version, digest of the artifact), not the artifact. Publish the manifest and its signature beside the
artifact and your public key where users already trust it (your site, your repository, a pinned fingerprint in your docs).

```ts test
import { createHash } from 'node:crypto';
import { HybridSign, SignedMessage, VerificationError, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using releaseKey = signer.generateKeyPair();
const CONTEXT = utf8('myapp-release-v1');

// Release job.
const artifact = utf8('pretend this is the 40 MB installer');
const manifest = JSON.stringify({ name: 'myapp', version: '1.2.3', sha256: createHash('sha256').update(artifact).digest('hex') });
const signedManifest = signer.sign(utf8(manifest), releaseKey.secretKey, { context: CONTEXT }).toBytes(); // publish with the artifact
const publishedFingerprint = releaseKey.publicKey.fingerprint();                                         // publish where users trust it

// User side.
function verifyDownload(download: Uint8Array, signedBytes: Uint8Array, publicKey: Parameters<typeof signer.verify>[1]): string {
  if (publicKey.fingerprint() !== publishedFingerprint) throw new Error('unexpected signing key');
  const signed = SignedMessage.fromBytes(signedBytes);
  signer.verify(signed, publicKey, { expectedContext: CONTEXT });
  const m = JSON.parse(new TextDecoder().decode(signed.message)) as { sha256: string; version: string };
  if (createHash('sha256').update(download).digest('hex') !== m.sha256) throw new Error('the download does not match the signed digest');
  return m.version;
}

if (verifyDownload(artifact, signedManifest, releaseKey.publicKey) !== '1.2.3') throw new Error('unexpected version');

let caught = 0;
try { verifyDownload(utf8('tampered installer'), signedManifest, releaseKey.publicKey); } catch { caught++; }       // altered artifact
try {
  const forged = SignedMessage.fromBytes(signedManifest);
  const other = SignedMessage.fromParts({ ...forged, message: utf8(manifest.replace('1.2.3', '9.9.9')) }).toBytes();
  verifyDownload(artifact, other, releaseKey.publicKey);                                                           // altered manifest
} catch (e) { if (e instanceof VerificationError) caught++; else throw e; }
if (caught !== 2) throw new Error('both attacks must be caught');
```

**Watch for.** Users must obtain the public key through a channel the attacker cannot also control: pin the fingerprint in your docs, your
package metadata or a second site. Include a version and an expiry in the manifest so an old signed release cannot be replayed as the latest.
For firmware that CNSA 2.0 covers you need LMS/XMSS signing, which this library does not provide.

## 3. A tamper-evident signed audit log

**Problem.** You keep a log that auditors will trust: entries must not be altered, removed or reordered without detection.

**Design.** Each entry holds a sequence number, the hash of the previous entry, and the event. Each entry is signed. Deleting or reordering breaks the
hash chain; editing breaks the signature.

```ts test
import { createHash } from 'node:crypto';
import { HybridSign, SignedMessage, utf8 } from 'quantum-safe-ts';

const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using logKey = signer.generateKeyPair();
const CONTEXT = utf8('auditlog-v1');
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

interface Entry { seq: number; prev: string; event: string }

function append(log: Uint8Array[], event: string): void {
  const prev = log.length === 0 ? '0'.repeat(64) : sha(log[log.length - 1]!);
  const entry: Entry = { seq: log.length, prev, event };
  log.push(signer.sign(utf8(JSON.stringify(entry)), logKey.secretKey, { context: CONTEXT }).toBytes());
}

function verifyLog(log: Uint8Array[], publicKey = logKey.publicKey): number {
  let prev = '0'.repeat(64);
  log.forEach((bytes, i) => {
    const signed = SignedMessage.fromBytes(bytes);
    signer.verify(signed, publicKey, { expectedContext: CONTEXT });             // altered entry -> throws
    const entry = JSON.parse(new TextDecoder().decode(signed.message)) as Entry;
    if (entry.seq !== i || entry.prev !== prev) throw new Error(`chain broken at ${i}`); // removed or reordered -> throws
    prev = sha(bytes);
  });
  return log.length;
}

const log: Uint8Array[] = [];
append(log, 'user alice logged in');
append(log, 'alice exported the customer list');
append(log, 'alice logged out');
if (verifyLog(log) !== 3) throw new Error('honest log must verify');

const missing = [log[0]!, log[2]!];                       // the incriminating entry is deleted
const swapped = [log[0]!, log[2]!, log[1]!];              // entries reordered
let caught = 0;
for (const bad of [missing, swapped]) { try { verifyLog(bad); } catch { caught++; } }
if (caught !== 2) throw new Error('deletion and reordering must be detected');
```

**Watch for.** Truncating the *end* of the log cannot be detected from the log alone: publish the latest entry hash somewhere the log's
operator cannot rewrite (a transparency log, another system, a signed daily checkpoint). Keep the signing key off the machines that write the
log if you can.

## 4. JWTs for an API, with rotating keys

**Problem.** Your auth service issues access tokens; many APIs verify them; you must be able to rotate the signing key without an outage.

**Design.** Use `StandardJwt` so any gateway can verify (RFC 9964). Give each key a `kid`; publish the public keys as a key set; the verifier
picks the key named in the token header. During rotation both the old and the new public key are in the set.

```ts test
import { StandardJwt, fromBase64Url } from 'quantum-safe-ts';
import type { AkpJwk } from 'quantum-safe-ts';

// Issuer: two generations of key.
const oldKey = StandardJwt.generateKeyPair('ML-DSA-65', { kid: '2026-09' });
const newKey = StandardJwt.generateKeyPair('ML-DSA-65', { kid: '2026-10' });
const jwks = { keys: [oldKey.publicJwk, newKey.publicJwk] };           // what you serve at /.well-known/jwks.json (public keys only)

const issue = (privateJwk: AkpJwk) =>
  StandardJwt.sign({ sub: 'user-1', aud: 'api', iss: 'https://auth.example' }, privateJwk, { expiresIn: 600 });

// API: pick the key by `kid`, then verify.
function verifyToken(token: string) {
  const header = JSON.parse(new TextDecoder().decode(fromBase64Url(token.split('.')[0]!))) as { kid?: string };
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown key id');
  return StandardJwt.verify(token, jwk, { audience: 'api', issuer: 'https://auth.example', requireExp: true });
}

if (verifyToken(issue(oldKey.privateJwk)).sub !== 'user-1') throw new Error('token from the old key must verify during rotation');
if (verifyToken(issue(newKey.privateJwk)).sub !== 'user-1') throw new Error('token from the new key must verify');

// After rotation completes, remove the old key from the set: its tokens stop verifying.
jwks.keys.splice(0, 1);
let retired = false;
try { verifyToken(issue(oldKey.privateJwk)); } catch (e) { retired = e instanceof Error && e.message === 'unknown key id'; }
if (!retired) throw new Error('a retired key must not verify');
```

**Watch for.** Keep token lifetimes short (minutes), so retiring a key takes effect quickly. Never serve a private JWK. Pin the issuer and
audience in every verifier. If every verifier is yours and you want hybrid signatures, use `JWTSigner` instead ([JWT](/guide/jwt)), accepting that
other libraries cannot verify them.

## 5. Encrypt database fields and bind them to their row

**Problem.** You store sensitive columns encrypted. An attacker (or a bug) with write access to the database must not be able to move a
ciphertext from one row, column or tenant to another.

**Design.** Seal each field to a public key, with an AAD that names its location (`table:column:row-id:tenant`). Open with the AAD you
derive from the row you are reading, never from stored data.

```ts test
import { DecryptionAuthenticationError, Envelope, HybridKEM, utf8 } from 'quantum-safe-ts';

using dataKey = new HybridKEM().generateKeyPair(); // in production the secret half lives in your KMS / secrets manager

const where = (table: string, column: string, id: number, tenant: string) => utf8(`${tenant}/${table}/${column}/${id}`);

const rows = new Map<number, { email: Uint8Array }>();
rows.set(17, { email: Envelope.seal(utf8('alice@example.org'), dataKey.publicKey, { aad: where('users', 'email', 17, 'acme') }).toBytes() });
rows.set(18, { email: Envelope.seal(utf8('bob@example.org'), dataKey.publicKey, { aad: where('users', 'email', 18, 'acme') }).toBytes() });

function readEmail(id: number, tenant: string): string {
  const row = rows.get(id)!;
  return new TextDecoder().decode(Envelope.open(row.email, dataKey.secretKey, { expectedAad: where('users', 'email', id, tenant) }));
}
if (readEmail(17, 'acme') !== 'alice@example.org') throw new Error('round trip failed');

// An attacker copies row 17's ciphertext into row 18, or reads it as another tenant's:
rows.get(18)!.email = rows.get(17)!.email;
let refused = 0;
for (const attempt of [() => readEmail(18, 'acme'), () => readEmail(17, 'globex')]) {
  try { attempt(); } catch (e) { if (e instanceof DecryptionAuthenticationError) refused++; else throw e; }
}
if (refused !== 2) throw new Error('moved ciphertexts must not open');
```

**Watch for.** Searching on encrypted columns is not possible with this scheme (store a keyed hash if you need equality lookups). Fields of
equal plaintext produce different ciphertexts. If the secret key is lost the data is lost: back it up. Encrypting millions of fields with one
public key is fine: every seal derives a fresh one-time key.

## 6. Rotate keys through the migration state machine

**Problem.** You are moving a fleet of classical keys to hybrid, then to post-quantum only, and need to know which keys are where, with an audit
trail, even when several workers act at once.

**Design.** Record each key's state in a `MigrationStateManager`. A transition names the state it expects the key to be in; a competing
writer gets an error instead of a silent overwrite. Use a store with an atomic `compareAndSet`: here the file store (one host, Node.js).

```ts test
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MigrationStateManager } from 'quantum-safe-ts';
import { FileMigrationStore } from 'quantum-safe-ts/file-store';

const dir = mkdtempSync(join(tmpdir(), 'qs-migration-'));
try {
  const manager = new MigrationStateManager(new FileMigrationStore(dir));
  if (!manager.crossProcessSafe) throw new Error('the file store supports compare-and-set');

  await manager.transition({ keyId: 'billing-signing', fromState: 'classical_only', toState: 'hybrid_transition', algorithm: 'Ed25519+ML-DSA-65', actor: 'rotation-job', reason: 'start of migration' });

  // Two workers race to advance the same key; both believe it is in hybrid_transition. Exactly one wins.
  const outcomes = await Promise.allSettled([
    manager.transition({ keyId: 'billing-signing', fromState: 'hybrid_transition', toState: 'pqc_preferred', algorithm: 'Ed25519+ML-DSA-65', actor: 'worker-1' }),
    manager.transition({ keyId: 'billing-signing', fromState: 'hybrid_transition', toState: 'pqc_preferred', algorithm: 'Ed25519+ML-DSA-65', actor: 'worker-2' }),
  ]);
  const won = outcomes.filter((o) => o.status === 'fulfilled').length;
  if (won !== 1) throw new Error(`exactly one writer must win, got ${won}`);

  const history = await manager.getHistory('billing-signing');
  if (history.length !== 2 || (await manager.getCurrentState('billing-signing')) !== 'pqc_preferred') throw new Error('unexpected history');
  const progress = await manager.migrationProgress();
  if (progress.pqc_preferred !== 1) throw new Error('unexpected progress');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
```

The key material itself moves with `Upgrader` (see [Migration](/guide/migration)). **Watch for:** the file store is for one host only (no NFS/SMB);
for several machines supply a store with an atomic `compareAndSet` (Redis, Postgres, DynamoDB). Going backwards needs `allowBackward: true`
and is recorded.

## 7. Exchange data with a Python service

**Problem.** A Python service using quantum-safe-py (0.3.2 or later for the `-v2` and envelope-v2 formats; 0.3.0 for the originals) and a
TypeScript service must exchange keys, ciphertexts and signatures.

**Design.** Exchange keys as PEM and everything else as the library's own bytes. Both libraries state their expectations on the receiving
side: signature context, AAD and (v1 only) hedging mode. The TypeScript side first:

```ts test
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Envelope, HybridKEM, HybridSign, utf8 } from 'quantum-safe-ts';

const dir = mkdtempSync(join(tmpdir(), 'qs-interop-'));

// TypeScript signs with the clean (-v2) format and publishes its public key as PEM.
const signer = new HybridSign('Ed25519+ML-DSA-65-v2');
using signing = signer.generateKeyPair();
const signed = signer.sign(utf8('hello from TypeScript'), signing.secretKey, { context: utf8('interop-v1') });
writeFileSync(join(dir, 'ts-signing-public.pem'), signing.publicKey.toPem());
writeFileSync(join(dir, 'ts-signed.bin'), signed.toBytes());

// TypeScript encrypts to a Python-held key: Python would have published its public key as PEM; here we make one to show the shape.
using pyStyleKey = new HybridKEM().generateKeyPair();
writeFileSync(join(dir, 'py-encryption-public.pem'), pyStyleKey.publicKey.toPem());
writeFileSync(join(dir, 'py-encryption-secret.pem'), pyStyleKey.secretKey.toPem()); // in reality this never leaves Python
writeFileSync(join(dir, 'ts-sealed.bin'), Envelope.seal(utf8('secret for Python'), pyStyleKey.publicKey, { aad: utf8('interop-v1') }).toBytes());
console.log('files for the Python side are in', dir);
```

And the Python side, which reads those files (this block is Python, not run by the TypeScript test suite; it was run against the files above
with quantum-safe-py 0.3.2):

```python
from quantum_safe import HybridSign
from quantum_safe.types import PublicKey, SecretKey
from quantum_safe.types.signatures import SignedMessage
from quantum_safe.protocols.envelope import Envelope, SealedMessage

dir = "..."  # the directory printed above

# Verify the TypeScript signature, stating the context we expect.
pub = PublicKey.from_pem(open(f"{dir}/ts-signing-public.pem").read())
sm = SignedMessage.from_cbor(open(f"{dir}/ts-signed.bin", "rb").read())
HybridSign("Ed25519", "ML-DSA-65-v2").verify(sm, pub, context=b"interop-v1")
print(sm.message)  # b'hello from TypeScript'

# Open the TypeScript envelope, stating the AAD we expect.
sk = SecretKey.from_pem(open(f"{dir}/py-encryption-secret.pem").read())
sealed = SealedMessage.from_bytes(open(f"{dir}/ts-sealed.bin", "rb").read())
print(Envelope.open(sealed, sk, expected_aad=b"interop-v1"))  # b'secret for Python'
```

**Watch for.** `context`, `expected_aad` and `expectedContext` / `expectedAad` must be the same on both sides, byte for byte. Default-format
(v1) signatures made with `hedged=False` verify only on a verifier in the same mode. The full table of what crosses and what does not is in
[Interop with quantum-safe-py](/guide/python-interop).

## Patterns to avoid

| Pattern | Why | Instead |
|---|---|---|
| Sign without a context | The signature is valid for any purpose of that key | Context per purpose, verified with `expectedContext` |
| `Envelope.open` without `expectedAad` where it matters | Any AAD opens | Pass `expectedAad` |
| Encrypt-then-sign | Anyone can strip the signature and substitute theirs | Sign-then-encrypt (recipe 1) |
| Using `signerFingerprint` / `signedAt` as proof | They are not signed | Put such facts in the signed message |
| Keeping secret keys in the easy layer's strings for long | They cannot be wiped | Class API with `using` |
| One key for the v1 and the `-v2` signature formats | Classical halves are not domain-separated | Separate keys |
| Hand-rolled use of a KEM's raw shared secret | Easy to misuse | `Envelope`, or `deriveKey` with a distinct `info` |
| Trusting a token's claims before verifying it | Anyone can write claims | Verify first |
| Sharing one `FileMigrationStore` directory across machines | Network filesystems break its locking | A store with atomic `compareAndSet` |
