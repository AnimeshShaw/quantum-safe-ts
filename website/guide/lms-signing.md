# LMS signing (Node.js)

LMS (RFC 8554, with HSS in NIST SP 800-208) is the stateful hash-based signature scheme CNSA 2.0 names for software and firmware signing.
`Lms.verify` checks LMS and HSS signatures in every runtime. `LmsSigner` signs, in **Node.js only**, with write-ahead durable state: the
index of the one-time key is made durable *before* a signature exists, so a crash can waste an index and can never reuse one.

```ts test
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Lms } from 'quantum-safe-ts';
import { LmsSigner } from 'quantum-safe-ts/lms-signer';

// Once, at key-ceremony time. The directory holds the key; keep it on a local disk and back it up only as described below.
// The seed is encrypted at rest: say how (a passphrase here; a 32-byte key from your KMS is the other choice).
const directory = join(mkdtempSync(join(tmpdir(), 'lms-')), 'release-key');
const signer = LmsSigner.create({
  directory,
  height: 5,
  winternitz: 8,
  protection: { passphrase: 'a long passphrase from your secrets manager', scryptLog2N: 14 },
});
const publicKey = signer.publicKey; // 60 bytes: publish it (it is not secret)

// Every release.
const firmware = new TextEncoder().encode('firmware image bytes');
const signature = signer.sign(firmware);

// Anywhere, in any runtime that runs quantum-safe-ts.
Lms.verify(publicKey, firmware, signature);
if (signer.remaining !== 31) throw new Error('one signature should have been consumed');
```

Later, open the same key by directory and give it what it was sealed under:
`LmsSigner.open(directory, { passphrase })` or `LmsSigner.open(directory, { key })`. Several processes on one host may sign with the same
directory; each takes the key's lock to reserve an index, and they never receive the same one.

## Protecting the key

The signing seed is the secret: anyone who has it can make signatures that verify under your public key. `LmsSigner.create` therefore asks you
to say how the seed is stored (there is no default):

| `protection` | The seed on disk | Use it when |
|---|---|---|
| `{ passphrase }` | Encrypted with AES-256-GCM under a key derived from the passphrase with scrypt (default cost 2^17, 128 MiB; salt and cost are stored; `scryptLog2N` lowers it for tests, from 14 to 18) | A person or a secrets manager supplies the passphrase at signing time |
| `{ key }` | Encrypted with AES-256-GCM under the 32-byte key you supply | The key comes from a KMS, an HSM-wrapped secret, or the environment of a build runner |
| `{ unprotected: true }` | In clear | The directory itself is protected (an encrypted volume, an ephemeral runner) |

What this gives you, and what it does not:

- A copy of the key directory taken **without** the passphrase or key (a backup, a leaked volume snapshot, a stray `cp -r`) cannot sign.
- The sealed seed is bound to the key's public parameters (an authenticated header), so it cannot be moved into another key file.
- The counter carries an HMAC keyed from the seed. A state file edited without the key is refused, by a running signer and on open. This
  catches accidents and tampering; it cannot catch **replacing the state file with an older valid copy** of itself, because an older copy
  was valid when it was written. Do not restore the directory from a backup while the key is in use.
- It does not protect a process that is running with the passphrase or key: that process can sign. Keep the signing host small, and keep the
  passphrase or key out of the directory and out of source control.
- For SP 800-208, which expects LMS key generation and signing inside a validated module, use a hardware module for the signing key.

## What it does, in order

1. Takes the key's lock file (exclusive create).
2. Reads the state, checks that one-time keys remain, and writes the **next** index to a temporary file, `fsync`s it, renames it over the state
   file and `fsync`s the directory.
3. Releases the lock. Only now does it compute the signature with the index it reserved.
4. Checks the signature against the tree's root before returning it.

Any problem with the state makes it **refuse** rather than guess: a missing or unreadable state file, a tree file that does not match the key, a
counter out of range, a state file that belongs to a different key, a lock held by someone else, an exhausted key. The errors are
`SigningError`, with a message that says which.

## Parameters

| Option | Values | Default | Notes |
|---|---|---|---|
| `height` | 5, 10, 15, 20 | 10 | The key makes at most `2^height` signatures (32; 1,024; 32,768; 1,048,576). |
| `winternitz` | 1, 2, 4, 8 | 8 | Larger is slower to generate and gives a shorter signature. |

The scheme is `LMS_SHA256_M32_H{h}` with `LMOTS_SHA256_N32_W{w}`: one LMS tree, which is an HSS key with one level. Multi-level HSS signing,
height 25, the 192-bit and SHAKE parameter sets, and XMSS are not provided. CNSA 2.0 asks for LMS or XMSS, and single-tree LMS covers it.
Verification of HSS keys with several levels is provided (`Lms.verify`).

Key generation computes every leaf of the tree and takes time that grows with it: seconds for height 10, minutes to hours for 15 and 20. Run it
in a worker thread or a separate process, once. Signing is quick (milliseconds) because the tree is stored.

## Keeping the state safe

- **Never restore the key directory from a backup while the key is in use.** A restored state file rewinds the counter, and the next signatures
  reuse indices that were already used. Back up the public key and the signed artefacts; to move a key, move the directory and stop using the old
  copy.
- Keep the directory on a **local** filesystem. Network filesystems may not give the atomic rename this relies on.
- The directory is created with mode 0700 and the files with 0600. With `{ unprotected: true }` the seed is in `key.json` and anyone who can
  read it can sign; with `{ passphrase }` or `{ key }` it is encrypted there.
- If a signer stops while holding the lock, the next signer refuses with a message that names `key.json.lock`. Remove it only when you are sure
  no signer is running.
- The key is generated here from the operating system's random source, for the cases it fits (build pipelines, internal tools).

## Other runtimes

`quantum-safe-ts/lms-signer` imports Node.js modules and refuses to run in browsers and Workers, because durable state cannot be guaranteed
there. Browsers and Workers verify with `Lms.verify`, which is in the main entry.

## Interop

Signatures made here verify with quantum-safe-py's LMS verification (pyhsslms), for every Winternitz parameter and for heights 5 and 10; the
vectors are `tests/vectors/ts_lms_signer_vectors.json`, regenerated by `scripts/gen_lms_signer_vectors.mjs`. quantum-safe-py writes the bare
LMS form (no HSS count); the HSS form here is the bare form with a 4-byte level count in front, for both the key and the signature.
