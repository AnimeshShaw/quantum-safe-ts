# Security model

The authoritative policy, including how to report a vulnerability privately, is
[SECURITY.md](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/SECURITY.md). This page explains the model behind it: what is protected,
from whom, what is not, and what to do about the gaps.

## Assets and adversaries

**What is being protected:** secret keys and shared secrets; plaintext; signing keys; the integrity of verification verdicts; the integrity of
the published packages.

| Adversary | Capability | What the library does about it |
|---|---|---|
| Harvest-now-decrypt-later | Records ciphertext today, breaks classical public-key crypto later with a quantum computer | Hybrid and pure ML-KEM envelopes; the [audit tool](/tools/audit) finds classical crypto to migrate |
| A network attacker or malicious input supplier | Controls ciphertexts, sealed messages, keys, signatures, tokens, CBOR, PEM and JWK input | Every parser fails closed with a typed error. Mutation tests, property tests and cargo-fuzz targets cover them. Keys, signed messages and sealed messages are capped at 10 MB and shape-checked (flat, definite-length, no duplicate keys, no trailing bytes, shortest-form integers) before decoding. Type-confusion and version-rollback rejection. The AEAD authenticates version, algorithm and AAD. JWT algorithm is pinned to the key; no `alg: none`. |
| Curious code in the same page or process | Reads the JavaScript heap, logs objects | Secrets are held in WebAssembly memory behind opaque objects. `toString`, `toJSON` and `util.inspect` never reveal them. Errors and hints never contain key material. |
| A hostile repository scanned by the audit tool | Embeds prompt-injection text or malformed files | Reports contain only short identifier-like details. The MCP server is read-only, offline and path-confined. |
| A supply-chain attacker | Compromises a dependency or the build | Pinned `Cargo.lock`, `cargo-deny`, `npm audit` in CI, no install scripts in the shipped packages, a provenance-capable release workflow, and a reproducible WebAssembly build check. |

## What it does not defend against

- **Side channels.** See [below](#timing-and-side-channels).
- **Memory disclosure** of the JavaScript heap, swap, core dumps, browser extensions with page access, or a compromised runtime.
- **Fault attacks.** Hedged signing mitigates some lattice fault attacks; it is not a general defence.
- **Weak passwords.** Argon2id slows guessing; it cannot rescue a guessable password.
- **Key management.** Storage, rotation, backup and access control are your responsibility ([Keys](/guide/keys)).
- **Sender authentication by encryption.** Envelopes and streams are anonymous: anyone with your public key can encrypt to you. Sign what must be attributable.
- **Replay.** A valid signed message or token is valid every time you see it. Put a nonce, id or expiry inside what is signed.

## Constructions to understand

Three properties follow from the formats and are worth knowing, because they explain the API.

1. **Verifiers state what they expect.** A signature context and an encryption AAD are only protection if the *verifier* supplies them. The
   library requires `expectedContext` (default: empty) and offers `expectedAad`; it never reads them from the message. See
   [Concepts](/guide/concepts#context-and-aad-the-verifier-says-what-it-expects).
2. **The default signature format (v1) has an unsigned prefix length.** quantum-safe-py's construction signs `len(ctx) ‖ ctx ‖ prefix ‖ message`
   and stores the prefix length *outside* the signed bytes. A verifier that accepted any length would let anyone move bytes between prefix and
   message and forge a signature on a suffix of a signed message. The TypeScript verifiers pin the length to their hedging mode (32 hedged, 0
   unhedged), which closes it without changing a byte on the wire. **Never use one key in both hedged and unhedged mode.** The `-v2` format
   has no prefix and no such caveat: [Signatures](/guide/signatures#format-v2-v2). (The same issue existed in quantum-safe-py 0.1.0 to 0.3.0 and was fixed in 0.3.1,
   [GHSA-wqv6-gm9x-69x8](https://github.com/AnimeshShaw/quantum-safe-py/security/advisories/GHSA-wqv6-gm9x-69x8). This library was never affected:
   every v1 verification path pins the prefix length before it checks the signature, and that pin was in the code before any release.)
3. **Hybrid halves.** In a default-format hybrid signature the classical and the post-quantum halves are independent signatures over the same bytes and
   neither commits to the other. Both must verify, so forging one half does not help; but halves from two signatures on the same message by the
   same key can be recombined (it changes the signature bytes, not the signed message). Do not use signature bytes as a unique identifier or a
   replay key. In `-v2` both halves sign the same bytes, which include the algorithm and the context.

## Timing and side channels

JavaScript and WebAssembly runtimes give **no constant-time guarantee**, and this library does not claim one. Concretely:

- The WebAssembly is compiled from Rust crates written to avoid secret-dependent branches, but the compiler, the WebAssembly engine's
  just-in-time compilation, caches and the operating system can all introduce secret-dependent timing, and none of that is under this
  library's control.
- ML-DSA signing time varies with the number of rejection-sampling iterations. That variation is by design and not secret-dependent, but it
  makes timing measurements noisy.
- Browsers coarsen timers and add their own noise; that makes attacks harder but is not a defence.
- The maintainer runs a timing-leakage *screen* (a dudect-style fixed-versus-random test with null controls) before releases. A screen can fail
  to detect a leak; a pass is **not a proof**.

**What to do:** if a local timing attacker (code on the same machine or in the same process) is in your threat model, do not use a
JavaScript or WebAssembly implementation for secret operations; use a native implementation in a hardened environment. For the usual web
and server threat models (a remote network attacker who sees ciphertexts and response times), this is the normal position of every
JavaScript cryptography library, but it is still an unreviewed one here.

## Memory

WebAssembly memory holds secret keys and shared secrets, and `.free()` (or leaving a `using` scope) wipes the owned buffers. That is not a
promise that no copy remains: the buffers used to pass arguments into WebAssembly and intermediate values created while parsing or serialising
a key are not all wiped, and a review found residual copies in WebAssembly linear memory after `.free()`. Anything you copy out into the
JavaScript heap (`exportBytes()`, `toPem()` of a secret, plaintext) is outside this library's control; call `wipe()` on those copies. Treat memory as not
reliably scrubbed.

## Evidence in the repository

| Evidence | Where |
|---|---|
| 1,317 NIST ACVP cases (ML-KEM, ML-DSA, SLH-DSA) | `crates/quantum-safe-core/tests/acvp.rs`; CI job "NIST ACVP" |
| Byte parity with the real quantum-safe-py, both directions | `scripts/generate_suite_vectors.py`, `scripts/verify_ts_vectors.py`; CI job "Parity" |
| Differential tests against `@noble/post-quantum` and Node WebCrypto | `packages/quantum-safe-ts/test/differential.test.ts` |
| cargo-fuzz targets for the main binary parsers (envelope, keys, signed message, ciphertexts, secret keys, LMS, streams); property and mutation tests for the rest | `fuzz/`, `test/`; CI job "cargo-fuzz" |
| Packed-tarball fixtures in 12 real toolchains | `tests/fixtures/` |
| Reproducible-build check | `scripts/repro-check.mjs` |

## Security history

| Advisory | Affected | Fixed in | Summary |
|---|---|---|---|
| None for quantum-safe-ts | | | |

The signature prefix forgery in quantum-safe-py 0.1.0 to 0.3.0
([GHSA-wqv6-gm9x-69x8](https://github.com/AnimeshShaw/quantum-safe-py/security/advisories/GHSA-wqv6-gm9x-69x8), High, fixed in quantum-safe-py 0.3.1) does
not affect this library. Every public TypeScript verification path for the default signature format (`verify`, `verifyBytes`, and the JWT verifier that
calls it) pins the prefix length to the verifier's hedging mode before it checks the signature, and that check was in the code before any release. The
Rust core's own `verify` is permissive by design; use the core only through the TypeScript layer. If you run quantum-safe-py next to this library, use
quantum-safe-py 0.3.2 or later.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting: on the [repository](https://github.com/AnimeshShaw/quantum-safe-ts) choose **Security,
then Report a vulnerability** (a GitHub Security Advisory), or email **animesh15b [at] iimk.edu.in**. Include the affected version and package, a
minimal reproduction with no real secrets, your runtime and operating system, and the impact.

You can expect an acknowledgement within **48 hours** and a full response within **7 days**. If the report is confirmed, a patch is prepared and released
before public disclosure, and a GitHub Security Advisory (with a CVE where one applies) is published with the fixed release. Please allow 90 days before
publishing details; reporters who want credit get it.

In scope: the Rust core, the WebAssembly bindings, the TypeScript package, the audit tool and MCP server, and the build and release workflows. Out of scope:
vulnerabilities in third-party dependencies that are not reachable through this library (report those upstream).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (the latest release) | Yes |
| Anything older than the latest release | **No. Upgrade.** |

Only the latest release receives security
fixes; the same applies to `quantum-safe-audit`, `quantum-safe-mcp` and the `pqc-audit` and `pqc-mcp` aliases. Pin an exact version in production and
read the [changelog](https://github.com/AnimeshShaw/quantum-safe-ts/blob/master/CHANGELOG.md) before upgrading ([Upgrading](/guide/upgrading)).
