# Independent review wanted

**No part of this library has had an independent cryptographic review.** It has had internal reviews by
the author, and quantum-safe-py (which shares its wire formats) found a High-severity signature flaw in
its own earlier releases through the same kind of internal audit. An internal audit is not a substitute
for another pair of eyes, so this page says exactly what we would like examined.

The primitives (ML-KEM, ML-DSA, SLH-DSA, X-Wing, X25519, Ed25519, AES-GCM, HKDF, SHA-2) come from
widely used Rust crates and are **not** what is being asked. The request is about the
*constructions and parsers built on top of them*, which are this project's own, and about the
WebAssembly boundary.

## What to review

Ordered by how much a mistake would matter. Paths are in `crates/quantum-safe-core/src/` unless noted.

| # | Construction | Where | The claim to check |
|---|---|---|---|
| 1 | **`-v2` signature format**, plain and hybrid | `sig/v2.rs` | Signing `M2 = u8(len(algo)) \|\| algo \|\| u8(len(ctx)) \|\| ctx \|\| message` with FIPS 204 native context `quantum-safe-sig-v2` (ML-DSA half) and `"quantum-safe-sig-v2" \|\| 0x00 \|\| M2` (Ed25519 or ECDSA P-256 half) gives domain separation between algorithms, contexts and formats; the `classical(64) \|\| ML-DSA` blob cannot be stripped or swapped; low-S-only raw ECDSA avoids malleability. Never use one key in both v1 and v2: the classical halves are not domain-separated between them. |
| 2 | **Streaming envelope (format v3)**, TypeScript only | `stream.rs` | The STREAM construction (7-byte random nonce prefix, 32-bit counter, last-chunk flag) with the key derived as `HKDF(shared secret, info = "qs-envelope-stream-v3" \|\| 0x00 \|\| H(header))` and each chunk's AAD `u32(len(header)) \|\| header \|\| u32(len(aad)) \|\| aad` prevents reordering, duplication, mid-stream deletion and truncation; the 7-byte random nonce prefix is sufficient given that each stream also has its own derived key. |
| 3 | **Hybrid KEM combiner** | `kem.rs`, `kdf.rs` | `HKDF-SHA256(ikm = ss_x \|\| ss_m, salt = ct_x \|\| ct_m, info = "quantum-safe hybrid KEM v1" \|\| 0x00 \|\| algorithm)` is a sound combiner (secure if either component is) and binding the ciphertexts through the salt is adequate. It is not X-Wing and not the TLS `X25519MLKEM768` construction; it has not been checked against NIST SP 800-227's key-combiner guidance. (`X-Wing` itself is also offered, using the `x-wing` crate.) |
| 4 | **Envelope v1 and v2** | `envelope.rs`, `kdf.rs` | Key and nonce derivation; AAD binding (v2: `2 \|\| len(algo) \|\| algo \|\| extra`); the version is bound to the algorithm on open; `expectedAad` checking is complete. |
| 5 | **Parsers for untrusted input** | `cbor_guard.rs`, `wire.rs`, `keys.rs`, `sig.rs` | Each parser accepts exactly one encoding of a value, and rejects duplicates, trailing bytes, indefinite lengths, tags, deep nesting and oversized containers *before* allocating; the Rust and Python parsers agree on every input (no parser differential). |
| 6 | **LMS / HSS verification** | `lms.rs` | RFC 8554 verification for the supported parameter sets, and rejection of unsupported ones. Verification only; there is no signing. |
| 7 | **The WebAssembly boundary** | `bindings/wasm/`, `packages/quantum-safe-ts/src/` | Secret key handling across the JS/WASM boundary and in `.free()`: a previous review found residual copies in WASM linear memory; what remains and what is documented. |
| 8 | **`StandardJwt` (RFC 9964)** | `packages/quantum-safe-ts/src/jwt.ts` | Strict verification: algorithm must match the key, `crit` refused, canonical base64url signature, claim checks. |

The Python implementation ([quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py)) shares
formats 1, 3, 4, 5 and 8; its own list is in that repository's `REVIEW_WANTED.md`. A finding in a shared
format affects both.

## What a useful review is

- A written report, even a short one, saying **what you looked at and what you did not**.
- Findings with a concrete failure scenario. A security finding should go through the private route in
  [SECURITY.md](SECURITY.md), not a public issue.
- "I read it and found nothing" is a valid and useful result, if the scope is stated.
- A formal analysis or proof sketch of items 1 to 4 is welcome but not required.

We will publish the report, or a summary you approve, and credit you if you want to be credited (in the
changelog, in any advisory, and in the acknowledgements of any paper).

## How to reach us

Email animesh15b@iimk.edu.in, or open an issue with the `review-wanted` label. Say which items you can
take. Partial reviews are fine.

Until at least items 1 to 4 have been reviewed, the documentation will keep saying so, and the roadmap
will not call any release 1.0.
