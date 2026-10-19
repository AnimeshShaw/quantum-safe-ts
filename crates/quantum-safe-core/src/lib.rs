//! quantum-safe-core: pure-Rust hybrid post-quantum crypto primitives,
//! wire-compatible with the quantum-safe-py Envelope format.
//!
//! The wire formats it implements are specified by quantum-safe-py's own source; COMPATIBILITY.md in the repository root lists them.

//!
//! Modules:
//!
//! - [`aead`]: AES-256-GCM encryption and decryption.
//! - [`cbor_guard`]: structural check of untrusted CBOR before it is decoded.
//! - [`envelope`]: the sealed-message envelope (seal and open), versions 1 and 2.
//! - [`kdf`]: HKDF-SHA256/SHA384 key derivation, the hybrid KEM combiner and Argon2id.
//! - [`kem`]: key encapsulation for the ML-KEM, hybrid and X-Wing suites.
//! - [`keys`]: key serialisation (CBOR, PEM, JWK, fingerprints, key-pair bundles).
//! - [`lms`]: LMS/HSS hash-based signature verification.
//! - [`sig`]: ML-DSA, SLH-DSA and hybrid signatures, the `-v2` format and standards-mode ML-DSA.
//! - [`stream`]: the chunked streaming envelope (format v3).
//! - [`suite`]: the KEM suite registry (names, sizes, NIST levels).
//! - [`wire`]: length-prefixed packing of two byte strings.

pub mod aead;
pub mod cbor_guard;
pub mod envelope;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod lms;
pub mod sig;
pub mod stream;
pub mod suite;
pub mod wire;
