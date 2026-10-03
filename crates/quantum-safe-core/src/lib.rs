//! quantum-safe-core: pure-Rust hybrid post-quantum crypto primitives,
//! wire-compatible with the quantum-safe-py Envelope format.
//!
//! The wire formats it implements are specified by quantum-safe-py's own source; COMPATIBILITY.md in the repository root lists them.

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
