//! quantum-safe-core: pure-Rust hybrid post-quantum crypto primitives,
//! wire-compatible with the quantum-safe-py Envelope format.
//!
//! See docs/superpowers/specs/2026-09-29-quantum-safe-ts-v0.1-design.md
//! in this repository for the exact wire format this crate implements.

pub mod aead;
pub mod envelope;
pub mod kdf;
pub mod wire;
