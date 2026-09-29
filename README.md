# quantum-safe-core

Pure-Rust hybrid post-quantum crypto core (X25519+ML-KEM-768, AES-256-GCM
envelope), wire-compatible with [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py).
Part of the [quantum-safe-ts](https://github.com/AnimeshShaw/quantum-safe-ts) project.

**Status:** pre-1.0, experimental. Conformance to the exact quantum-safe-py
wire format is tested; no independent security audit has been performed yet.

See `docs/superpowers/specs/` for the design and `docs/superpowers/plans/`
for the implementation plan this crate was built from.
