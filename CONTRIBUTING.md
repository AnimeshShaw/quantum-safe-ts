# Contributing to quantum-safe-ts

Thank you for helping. This is a cryptography library, so the bar for changes is deliberately conservative. This page tells you what we
need, what we cannot accept, and how to get a change merged quickly.

## Ground rules

1. **Wire formats never change.** Anything that changes the bytes an existing algorithm identifier produces or accepts will be
   declined. New behaviour gets a new, explicit identifier. See [COMPATIBILITY.md](COMPATIBILITY.md).
2. **Parity is proven by fixtures.** A feature that claims compatibility with
   [quantum-safe-py](https://github.com/AnimeshShaw/quantum-safe-py) needs a fixture generated from the real Python library, consumed by a test
   that runs against the **built WASM artifact**, not only native Rust.
3. **Parsers fail closed.** Any function that parses bytes or text from a caller returns a typed error; it never panics or throws a raw
   `TypeError`. New parsers need a fuzz target or a property test.
4. **No overclaiming.** Say what is tested and what is not.
5. **No secrets in logs, errors or hints.**
6. **Pure Rust, no C dependencies**, so `npm install` never needs a toolchain.

## Setting up

Requirements: Rust (stable, with `rustfmt` and `clippy`), the `wasm32-unknown-unknown` target, [`wasm-pack`](https://rustwasm.github.io/wasm-pack/),
Node.js 20 or newer (24 recommended), and Python 3.11+ with `quantum-safe-py[liboqs]==0.3.0` only if you run the parity scripts.

```bash
git clone https://github.com/AnimeshShaw/quantum-safe-ts && cd quantum-safe-ts
cargo test --workspace                                   # Rust core and bindings (the ACVP vectors are opt-in, see below)
cd packages/quantum-safe-ts && npm ci && npm run build   # wasm-pack + tsup
npx vitest run                                           # the TypeScript test suite against the built WASM
```

Other checks that CI runs:

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown -p quantum-safe-wasm
(cd packages/quantum-safe-audit && npm ci && npm test) && (cd packages/quantum-safe-mcp && npm ci && npm test)
node tests/fixtures/run.mjs                              # packed tarball in real toolchains (slow; needs browsers for some)
python scripts/fetch_acvp.py && QS_REQUIRE_ACVP=1 cargo test --release -p quantum-safe-core --test acvp   # NIST ACVP, several minutes
```

## Making a change

- Keep one logical change per pull request, with tests first or alongside.
- Update `CHANGELOG.md` (Unreleased) and `COMPATIBILITY.md` if a status changes.
- Run the checks above that touch what you changed. CI runs all of them.
- By submitting a contribution you agree it is licensed under the Apache License 2.0 (the project license). There is no separate CLA.

## What helps most right now

- False-positive and false-negative reports for `quantum-safe-audit` (a minimal snippet is ideal).
- Reports from runtimes and bundlers we do not list yet, with a minimal reproduction.
- Cross-implementation test vectors, especially from other languages.

## Reporting security problems

Not in a public issue. Use GitHub's "Report a vulnerability" as described in [SECURITY.md](SECURITY.md).
