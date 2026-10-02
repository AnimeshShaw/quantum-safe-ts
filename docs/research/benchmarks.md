# Benchmarks (indicative only)

`bench/bench.mjs` times the WASM core against `@noble/post-quantum` and Node's native WebCrypto ML-KEM. The committed
`results/bench_local.json` is **one run on a laptop** (Intel i9-14900HX hybrid cores, Windows 11, Node 24.18) that was not idle and was
not frequency-pinned. Results were noisy and bimodal (performance vs efficiency cores).

What the single run suggests, not proves: the WASM build is several times faster than the pure-JS implementation for ML-KEM-768
encapsulation and roughly 2x for ML-DSA-65 verification. Do not quote absolute numbers. A publishable comparison needs an idle, pinned
machine, repeated runs, medians with spreads, and the environment stated. Timing stability says nothing about constant-time behaviour;
JavaScript and WASM runtimes give no such guarantee.

Reproduce: `node bench/bench.mjs` (after `npm run build` in `packages/quantum-safe-ts`).
