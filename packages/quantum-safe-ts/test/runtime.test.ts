/** Initialisation behaviour. Each test gets a fresh copy of the runtime module (its state is module-level). */
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const wasmBytes = readFileSync(new URL('../wasm/quantum_safe_wasm_bg.wasm', import.meta.url));

async function fresh() {
  vi.resetModules();
  const runtime = await import('../src/runtime.js');
  const errors = await import('../src/errors.js');
  return { runtime, errors };
}

describe('runtime initialisation', () => {
  beforeEach(() => vi.resetModules());

  it('using the library before init throws NotInitializedError with a hint', async () => {
    const { runtime, errors } = await fresh();
    expect(runtime.isInitialized()).toBe(false);
    expect(() => runtime.wasm()).toThrow(errors.NotInitializedError);
    expect(() => runtime.call((w) => w)).toThrow(errors.NotInitializedError);
    try {
      runtime.wasm();
    } catch (e) {
      expect((e as { hint: string }).hint).toMatch(/init\(\)/);
    }
  });

  it('init() with no source at all fails cleanly, and can be retried with a good source', async () => {
    const { runtime, errors } = await fresh();
    await expect(runtime.init()).rejects.toThrow(errors.NotInitializedError);
    expect(runtime.isInitialized()).toBe(false);
    await runtime.init({ wasm: new Uint8Array(wasmBytes) }); // a failed attempt must not wedge later attempts
    expect(runtime.isInitialized()).toBe(true);
  });

  it('a corrupt source fails with a typed error and does not wedge init', async () => {
    const { runtime, errors } = await fresh();
    await expect(runtime.init({ wasm: new Uint8Array([1, 2, 3, 4]) })).rejects.toThrow(errors.QuantumSafeError);
    expect(runtime.isInitialized()).toBe(false);
    await runtime.init({ wasm: new Uint8Array(wasmBytes) });
    expect(runtime.isInitialized()).toBe(true);
  });

  it('init() is idempotent and safe to call concurrently', async () => {
    const { runtime } = await fresh();
    await Promise.all([1, 2, 3, 4].map(() => runtime.init({ wasm: new Uint8Array(wasmBytes) })));
    expect(runtime.isInitialized()).toBe(true);
    await runtime.init(); // already initialised: no source needed
    expect(runtime.isInitialized()).toBe(true);
  });

  it('call() converts thrown values to typed errors instead of leaking raw ones', async () => {
    const { runtime, errors } = await fresh();
    await runtime.init({ wasm: new Uint8Array(wasmBytes) });
    expect(() =>
      runtime.call(() => {
        throw new Error('raw failure with details');
      }),
    ).toThrow(errors.QuantumSafeError);
    try {
      runtime.call(() => {
        throw 'a string';
      });
    } catch (e) {
      expect(errors.QuantumSafeError.is(e)).toBe(true);
    }
  });
});
