import * as q from 'quantum-safe-ts';
import wasm from 'quantum-safe-ts/quantum_safe_wasm_bg.wasm';
import { smoke } from './shared/smoke.mjs';

export default {
  async fetch() {
    try {
      await q.init({ wasm }); // Workers forbid compiling WASM from bytes; use the precompiled module
      return Response.json(await smoke(q));
    } catch (e) {
      return Response.json({ ok: false, error: String((e && e.stack) || e) });
    }
  },
};
