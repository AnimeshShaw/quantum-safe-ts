import { WASM_BASE64 } from './wasm-inline.generated.js';

/** @internal Decodes the embedded WASM module (base64) to bytes. Works in every JS runtime. */
export function inlineWasmBytes(): Uint8Array {
  const bin = atob(WASM_BASE64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
