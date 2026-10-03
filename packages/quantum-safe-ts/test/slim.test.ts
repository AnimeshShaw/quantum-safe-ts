/**
 * The slim entry has the same API but embeds no WebAssembly: it must refuse to work until init() is given a module.
 * Tested on the built artifact in a fresh process (the shared test setup initialises the library in this one).
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const dist = (f: string) => new URL(`../dist/${f}`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

describe('slim entry (built artifact)', () => {
  it('is not initialised until a module is supplied, then works; the entry carries no WebAssembly', () => {
    const script = `
      const q = require(${JSON.stringify(dist('slim.cjs'))});
      const fs = require('fs');
      (async () => {
        if (q.isInitialized()) throw new Error('slim must not be initialised on import');
        try { new q.HybridKEM().generateKeyPair(); throw new Error('expected NotInitializedError'); } catch (e) { if (!(e instanceof q.NotInitializedError)) throw e; }
        try { await q.init(); throw new Error('init() without a module must fail'); } catch (e) { if (!(e instanceof q.NotInitializedError)) throw e; }
        await q.init({ wasm: fs.readFileSync(${JSON.stringify(dist('quantum_safe_wasm_bg.wasm'))}) });
        const kem = new q.HybridKEM();
        const pair = kem.generateKeyPair();
        const enc = kem.encapsulate(pair.publicKey);
        const shared = kem.decapsulate(pair.secretKey, enc.ciphertext);
        if (Buffer.compare(Buffer.from(shared.exportBytes()), Buffer.from(enc.sharedSecret.exportBytes())) !== 0) throw new Error('mismatch');
        console.log('slim-ok');
      })().catch((e) => { console.error(e); process.exit(1); });
    `;
    const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
    expect(r.stderr).toBe('');
    expect(r.stdout.trim()).toBe('slim-ok');
    // neither the entry nor any chunk it loads contains the base64 WebAssembly (it starts with 'AGFzbQ', the base64 of the WebAssembly magic number)
    const files = ['slim.cjs'];
    for (const f of files) {
      const text = readFileSync(dist(f), 'utf8');
      for (const m of text.matchAll(/require\('\.\/(chunk-[^']+\.cjs)'\)/g)) if (!files.includes(m[1]!)) files.push(m[1]!);
    }
    for (const f of files) expect(readFileSync(dist(f), 'utf8'), f).not.toContain('AGFzbQ');
    expect(files.reduce((n, f) => n + statSync(dist(f)).size, 0)).toBeLessThan(250_000);
  });
});
