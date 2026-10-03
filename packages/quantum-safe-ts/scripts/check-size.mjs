// Fails CI if the shipped WASM or inline bundle exceeds the budget. Budgets are measured, not guessed:
// raw WASM ~1.30 MB / ~411 KB gzip at opt-level 3 (was 0.86 MB / 292 KB at opt-level s; 2-3x faster). Raise deliberately (and note why in the CHANGELOG), never silently.
import { gzipSync } from 'node:zlib';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
// The generic (browser) entry is index.js plus the shared chunks it imports; measure them together.
const chunkFiles = readdirSync(dist).filter((f) => /^chunk-.*\.js$/.test(f));
const BUDGET = {
  'quantum_safe_wasm_bg.wasm': { files: ['quantum_safe_wasm_bg.wasm'], raw: 1_340_000, gzip: 430_000 },
  'browser bundle (index.js + chunks)': { files: ['index.js', ...chunkFiles], raw: 1_950_000, gzip: 640_000 },
};
let failed = false;
for (const [file, b] of Object.entries(BUDGET)) {
  const buf = Buffer.concat(b.files.map((f) => readFileSync(resolve(dist, f))));
  const gz = gzipSync(buf, { level: 9 }).length;
  const raw = b.files.reduce((n, f) => n + statSync(resolve(dist, f)).size, 0);
  const ok = raw <= b.raw && gz <= b.gzip;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${file}: ${raw} B raw (budget ${b.raw}), ${gz} B gzip (budget ${b.gzip})`);
  if (!ok) failed = true;
}
process.exit(failed ? 1 : 0);
