import { build } from 'esbuild';
import { mkdirSync, writeFileSync } from 'node:fs';
mkdirSync('out', { recursive: true });
await build({ entryPoints: ['shared/entry.js'], bundle: true, format: 'esm', platform: 'browser', outfile: 'out/app.js', minify: true });
writeFileSync('out/index.html', '<!doctype html><meta charset="utf-8"><title>qs</title><script type="module" src="app.js"></script>');
console.log('esbuild ok');
