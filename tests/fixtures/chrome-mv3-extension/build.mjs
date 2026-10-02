import { build } from 'esbuild';
await build({ entryPoints: ['sw.js'], bundle: true, format: 'esm', platform: 'browser', outfile: 'ext/background.js' });
console.log('built extension service worker');
