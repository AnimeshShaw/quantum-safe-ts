import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', node: 'src/node.ts', 'file-store': 'src/file-store.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  platform: 'neutral',
  splitting: true,
  shims: true,
  treeshake: true,
  // Do not embed the TypeScript sources in the source maps (about 3 MB of the unpacked size).
  esbuildOptions(options) {
    options.sourcesContent = false;
  },
});
