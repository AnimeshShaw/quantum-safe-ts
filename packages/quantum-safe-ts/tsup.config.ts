import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', node: 'src/node.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  platform: 'neutral',
  splitting: true,
  shims: true,
  treeshake: true,
  // Node built-ins are referenced only from the Node entry via dynamic `node:` imports.
  external: ['node:fs', 'node:path', 'node:url', 'node:module'],
});
