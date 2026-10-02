import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', cli: 'src/cli.ts' },
  format: ['esm', 'cjs'],
  dts: { entry: { index: 'src/index.ts' } },
  sourcemap: true,
  clean: true,
  target: 'node18',
  platform: 'node',
  // typescript is a runtime dependency (the scanner uses its parser), pinned in package.json; it is not bundled.
  external: ['typescript'],
  banner: ({ format }) => ({ js: '' }),
});
