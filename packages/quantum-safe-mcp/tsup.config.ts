import { defineConfig } from 'tsup';
export default defineConfig({
  entry: { index: 'src/index.ts', server: 'src/server.ts' },
  format: ['esm'], dts: { entry: { index: 'src/index.ts' } }, sourcemap: true, clean: true, target: 'node18', platform: 'node',
  external: ['quantum-safe-audit', '@modelcontextprotocol/sdk', 'zod', 'typescript'],
});
