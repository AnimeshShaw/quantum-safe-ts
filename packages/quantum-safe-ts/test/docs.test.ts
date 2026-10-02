/**
 * Executes every ```ts test block in llms-full.txt (and the README quickstart) against the built WASM.
 * Documentation that does not run is documentation that lies; agents copy these snippets verbatim.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '.generated-docs');

function blocks(file: string, fence = 'ts test'): string[] {
  const text = readFileSync(file, 'utf8');
  const re = new RegExp('```' + fence + '\\r?\\n([\\s\\S]*?)```', 'g');
  return [...text.matchAll(re)].map((m) => m[1]!);
}

describe('documentation snippets run', () => {
  const all = blocks(join(here, '..', 'llms-full.txt'));
  it('llms-full.txt has runnable examples', () => {
    expect(all.length).toBeGreaterThanOrEqual(6);
  });
  all.forEach((code, i) => {
    it(`llms-full.txt snippet #${i + 1}`, async () => {
      mkdirSync(out, { recursive: true });
      const file = join(out, `snippet-${i + 1}.ts`);
      // Run against the source entry (initialised by test/setup.ts) rather than the published name.
      const rewritten = code.replace(/from 'quantum-safe-ts'/g, "from '../../src/core.js'");
      writeFileSync(file, `export default async function run() {\n${rewritten.replace(/^import .*$/gm, '')}\n}\n${rewritten
        .split('\n')
        .filter((l) => l.startsWith('import '))
        .join('\n')}\n`);
      const mod = (await import(/* @vite-ignore */ pathToFileURL(file).href)) as { default: () => Promise<void> };
      await mod.default();
    });
  });
  it('cleanup', () => {
    rmSync(out, { recursive: true, force: true });
  });
});
