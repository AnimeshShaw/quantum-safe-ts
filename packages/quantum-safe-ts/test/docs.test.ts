/**
 * Executes every ```ts test block in llms-full.txt (and the README quickstart) against the built WASM.
 * Documentation that does not run is documentation that lies; agents copy these snippets verbatim.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '.generated-docs');
const NL = String.fromCharCode(10);

function blocks(file: string, fence = 'ts test'): string[] {
  const text = readFileSync(file, 'utf8');
  const re = new RegExp('```' + fence + '\\r?\\n([\\s\\S]*?)```', 'g');
  return [...text.matchAll(re)].map((m) => m[1]!);
}

/** Every markdown/text file whose ```ts test blocks must run: the LLM reference, the package README, and the documentation website. */
function documentFiles(): string[] {
  const root = join(here, '..', '..', '..');
  const files = [join(here, '..', 'llms-full.txt'), join(here, '..', 'README.md')];
  const site = join(root, 'website');
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === 'api' || e.name.startsWith('.')) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.md')) files.push(p);
    }
  };
  if (existsSync(site)) walk(site);
  return files;
}

describe('documentation snippets run', () => {
  const docs = documentFiles().map((file) => ({ file, blocks: blocks(file) })).filter((d) => d.blocks.length > 0);
  it('llms-full.txt has runnable examples', () => {
    expect(docs.find((d) => d.file.endsWith('llms-full.txt'))!.blocks.length).toBeGreaterThanOrEqual(6);
    expect(docs.some((d) => d.file.endsWith('README.md') && d.file.includes('quantum-safe-ts'))).toBe(true);
  });
  docs.forEach(({ file, blocks: bs }, d) => {
    bs.forEach((code, i) => {
      const label = file.split(sep).slice(-3).join('/');
      it(`${label} snippet #${i + 1}`, async () => {
        mkdirSync(out, { recursive: true });
        const path = join(out, `snippet-${d}-${i + 1}.ts`);
        // Run against the source entry (initialised by test/setup.ts) rather than the published name.
        const rewritten = code.replace(/from 'quantum-safe-ts'/g, "from '../../src/core.js'");
        const lines = rewritten.split(NL);
        const imports = lines.filter((l) => l.startsWith('import ')).join(NL);
        const body = lines.filter((l) => !l.startsWith('import ')).join(NL);
        writeFileSync(path, ['export default async function run() {', body, '}', imports, ''].join(NL));
        const mod = (await import(/* @vite-ignore */ pathToFileURL(path).href)) as { default: () => Promise<void> };
        await mod.default();
      });
    });
  });
  it('cleanup', () => {
    rmSync(out, { recursive: true, force: true });
  });
});
