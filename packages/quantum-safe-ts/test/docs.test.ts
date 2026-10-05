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
        const rewritten = code
          .replace(/from 'quantum-safe-ts'/g, "from '../../src/core.js'")
          .replace(/from 'quantum-safe-ts\/file-store'/g, "from '../../src/file-store.js'")
          .replace(/from 'quantum-safe-audit'/g, "from '../../../quantum-safe-audit/src/index.js'");
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

/** Guards that keep the documentation honest as it grows. */
describe('documentation completeness', () => {
  const root = join(here, '..', '..', '..');
  const siteFiles = documentFiles().filter((f) => f.includes(`${sep}website${sep}`));
  const read = (f: string) => readFileSync(f, 'utf8').split(String.fromCharCode(13) + NL).join(NL);

  it('every TypeScript code block on the site either runs (ts test) or says why not (ts no-run)', () => {
    const offenders: string[] = [];
    for (const file of siteFiles) {
      for (const m of read(file).matchAll(/^```(ts|typescript|js|javascript|tsx)(?![A-Za-z0-9])([^\r\n]*)$/gm)) {
        const info = m[2]!.trim();
        if (info !== 'test' && info !== 'no-run') offenders.push(`${file}: \`\`\`${m[1]}${m[2]}`);
      }
    }
    expect(offenders, 'untagged code blocks would never be executed; tag them `ts test` or `ts no-run`').toEqual([]);
  });

  it('there are only a few ts no-run blocks, and they are in the environment-specific pages', () => {
    const noRun = siteFiles.map((f) => ({ f, n: (read(f).match(/^```ts no-run$/gm) ?? []).length })).filter((x) => x.n > 0);
    expect(noRun.reduce((a, x) => a + x.n, 0)).toBeLessThanOrEqual(8);
  });

  it('the site has the pages the plan calls for, each of real size', () => {
    const pages: Record<string, number> = {
      'guide/getting-started.md': 60, 'guide/quick-start.md': 60, 'guide/choosing.md': 80, 'guide/cookbook.md': 150, 'guide/concepts.md': 80,
      'guide/kem.md': 60, 'guide/encryption.md': 80, 'guide/signatures.md': 80, 'guide/streaming.md': 60, 'guide/jwt.md': 60, 'guide/keys.md': 70,
      'guide/errors.md': 60, 'guide/migration.md': 100, 'guide/standards.md': 90, 'guide/python-interop.md': 80, 'guide/security.md': 70,
      'guide/runtimes.md': 60, 'guide/upgrading.md': 50, 'guide/faq.md': 60, 'guide/glossary.md': 40,
      'tools/audit.md': 80, 'tools/github-action.md': 50, 'tools/mcp.md': 80,
    };
    for (const [page, minLines] of Object.entries(pages)) {
      const f = join(root, 'website', page);
      expect(existsSync(f), `${page} is missing`).toBe(true);
      expect(read(f).split(NL).length, `${page} is too thin`).toBeGreaterThanOrEqual(minLines);
    }
  });

  it('every page is reachable from the sidebar', () => {
    const config = read(join(root, 'website', '.vitepress', 'config.ts'));
    for (const f of siteFiles) {
      const rel = f.slice(join(root, 'website').length + 1).split(sep).join('/');
      if (!rel.startsWith('guide/') && !rel.startsWith('tools/')) continue;
      const link = '/' + rel.replace(/\.md$/, '');
      expect(config, `${rel} is not in the sidebar`).toContain(`'${link}'`);
    }
  });

  it('every internal link points at a page or anchor that exists', () => {
    // The same slug rule VitePress uses: specials become '-', runs collapse, the ends are trimmed, a leading digit gets '_'.
    const slug = (h: string) => {
      const x = h.replace(/[\s~`!@#$%^&*()\-_+=[\]{}|\;:"'<>,.?/]+/g, '-').replace(/-{2,}/g, '-').replace(/^-+|-+$/g, '').toLowerCase();
      return /^\d/.test(x) ? '_' + x : x;
    };
    const anchors = new Map<string, Set<string>>();
    const pageOf = (f: string) => '/' + f.slice(join(root, 'website').length + 1).split(sep).join('/').replace(/\.md$/, '').replace(/\/index$/, '/');
    for (const f of siteFiles) {
      const set = new Set<string>();
      let inFence = false;
      for (const line of read(f).split(NL)) {
        if (line.startsWith('```')) inFence = !inFence;
        const h = !inFence && /^#{1,6} (.+)$/.exec(line);
        if (h) set.add(slug(h[1]!));
      }
      anchors.set(pageOf(f), set);
    }
    const problems: string[] = [];
    for (const f of siteFiles) {
      for (const m of read(f).matchAll(/\]\((\/[^)\s]*)\)/g)) {
        const [path, hash] = m[1]!.split('#') as [string, string | undefined];
        if (path.startsWith('/api')) continue; // generated by TypeDoc at build time
        const target = path === '/compare' || path === '/' ? path : path.replace(/\/$/, '');
        if (!anchors.has(target)) problems.push(`${pageOf(f)} -> ${m[1]} (no such page)`);
        else if (hash && !anchors.get(target)!.has(hash)) problems.push(`${pageOf(f)} -> ${m[1]} (no such heading)`);
      }
    }
    expect(problems).toEqual([]);
  });

  it('the MCP page names every tool and the resource the server registers', () => {
    const src = read(join(root, 'packages', 'quantum-safe-mcp', 'src', 'index.ts'));
    const page = read(join(root, 'website', 'tools', 'mcp.md'));
    const tools = [...src.matchAll(/registerTool\(\s*'([a-z_]+)'/g)].map((m) => m[1]!);
    expect(tools.length).toBe(5);
    for (const t of tools) expect(page, `mcp.md does not document ${t}`).toContain('`' + t + '`');
    const resource = /registerResource\(\s*'[^']+',\s*'([^']+)'/.exec(src)![1]!;
    expect(page).toContain(resource);
  });

  it('does not call -v2 a standard signature, and pairs with quantum-safe-py 0.3.2 or later', () => {
    // quantum-safe-py's docs: `-v2` signs a wrapped message M2 under a native context; a standard FIPS 204 library can verify it only by rebuilding M2.
    const publicDocs = [
      ...siteFiles,
      join(root, 'README.md'),
      join(root, 'COMPATIBILITY.md'),
      join(root, 'SECURITY.md'),
      join(here, '..', 'README.md'),
      join(here, '..', 'llms.txt'),
      join(here, '..', 'llms-full.txt'),
      join(root, 'packages', 'quantum-safe-mcp', 'src', 'knowledge.ts'),
      join(here, '..', 'src', 'algorithms.ts'),
    ];
    const banned: [RegExp, string][] = [
      [/any FIPS 204 librar(y|ies)[^.\r\n]*\bverif/i, 'says any FIPS 204 library can verify -v2'],
      [/plain FIPS 204[^.\r\n]*(-v2|\bv2\b|\bhalf\b)/i, 'calls the -v2 ML-DSA half plain FIPS 204'],
      [/quantum-safe-py\)? ?\(?0\.3\.1(\+| and later| or later)/, 'names 0.3.1 as the matching Python version'],
    ];
    const problems: string[] = [];
    for (const f of publicDocs) {
      if (!existsSync(f)) continue;
      const text = read(f);
      for (const [re, why] of banned) if (re.test(text)) problems.push(`${f}: ${why}`);
    }
    expect(problems).toEqual([]);
  });

  it('the error page lists every error code', () => {
    const errors = read(join(here, '..', 'src', 'errors.ts'));
    const page = read(join(root, 'website', 'guide', 'errors.md'));
    const codes = [...new Set([...errors.matchAll(/'(QS_[A-Z_]+)'/g)].map((m) => m[1]!))];
    for (const code of codes) expect(page, `errors.md does not list ${code}`).toContain(code);
  });
});
