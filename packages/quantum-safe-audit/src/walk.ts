import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { scanSource } from './scanner.js';
import type { Finding, ScanOptions } from './scanner.js';
import { SEVERITY_ORDER, ruleById } from './rules.js';
import type { Severity } from './rules.js';

export interface Policy {
  /** Exit non-zero if any finding is at or above this severity. Default: `high`. */
  failOn?: Severity | 'none';
  /** Rule ids to ignore entirely (for example `["QSJ050"]`). */
  ignoreRules?: string[];
  /** Extra path globs to exclude (`**` and `*` supported). */
  exclude?: string[];
  /** Report CNSA 2.0 hash gaps too. */
  cnsa2?: boolean;
}

export interface ScanReport {
  /** Absolute scan root(s). */
  readonly roots: readonly string[];
  readonly filesScanned: number;
  readonly findings: readonly Finding[];
  /** Files that could not be read or parsed (never silently dropped). */
  readonly errors: readonly string[];
  readonly policy: Policy;
}

const DEFAULT_EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.svelte-kit', '.turbo', '.cache',
  '.parcel-cache', '.vercel', '.output', 'vendor', 'target', '__pycache__', '.venv', 'venv', '.wrangler',
]);
const CODE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i;
const MAX_BYTES = 1_000_000;

/** Converts a simple glob (`**`, `*`, `?`) to an anchored regular expression. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else {
          re += '.*';
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

export function loadPolicy(path: string): Policy {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Policy;
  if (raw.failOn !== undefined && raw.failOn !== 'none' && !(raw.failOn in SEVERITY_ORDER)) {
    throw new Error(`policy: invalid failOn '${String(raw.failOn)}'`);
  }
  return raw;
}

function* walk(dir: string, excludes: RegExp[], root: string): Generator<string> {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    const rel = relative(root, full).split(sep).join('/');
    if (excludes.some((r) => r.test(rel))) continue;
    if (e.isDirectory()) {
      if (DEFAULT_EXCLUDED_DIRS.has(e.name) || e.name.startsWith('.git')) continue;
      yield* walk(full, excludes, root);
    } else if (e.isFile()) {
      if (CODE_EXT.test(e.name) && !/\.min\.[cm]?js$/i.test(e.name)) yield full;
      else if (e.name === 'package.json') yield full;
    }
  }
}

/** Scans files and directories. Paths in findings are relative to each scan root. */
export function scanPaths(paths: readonly string[], policy: Policy = {}): ScanReport {
  const options: ScanOptions = { cnsa2: policy.cnsa2 ?? false };
  const excludes = (policy.exclude ?? []).map(globToRegExp);
  const ignore = new Set(policy.ignoreRules ?? []);
  const roots = paths.map((p) => resolve(p));
  const findings: Finding[] = [];
  const errors: string[] = [];
  let filesScanned = 0;

  for (const root of roots) {
    let st;
    try {
      st = statSync(root);
    } catch (e) {
      errors.push(`${root}: ${(e as Error).message}`);
      continue;
    }
    const base = st.isDirectory() ? root : resolve(root, '..');
    const files = st.isDirectory() ? [...walk(root, excludes, root)] : [root];
    for (const file of files) {
      try {
        const size = statSync(file).size;
        if (size > MAX_BYTES) {
          errors.push(`${file}: skipped (larger than ${MAX_BYTES} bytes)`);
          continue;
        }
        const text = readFileSync(file, 'utf8');
        const rel = relative(base, file).split(sep).join('/') || file;
        for (const f of scanSource(rel, text, options)) {
          if (!ignore.has(f.ruleId) && ruleById(f.ruleId)) findings.push(f);
        }
        filesScanned++;
      } catch (e) {
        errors.push(`${file}: ${(e as Error).message}`);
      }
    }
  }
  findings.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.file.localeCompare(b.file) || a.line - b.line,
  );
  return { roots, filesScanned, findings, errors, policy };
}
