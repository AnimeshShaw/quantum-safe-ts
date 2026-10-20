import { closeSync, openSync, readSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { scanSource } from './scanner.js';
import type { Finding, ScanOptions } from './scanner.js';
import { SEVERITY_ORDER, ruleById } from './rules.js';
import type { Severity } from './rules.js';

/** Scan policy, read from a JSON file by {@link loadPolicy} or built in code; every field is optional. */
export interface Policy {
  /** Exit non-zero if any finding is at or above this severity. Default: `high`. `none` never fails. */
  failOn?: Severity | 'none';
  /** Rule ids to ignore entirely (for example `["QSJ050"]`). */
  ignoreRules?: string[];
  /** Extra path globs to exclude (`**` and `*` supported). Matched against the path relative to the scan root, with `/` separators. */
  exclude?: string[];
  /** Report CNSA 2.0 hash gaps too. */
  cnsa2?: boolean;
  /** Also scan directories that are skipped by default (node_modules, dist, build, vendor, ...). */
  noDefaultExcludes?: boolean;
  /** Ignore `// qs-audit-ignore` comments (use in CI gates for untrusted code). */
  noInlineIgnore?: boolean;
}

/** Result of {@link scanPaths}. */
export interface ScanReport {
  /** Absolute scan root(s). */
  readonly roots: readonly string[];
  /** Number of files read and analysed successfully (files with no findings included; skipped and failed files are not). */
  readonly filesScanned: number;
  /** Findings after rule ignores, sorted by severity (most serious first), then file, then line. */
  readonly findings: readonly Finding[];
  /** Files that could not be read or parsed (never silently dropped). */
  readonly errors: readonly string[];
  /** Non-fatal facts a reader should know: directories skipped by default, findings suppressed by inline comments. */
  readonly notes: readonly string[];
  /** Number of findings suppressed by inline `qs-audit-ignore` comments. */
  readonly suppressed: number;
  /** The policy the scan ran with. */
  readonly policy: Policy;
}

/** Directory names skipped at any depth unless `noDefaultExcludes` is set. */
const DEFAULT_EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.svelte-kit', '.turbo', '.cache',
  '.parcel-cache', '.vercel', '.output', 'vendor', 'target', '__pycache__', '.venv', 'venv', '.wrangler',
]);
/** File extensions the directory walk treats as code. */
const CODE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|es6)$/i;
/** Largest file size, in bytes, that is read; larger files are skipped and reported as errors. */
const MAX_BYTES = 1_000_000;

/** Escapes one character for use as a literal inside a regular expression. */
function escapeRegExpChar(c: string): string {
  return c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Converts a simple glob (`**`, `*`, `?`) to an anchored regular expression. Every other character is matched literally. Runs of the same
 * wildcard (`**\/**\/**`, `***`) are collapsed to one, which matches exactly the same strings but keeps the expression from backtracking
 * super-linearly when a policy file contains such a pattern.
 *
 * `**` matches any characters including `/`, `**` followed by `/` also matches zero directories, `*` matches any characters except `/`
 * and `?` matches one character except `/`.
 * @param glob - Glob pattern, matched against a whole path.
 * @returns A regular expression anchored at both ends.
 * @example
 * globToRegExp('src/**\/*.test.ts').test('src/a/b.test.ts'); // true
 * globToRegExp('*.js').test('lib/a.js'); // false
 */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  let lastWildcard = '';
  const wildcard = (token: string): void => {
    if (token !== lastWildcard) re += token;
    lastWildcard = token;
  };
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          wildcard('(?:.*/)?');
        } else {
          wildcard('.*');
        }
      } else {
        wildcard('[^/]*');
      }
    } else {
      lastWildcard = '';
      re += c === '?' ? '[^/]' : escapeRegExpChar(c);
    }
  }
  return new RegExp(`^${re}$`);
}

/**
 * Reads a policy from a JSON file.
 * @param path - Path of the JSON policy file.
 * @returns The parsed policy. Only `failOn` is validated; the other fields are used as written.
 * @throws {Error} If the file cannot be read or parsed, or `failOn` is neither `none` nor a severity name.
 * @example
 * const policy = loadPolicy('.qs-audit.json'); // { "failOn": "medium", "ignoreRules": ["QSJ050"] }
 */
export function loadPolicy(path: string): Policy {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Policy;
  if (raw.failOn !== undefined && raw.failOn !== 'none' && !Object.hasOwn(SEVERITY_ORDER, raw.failOn)) {
    throw new Error(`policy: invalid failOn '${String(raw.failOn)}'`);
  }
  return raw;
}

/** True for an extensionless file that starts with a Node shebang (a CLI script that would otherwise never be scanned). */
function isNodeScript(file: string): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(file, 'r');
    const buf = Buffer.alloc(80);
    const n = readSync(fd, buf, 0, 80, 0);
    const head = buf.subarray(0, n).toString('latin1');
    return head.startsWith('#!') && /node|deno|bun/.test(head.split(String.fromCharCode(10))[0] ?? '');
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Yields the absolute path of every scannable file under `dir`. Skips `.git` always, the default-excluded directories unless
 * `noDefaultExcludes` is set, minified `.min.js` files and paths matching `excludes` (tested against the path relative to `root`).
 * Unreadable directories, broken symlinks and symlinks to directories are added to `errors`; skipped directories and minified files are
 * added to `notes` (at most 50 notes of these kinds). Symlinks to files are followed.
 */
function* walk(dir: string, excludes: RegExp[], root: string, errors: string[], notes: string[], noDefaultExcludes: boolean): Generator<string> {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    // Never silently drop a directory: an unreadable directory makes the scan incomplete.
    errors.push(`${dir}: could not be read (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    const rel = relative(root, full).split(sep).join('/');
    if (excludes.some((r) => r.test(rel))) continue;
    if (e.isDirectory()) {
      if (e.name === '.git' || (!noDefaultExcludes && DEFAULT_EXCLUDED_DIRS.has(e.name))) {
        if (e.name !== '.git' && notes.length < 50) notes.push(`not scanned (default exclusion): ${rel}/`);
        continue;
      }
      yield* walk(full, excludes, root, errors, notes, noDefaultExcludes);
    } else if (e.isSymbolicLink()) {
      // A symlink is followed for files (the target is scanned) and reported for directories, so one cannot be used to hide code.
      let target;
      try {
        target = statSync(full);
      } catch {
        errors.push(`${rel}: broken symbolic link`);
        continue;
      }
      if (target.isDirectory()) errors.push(`${rel}: symbolic link to a directory was not followed`);
      else if (target.isFile() && (CODE_EXT.test(e.name) || e.name === 'package.json')) yield full;
    } else if (e.isFile()) {
      if (/\.min\.[cm]?js$/i.test(e.name)) {
        if (notes.length < 50) notes.push(`not scanned (minified): ${rel}`);
      } else if (CODE_EXT.test(e.name) || e.name === 'package.json') yield full;
      else if (!e.name.includes('.') && isNodeScript(full)) yield full;
    }
  }
}

/**
 * Scans files and directories. Paths in findings are relative to each scan root.
 *
 * A directory is walked recursively and only files with a code extension (`.js`, `.ts`, `.jsx`, `.tsx`, their `m`/`c` variants, `.vue`,
 * `.svelte`, `.astro`, `.html`, `.htm`, `.es6`), files named `package.json` and extensionless files with a node, deno or bun shebang
 * are read.
 * A path that names a file is scanned whatever its extension. Files larger than 1,000,000 bytes, unreadable files and files that cannot be
 * analysed are listed in `errors` and not counted in `filesScanned`. A root that does not exist is also listed in `errors`.
 * @param paths - Files and directories to scan.
 * @param policy - Scan policy; defaults to `{}` (no extra excludes, no ignored rules, `cnsa2` off, inline ignores honoured).
 * @returns The report with findings sorted by severity (most serious first), then file, then line.
 * @example
 * const report = scanPaths(['src'], { failOn: 'medium', exclude: ['**\/*.test.ts'] });
 * report.findings.length; // number of findings
 */
export function scanPaths(paths: readonly string[], policy: Policy = {}): ScanReport {
  let suppressed = 0;
  const options: ScanOptions = {
    cnsa2: policy.cnsa2 ?? false,
    ignoreInline: !policy.noInlineIgnore,
    onSuppressed: (n) => {
      suppressed += n;
    },
  };
  const notes: string[] = [];
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
    const files = st.isDirectory() ? [...walk(root, excludes, root, errors, notes, policy.noDefaultExcludes === true)] : [root];
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
  if (suppressed > 0) notes.push(`${suppressed} finding(s) were suppressed by inline qs-audit-ignore comments`);
  return { roots, filesScanned, findings, errors, notes, suppressed, policy };
}
