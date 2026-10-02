#!/usr/bin/env node
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { buildCbom } from './cbom.js';
import { shouldFail, toJson, toSarif, toText } from './report.js';
import { enrichSbom, KNOWLEDGE_DATE } from './sbom.js';
import { RULES, SEVERITY_ORDER, ruleById } from './rules.js';
import type { Severity } from './rules.js';
import { loadPolicy, scanPaths } from './walk.js';
import type { Policy } from './walk.js';

const VERSION = '0.1.0';

const HELP = `quantum-safe-audit: find classical (quantum-vulnerable) cryptography in JavaScript/TypeScript projects

Usage:
  quantum-safe-audit scan [paths...]      Scan files/directories (default: .)
  quantum-safe-audit cbom [paths...]      Emit a CycloneDX 1.6 CBOM (same as: scan --format cbom)
  quantum-safe-audit sbom <file.json>     Add post-quantum readiness properties to a CycloneDX SBOM (npm components)
  quantum-safe-audit rules                List rules (add --json for machine-readable output)
  quantum-safe-audit explain <RULE_ID>    Explain a rule and show the migration (add --json)

Options for scan/cbom:
  --format <text|json|sarif|cbom>   Output format (default: text)
  --output <file>                   Write to a file instead of stdout
  --fail-on <critical|high|medium|low|info|none>   Exit 1 at or above this severity (default: high)
  --policy <file>                   JSON policy { failOn, ignoreRules, exclude, cnsa2 }; default ./.qs-audit.json if present
  --exclude <glob>                  Exclude paths (repeatable; ** and * supported)
  --ignore-rule <ID>                Ignore a rule (repeatable)
  --cnsa2                           Also report CNSA 2.0 hash gaps (SHA-256)
  --no-provided                     Omit the provided post-quantum algorithms from the CBOM
  --allow-incomplete                Do not exit 2 when files were skipped/unanalysable or nothing was scanned (default: that is an error)
  --no-config                       Do not auto-load ./.qs-audit.json (CI should use this, or pass --policy from a trusted ref)
  --no-inline-ignore                Ignore // qs-audit-ignore comments (CI gates for untrusted code: a PR could add one to pass its own check)
  --no-default-excludes             Also scan node_modules, dist, build, vendor, ... (skipped by default; skipped paths are listed as notes)
  --app-name <name>                 Application name recorded in the CBOM
  -h, --help                        Show this help
  -v, --version                     Show the version

Exit codes: 0 ok; 1 findings at or above --fail-on; 2 usage or I/O error.
Suppress a finding in code with:  // qs-audit-ignore QSJ010 reason   (same or next line)
This tool reports what the source names. It is an inventory, not a compliance verdict.`;

interface Parsed {
  flags: Record<string, string | boolean | string[]>;
  positional: string[];
}

function parseArgs(argv: string[]): Parsed {
  const flags: Parsed['flags'] = {};
  const positional: string[] = [];
  const multi = new Set(['exclude', 'ignore-rule']);
  const bool = new Set(['cnsa2', 'no-provided', 'json', 'help', 'version', 'allow-incomplete', 'no-config', 'no-inline-ignore', 'no-default-excludes']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h') flags.help = true;
    else if (a === '-v') flags.version = true;
    else if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const k = eq === -1 ? a.slice(2) : a.slice(2, eq);
      const inline = eq === -1 ? undefined : a.slice(eq + 1);
      if (bool.has(k)) flags[k] = true;
      else {
        const v = inline ?? argv[++i];
        if (v === undefined) throw new Error(`--${k} requires a value`);
        if (multi.has(k)) {
          const list = (flags[k] as string[] | undefined) ?? [];
          list.push(v);
          flags[k] = list;
        } else flags[k] = v;
      }
    } else positional.push(a);
  }
  return { flags, positional };
}

function main(): number {
  let parsed: Parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n${HELP}\n`);
    return 2;
  }
  const { flags, positional } = parsed;
  if (flags.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (flags.help || positional.length === 0) {
    process.stdout.write(`${HELP}\n`);
    return flags.help ? 0 : 2;
  }
  const [command, ...rest] = positional;

  if (command === 'sbom') {
    const file = rest[0];
    if (!file) {
      process.stderr.write('Usage: quantum-safe-audit sbom <file.json> [--output <file>]\n');
      return 2;
    }
    try {
      if (statSync(file).size > 64 * 1024 * 1024) throw new Error('SBOM file is larger than 64 MiB');
      const { bom, summary } = enrichSbom(JSON.parse(readFileSync(file, 'utf8')));
      const json = `${JSON.stringify(bom, null, 2)}\n`;
      if (typeof flags.output === 'string') writeFileSync(flags.output, json);
      else process.stdout.write(json);
      process.stderr.write(
        `Readiness (name-based, knowledge base ${KNOWLEDGE_DATE}): ${Object.entries(summary).map(([k, v]) => `${k}=${v}`).join(' ')}\n`,
      );
      return 0;
    } catch (e) {
      process.stderr.write(`Could not enrich the SBOM: ${(e as Error).message}\n`);
      return 2;
    }
  }
  if (command === 'rules') {
    if (flags.json) process.stdout.write(`${JSON.stringify(RULES, null, 2)}\n`);
    else for (const r of RULES) process.stdout.write(`${r.id}  ${r.severity.padEnd(8)}  ${r.title}\n`);
    return 0;
  }
  if (command === 'explain') {
    const rule = ruleById((rest[0] ?? '').toUpperCase());
    if (!rule) {
      process.stderr.write(`Unknown rule '${rest[0] ?? ''}'. Run: quantum-safe-audit rules\n`);
      return 2;
    }
    if (flags.json) {
      process.stdout.write(`${JSON.stringify(rule, null, 2)}\n`);
    } else {
      process.stdout.write(
        `${rule.id}: ${rule.title}\nSeverity: ${rule.severity}\nQuantum-vulnerable: ${rule.quantumVulnerable}\n\n${rule.description}\n\nMigrate to: ${rule.replacement}\n`,
      );
      if (rule.example) process.stdout.write(`\nExample:\n${rule.example}\n`);
      process.stdout.write(`\nReferences:\n${rule.references.map((r) => `  ${r}`).join('\n')}\n`);
    }
    return 0;
  }
  if (command !== 'scan' && command !== 'cbom') {
    process.stderr.write(`Unknown command '${command ?? ''}'.\n${HELP}\n`);
    return 2;
  }

  let policy: Policy = {};
  try {
    const policyPath =
      typeof flags.policy === 'string' ? flags.policy : !flags['no-config'] && existsSync('.qs-audit.json') ? '.qs-audit.json' : undefined;
    if (policyPath) policy = loadPolicy(policyPath);
  } catch (e) {
    process.stderr.write(`Could not read policy: ${(e as Error).message}\n`);
    return 2;
  }
  if (typeof flags['fail-on'] === 'string') {
    const v = flags['fail-on'];
    if (v !== 'none' && !Object.hasOwn(SEVERITY_ORDER, v)) {
      process.stderr.write(`Invalid --fail-on '${v}'.\n`);
      return 2;
    }
    policy.failOn = v as Severity | 'none';
  }
  if (Array.isArray(flags.exclude)) policy.exclude = [...(policy.exclude ?? []), ...flags.exclude];
  if (Array.isArray(flags['ignore-rule'])) policy.ignoreRules = [...(policy.ignoreRules ?? []), ...flags['ignore-rule']];
  if (flags.cnsa2) policy.cnsa2 = true;
  if (flags['no-inline-ignore']) policy.noInlineIgnore = true;
  if (flags['no-default-excludes']) policy.noDefaultExcludes = true;

  const paths = rest.length ? rest : ['.'];
  const report = scanPaths(paths, policy);
  const format = command === 'cbom' ? 'cbom' : ((flags.format as string | undefined) ?? 'text');
  let out: string;
  switch (format) {
    case 'text':
      out = toText(report);
      break;
    case 'json':
      out = toJson(report);
      break;
    case 'sarif':
      out = toSarif(report, VERSION);
      break;
    case 'cbom':
      out = JSON.stringify(
        buildCbom(report, {
          includeProvided: !flags['no-provided'],
          applicationName: (flags['app-name'] as string | undefined) ?? resolve(paths[0]!).split(/[\\/]/).pop() ?? 'app',
          toolVersion: VERSION,
        }),
        null,
        2,
      );
      break;
    default:
      process.stderr.write(`Unknown --format '${format}'.\n`);
      return 2;
  }
  if (typeof flags.output === 'string') writeFileSync(flags.output, `${out}\n`);
  else process.stdout.write(`${out}\n`);
  // An incomplete scan must never look clean: a file that was skipped (too large, unreadable) or could not be parsed, and a scan that covered
  // no files at all, are errors, not silence. Without this, padding a file past the size limit would bypass the gate.
  if (!flags['allow-incomplete'] && (report.errors.length > 0 || report.filesScanned === 0)) {
    process.stderr.write(
      report.filesScanned === 0 && report.errors.length === 0
        ? 'No files were scanned (nothing matched, or everything was excluded). Exiting with an error; use --allow-incomplete to accept this.\n'
        : `${report.errors.length} problem(s) while scanning (files skipped or not analysable; see the report). The scan is incomplete, so exiting with an error. Use --allow-incomplete to accept this.\n`,
    );
    return 2;
  }
  // `scan --format cbom` is gated like any other scan; the dedicated `cbom` command is an inventory and exits 0.
  return command === 'cbom' ? 0 : shouldFail(report) ? 1 : 0;
}

process.exit(main());
