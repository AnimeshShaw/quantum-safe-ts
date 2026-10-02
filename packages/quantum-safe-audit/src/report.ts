import { RULES, SEVERITY_ORDER, ruleById } from './rules.js';
import type { Severity } from './rules.js';
import type { ScanReport } from './walk.js';

const LEVEL: Record<Severity, string> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

export function summary(report: ScanReport): Record<Severity, number> {
  const s: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.findings) s[f.severity]++;
  return s;
}

/** True if any finding is at or above the policy's `failOn` severity (default `high`). */
export function shouldFail(report: ScanReport, failOn: Severity | 'none' = report.policy.failOn ?? 'high'): boolean {
  if (failOn === 'none') return false;
  const threshold = SEVERITY_ORDER[failOn];
  return report.findings.some((f) => SEVERITY_ORDER[f.severity] >= threshold);
}

export function toText(report: ScanReport): string {
  const s = summary(report);
  const lines: string[] = [];
  for (const f of report.findings) {
    lines.push(`[${f.severity.toUpperCase().padEnd(8)}] ${f.file}:${f.line}:${f.column}  ${f.ruleId}  ${f.message}`);
    const rule = ruleById(f.ruleId);
    if (rule && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.medium) lines.push(`           fix: ${rule.replacement}`);
  }
  if (report.findings.length) lines.push('');
  lines.push(
    `Scanned ${report.filesScanned} file(s): ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low, ${s.info} info.`,
  );
  for (const e of report.errors) lines.push(`warning: ${e}`);
  for (const n of report.notes) lines.push(`note: ${n}`);
  lines.push(
    'Static analysis sees only what the source names; an empty result is not evidence of absence. This is an inventory, not a compliance verdict or a FIPS 140-3 validation.',
  );
  return lines.join('\n');
}

export function toJson(report: ScanReport): string {
  return JSON.stringify(
    {
      tool: 'quantum-safe-audit',
      filesScanned: report.filesScanned,
      summary: summary(report),
      findings: report.findings.map((f) => ({ ...f, fix: ruleById(f.ruleId)?.replacement })),
      errors: report.errors,
      notes: report.notes,
      suppressed: report.suppressed,
    },
    null,
    2,
  );
}

function secScore(s: Severity): string {
  return { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' }[s];
}

/** SARIF 2.1.0 for GitHub Code Scanning and other consumers. */
export function toSarif(report: ScanReport, toolVersion = '0.1.0'): string {
  const used = new Set(report.findings.map((f) => f.ruleId));
  const rules = RULES.filter((r) => used.has(r.id)).map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    help: {
      text: `${r.replacement}${r.example ? `\n\nExample:\n${r.example}` : ''}`,
      markdown: `**Migrate to:** ${r.replacement}`,
    },
    helpUri: r.references[0] ?? 'https://github.com/AnimeshShaw/quantum-safe-ts',
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: {
      tags: ['security', 'cryptography', 'post-quantum', ...(r.quantumVulnerable ? ['quantum-vulnerable'] : [])],
      'security-severity': secScore(r.severity),
    },
  }));
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'quantum-safe-audit',
            version: toolVersion,
            informationUri: 'https://github.com/AnimeshShaw/quantum-safe-ts',
            rules,
          },
        },
        // An incomplete scan is reported as such, so a consumer can tell "nothing found" from "could not look".
        invocations: [
          {
            executionSuccessful: report.errors.length === 0,
            toolExecutionNotifications: [
              ...report.errors.map((e) => ({ level: 'error', message: { text: e.slice(0, 300) } })),
              ...report.notes.map((n) => ({ level: 'note', message: { text: n.slice(0, 300) } })),
            ],
          },
        ],
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: f.message },
          locations: [
            { physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, startColumn: f.column } } },
          ],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
