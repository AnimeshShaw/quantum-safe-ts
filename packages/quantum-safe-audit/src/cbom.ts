/**
 * CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).
 *
 * Two kinds of asset, deliberately distinguished (as in quantum-safe-py's CBOM):
 *  - *detected* assets come from scanning source: cryptography the codebase uses, one component per
 *    (algorithm, location) so every site that needs changing is visible;
 *  - *provided* assets are the post-quantum algorithms quantum-safe-ts offers to migrate to.
 *
 * This is an inventory, not a compliance verdict. nistQuantumSecurityLevel is 0 for classical
 * public-key assets (the CycloneDX encoding for "no security against a quantum adversary").
 */
import { randomUUID } from 'node:crypto';
import { ruleById } from './rules.js';
import type { Primitive } from './rules.js';
import type { ScanReport } from './walk.js';

interface Provided {
  name: string;
  primitive: Primitive;
  oid: string;
  classical: number;
  quantum: number;
}

const PROVIDED: readonly Provided[] = [
  { name: 'ML-KEM-512', primitive: 'kem', oid: '2.16.840.1.101.3.4.4.1', classical: 128, quantum: 1 },
  { name: 'ML-KEM-768', primitive: 'kem', oid: '2.16.840.1.101.3.4.4.2', classical: 192, quantum: 3 },
  { name: 'ML-KEM-1024', primitive: 'kem', oid: '2.16.840.1.101.3.4.4.3', classical: 256, quantum: 5 },
  { name: 'ML-DSA-44', primitive: 'signature', oid: '2.16.840.1.101.3.4.3.17', classical: 128, quantum: 2 },
  { name: 'ML-DSA-65', primitive: 'signature', oid: '2.16.840.1.101.3.4.3.18', classical: 192, quantum: 3 },
  { name: 'ML-DSA-87', primitive: 'signature', oid: '2.16.840.1.101.3.4.3.19', classical: 256, quantum: 5 },
  { name: 'SLH-DSA-SHAKE-128s', primitive: 'signature', oid: '2.16.840.1.101.3.4.3.26', classical: 128, quantum: 1 },
  { name: 'SLH-DSA-SHAKE-256s', primitive: 'signature', oid: '2.16.840.1.101.3.4.3.30', classical: 256, quantum: 5 },
];

export interface CbomOptions {
  includeProvided?: boolean;
  applicationName?: string;
  serialNumber?: string;
  timestamp?: string;
  toolVersion?: string;
}

interface ComponentExtra {
  occurrences?: Array<{ location: string; line: number; offset: number }>;
  properties?: Array<{ name: string; value: string }>;
}

function algorithmComponent(
  ref: string,
  name: string,
  primitive: Primitive,
  oid: string | undefined,
  classical: number | undefined,
  quantum: number,
  extra: ComponentExtra = {},
) {
  return {
    type: 'cryptographic-asset',
    'bom-ref': ref,
    name,
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive,
        ...(classical !== undefined ? { classicalSecurityLevel: classical } : {}),
        nistQuantumSecurityLevel: quantum,
      },
      ...(oid ? { oid } : {}),
    },
    ...(extra.occurrences ? { evidence: { occurrences: extra.occurrences } } : {}),
    ...(extra.properties ? { properties: extra.properties } : {}),
  };
}

export function buildCbom(report: ScanReport, options: CbomOptions = {}): Record<string, unknown> {
  const components: unknown[] = [];
  let detected = 0;
  report.findings.forEach((f, i) => {
    const rule = ruleById(f.ruleId);
    // Inventory-only rules (libraries, embedded keys, PQ usage) are not algorithms to migrate.
    if (!rule || rule.id === 'QSJ050' || rule.id === 'QSJ060' || rule.id === 'QSJ900') return;
    detected++;
    components.push(
      algorithmComponent(
        `detected-${rule.algorithm.replace(/[^A-Za-z0-9]+/g, '-')}-${i}`,
        rule.algorithm,
        rule.primitive,
        rule.oid,
        rule.classicalLevel,
        rule.quantumLevel,
        {
          occurrences: [{ location: f.file, line: f.line, offset: f.column - 1 }],
          properties: [
            { name: 'quantum-safe:rule-id', value: rule.id },
            { name: 'quantum-safe:severity', value: f.severity.toUpperCase() },
            { name: 'quantum-safe:quantum-vulnerable', value: String(rule.quantumVulnerable) },
          ],
        },
      ),
    );
  });
  if (options.includeProvided ?? true) {
    for (const p of PROVIDED) {
      components.push(
        algorithmComponent(`provided-${p.name}`, p.name, p.primitive, p.oid, p.classical, p.quantum, {
          properties: [{ name: 'quantum-safe:availability', value: 'provided-by-quantum-safe-ts' }],
        }),
      );
    }
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: options.serialNumber ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: options.timestamp ?? new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'quantum-safe-audit',
            version: options.toolVersion ?? '0.1.0',
            description: 'Static cryptographic asset discovery for JavaScript and TypeScript',
          },
        ],
      },
      component: { type: 'application', 'bom-ref': 'subject', name: options.applicationName ?? 'scanned-application' },
      properties: [
        { name: 'quantum-safe:detected-asset-count', value: String(detected) },
        {
          name: 'quantum-safe:scope-note',
          value:
            'Static analysis of JavaScript/TypeScript source. Cryptography reached via configuration, plugins, or dependency internals is not visible here, so an empty result is not evidence of absence.',
        },
        {
          name: 'quantum-safe:not-a-compliance-verdict',
          value:
            'Inventory only. Neither this document nor the scanner is a CNSA 2.0 assessment or a FIPS 140-3 validation.',
        },
      ],
    },
    components,
  };
}
