#!/usr/bin/env node
// Generates, for the quantum-safe-ts package:
//   sbom/quantum-safe-ts.cdx.json   CycloneDX 1.6 SBOM of what is compiled into the WebAssembly (the Rust crates reachable from the
//                                   bindings crate by normal dependencies, with Cargo.lock checksums) plus the npm package itself
//   sbom/quantum-safe-ts.cbom.json  CycloneDX 1.6 CBOM of the cryptographic algorithms the library implements, produced by running this
//                                   repository's own quantum-safe-audit on the library source
// and validates both against the official CycloneDX 1.6 JSON schema (vendored under packages/quantum-safe-audit/test/schemas).
//
//   node scripts/generate-sboms.mjs [--out sbom]
//
// Requires: cargo on PATH, the audit package built (npm run build in packages/quantum-safe-audit) and its dev dependencies installed.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = resolve(repo, process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'sbom');
mkdirSync(outDir, { recursive: true });

const pkgJson = JSON.parse(readFileSync(join(repo, 'packages', 'quantum-safe-ts', 'package.json'), 'utf8'));
const meta = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--locked', '--filter-platform', 'wasm32-unknown-unknown'], {
    cwd: repo,
    maxBuffer: 1 << 28,
  }).toString('utf8'),
);

// Cargo.lock checksums (registry crates only).
const checksums = new Map();
{
  const lock = readFileSync(join(repo, 'Cargo.lock'), 'utf8').split('[[package]]').slice(1);
  for (const block of lock) {
    const name = /name = "([^"]+)"/.exec(block)?.[1];
    const version = /version = "([^"]+)"/.exec(block)?.[1];
    const sum = /checksum = "([0-9a-f]{64})"/.exec(block)?.[1];
    if (name && version && sum) checksums.set(`${name}@${version}`, sum);
  }
}

// Reachability from the bindings crate through NORMAL dependencies only (build/dev dependencies are not shipped in the WASM).
const byId = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const root = meta.packages.find((p) => p.name === 'quantum-safe-wasm');
if (!root) throw new Error('quantum-safe-wasm not found in cargo metadata');
const reach = new Set();
const stack = [root.id];
while (stack.length) {
  const id = stack.pop();
  if (reach.has(id)) continue;
  reach.add(id);
  for (const d of nodes.get(id)?.deps ?? []) if (d.dep_kinds.some((k) => k.kind === null)) stack.push(d.pkg);
}

const purl = (p) => `pkg:cargo/${p.name}@${p.version}`;
const ref = (p) => `cargo:${p.name}@${p.version}`;
const components = [...reach]
  .map((id) => byId.get(id))
  .filter((p) => p.id !== root.id)
  .sort((a, b) => (a.name + a.version).localeCompare(b.name + b.version))
  .map((p) => {
    const sum = checksums.get(`${p.name}@${p.version}`);
    const c = {
      type: 'library',
      'bom-ref': ref(p),
      name: p.name,
      version: p.version,
      purl: purl(p),
      scope: 'required',
    };
    if (sum) c.hashes = [{ alg: 'SHA-256', content: sum }];
    if (p.license) c.licenses = [{ expression: p.license.replace(/ \/ /g, ' OR ').replace(/\//g, ' OR ') }];
    if (p.repository) c.externalReferences = [{ type: 'vcs', url: p.repository }];
    if (!p.source) c.description = 'Workspace crate of this repository';
    return c;
  });

const rootRef = `npm:${pkgJson.name}@${pkgJson.version}`;
const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: process.env.SOURCE_DATE_EPOCH ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString() : new Date().toISOString(),
    tools: { components: [{ type: 'application', name: 'quantum-safe-ts scripts/generate-sboms.mjs', version: pkgJson.version }] },
    component: {
      type: 'library',
      'bom-ref': rootRef,
      name: pkgJson.name,
      version: pkgJson.version,
      purl: `pkg:npm/${pkgJson.name}@${pkgJson.version}`,
      licenses: [{ license: { id: pkgJson.license } }],
      description: 'The npm package. It has no npm runtime dependencies; the components below are the Rust crates reachable from the bindings crate by normal dependencies: compiled into its WebAssembly module, or used at compile time (procedural macros).',
    },
  },
  components,
  dependencies: [
    { ref: rootRef, dependsOn: [ref(root)] },
    ...[...reach].map((id) => {
      const p = byId.get(id);
      const deps = (nodes.get(id)?.deps ?? []).filter((d) => d.dep_kinds.some((k) => k.kind === null) && reach.has(d.pkg)).map((d) => ref(byId.get(d.pkg)));
      return { ref: ref(p), dependsOn: deps.sort() };
    }),
  ],
};
// The workspace root crate is also a component so that the graph is closed.
bom.components.unshift({ type: 'library', 'bom-ref': ref(root), name: root.name, version: root.version, purl: purl(root), licenses: [{ license: { id: pkgJson.license } }] });

const sbomPath = join(outDir, 'quantum-safe-ts.cdx.json');
writeFileSync(sbomPath, JSON.stringify(bom, null, 2) + '\n');

// CBOM from this repository's own scanner.
const auditCli = join(repo, 'packages', 'quantum-safe-audit', 'dist', 'cli.js');
const cbomPath = join(outDir, 'quantum-safe-ts.cbom.json');
execFileSync(process.execPath, [auditCli, 'cbom', join(repo, 'packages', 'quantum-safe-ts', 'src'), '--app-name', pkgJson.name, '--exclude', '**/wasm-inline.generated.ts', '--output', cbomPath], { stdio: 'inherit' });

// Validate both against the official schema.
const req = createRequire(join(repo, 'packages', 'quantum-safe-audit', 'package.json'));
const Ajv = req('ajv');
const schemaDir = join(repo, 'packages', 'quantum-safe-audit', 'test', 'schemas');
const ajv = new (Ajv.default ?? Ajv)({ strict: false, allErrors: true });
for (const f of ['spdx.schema.json', 'jsf-0.82.schema.json']) ajv.addSchema(JSON.parse(readFileSync(join(schemaDir, f), 'utf8')));
const validate = ajv.compile(JSON.parse(readFileSync(join(schemaDir, 'bom-1.6.schema.json'), 'utf8')));
let ok = true;
for (const p of [sbomPath, cbomPath]) {
  const valid = validate(JSON.parse(readFileSync(p, 'utf8')));
  console.log(`${valid ? 'valid  ' : 'INVALID'} ${p}`);
  if (!valid) {
    ok = false;
    console.log(JSON.stringify(validate.errors?.slice(0, 5), null, 2));
  }
}
console.log(`${components.length - 1} Rust crates compiled into the WebAssembly besides the bindings crate (reachable by normal dependencies).`);
process.exit(ok ? 0 : 1);
