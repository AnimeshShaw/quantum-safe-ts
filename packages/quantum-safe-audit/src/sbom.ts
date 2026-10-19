/**
 * CycloneDX SBOM enrichment: adds a post-quantum readiness property to every npm component that this tool has a record for.
 *
 * Name-based and best effort. It cannot run a dependency's code, so it knows only what is written in KNOWLEDGE below, as of
 * {@link KNOWLEDGE_DATE}. Components it has no record for are marked UNKNOWN, never READY. Counterpart of `qs-audit sbom` in quantum-safe-py.
 */

/**
 * Post-quantum readiness of a package: `READY` (provides post-quantum algorithms), `PARTIAL`, `NOT_READY` (classical public-key
 * cryptography only), `NOT_APPLICABLE` (no public-key primitive) or `UNKNOWN` (no record, or support not verified).
 */
export type Readiness = 'READY' | 'PARTIAL' | 'NOT_READY' | 'NOT_APPLICABLE' | 'UNKNOWN';

/** Readiness assessment of one npm package. */
export interface ComponentAssessment {
  /** npm package name, for example `@noble/post-quantum`. */
  name: string;
  /** Version the SBOM lists for the component, if it lists one. */
  version: string | undefined;
  /** Assessed readiness. */
  readiness: Readiness;
  /** Why the package got this readiness. */
  reason: string;
  /** Suggested next step. */
  action: string;
}

/** Date the knowledge base was last reviewed. Treat anything older as stale. */
export const KNOWLEDGE_DATE = '2026-10-02';

/** Knowledge-base record for one package; `before` replaces the main fields for versions whose major version is below `majorAtLeast`. */
interface Entry {
  readiness: Readiness;
  reason: string;
  action: string;
  /** If set, versions below this major version get `before` instead. */
  majorAtLeast?: number;
  before?: { readiness: Readiness; reason: string; action: string };
}

/** Builds a `NOT_READY` record for a package that offers classical public-key cryptography only. */
const classical = (what: string): Entry => ({
  readiness: 'NOT_READY',
  reason: `${what}: classical public-key cryptography only (quantum-vulnerable).`,
  action: 'Plan a migration to a hybrid or post-quantum alternative (for example quantum-safe-ts) and inventory where it is used.',
});
/** Builds a `READY` record for a package that provides post-quantum algorithms. */
const pq = (reason: string): Entry => ({ readiness: 'READY', reason, action: 'No action required for the library itself. Review how your code uses it.' });

/** Readiness records by npm package name. */
const KNOWLEDGE: Readonly<Record<string, Entry>> = {
  'quantum-safe-ts': pq('Provides ML-KEM, ML-DSA, SLH-DSA, hybrids and migration tooling.'),
  '@noble/post-quantum': pq('Provides ML-KEM, ML-DSA, SLH-DSA and hybrids.'),
  mlkem: pq('Provides ML-KEM (FIPS 203) only.'),
  'crystals-kyber-js': pq('Provides ML-KEM (FIPS 203) only.'),
  '@hpke/hybridkem-x-wing': pq('Provides the X-Wing hybrid KEM for HPKE.'),
  '@oqs/liboqs-js': pq('WebAssembly bindings to liboqs. Its documentation says it is for research and prototyping and not an official OQS product.'),
  'pqc-kyber': {
    readiness: 'PARTIAL',
    reason: 'Implements the pre-standard Kyber, not FIPS 203 ML-KEM, and appears unmaintained.',
    action: 'Move to a library that implements ML-KEM (FIPS 203).',
  },
  openpgp: {
    readiness: 'PARTIAL',
    reason: 'OpenPGP.js 6.x adds opt-in post-quantum (ML-KEM hybrid) support; defaults and classical keys remain.',
    action: 'Review the release notes for the version in use and enable the post-quantum algorithms where your peers support them.',
    majorAtLeast: 6,
    before: { readiness: 'NOT_READY', reason: 'OpenPGP.js before 6.x has no post-quantum algorithms.', action: 'Upgrade to 6.x and review its post-quantum options.' },
  },
  jose: {
    readiness: 'UNKNOWN',
    reason: 'Documents classical JOSE algorithms; support for RFC 9964 (ML-DSA) was not verified for the version in use.',
    action: 'Check the release notes for RFC 9964 support; if absent, use quantum-safe-ts StandardJwt for post-quantum tokens.',
  },
  'node-forge': classical('node-forge (RSA, ECDSA via curves, TLS, X.509)'),
  jsonwebtoken: classical('jsonwebtoken (RS*, ES*, PS*, EdDSA JWTs)'),
  jws: classical('jws'),
  jwa: classical('jwa'),
  'jwk-to-pem': classical('jwk-to-pem'),
  'ecdsa-sig-formatter': classical('ecdsa-sig-formatter'),
  elliptic: classical('elliptic (ECDSA/ECDH/EdDSA)'),
  tweetnacl: classical('tweetnacl (X25519, Ed25519)'),
  'tweetnacl-ts': classical('tweetnacl-ts (X25519, Ed25519)'),
  jsrsasign: classical('jsrsasign (RSA, ECDSA, X.509)'),
  'node-rsa': classical('node-rsa (RSA)'),
  sshpk: classical('sshpk (SSH key formats: RSA, ECDSA, Ed25519)'),
  ssh2: classical('ssh2 (SSH: classical key exchange and host keys by default)'),
  secp256k1: classical('secp256k1 (ECDSA)'),
  '@noble/secp256k1': classical('@noble/secp256k1'),
  '@noble/ed25519': classical('@noble/ed25519'),
  '@noble/curves': classical('@noble/curves (elliptic curves)'),
  'libsodium-wrappers': classical('libsodium (X25519, Ed25519)'),
  'libsodium-wrappers-sumo': classical('libsodium (X25519, Ed25519)'),
  'sodium-native': classical('sodium-native (libsodium: X25519, Ed25519)'),
  selfsigned: classical('selfsigned (RSA certificates)'),
  '@peculiar/x509': classical('@peculiar/x509 (X.509 with RSA/ECDSA)'),
  '@peculiar/webcrypto': classical('@peculiar/webcrypto (WebCrypto polyfill: RSA, ECDSA, ECDH)'),
  'crypto-js': {
    readiness: 'NOT_APPLICABLE',
    reason: 'Symmetric ciphers and hashes only. Not broken by Shor; Grover halves effective key length, so prefer 256-bit keys and SHA-256 or better.',
    action: 'Check key sizes (AES-256), and that nothing relies on it for key exchange or signatures.',
  },
  bcryptjs: { readiness: 'NOT_APPLICABLE', reason: 'Password hashing. Not a public-key primitive.', action: 'None for quantum readiness.' },
  argon2: { readiness: 'NOT_APPLICABLE', reason: 'Password hashing. Not a public-key primitive.', action: 'None for quantum readiness.' },
};

/** Largest number of components `enrichSbom` visits (nested components included) before it throws. */
const MAX_COMPONENTS = 200_000;

/**
 * npm package name from a CycloneDX component: prefers the purl, falls back to group/name. Returns undefined for non-npm components.
 *
 * A `pkg:npm/` purl gives its percent-decoded name without the version; a purl of any other type gives `undefined`. Without a purl the
 * `name` is used, prefixed with `group/` when the group starts with `@`; a component with no usable name gives `undefined`.
 * @param component - A CycloneDX component object.
 * @returns The npm package name, or `undefined`.
 * @example
 * npmNameOf({ purl: 'pkg:npm/%40noble/post-quantum@0.5.0' }); // '@noble/post-quantum'
 * npmNameOf({ group: '@noble', name: 'curves' }); // '@noble/curves'
 */
export function npmNameOf(component: Record<string, unknown>): string | undefined {
  const purl = typeof component.purl === 'string' ? component.purl : undefined;
  if (purl?.startsWith('pkg:npm/')) {
    const rest = purl.slice('pkg:npm/'.length).split(/[?#]/)[0]!;
    const at = rest.lastIndexOf('@');
    const raw = at > 0 ? rest.slice(0, at) : rest;
    try {
      return decodeURIComponent(raw);
    } catch {
      return undefined;
    }
  }
  if (purl && !purl.startsWith('pkg:npm/')) return undefined;
  const name = typeof component.name === 'string' ? component.name : undefined;
  if (!name) return undefined;
  const group = typeof component.group === 'string' ? component.group : undefined;
  return group?.startsWith('@') ? `${group}/${name}` : name;
}

/** Major version from a version string such as `6.1.0` or `v6.1.0`; `undefined` if it does not start with digits and a dot. */
function major(version: string | undefined): number | undefined {
  const m = /^v?(\d+)\./.exec(version ?? '');
  return m ? Number(m[1]) : undefined;
}

/**
 * Assesses one npm package by name (and optionally version).
 *
 * A name with no record gets `UNKNOWN`. A record with a version cut-off (`openpgp`) gives its earlier-version assessment when the version's
 * major number is below the cut-off; a missing or unparseable version gets the main record.
 * @param name - npm package name, matched exactly.
 * @param version - Package version, for example `6.1.0`.
 * @returns The assessment, with the name and version echoed.
 * @example
 * assessComponent('jsonwebtoken', '9.0.2').readiness; // 'NOT_READY'
 * assessComponent('openpgp', '5.11.0').readiness; // 'NOT_READY'
 */
export function assessComponent(name: string, version?: string): ComponentAssessment {
  const entry = Object.prototype.hasOwnProperty.call(KNOWLEDGE, name) ? KNOWLEDGE[name]! : undefined;
  if (!entry) {
    return {
      name,
      version,
      readiness: 'UNKNOWN',
      reason: `No record of '${name}' in the knowledge base (${KNOWLEDGE_DATE}). This does not mean it is safe.`,
      action: 'Check whether it performs public-key cryptography; if it does, find out how it plans to support post-quantum algorithms.',
    };
  }
  if (entry.majorAtLeast !== undefined && entry.before) {
    const m = major(version);
    if (m !== undefined && m < entry.majorAtLeast) return { name, version, ...entry.before };
  }
  return { name, version, readiness: entry.readiness, reason: entry.reason, action: entry.action };
}

/** Result of {@link enrichSbom}. */
export interface EnrichResult {
  /** A copy of the input SBOM with properties added. The input is not modified. */
  bom: Record<string, unknown>;
  /** One assessment per npm component, in document order (nested components after their parent). */
  assessments: ComponentAssessment[];
  /** Number of assessed components per readiness value. */
  summary: Record<Readiness, number>;
}

/**
 * Enriches a CycloneDX JSON SBOM. Adds `quantum-safe:pqc-readiness`, `quantum-safe:reason` and `quantum-safe:action` properties to each
 * npm component, and a document-level note. Existing properties are kept.
 * @param input - Parsed CycloneDX JSON document (an object whose `bomFormat` is `CycloneDX`).
 * @returns The enriched copy, the per-component assessments and the count per readiness value.
 * @throws {Error} if the input is not a CycloneDX document, or has more than 200,000 components.
 * @example
 * const { bom, summary } = enrichSbom(JSON.parse(readFileSync('sbom.json', 'utf8')));
 * summary.NOT_READY; // number of classical-only packages
 */
export function enrichSbom(input: unknown): EnrichResult {
  if (typeof input !== 'object' || input === null || (input as { bomFormat?: unknown }).bomFormat !== 'CycloneDX') {
    throw new Error('Not a CycloneDX JSON document (expected bomFormat "CycloneDX").');
  }
  const bom = structuredClone(input) as Record<string, unknown>;
  const summary: Record<Readiness, number> = { READY: 0, PARTIAL: 0, NOT_READY: 0, NOT_APPLICABLE: 0, UNKNOWN: 0 };
  const assessments: ComponentAssessment[] = [];
  let seen = 0;
  const visit = (components: unknown): void => {
    if (!Array.isArray(components)) return;
    for (const c of components) {
      if (typeof c !== 'object' || c === null) continue;
      if (++seen > MAX_COMPONENTS) throw new Error('SBOM has too many components.');
      const comp = c as Record<string, unknown>;
      const name = npmNameOf(comp);
      if (name !== undefined) {
        const version = typeof comp.version === 'string' ? comp.version : undefined;
        const a = assessComponent(name, version);
        assessments.push(a);
        summary[a.readiness]++;
        const props = Array.isArray(comp.properties) ? (comp.properties as unknown[]) : [];
        comp.properties = [
          ...props,
          { name: 'quantum-safe:pqc-readiness', value: a.readiness },
          { name: 'quantum-safe:reason', value: a.reason },
          { name: 'quantum-safe:action', value: a.action },
        ];
      }
      visit(comp.components);
    }
  };
  visit(bom.components);

  const metadata = typeof bom.metadata === 'object' && bom.metadata !== null ? (bom.metadata as Record<string, unknown>) : {};
  const mprops = Array.isArray(metadata.properties) ? (metadata.properties as unknown[]) : [];
  metadata.properties = [
    ...mprops,
    {
      name: 'quantum-safe:sbom-enrichment-note',
      value: `Name-based, best effort, knowledge base reviewed ${KNOWLEDGE_DATE}. UNKNOWN means no record, not safe. Not a compliance verdict.`,
    },
  ];
  bom.metadata = metadata;
  return { bom, assessments, summary };
}
