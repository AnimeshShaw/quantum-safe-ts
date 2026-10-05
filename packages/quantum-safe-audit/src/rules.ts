/**
 * Rule catalog. Each rule is both a detection target and a CycloneDX cryptographic-asset
 * description, so the scan report and the CBOM never drift apart.
 *
 * Severity model (mirrors quantum-safe-py's scanner):
 *  - critical: key material embedded in source, or RSA below 2048 bits
 *  - high:     asymmetric cryptography a cryptographically relevant quantum computer breaks outright
 *              (RSA, ECDSA/ECDH, DSA, finite-field DH, Ed25519/X25519), and classically broken ciphers
 *  - medium:   AES-128 (thin margin under Grover), SHA-1 and MD5 (classically broken)
 *  - info:     inventory of classical-crypto libraries, and post-quantum usage (a good sign)
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export type Primitive = 'pke' | 'signature' | 'key-agree' | 'kem' | 'block-cipher' | 'hash' | 'other';

export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  /** Algorithm name as it should appear in an inventory. */
  readonly algorithm: string;
  /** CycloneDX `primitive` value. */
  readonly primitive: Primitive;
  readonly oid?: string;
  /** Approximate classical security level in bits. */
  readonly classicalLevel?: number;
  /** CycloneDX `nistQuantumSecurityLevel`; 0 = no security against a quantum adversary. */
  readonly quantumLevel: number;
  /** True if a cryptographically relevant quantum computer breaks the algorithm outright. */
  readonly quantumVulnerable: boolean;
  readonly description: string;
  /** What to migrate to (names quantum-safe-ts APIs where one exists). */
  readonly replacement: string;
  /** Minimal replacement example. */
  readonly example?: string;
  readonly references: readonly string[];
}

const NIST_IR_8547 = 'https://csrc.nist.gov/pubs/ir/8547/ipd';
const CNSA2 = 'https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF';

export const RULES: readonly Rule[] = [
  {
    id: 'QSJ001',
    title: 'RSA key generation or use',
    severity: 'high',
    algorithm: 'RSA',
    primitive: 'pke',
    oid: '1.2.840.113549.1.1.1',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: true,
    description:
      "RSA is broken by Shor's algorithm on a cryptographically relevant quantum computer. Data encrypted or signed under RSA today can be harvested now and attacked later.",
    replacement:
      'Encryption/key transport: HybridKEM + Envelope (X25519+ML-KEM-768; CNSA 2.0: pure ML-KEM-1024 via cnsa2.kem()). Signatures: HybridSign (Ed25519+ML-DSA-65; CNSA 2.0: pure ML-DSA-87).',
    example:
      "import { HybridKEM, Envelope, utf8 } from 'quantum-safe-ts';\nconst kem = new HybridKEM();\nconst pair = kem.generateKeyPair();\nconst sealed = Envelope.seal(utf8('data'), pair.publicKey);",
    references: [NIST_IR_8547, CNSA2],
  },
  {
    id: 'QSJ002',
    title: 'RSA PKCS#1 v1.5 or RSA-SHA signature',
    severity: 'high',
    algorithm: 'RSA-PKCS1v15',
    primitive: 'signature',
    oid: '1.2.840.113549.1.1.1',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'RSA signatures (PKCS#1 v1.5 / RSA-SHA*) are quantum-vulnerable.',
    replacement: 'HybridSign (Ed25519+ML-DSA-65; CNSA 2.0: pure ML-DSA-87), or StandardJwt for JOSE interoperability.',
    example: "import { HybridSign, utf8 } from 'quantum-safe-ts';\nconst signer = new HybridSign();\nconst pair = signer.generateKeyPair();\nconst sm = signer.sign(utf8('doc'), pair.secretKey, { context: utf8('app-v1') });",
    references: [NIST_IR_8547, CNSA2],
  },
  {
    id: 'QSJ003',
    title: 'RSA encryption (RSA-OAEP / publicEncrypt)',
    severity: 'high',
    algorithm: 'RSA-OAEP',
    primitive: 'pke',
    oid: '1.2.840.113549.1.1.7',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'RSA public-key encryption is quantum-vulnerable.',
    replacement: 'Envelope.seal() with a HybridKEM public key.',
    example: "import { Envelope, utf8 } from 'quantum-safe-ts';\nconst sealed = Envelope.seal(plaintext, recipientPublicKey, { aad: utf8('context') });",
    references: [NIST_IR_8547, CNSA2],
  },
  {
    id: 'QSJ010',
    title: 'Elliptic-curve signatures (ECDSA / secp256k1 / P-curves)',
    severity: 'high',
    algorithm: 'ECDSA',
    primitive: 'signature',
    oid: '1.2.840.10045.4',
    classicalLevel: 128,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'ECDSA and other elliptic-curve signatures are broken by a quantum computer (Shor).',
    replacement: 'HybridSign (Ed25519+ML-DSA-65; CNSA 2.0: ML-DSA-87). For JWT: StandardJwt (RFC 9964).',
    example: "import { StandardJwt } from 'quantum-safe-ts';\nconst { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65');\nconst token = StandardJwt.sign({ sub: 'u1' }, privateJwk);",
    references: [NIST_IR_8547, CNSA2],
  },
  {
    id: 'QSJ011',
    title: 'Elliptic-curve / X25519 key agreement (ECDH)',
    severity: 'high',
    algorithm: 'ECDH',
    primitive: 'key-agree',
    oid: '1.3.132.1.12',
    classicalLevel: 128,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'ECDH and X25519/X448 key agreement are broken by a quantum computer, and are exposed to harvest-now-decrypt-later.',
    replacement: 'HybridKEM (X25519+ML-KEM-768; CNSA 2.0: pure ML-KEM-1024 via cnsa2.kem(), as NSA does not require hybrids). Keeps the classical component for defence in depth.',
    example: "import { HybridKEM } from 'quantum-safe-ts';\nconst kem = new HybridKEM();\nconst { ciphertext, sharedSecret } = kem.encapsulate(peerPublicKey);",
    references: [NIST_IR_8547, CNSA2],
  },
  {
    id: 'QSJ012',
    title: 'EdDSA (Ed25519 / Ed448) signatures',
    severity: 'high',
    algorithm: 'EdDSA',
    primitive: 'signature',
    oid: '1.3.101.112',
    classicalLevel: 128,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'Ed25519/Ed448 are elliptic-curve signatures and are broken by a quantum computer.',
    replacement: 'HybridSign keeps Ed25519 and adds ML-DSA: new HybridSign("Ed25519+ML-DSA-65").',
    example: "import { HybridSign } from 'quantum-safe-ts';\nconst signer = new HybridSign('Ed25519+ML-DSA-65');",
    references: [NIST_IR_8547, CNSA2],
  },
  {
    id: 'QSJ015',
    title: 'DSA',
    severity: 'high',
    algorithm: 'DSA',
    primitive: 'signature',
    oid: '1.2.840.10040.4.1',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'DSA is quantum-vulnerable and deprecated.',
    replacement: 'HybridSign (Ed25519+ML-DSA-65).',
    references: [NIST_IR_8547],
  },
  {
    id: 'QSJ016',
    title: 'Finite-field Diffie-Hellman',
    severity: 'high',
    algorithm: 'DH',
    primitive: 'key-agree',
    oid: '1.2.840.113549.1.3.1',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'Finite-field Diffie-Hellman is broken by a quantum computer.',
    replacement: 'HybridKEM (X25519+ML-KEM-768).',
    references: [NIST_IR_8547],
  },
  {
    id: 'QSJ020',
    title: 'AES-128',
    severity: 'medium',
    algorithm: 'AES-128',
    primitive: 'block-cipher',
    oid: '2.16.840.1.101.3.4.1.2',
    classicalLevel: 128,
    quantumLevel: 1,
    quantumVulnerable: false,
    description: "AES-128 is not broken by a quantum computer the way RSA/ECC are, but Grover's algorithm halves its effective strength. CNSA 2.0 requires AES-256.",
    replacement: 'AES-256 (use AES-256-GCM; Envelope uses AES-256-GCM).',
    references: [CNSA2],
  },
  {
    id: 'QSJ021',
    title: 'DES / 3DES / RC4 / Blowfish',
    severity: 'high',
    algorithm: 'TripleDES',
    primitive: 'block-cipher',
    oid: '1.2.840.113549.3.7',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: false,
    description: 'Broken or deprecated block/stream ciphers, independent of quantum computers.',
    replacement: 'AES-256-GCM.',
    references: ['https://csrc.nist.gov/pubs/sp/800/131/a/r2/final'],
  },
  {
    id: 'QSJ030',
    title: 'SHA-1',
    severity: 'medium',
    algorithm: 'SHA-1',
    primitive: 'hash',
    oid: '1.3.14.3.2.26',
    classicalLevel: 0,
    quantumLevel: 0,
    quantumVulnerable: false,
    description: 'SHA-1 is classically broken (collisions). CNSA 2.0 requires SHA-384 or SHA-512.',
    replacement: 'SHA-384 or SHA-512.',
    references: [CNSA2],
  },
  {
    id: 'QSJ031',
    title: 'MD5',
    severity: 'medium',
    algorithm: 'MD5',
    primitive: 'hash',
    oid: '1.2.840.113549.2.5',
    classicalLevel: 0,
    quantumLevel: 0,
    quantumVulnerable: false,
    description: 'MD5 is classically broken.',
    replacement: 'SHA-384 or SHA-512.',
    references: [CNSA2],
  },
  {
    id: 'QSJ032',
    title: 'SHA-256 where CNSA 2.0 applies',
    severity: 'low',
    algorithm: 'SHA-256',
    primitive: 'hash',
    oid: '2.16.840.1.101.3.4.2.1',
    classicalLevel: 128,
    quantumLevel: 1,
    quantumVulnerable: false,
    description: 'SHA-256 is secure today, but CNSA 2.0 requires SHA-384 or SHA-512. Only reported with --cnsa2.',
    replacement: 'SHA-384 or SHA-512 for CNSA 2.0 deployments.',
    references: [CNSA2],
  },
  {
    id: 'QSJ040',
    title: 'Classical JOSE/JWT signature or encryption algorithm',
    severity: 'high',
    algorithm: 'JWT classical algorithm',
    primitive: 'signature',
    classicalLevel: 112,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'JWT/JWS/JWE algorithms RS*, PS*, ES*, EdDSA, RSA-OAEP and ECDH-ES are quantum-vulnerable.',
    replacement: 'StandardJwt (RFC 9964, ML-DSA-44/65/87) for interoperable tokens.',
    example: "import { StandardJwt } from 'quantum-safe-ts';\nconst token = StandardJwt.sign(claims, privateJwk); // alg: ML-DSA-65",
    references: ['https://www.rfc-editor.org/info/rfc9964'],
  },
  {
    id: 'QSJ050',
    title: 'Classical-cryptography library in use',
    severity: 'info',
    algorithm: 'Classical crypto library',
    primitive: 'other',
    quantumLevel: 0,
    quantumVulnerable: false,
    description: 'Inventory entry: the project imports a library that implements classical (quantum-vulnerable) public-key cryptography. Review how it is used.',
    replacement: 'See the rules reported at the call sites.',
    references: [NIST_IR_8547],
  },
  {
    id: 'QSJ060',
    title: 'Private key material embedded in source',
    severity: 'critical',
    algorithm: 'Embedded private key',
    primitive: 'other',
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'A PEM-encoded private key appears in source code. Beyond quantum risk this is a direct secret leak.',
    replacement: 'Remove the key, rotate it, and load keys from a secrets manager at runtime.',
    references: ['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key'],
  },
  {
    id: 'QSJ070',
    title: 'RSA key shorter than 2048 bits',
    severity: 'critical',
    algorithm: 'RSA',
    primitive: 'pke',
    oid: '1.2.840.113549.1.1.1',
    classicalLevel: 80,
    quantumLevel: 0,
    quantumVulnerable: true,
    description: 'RSA keys below 2048 bits are classically weak, in addition to being quantum-vulnerable.',
    replacement: 'Migrate to a hybrid post-quantum scheme; do not simply enlarge RSA.',
    references: ['https://csrc.nist.gov/pubs/sp/800/131/a/r2/final'],
  },
  {
    id: 'QSJ900',
    title: 'Post-quantum cryptography in use',
    severity: 'info',
    algorithm: 'Post-quantum library',
    primitive: 'other',
    quantumLevel: 3,
    quantumVulnerable: false,
    description: 'Inventory entry: the project already uses a post-quantum library or algorithm.',
    replacement: 'Check parameter sets against CNSA 2.0 (ML-KEM-1024, ML-DSA-87) if required.',
    references: [CNSA2],
  },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function ruleById(id: string): Rule | undefined {
  return BY_ID.get(id);
}
