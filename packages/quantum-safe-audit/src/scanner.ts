/**
 * AST-based scanner for classical (quantum-vulnerable) cryptography in JavaScript/TypeScript.
 *
 * Why an AST and not grep: matching string literals finds comments and prose; walking the AST
 * resolves what is actually called, with which literal arguments (`generateKeyPairSync('rsa', ...)`,
 * `{ name: 'ECDSA' }`, `createHash('md5')`), and ignores commentary.
 *
 * Honest limits: static analysis sees only what the source names. Algorithms chosen at runtime
 * from configuration, constructed strings, plugins, or dependency internals are invisible, so an
 * empty result is not evidence of absence. This is an inventory and a migration aid, not a
 * compliance verdict.
 */
import ts from 'typescript';
import { SEVERITY_ORDER, ruleById } from './rules.js';
import type { Severity } from './rules.js';

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly file: string;
  /** 1-based. */
  readonly line: number;
  /** 1-based. */
  readonly column: number;
  readonly message: string;
  /** Short context (the matched literal / call), never a secret. */
  readonly detail?: string;
}

/** Thrown when a file cannot be analysed (for example pathologically deep nesting). Reported, never swallowed. */
export class ScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanError';
  }
}

export interface ScanOptions {
  /** Also report CNSA 2.0 hash gaps (SHA-256) as findings. */
  cnsa2?: boolean;
  /**
   * Honour `// qs-audit-ignore` comments (default true). Turn off in CI gates for untrusted code: a pull request could otherwise add the comment to
   * pass its own check.
   */
  ignoreInline?: boolean;
  /** Called with the number of findings suppressed by inline comments in a file. */
  onSuppressed?: (count: number) => void;
}

// ----------------------------------------------------------------------------------------------
// Knowledge tables
// ----------------------------------------------------------------------------------------------

/** JOSE algorithms that rely on RSA or elliptic curves. HS* (HMAC) and `none` are out of scope here. */
const CLASSICAL_JOSE = new Set([
  'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA',
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW',
  'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
]);

const JOSE_ALG_PROPERTIES = new Set(['alg', 'algorithm', 'algorithms']);
const JOSE_ALG_ARG_FUNCTIONS = new Set(['importPKCS8', 'importSPKI', 'importX509', 'generateKeyPair', 'importJWK', 'sign', 'verify']);

/** Libraries whose presence makes `{ alg|algorithm|algorithms: 'RS256' }` a JWT setting rather than a label. */
const JOSE_LIBS = /^(jsonwebtoken|jose|jws|jwa|node-jose|jwt-simple|njwt|express-jwt|express-jwt-authz|passport-jwt|@fastify\/jwt|fastify-jwt|jsrsasign|@panva\/.+|fast-jwt|@hapi\/jwt)$/;
/** Calls that take JOSE header/option objects. */
const JOSE_CALLS = new Set(['sign', 'verify', 'decode', 'setProtectedHeader', 'importJWK', 'importPKCS8', 'importSPKI', 'importX509', 'generateKeyPair', 'compactVerify', 'jwtVerify', 'jwtDecrypt']);

/** WebCrypto algorithm `name` -> rule. */
const WEBCRYPTO_NAMES: Record<string, string> = {
  'rsa-oaep': 'QSJ003',
  'rsassa-pkcs1-v1_5': 'QSJ002',
  'rsa-pss': 'QSJ001',
  ecdsa: 'QSJ010',
  ecdh: 'QSJ011',
  ed25519: 'QSJ012',
  ed448: 'QSJ012',
  x25519: 'QSJ011',
  x448: 'QSJ011',
};

const SUBTLE_METHODS = new Set([
  'generateKey', 'importKey', 'exportKey', 'sign', 'verify', 'encrypt', 'decrypt', 'deriveKey', 'deriveBits',
  'wrapKey', 'unwrapKey', 'encapsulateBits', 'decapsulateBits', 'encapsulateKey', 'decapsulateKey',
]);

/** node:crypto key-type literal -> rule. */
const KEYGEN_TYPES: Record<string, string> = {
  rsa: 'QSJ001', 'rsa-pss': 'QSJ001', ec: 'QSJ010', ed25519: 'QSJ012', ed448: 'QSJ012',
  x25519: 'QSJ011', x448: 'QSJ011', dsa: 'QSJ015', dh: 'QSJ016',
};

/** Module specifier -> what importing it means. `rule` set => a finding at the import; `inventory` => QSJ050. */
const MODULES: Array<{ match: RegExp; rule?: string; inventory?: string; pq?: boolean }> = [
  { match: /^node-rsa$/, rule: 'QSJ001' },
  { match: /^(@noble\/secp256k1|secp256k1|ecdsa-sig-formatter)$/, rule: 'QSJ010' },
  { match: /^@noble\/curves\/(secp256k1|p256|p384|p521|nist|bls12-381|bn254|jubjub|abstract\/weierstrass)(\.js)?$/, rule: 'QSJ010' },
  { match: /^(@noble\/ed25519)$/, rule: 'QSJ012' },
  { match: /^@noble\/curves\/(ed25519|ed448)(\.js)?$/, rule: 'QSJ012' },
  { match: /^@noble\/curves\/(x25519|x448)(\.js)?$/, rule: 'QSJ011' },
  { match: /^(elliptic|node-forge|tweetnacl|tweetnacl-ts|jsrsasign|libsodium(-wrappers(-sumo)?)?|sodium-native|openpgp|jsonwebtoken|jose|jws|jwa|jwk-to-pem|pem|selfsigned|node-jose|ssh2|sshpk|@peculiar\/webcrypto|@peculiar\/x509|asn1\.js)$/, inventory: '$1' },
  { match: /^(quantum-safe-ts|@noble\/post-quantum(\/.*)?|mlkem|crystals-kyber-js|@openpgp\/crystals-kyber-js|@oqs\/liboqs-js|pqc-kyber|@hpke\/hybridkem-x-wing|libcrux.*)$/, pq: true },
];

// ----------------------------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------------------------

/**
 * Finding details echo literals from the scanned code (algorithm names, module specifiers). That code
 * may be hostile, and reports are routinely pasted into LLM context (agents, MCP tools, PR bots), so a
 * literal is a prompt-injection channel. Keep only short, identifier-like text; redact the rest.
 */
export function safeDetail(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  if (text.length <= 64 && /^[A-Za-z0-9_.@/:+#\- ]*$/.test(text)) return text;
  return '[redacted: not an identifier-like string]';
}

function literalText(node: ts.Node | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return undefined;
}

function propertyNameText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return undefined;
}

/** `a.b.c` / `a.b['c']` -> ['a','b','c'] (best effort). */
function dottedPath(expr: ts.Expression): string[] {
  const parts: string[] = [];
  let cur: ts.Expression = expr;
  for (;;) {
    if (ts.isCallExpression(cur) || ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur) || ts.isAwaitExpression(cur)) {
      cur = (cur as ts.CallExpression | ts.NonNullExpression | ts.ParenthesizedExpression | ts.AwaitExpression).expression;
    } else if (ts.isPropertyAccessExpression(cur)) {
      parts.unshift(cur.name.text);
      cur = cur.expression;
    } else if (ts.isElementAccessExpression(cur)) {
      const t = literalText(cur.argumentExpression);
      if (t !== undefined) parts.unshift(t);
      cur = cur.expression;
    } else if (ts.isIdentifier(cur)) {
      parts.unshift(cur.text);
      break;
    } else {
      break;
    }
  }
  return parts;
}

function calleeName(call: ts.CallExpression | ts.NewExpression): string | undefined {
  const e = call.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  if (ts.isElementAccessExpression(e)) return literalText(e.argumentExpression);
  return undefined;
}

const PEM_PRIVATE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,40}?[A-Za-z0-9+/=\\n\r]{40,}/;

// ----------------------------------------------------------------------------------------------
// Per-file scan
// ----------------------------------------------------------------------------------------------

interface Pending {
  ruleId: string;
  node: ts.Node;
  detail?: string;
}

function scriptKind(file: string): ts.ScriptKind {
  const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
  switch (ext) {
    case '.tsx': return ts.ScriptKind.TSX;
    case '.jsx': return ts.ScriptKind.JSX;
    case '.js': case '.mjs': case '.cjs': return ts.ScriptKind.JS;
    default: return ts.ScriptKind.TS;
  }
}

/** Extracts `<script>` blocks from single-file components so Vue/Svelte/Astro code is scanned too. */
function extractScripts(text: string): Array<{ code: string; lineOffset: number; lang: 'ts' | 'js' }> {
  const out: Array<{ code: string; lineOffset: number; lang: 'ts' | 'js' }> = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const before = text.slice(0, m.index + m[0].indexOf('>') + 1);
    out.push({ code: m[2] ?? '', lineOffset: before.split('\n').length - 1, lang: /lang\s*=\s*["']ts["']/.test(m[1] ?? '') ? 'ts' : 'js' });
  }
  return out;
}

/** `// qs-audit-ignore QSJ010 [reason]` suppresses on the same line or the next code line. */
function suppressions(text: string): { fileWide: Set<string> | 'all' | null; lines: Map<number, Set<string> | 'all'> } {
  const lines = new Map<number, Set<string> | 'all'>();
  let fileWide: Set<string> | 'all' | null = null;
  const src = text.split('\n');
  const re = /(?:\/\/|\/\*|#|<!--)\s*qs-audit-ignore(-file)?\b([^\n]*)/;
  src.forEach((line, i) => {
    const m = re.exec(line);
    if (!m) return;
    const ids = (m[2] ?? '').match(/QSJ\d{3}/g);
    const set: Set<string> | 'all' = ids ? new Set(ids) : 'all';
    if (m[1]) {
      fileWide = set === 'all' || fileWide === 'all' ? 'all' : new Set([...(fileWide ?? []), ...set]);
      return;
    }
    for (const target of [i + 1, i + 2]) {
      const prev = lines.get(target);
      lines.set(target, prev === 'all' || set === 'all' ? 'all' : new Set([...(prev ?? []), ...set]));
    }
  });
  return { fileWide, lines };
}

function scanCode(file: string, code: string, lineOffset: number, kind: ts.ScriptKind, options: ScanOptions): Finding[] {
  const sf = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, true, kind);
  const pending: Pending[] = [];
  const add = (ruleId: string, node: ts.Node, detail?: string) => {
    const safe = safeDetail(detail);
    pending.push({ ruleId, node, ...(safe !== undefined ? { detail: safe } : {}) });
  };

  const handleModule = (spec: string, node: ts.Node) => {
    for (const m of MODULES) {
      const hit = m.match.exec(spec);
      if (!hit) continue;
      if (m.pq) add('QSJ900', node, spec);
      else if (m.rule) add(m.rule, node, spec);
      else if (m.inventory) add('QSJ050', node, spec);
      return;
    }
  };

  const joseLiteral = (node: ts.Node | undefined, anchor: ts.Node) => {
    const t = literalText(node);
    if (t !== undefined && CLASSICAL_JOSE.has(t)) add('QSJ040', anchor, t);
  };

  const keyType = (call: ts.CallExpression) => {
    const first = literalText(call.arguments[0]);
    if (first === undefined) return;
    const lower = first.toLowerCase();
    const rule = KEYGEN_TYPES[lower];
    if (rule) {
      add(rule, call, first);
      const opts = call.arguments[1];
      if (rule === 'QSJ001' && opts && ts.isObjectLiteralExpression(opts)) checkKeySize(opts);
    } else if (/^ml-(kem|dsa)-/i.test(first) || /^slh-dsa/i.test(first)) {
      add('QSJ900', call, first);
    } else if (CLASSICAL_JOSE.has(first)) {
      add('QSJ040', call, first); // jose.generateKeyPair('ES256')
    }
  };

  const checkKeySize = (obj: ts.ObjectLiteralExpression) => {
    for (const p of obj.properties) {
      if (!ts.isPropertyAssignment(p)) continue;
      const n = propertyNameText(p.name);
      if (n && /^(modulusLength|bits|keySize|keysize)$/i.test(n) && ts.isNumericLiteral(p.initializer)) {
        const bits = Number(p.initializer.text);
        if (bits > 0 && bits < 2048) add('QSJ070', p.initializer, `${bits} bits`);
      }
    }
  };

  const webCryptoDescriptor = (node: ts.Expression) => {
    // Accept `{ name: 'ECDSA', ... }` or a bare string algorithm name.
    const direct = literalText(node);
    if (direct !== undefined) {
      const rule = WEBCRYPTO_NAMES[direct.toLowerCase()];
      if (rule) add(rule, node, direct);
      else if (/^ml-(kem|dsa)-/i.test(direct)) add('QSJ900', node, direct);
      return;
    }
    if (!ts.isObjectLiteralExpression(node)) return;
    let name: string | undefined;
    let length: number | undefined;
    for (const p of node.properties) {
      if (!ts.isPropertyAssignment(p)) continue;
      const n = propertyNameText(p.name);
      if (n === 'name') name = literalText(p.initializer);
      if (n === 'length' && ts.isNumericLiteral(p.initializer)) length = Number(p.initializer.text);
      if (n === 'modulusLength' && ts.isNumericLiteral(p.initializer)) {
        const bits = Number(p.initializer.text);
        if (bits > 0 && bits < 2048) add('QSJ070', p.initializer, `${bits} bits`);
      }
    }
    if (name === undefined) return;
    const lower = name.toLowerCase();
    if (WEBCRYPTO_NAMES[lower]) add(WEBCRYPTO_NAMES[lower]!, node, name);
    else if (/^aes-/.test(lower) && length === 128) add('QSJ020', node, `${name}-128`);
    else if (/^ml-(kem|dsa)-/.test(lower)) add('QSJ900', node, name);
  };

  const handleCall = (call: ts.CallExpression) => {
    const name = calleeName(call);
    const path = dottedPath(call.expression);
    const first = literalText(call.arguments[0]);
    if (!name) return;

    switch (name) {
      case 'generateKeyPair':
      case 'generateKeyPairSync':
        keyType(call);
        break;
      case 'createSign':
      case 'createVerify':
        if (first && /^rsa-/i.test(first)) add('QSJ002', call, first);
        else if (first && /^ecdsa-with-/i.test(first)) add('QSJ010', call, first);
        break;
      case 'createECDH':
        add('QSJ011', call, first ?? 'ECDH');
        break;
      case 'createDiffieHellman':
      case 'createDiffieHellmanGroup':
      case 'getDiffieHellman':
        add('QSJ016', call, first);
        break;
      case 'publicEncrypt':
      case 'privateDecrypt':
      case 'privateEncrypt':
      case 'publicDecrypt':
        add('QSJ003', call, name);
        break;
      case 'createHash':
        if (first) {
          const h = first.toLowerCase().replace(/-/g, '');
          if (h === 'md5') add('QSJ031', call, first);
          else if (h === 'sha1') add('QSJ030', call, first);
          else if (h === 'sha256' && options.cnsa2) add('QSJ032', call, first);
        }
        break;
      case 'createCipheriv':
      case 'createDecipheriv':
      case 'createCipher':
      case 'createDecipher':
        if (first) {
          const c = first.toLowerCase();
          if (/^aes-?128/.test(c) || /^id-aes128/.test(c)) add('QSJ020', call, first);
          else if (/^(des|des-ede|des-ede3|des3|rc4|rc2|bf|blowfish)\b/.test(c)) add('QSJ021', call, first);
        }
        break;
      default:
        break;
    }

    // WebCrypto: crypto.subtle.* / subtle.*
    if (SUBTLE_METHODS.has(name) && path.length >= 2 && /^subtle$/i.test(path[path.length - 2] ?? '')) {
      for (const arg of call.arguments) webCryptoDescriptor(arg);
    }

    // JOSE helpers taking an algorithm literal: importPKCS8(pem, 'RS256'), generateKeyPair('ES256')
    if (JOSE_ALG_ARG_FUNCTIONS.has(name) && name !== 'generateKeyPair' && name !== 'sign' && name !== 'verify') {
      for (const arg of call.arguments) joseLiteral(arg, call);
    }

    // forge / tweetnacl / libsodium shapes
    const joined = path.join('.');
    if (/(^|\.)pki\.rsa(\.|$)/.test(joined) || /(^|\.)rsa\.(generateKeyPair|setPublicKey|setPrivateKey)$/.test(joined)) add('QSJ001', call, joined);
    else if (/(^|\.)pki\.ed25519(\.|$)/.test(joined)) add('QSJ012', call, joined);
    else if (/^(nacl|tweetnacl)\.sign(\.|$)/.test(joined)) add('QSJ012', call, joined);
    else if (/^(nacl|tweetnacl)\.(box|scalarMult)(\.|$)/.test(joined)) add('QSJ011', call, joined);
    else if (/(^|\.)crypto_(sign)(_|$)/.test(joined) || /^crypto_sign/.test(name)) add('QSJ012', call, name);
    else if (/^crypto_(box|kx|scalarmult)/.test(name)) add('QSJ011', call, name);

    // CommonJS require / dynamic import
    if (name === 'require' && ts.isIdentifier(call.expression) && first !== undefined) handleModule(first, call);
    if (call.expression.kind === ts.SyntaxKind.ImportKeyword && first !== undefined) handleModule(first, call);
  };

  const handleNew = (n: ts.NewExpression) => {
    const name = calleeName(n);
    const first = literalText(n.arguments?.[0]);
    if (name === 'NodeRSA') add('QSJ001', n, 'NodeRSA');
    else if (name === 'RSAKey') add('QSJ001', n, 'RSAKey');
    else if ((name === 'EC' || (name === 'ec' && dottedPath(n.expression).includes('elliptic'))) && first !== undefined) {
      add('QSJ010', n, first); // elliptic: new EC('secp256k1') / new elliptic.ec('secp256k1')
    }
    else if (name === 'SignJWT' || name === 'EncryptJWT' || name === 'CompactSign' || name === 'FlattenedSign') {
      /* algorithm arrives via setProtectedHeader({ alg }), detected below */
    }
  };

  const insideJoseCall = (node: ts.Node): boolean => {
    for (let cur: ts.Node | undefined = node.parent, depth = 0; cur && depth < 6; cur = cur.parent, depth++) {
      if (ts.isCallExpression(cur)) {
        const callee = calleeName(cur);
        if (callee && JOSE_CALLS.has(callee)) return true;
      }
    }
    return false;
  };

  const handleProperty = (p: ts.PropertyAssignment) => {
    const n = propertyNameText(p.name);
    if (!n) return;
    if (JOSE_ALG_PROPERTIES.has(n) && (joseFile || insideJoseCall(p))) {
      if (ts.isArrayLiteralExpression(p.initializer)) for (const el of p.initializer.elements) joseLiteral(el, el);
      else joseLiteral(p.initializer, p.initializer);
    }
    if (/^(modulusLength|bits|keySize|keysize)$/i.test(n) && ts.isNumericLiteral(p.initializer)) {
      const bits = Number(p.initializer.text);
      if (bits > 0 && bits < 2048) add('QSJ070', p.initializer, `${bits} bits`);
    }
    if (n === 'ecdhCurve' || n === 'groups') {
      const t = literalText(p.initializer);
      if (t && /MLKEM|kyber/i.test(t)) add('QSJ900', p.initializer, t);
    }
  };

  const handleString = (node: ts.StringLiteral | ts.NoSubstitutionTemplateLiteral | ts.TemplateExpression) => {
    const text = ts.isTemplateExpression(node) ? node.head.text + node.templateSpans.map((s) => s.literal.text).join('') : node.text;
    if (text.length > 60 && PEM_PRIVATE.test(text)) add('QSJ060', node, 'PEM private key');
  };

  // Pre-pass: does this file import a JOSE/JWT library? (Needed to tell a JWT `alg` setting from a label.)
  let joseFile = false;
  const probe = (node: ts.Node): void => {
    if (joseFile) return;
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && JOSE_LIBS.test(node.moduleSpecifier.text)) joseFile = true;
    else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
      const t = literalText(node.arguments[0]);
      if (t !== undefined && JOSE_LIBS.test(t)) joseFile = true;
    }
    ts.forEachChild(node, probe);
  };
  probe(sf);

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) handleModule(node.moduleSpecifier.text, node);
    else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) && ts.isStringLiteral(node.moduleReference.expression)) {
      handleModule(node.moduleReference.expression.text, node);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) handleModule(node.moduleSpecifier.text, node);
    else if (ts.isCallExpression(node)) handleCall(node);
    else if (ts.isNewExpression(node)) handleNew(node);
    else if (ts.isPropertyAssignment(node)) handleProperty(node);
    else if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node)) handleString(node);
    ts.forEachChild(node, visit);
  };
  visit(sf);

  // setProtectedHeader({ alg: 'RS256' }) is covered by handleProperty (alg). Dedupe + convert.
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const p of pending) {
    const rule = ruleById(p.ruleId);
    if (!rule) continue;
    const { line, character } = sf.getLineAndCharacterOfPosition(p.node.getStart(sf));
    const key = `${line}:${character}:${p.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      ruleId: rule.id,
      severity: rule.severity,
      file,
      line: line + 1 + lineOffset,
      column: character + 1,
      message: p.detail ? `${rule.title} (${p.detail})` : rule.title,
      ...(p.detail !== undefined ? { detail: p.detail } : {}),
    });
  }
  return findings;
}

/** Scans one file's text. Pure function: no filesystem access. Throws {@link ScanError} if the file cannot be analysed. */
export function scanSource(file: string, text: string, options: ScanOptions = {}): Finding[] {
  try {
    return scanSourceUnchecked(file, text, options);
  } catch (e) {
    if (e instanceof ScanError) throw e;
    if (e instanceof RangeError) throw new ScanError(`${file}: too deeply nested to analyse`);
    throw new ScanError(`${file}: ${(e as Error).message}`);
  }
}

function scanSourceUnchecked(file: string, text: string, options: ScanOptions): Finding[] {
  const lower = file.toLowerCase();
  let findings: Finding[];
  if (lower.endsWith('package.json')) {
    findings = scanPackageJson(file, text);
  } else if (/\.(vue|svelte|astro|html?)$/.test(lower)) {
    findings = extractScripts(text).flatMap((s) => scanCode(file, s.code, s.lineOffset, s.lang === 'ts' ? ts.ScriptKind.TS : ts.ScriptKind.JS, options));
  } else {
    findings = scanCode(file, text, 0, scriptKind(file), options);
  }
  if (options.ignoreInline === false) return findings;
  const sup = suppressions(text);
  let suppressed = 0;
  const kept = findings.filter((f) => {
    if (sup.fileWide === 'all' || sup.fileWide?.has(f.ruleId)) {
      suppressed++;
      return false;
    }
    const s = sup.lines.get(f.line);
    if (s === 'all' || s?.has(f.ruleId)) {
      suppressed++;
      return false;
    }
    return true;
  });
  if (suppressed > 0) options.onSuppressed?.(suppressed);
  return kept;
}

const CLASSICAL_DEPS = /^(node-rsa|elliptic|node-forge|tweetnacl|tweetnacl-ts|jsrsasign|libsodium(-wrappers(-sumo)?)?|sodium-native|openpgp|jsonwebtoken|jose|jws|jwa|jwk-to-pem|pem|selfsigned|node-jose|ssh2|sshpk|@peculiar\/webcrypto|@peculiar\/x509|secp256k1|@noble\/secp256k1|@noble\/ed25519|@noble\/curves|ecdsa-sig-formatter)$/;
const PQ_DEPS = /^(quantum-safe-ts|@noble\/post-quantum|mlkem|crystals-kyber-js|@openpgp\/crystals-kyber-js|@oqs\/liboqs-js|pqc-kyber|@hpke\/hybridkem-x-wing)$/;

function scanPackageJson(file: string, text: string): Finding[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return [];
  }
  const lines = text.split('\n');
  const out: Finding[] = [];
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = pkg[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const dep of Object.keys(deps)) {
      const ruleId = PQ_DEPS.test(dep) ? 'QSJ900' : CLASSICAL_DEPS.test(dep) ? (dep === 'node-rsa' ? 'QSJ001' : 'QSJ050') : undefined;
      if (!ruleId) continue;
      const rule = ruleById(ruleId)!;
      const idx = lines.findIndex((l) => l.includes(`"${dep}"`));
      out.push({
        ruleId,
        severity: rule.severity,
        file,
        line: idx >= 0 ? idx + 1 : 1,
        column: 1,
        message: `${rule.title} (${safeDetail(dep)} in ${section})`,
        detail: safeDetail(dep) ?? '',
      });
    }
  }
  return out;
}

/** Highest severity among findings, or `null` if there are none. */
export function maxSeverity(findings: readonly Finding[]): Severity | null {
  let best: Severity | null = null;
  for (const f of findings) if (best === null || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[best]) best = f.severity;
  return best;
}
