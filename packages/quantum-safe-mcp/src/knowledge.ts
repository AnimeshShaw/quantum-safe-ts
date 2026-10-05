/**
 * Static knowledge served by the MCP tools. Everything here is deterministic and offline: the server
 * never touches the network and never executes scanned code.
 */

export type UseCase = 'encrypt-data' | 'key-exchange' | 'sign-data' | 'jwt' | 'password-kdf' | 'file-or-vault-encryption';
export type Interop = 'none' | 'quantum-safe-py' | 'other-ecosystems';

export interface Recommendation {
  useCase: UseCase;
  summary: string;
  algorithm: string;
  api: string;
  code: string;
  compatibility: string;
  caveats: string[];
  alternatives: string[];
}

const COMMON_CAVEATS = [
  'quantum-safe-ts is pre-1.0, not independently audited, and not FIPS 140-3 validated.',
  'JavaScript/WebAssembly runtimes give no constant-time guarantee.',
  'Outside Node.js call `await init()` once before use; in Cloudflare Workers pass the precompiled module: init({ wasm }).',
  'Secret objects live in WASM memory: free() them or use `using`; wipe() any bytes you export.',
];

export function recommend(useCase: UseCase, requireCnsa2: boolean, interop: Interop): Recommendation {
  // CNSA 2.0: pure ML-KEM-1024 satisfies key establishment (NSA does not require hybrid and says not to use one on NSS
  // mission systems except NSA-specified exceptions). Pure ML-KEM-1024 seals as envelope v2 (HKDF-SHA-384).
  const kemName = requireCnsa2 ? 'ML-KEM-1024' : interop === 'other-ecosystems' ? 'X-Wing' : 'X25519+ML-KEM-768';
  const kemCtor = requireCnsa2 ? 'new KEM' : 'new HybridKEM';
  const kemImport = requireCnsa2 ? 'KEM' : 'HybridKEM';
  // Signatures: pure ML-DSA-87 under CNSA 2.0 (a hybrid is only `partial`); for other ecosystems the clean -v2 format; otherwise the default hybrid.
  const sigName = requireCnsa2 ? 'ML-DSA-87' : interop === 'other-ecosystems' ? 'ML-DSA-65-v2' : 'Ed25519+ML-DSA-65';
  const sigCls = sigName.includes('+') ? 'HybridSign' : 'Sign';
  const cnsaCaveats = requireCnsa2
    ? [
        'CNSA 2.0 parameter sets are selected (pure ML-KEM-1024, ML-DSA-87), but compliance for National Security Systems runs through FIPS 140-3 validated modules, which this library is not.',
        'CNSA 2.0 software/firmware signing requires LMS or XMSS (SP 800-208); neither is implemented yet.',
        'Pure ML-KEM-1024 envelopes (v2: HKDF-SHA-384 + AES-256-GCM) are read and written by quantum-safe-py too. X25519+ML-KEM-1024 hybrids are NOT CNSA 2.0 compliant: NSA\'s CNSA 2.0 FAQ says hybrids are not required and not to be used on NSS mission systems except NSA-specified exceptions.',
        'Run cnsa2.report() to see exactly which requirements are and are not met.',
      ]
    : [];
  const interopNote =
    interop === 'other-ecosystems'
      ? 'Interoperable with other X-Wing / RFC 9964 implementations (for example @noble/post-quantum, @hpke/hybridkem-x-wing). X-Wing is NOT readable by quantum-safe-py; RFC 9964 (StandardJwt) tokens and public JWKs are readable by quantum-safe-py 0.3.1 and later.'
      : interop === 'quantum-safe-py'
        ? 'Byte-compatible with quantum-safe-py in both directions (envelopes, keys, signed messages). Not readable by third-party libraries.'
        : 'Default suites are byte-compatible with quantum-safe-py; use the X-Wing / RFC 9964 options when other ecosystems must read the data.';

  const base = { useCase, caveats: [...cnsaCaveats, ...COMMON_CAVEATS] };
  switch (useCase) {
    case 'encrypt-data':
    case 'file-or-vault-encryption':
      return {
        ...base,
        summary: 'Encrypt data to a recipient public key with a hybrid KEM + AES-256-GCM envelope.',
        algorithm: kemName,
        api: `${kemImport} + Envelope.seal / Envelope.open`,
        code: `import { init, ${kemImport}, Envelope, utf8 } from 'quantum-safe-ts';
await init(); // no-op on Node.js
const kem = ${kemCtor}('${kemName}');
using pair = kem.generateKeyPair();
const sealed = Envelope.seal(plaintext, pair.publicKey, { aad: utf8('context-binding') });
const recovered = Envelope.open(sealed, pair.secretKey); // wipe(recovered) when done${useCase === 'file-or-vault-encryption' ? '\n// For per-item keys derive subkeys from a master key: (await deriveMasterKey(password, salt)).deriveKey(32, utf8("item-key-v1"))' : ''}`,
        compatibility: interopNote,
        alternatives: [
          'For the shortest code with nothing to free, use the easy layer: const { publicKey, secretKey } = easy.generateEncryptionKeys(); easy.encrypt(publicKey, data); easy.decrypt(secretKey, sealed). Keys are PEM strings in the JS heap, so prefer the class API when keys must stay in WASM memory.',
          'If you only need a raw KEM primitive, use WebCrypto ML-KEM (Node >= 24.7) or @noble/post-quantum.',
        ],
      };
    case 'key-exchange':
      return {
        ...base,
        summary: 'Establish a shared secret with a hybrid KEM, then derive purpose-specific keys with HKDF.',
        algorithm: kemName,
        api: `${kemImport}.encapsulate / decapsulate, SecretBytes.deriveKey`,
        code: `const kem = ${kemCtor}('${kemName}');
// Receiver: pair = kem.generateKeyPair(); publish pair.publicKey
const { ciphertext, sharedSecret } = kem.encapsulate(receiverPublicKey); // sender
using recovered = kem.decapsulate(pair.secretKey, ciphertext);          // receiver
const sessionKey = sharedSecret.deriveKey(32, utf8('myapp-session-v1'));`,
        compatibility: interopNote,
        alternatives: ['For TLS, rely on the platform: Node >= 24 and current browsers negotiate X25519MLKEM768 natively (RFC 10024).'],
      };
    case 'sign-data':
      return {
        ...base,
        summary: requireCnsa2
          ? 'Sign with pure ML-DSA-87, the CNSA 2.0 signature parameter set.'
          : interop === 'other-ecosystems'
            ? 'Sign with the clean -v2 format, whose ML-DSA half is plain FIPS 204 with a native context.'
            : 'Sign with a hybrid classical + post-quantum signature; both halves must verify.',
        algorithm: sigName,
        api: `${sigCls}.sign / verify`,
        code: `import { ${sigCls}, utf8 } from 'quantum-safe-ts';
const signer = new ${sigCls}('${sigName}');
using pair = signer.generateKeyPair();
const signed = signer.sign(message, pair.secretKey, { context: utf8('myapp-v1-docs') });
signer.verify(signed, pair.publicKey, { expectedContext: utf8('myapp-v1-docs') }); // throws VerificationError on failure`,
        compatibility:
          interop === 'other-ecosystems'
            ? 'The -v2 ML-DSA half is plain FIPS 204 ML-DSA with context quantum-safe-sig-v2 over M2 = len(algo)||algo||len(ctx)||ctx||message, so a third-party FIPS 204 library can verify it given M2. quantum-safe-py 0.3.1 and later reads it too; 0.3.0 does not.'
            : 'Default format: byte-compatible with every quantum-safe-py version (a message prefix with an empty FIPS 204 context); third-party ML-DSA libraries cannot verify it. The -v2 format (for example Ed25519+ML-DSA-65-v2) is cleaner and is read by quantum-safe-py 0.3.1 and later. Never use one key in both formats.',
        alternatives: [
          'Always sign with a context and verify with expectedContext: a signature without one is valid for any purpose of the key.',
          'For signatures other ecosystems must verify, use StandardJwt (RFC 9964) or the -v2 format with their FIPS 204 library.',
        ],
      };
    case 'jwt':
      return {
        ...base,
        summary: 'Issue JWTs signed with ML-DSA per RFC 9964 so any compliant JOSE library can verify them.',
        algorithm: requireCnsa2 ? 'ML-DSA-87' : 'ML-DSA-65',
        api: 'StandardJwt.generateKeyPair / sign / verify',
        code: `import { StandardJwt } from 'quantum-safe-ts';
const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('${requireCnsa2 ? 'ML-DSA-87' : 'ML-DSA-65'}', { kid: 'key-1' });
const token = StandardJwt.sign({ sub: 'user-1', aud: 'api' }, privateJwk, { issuer: 'https://issuer.example', expiresIn: 900 });
const claims = StandardJwt.verify(token, publicJwk, { issuer: 'https://issuer.example', audience: 'api' });`,
        compatibility:
          interop === 'quantum-safe-py'
            ? 'Use JWTSigner/JWTVerifier for tokens quantum-safe-py must verify: those are NOT RFC 9964 and only quantum-safe-py/-ts can verify them.'
            : 'RFC 9964 (published May 2026). Verified in tests against @noble/post-quantum and Node WebCrypto.',
        alternatives: ['The private JWK contains the secret seed as a string: store it like any secret key.'],
      };
    case 'password-kdf':
      return {
        ...base,
        summary: 'Stretch a password with Argon2id; derive separate auth and encryption keys from the result.',
        algorithm: 'Argon2id (19 MiB, t=2, p=1)',
        api: 'deriveMasterKey + SecretBytes.deriveKey',
        code: `import { deriveMasterKey, utf8 } from 'quantum-safe-ts';
using master = await deriveMasterKey(password.normalize('NFKC'), salt16); // run in a Web Worker in browsers
const authKey = master.deriveKey(32, utf8('myapp-auth-v1'));
const vaultKey = master.deriveKey(32, utf8('myapp-vault-v1'));`,
        compatibility: 'No quantum-safe-py equivalent (it has no master-password concept). Matches Node WebCrypto Argon2id in tests.',
        alternatives: ['Normalise Unicode passwords (NFKC) consistently everywhere: the library does not.'],
      };
  }
}

export interface ErrorInfo {
  name: string;
  code: string;
  meaning: string;
  fix: string;
}

/** Keep in sync with packages/quantum-safe-ts/src/errors.ts (a test in that package enforces it). */
export const ERRORS: readonly ErrorInfo[] = [
  { name: 'NotInitializedError', code: 'QS_NOT_INITIALIZED', meaning: 'The WASM module is not loaded yet.', fix: 'Call `await init()` once at startup (automatic on Node.js).' },
  { name: 'DecapsulationError', code: 'QS_DECAPSULATION_FAILED', meaning: 'The classical key-agreement half failed (invalid or low-order point).', fix: 'The ciphertext was not produced for this key, or is corrupted.' },
  { name: 'DecryptionAuthenticationError', code: 'QS_DECRYPTION_FAILED', meaning: 'AES-GCM authentication failed: wrong key, wrong AAD, or tampered data.', fix: 'Use the recipient secret key, the same `aad`, and unmodified data. ML-KEM implicit rejection surfaces here, not at decapsulate().' },
  { name: 'VerificationError', code: 'QS_VERIFICATION_FAILED', meaning: 'A signature or JWT did not verify. No detail is given by design.', fix: 'Check message, context, signature, public key, and for JWTs exp/nbf/iss/aud.' },
  { name: 'SigningError', code: 'QS_SIGNING_FAILED', meaning: 'Signing failed (RNG unavailable or key problem).', fix: 'Check the secret key matches the algorithm.' },
  { name: 'MalformedKeyError', code: 'QS_MALFORMED_KEY', meaning: 'A key has the wrong length or encoding for its algorithm.', fix: 'Use keys produced by this library or quantum-safe-py for the same algorithm; look for truncation.' },
  { name: 'MalformedCiphertextError', code: 'QS_MALFORMED_CIPHERTEXT', meaning: 'A ciphertext, sealed message or signature blob is truncated or invalid.', fix: 'Pass the exact bytes produced by seal()/encapsulate().' },
  { name: 'MalformedSignatureError', code: 'QS_MALFORMED_SIGNATURE', meaning: 'A signature (for example an LMS/HSS signature) is truncated, has trailing bytes, or disagrees with the level count of the key.', fix: 'Pass the exact signature bytes the signer produced.' },
  { name: 'AlgorithmMismatchError', code: 'QS_ALGORITHM_MISMATCH', meaning: 'Key and message algorithm identifiers disagree.', fix: 'Use a key generated for the same algorithm string.' },
  { name: 'HkdfOutputTooLongError', code: 'QS_HKDF_OUTPUT_TOO_LONG', meaning: 'Requested more than 8160 bytes from HKDF-SHA256.', fix: 'Request at most 8160 bytes from deriveKey().' },
  { name: 'KdfError', code: 'QS_KDF_FAILED', meaning: 'Argon2id derivation failed (for example salt shorter than 8 bytes).', fix: 'Use a random salt of at least 16 bytes.' },
  { name: 'KeyParseError', code: 'QS_KEY_PARSE_ERROR', meaning: 'A key could not be parsed from PEM, CBOR or JWK (also: public/secret type confusion).', fix: 'Check the format, the key type, and that the data is complete.' },
  { name: 'IncompatibleKeyVersionError', code: 'QS_INCOMPATIBLE_KEY_VERSION', meaning: 'The key was written by a newer format version.', fix: 'Upgrade quantum-safe-ts.' },
  { name: 'PayloadTooLargeError', code: 'QS_PAYLOAD_TOO_LARGE', meaning: 'A payload exceeded the 10 MB parsing limit.', fix: 'Check you passed the right data.' },
  { name: 'UnsupportedFormatError', code: 'QS_UNSUPPORTED_FORMAT', meaning: 'The requested serialization is unsupported (for example a secret key as JWK).', fix: 'Export secret keys as CBOR or PEM.' },
  { name: 'UnsupportedAlgorithmError', code: 'QS_UNSUPPORTED_ALGORITHM', meaning: 'The algorithm name is unknown or not approved.', fix: 'Use kemSuites()/sigSuites() for valid names, e.g. "X25519+ML-KEM-768".' },
  { name: 'InvalidArgumentError', code: 'QS_INVALID_ARGUMENT', meaning: 'An argument has the wrong type or violates a limit (empty message, context > 255 bytes, freed object).', fix: 'Check argument types and limits.' },
  { name: 'PolicyViolationError', code: 'QS_POLICY_VIOLATION', meaning: 'A configured policy (for example CNSA 2.0 enforcement) rejected an algorithm.', fix: 'Use cnsa2.kem() (pure ML-KEM-1024) and cnsa2.hybridSign() or ML-DSA-87; cnsa2.report() lists what is still missing.' },
  { name: 'CryptoError', code: 'QS_INTERNAL_ERROR', meaning: 'Unexpected internal error in the WASM module (a bug).', fix: 'Report at https://github.com/AnimeshShaw/quantum-safe-ts/issues without secret data.' },
];

export function findError(query: string): ErrorInfo | undefined {
  const q = query.trim().toLowerCase();
  return ERRORS.find((e) => e.code.toLowerCase() === q || e.name.toLowerCase() === q || e.code.toLowerCase() === `qs_${q}`);
}

export const LLMS_TXT = `quantum-safe-ts: hybrid post-quantum cryptography for TypeScript/JavaScript (Rust core compiled to WASM).
Install: npm install quantum-safe-ts. Outside Node.js call await init() first.
Defaults: X25519+ML-KEM-768 (HybridKEM), Ed25519+ML-DSA-65 (HybridSign). CNSA 2.0 needs pure ML-KEM-1024 (cnsa2.kem(); Envelope v2 uses HKDF-SHA-384) and ML-DSA-87 (new Sign('ML-DSA-87')); hybrids are reported partial.
Envelope.seal(plaintext, publicKey, {aad}) / Envelope.open(sealed, secretKey). StandardJwt for RFC 9964 tokens. deriveMasterKey for Argon2id.
Pre-1.0, unaudited, not FIPS-validated, no constant-time guarantee in JS/WASM.
Docs: https://github.com/AnimeshShaw/quantum-safe-ts`;
