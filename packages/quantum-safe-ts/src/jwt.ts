/**
 * JSON Web Tokens with post-quantum signatures, in two explicit modes.
 *
 * 1. **quantum-safe-py mode** ({@link JWTSigner} / {@link JWTVerifier}): byte-compatible with
 *    `quantum_safe.protocols.jwt`. The signature part is quantum-safe-py's signature blob (with a
 *    hidden 32-byte hedge prefix and a `jwt` context prefix), so **only quantum-safe-py and
 *    quantum-safe-ts can verify these tokens**; a generic JOSE library cannot.
 * 2. **Standards mode** ({@link StandardJwt}): RFC 9964 (ML-DSA for JOSE/COSE). FIPS 204 pure
 *    signatures with an empty context over the JWS signing input, `AKP` JWKs with a 32-byte
 *    seed as `priv`. Any RFC 9964 implementation can verify these. Prefer this mode unless you
 *    must interoperate with existing quantum-safe-py tokens.
 *
 * Neither mode accepts `alg: "none"` or symmetric algorithms, and the verifier always pins the
 * algorithm to the key rather than trusting the header.
 */
import { DEFAULT_SIGNATURE } from './algorithms.js';
import { AlgorithmMismatchError, InvalidArgumentError, UnsupportedAlgorithmError, VerificationError } from './errors.js';
import { KeyPair, PublicKey, SecretBytes, SecretKey } from './keys.js';
import { call } from './runtime.js';
import { HybridSign, Sign } from './signatures.js';
import type { SignatureAlgorithm } from './algorithms.js';
import { bytes, fromBase64Url, fromBase64UrlStrict, toBase64Url, utf8 } from './utils.js';

/** JWT claims. Standard registered claims are typed; any other JSON-serializable claim is allowed. */
export interface JwtClaims {
  /** Issuer. */
  iss?: string;
  /** Subject. */
  sub?: string;
  /** Audience: one value or a list. A verifier given `audience` requires it to be among them. */
  aud?: string | string[];
  /** Expiry, in Unix seconds. */
  exp?: number;
  /** Not-before time, in Unix seconds. */
  nbf?: number;
  /** Issued-at time, in Unix seconds. */
  iat?: number;
  /** Token identifier. */
  jti?: string;
  /** Any other claim. */
  [claim: string]: unknown;
}

/** Clock-skew tolerance applied to `exp` / `nbf` (seconds), as in quantum-safe-py. */
const CLOCK_SKEW_SECONDS = 30;

/** Strict UTF-8 decoder: invalid byte sequences throw instead of being replaced. */
const dec = new TextDecoder('utf-8', { fatal: true });

/** Serializes `obj` as JSON text and encodes it as unpadded base64url (one header or payload part of a token). */
function jsonB64(obj: unknown): string {
  return toBase64Url(utf8(JSON.stringify(obj)));
}

/**
 * Decodes one base64url token part as UTF-8 JSON and returns it, which must be a JSON object.
 * Any decoding or parsing failure, or a non-object value, is reported as `Malformed JWT: could not decode the <what>.`
 */
function decodeJson(part: string, what: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(dec.decode(fromBase64Url(part)));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value as Record<string, unknown>;
  } catch {
    throw new InvalidArgumentError(`Malformed JWT: could not decode the ${what}.`);
  }
}

/** Splits a compact token on `.` into exactly three non-empty parts, else throws {@link InvalidArgumentError}. */
function splitToken(token: string): [string, string, string] {
  if (typeof token !== 'string') throw new InvalidArgumentError('token must be a string.');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new InvalidArgumentError(`Malformed JWT: expected 3 non-empty parts, got ${parts.length}.`);
  }
  return parts as [string, string, string];
}

/** Checks applied to the claims of a token whose signature has already verified. */
interface ClaimChecks {
  /** Required value of `iss`; no check when undefined. */
  issuer?: string | undefined;
  /** Value that `aud` (a string or a list) must contain; no check when undefined. */
  audience?: string | undefined;
  /** Check `exp` when present (default true). */
  validateExp?: boolean | undefined;
  /** Fail when `exp` is absent (default false). */
  requireExp?: boolean | undefined;
  /** Check `nbf` when present (default true). */
  validateNbf?: boolean | undefined;
  /** The current time in Unix seconds (default: the system clock). */
  now?: number | undefined;
}

/** Claim validation shared by both modes. Failures are a bare VerificationError (no oracle). */
const CLAIMS_MESSAGE = 'Token verification failed: the signature or a claim check (exp, nbf, iss, aud) did not pass.';

/**
 * Applies `c` to `claims`: `exp` and `nbf` must be numbers and are compared with a 30-second tolerance ({@link CLOCK_SKEW_SECONDS}),
 * `iss` must equal `c.issuer` and `aud` must contain `c.audience` when those are set. Throws {@link VerificationError} with one fixed message
 * for every failure, so the caller cannot tell which check failed.
 */
function checkClaims(claims: Record<string, unknown>, c: ClaimChecks): void {
  const now = c.now ?? Date.now() / 1000;
  if (c.requireExp && !('exp' in claims)) throw new VerificationError(CLAIMS_MESSAGE);
  if ((c.validateExp ?? true) && 'exp' in claims) {
    const exp = claims.exp;
    if (typeof exp !== 'number' || now > exp + CLOCK_SKEW_SECONDS) throw new VerificationError(CLAIMS_MESSAGE);
  }
  if ((c.validateNbf ?? true) && 'nbf' in claims) {
    const nbf = claims.nbf;
    if (typeof nbf !== 'number' || now < nbf - CLOCK_SKEW_SECONDS) throw new VerificationError(CLAIMS_MESSAGE);
  }
  if (c.issuer !== undefined && claims.iss !== c.issuer) throw new VerificationError(CLAIMS_MESSAGE);
  if (c.audience !== undefined) {
    const aud = claims.aud;
    const list = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud : [];
    if (!list.includes(c.audience)) throw new VerificationError(CLAIMS_MESSAGE);
  }
}

/**
 * Builds the payload to sign: `iss` (when `issuer` is non-empty), `iat` (now, in Unix seconds) and `exp` (`iat + expiresIn` when `expiresIn`
 * is above 0), then the caller's `claims` on top, which override those. A negative or non-finite `expiresIn` throws
 * {@link InvalidArgumentError}.
 */
function buildClaims(claims: JwtClaims, issuer: string | undefined, expiresIn: number): JwtClaims {
  const now = Math.floor(Date.now() / 1000);
  const full: JwtClaims = {};
  if (issuer) full.iss = issuer;
  full.iat = now;
  if (expiresIn < 0 || !Number.isFinite(expiresIn)) {
    throw new InvalidArgumentError('expiresIn must be a finite number of seconds, 0 to omit exp, or positive. A negative value would silently produce a token without exp.');
  }
  if (expiresIn > 0) full.exp = now + expiresIn;
  return Object.assign(full, claims); // caller claims override, as in quantum-safe-py
}

// ---------------------------------------------------------------------------------------------
// quantum-safe-py mode
// ---------------------------------------------------------------------------------------------

/** Options for {@link JWTSigner}. */
export interface JwtSignerOptions {
  /** Added as the `iss` claim. */
  issuer?: string;
  /** Hedged signing (default true). */
  hedged?: boolean;
}

/** Per-token options for {@link JWTSigner.sign}. */
export interface JwtSignOptions {
  /** Token lifetime in seconds (default 3600). `0` omits `exp` (not recommended). */
  expiresIn?: number;
  /** Signing context for domain separation (default `"jwt"`). Must match on verification. */
  context?: Uint8Array;
}

/**
 * Signs quantum-safe-py-compatible JWTs. See the module notes: other JOSE libraries cannot verify them.
 *
 * The header is `{ alg, typ: "JWT", "qs-version": 1 }` with `alg` the key's algorithm name; the payload is built from the claims you pass plus
 * `iss`, `iat` and `exp`. The signature part is base64url of the signature blob over `header.payload`.
 *
 * @example
 * ```ts
 * using pair = new Sign('ML-DSA-65').generateKeyPair();
 * const token = new JWTSigner(pair, { issuer: 'auth.example' }).sign({ sub: 'alice' }, { expiresIn: 600 });
 * const claims = new JWTVerifier(pair.publicKey, { issuer: 'auth.example' }).verify(token);
 * ```
 */
export class JWTSigner {
  /** The signature algorithm of the key; it is written to the header `alg`. */
  readonly algorithm: SignatureAlgorithm;
  readonly #secret: SecretKey;
  readonly #issuer: string | undefined;
  readonly #signer: Sign | HybridSign;

  /**
   * Creates a signer for `key`, using a hybrid signer when the algorithm name contains `+` and a single-algorithm signer otherwise.
   * @param key - The secret key, or a key pair whose secret key is used.
   * @param options - Issuer and hedging. Hedged signing is on by default.
   * @throws {InvalidArgumentError} if `key` is not a {@link SecretKey} or {@link KeyPair}.
   * @throws {UnsupportedAlgorithmError} if the key's algorithm is not a supported signature algorithm.
   */
  constructor(key: SecretKey | KeyPair, options: JwtSignerOptions = {}) {
    this.#secret = key instanceof KeyPair ? key.secretKey : key;
    if (!(this.#secret instanceof SecretKey)) throw new InvalidArgumentError('key must be a SecretKey or KeyPair.');
    this.algorithm = this.#secret.algorithm as SignatureAlgorithm;
    this.#issuer = options.issuer;
    const hedged = options.hedged ?? true;
    this.#signer = this.algorithm.includes('+')
      ? new HybridSign(this.algorithm as never, { hedged })
      : new Sign(this.algorithm as never, { hedged });
  }

  /**
   * Signs `claims` and returns `header.payload.signature`.
   * @param claims - Claims to include; they override the generated `iss`, `iat` and `exp`.
   * @param options - `expiresIn` in seconds (default 3600; `0` omits `exp`) and the signing `context` (default the bytes of `"jwt"`).
   * @returns The compact token.
   * @throws {InvalidArgumentError} if `expiresIn` is negative or not finite, or `context` is longer than 255 bytes.
   * @throws {SigningError} if the underlying signing operation fails.
   */
  sign(claims: JwtClaims = {}, options: JwtSignOptions = {}): string {
    const header = { alg: this.algorithm, typ: 'JWT', 'qs-version': 1 };
    const headerB64 = jsonB64(header);
    const payloadB64 = jsonB64(buildClaims(claims, this.#issuer, options.expiresIn ?? 3600));
    const signingInput = utf8(`${headerB64}.${payloadB64}`);
    const sm = this.#signer.sign(signingInput, this.#secret, { context: options.context ?? utf8('jwt') });
    return `${headerB64}.${payloadB64}.${toBase64Url(sm.signature)}`;
  }
}

/** Options for {@link JWTVerifier}. */
export interface JwtVerifierOptions {
  /** If set, the `iss` claim must equal this. */
  issuer?: string;
  /** If set, the `aud` claim must include this. */
  audience?: string;
  /** Whether tokens were signed hedged (a 32-byte random prefix; the default, as in quantum-safe-py). Set `false` only for tokens from an unhedged signer. */
  hedged?: boolean;
}

/** Per-token options for {@link JWTVerifier.verify}. */
export interface JwtVerifyOptions {
  /** Must equal the context used to sign (default `"jwt"`). */
  context?: Uint8Array;
  /** Check `exp` when the token has one (default true). */
  validateExp?: boolean;
  /** Check `nbf` when the token has one (default true). */
  validateNbf?: boolean;
  /** Reject tokens that carry no `exp` claim (default false, as in quantum-safe-py). Recommended for anything that should expire. */
  requireExp?: boolean;
  /** Override "now" (Unix seconds), mainly for tests. */
  now?: number;
}

/**
 * Verifies quantum-safe-py-compatible JWTs.
 *
 * The algorithm is fixed by the public key: a token whose header names another algorithm is refused. The constructor's `issuer` and
 * `audience` apply to every token verified; the per-token options of {@link JWTVerifier.verify} are merged over the constructor's options.
 */
export class JWTVerifier {
  /** The signature algorithm of the public key; tokens must name it in their header. */
  readonly algorithm: SignatureAlgorithm;
  readonly #public: PublicKey;
  readonly #opts: JwtVerifierOptions;
  readonly #verifier: Sign | HybridSign;

  /**
   * Creates a verifier for `publicKey`, using a hybrid verifier when the algorithm name contains `+`.
   * @param publicKey - The signer's public key.
   * @param options - Required issuer and audience, and whether the tokens were signed hedged (default true).
   * @throws {InvalidArgumentError} if `publicKey` is not a {@link PublicKey}.
   * @throws {UnsupportedAlgorithmError} if the key's algorithm is not a supported signature algorithm.
   */
  constructor(publicKey: PublicKey, options: JwtVerifierOptions = {}) {
    if (!(publicKey instanceof PublicKey)) throw new InvalidArgumentError('publicKey must be a PublicKey.');
    this.#public = publicKey;
    this.#opts = options;
    this.algorithm = publicKey.algorithm as SignatureAlgorithm;
    const hedged = options.hedged ?? true;
    this.#verifier = this.algorithm.includes('+')
      ? new HybridSign(this.algorithm as never, { hedged })
      : new Sign(this.algorithm as never, { hedged });
  }

  /**
   * Verifies the signature, then the `exp`/`nbf`/`iss`/`aud` claims, and returns the claims.
   *
   * The signature part must be canonical unpadded base64url. `exp` and `nbf` are checked with a 30-second tolerance.
   * @param token - The compact token.
   * @param options - The signing `context` (default the bytes of `"jwt"`), which must equal the one used to sign, and per-token claim checks.
   * @returns The payload claims.
   * @throws {VerificationError} for an invalid signature or failed claim check (no detail, by design).
   * @throws {InvalidArgumentError} if the token is structurally malformed.
   * @throws {UnsupportedAlgorithmError} if the header `alg` differs from the key's algorithm.
   */
  verify(token: string, options: JwtVerifyOptions = {}): JwtClaims {
    const [h, p, s] = splitToken(token);
    const header = decodeJson(h, 'header');
    if (header.alg !== this.algorithm) {
      throw new UnsupportedAlgorithmError(`Token algorithm '${String(header.alg)}' does not match the key ('${this.algorithm}').`);
    }
    const claims = decodeJson(p, 'payload');
    let blob: Uint8Array;
    try {
      blob = fromBase64UrlStrict(s); // one spelling per signature: no padding, no non-canonical trailing bits
    } catch {
      throw new VerificationError();
    }
    this.#verifier.verifyBytes(utf8(`${h}.${p}`), blob, this.#public, { context: options.context ?? utf8('jwt') });
    checkClaims(claims, { ...this.#opts, ...options });
    return claims as JwtClaims;
  }
}

// ---------------------------------------------------------------------------------------------
// Standards mode (RFC 9964)
// ---------------------------------------------------------------------------------------------

/** JOSE `alg` values for ML-DSA (RFC 9964). */
export type MlDsaJoseAlg = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

/** An `AKP` JSON Web Key for ML-DSA (RFC 9964). `priv` (the 32-byte seed) is present only on private keys. */
export interface AkpJwk {
  /** Key type: always `"AKP"`. */
  kty: 'AKP';
  /** The ML-DSA parameter set of the key. */
  alg: MlDsaJoseAlg;
  /** base64url of the FIPS 204 public key. */
  pub: string;
  /** base64url of the 32-byte seed. **Secret.** */
  priv?: string;
  /** Key identifier; copied into the token header when signing. */
  kid?: string;
  /** Intended use of the key. */
  use?: 'sig';
  /** Permitted key operations. */
  key_ops?: string[];
}

/** The three ML-DSA JOSE `alg` names accepted by {@link checkAlg}. */
const ML_DSA_ALGS: readonly string[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

/** Returns `alg` typed as an {@link MlDsaJoseAlg}, or throws {@link UnsupportedAlgorithmError} for any other value. */
function checkAlg(alg: unknown): MlDsaJoseAlg {
  if (typeof alg !== 'string' || !ML_DSA_ALGS.includes(alg)) {
    throw new UnsupportedAlgorithmError(`'${String(alg)}' is not an ML-DSA JOSE algorithm (ML-DSA-44/65/87).`);
  }
  return alg as MlDsaJoseAlg;
}

/**
 * Checks that `jwk` is an AKP key with a supported `alg` and a string `pub` (and a string `priv` when `needPrivate`), and returns its `alg`.
 * Throws {@link InvalidArgumentError} for a missing member or another `kty`, and {@link UnsupportedAlgorithmError} for another `alg`.
 */
function checkJwk(jwk: AkpJwk, needPrivate: boolean): MlDsaJoseAlg {
  if (jwk === null || typeof jwk !== 'object' || jwk.kty !== 'AKP') throw new InvalidArgumentError('JWK must have kty "AKP".');
  const alg = checkAlg(jwk.alg);
  if (typeof jwk.pub !== 'string') throw new InvalidArgumentError('JWK is missing "pub".');
  if (needPrivate && typeof jwk.priv !== 'string') throw new InvalidArgumentError('JWK is missing "priv" (seed).');
  return alg;
}

/** Options for {@link StandardJwt.sign}. */
export interface StandardSignOptions {
  /** Added as the `iss` claim. */
  issuer?: string;
  /** Token lifetime in seconds (default 3600). `0` omits `exp`. */
  expiresIn?: number;
}

/** Options for {@link StandardJwt.verify}. */
export interface StandardVerifyOptions {
  /** If set, the `iss` claim must equal this. */
  issuer?: string;
  /** If set, the `aud` claim must include this. */
  audience?: string;
  /** Check `exp` when the token has one (default true). */
  validateExp?: boolean;
  /** Check `nbf` when the token has one (default true). */
  validateNbf?: boolean;
  /** Reject tokens that carry no `exp` claim (default false). Recommended for anything that should expire. */
  requireExp?: boolean;
  /** Override "now" (Unix seconds), mainly for tests. */
  now?: number;
}

/**
 * RFC 9964 ML-DSA JWTs: interoperable with any compliant JOSE implementation.
 *
 * @example
 * ```ts
 * const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65');
 * const token = StandardJwt.sign({ sub: 'alice' }, privateJwk, { expiresIn: 600 });
 * const claims = StandardJwt.verify(token, publicJwk, { requireExp: true });
 * ```
 */
export const StandardJwt = {
  /**
   * Generates an ML-DSA key pair as AKP JWKs. The private JWK contains the secret seed as a string
   * (inherent to JWK): store it as carefully as any secret key.
   * @param alg - The ML-DSA parameter set (default: the library's default signature algorithm).
   * @param options - `kid` is copied into both JWKs when non-empty.
   * @returns The public JWK (no `priv`) and the private JWK (with `priv`, the base64url 32-byte seed).
   * @throws {UnsupportedAlgorithmError} if `alg` is not `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`.
   */
  generateKeyPair(alg: MlDsaJoseAlg = DEFAULT_SIGNATURE as MlDsaJoseAlg, options: { kid?: string } = {}): {
    publicJwk: AkpJwk;
    privateJwk: AkpJwk;
  } {
    checkAlg(alg);
    const pair = call((w) => w.mldsaStandardKeyGen(alg));
    try {
      const pub = toBase64Url(pair.publicKey);
      const seed = new SecretBytes(pair.takeSeed());
      try {
        const seedBytes = seed.exportBytes();
        const priv = toBase64Url(seedBytes);
        seedBytes.fill(0);
        const common = { kty: 'AKP' as const, alg, pub, ...(options.kid ? { kid: options.kid } : {}) };
        return { publicJwk: { ...common }, privateJwk: { ...common, priv } };
      } finally {
        seed.free();
      }
    } finally {
      pair.free();
    }
  },

  /**
   * Derives the public JWK from a private one.
   * @param privateJwk - An AKP JWK with `priv`.
   * @returns A JWK with `kty`, `alg`, `pub` and, when the private JWK has a non-empty `kid`, `kid`.
   * @throws {InvalidArgumentError} if `privateJwk` is not an AKP key, lacks `pub` or `priv`, or has a `priv` that is not base64url.
   * @throws {UnsupportedAlgorithmError} if its `alg` is not an ML-DSA JOSE algorithm.
   * @throws {MalformedKeyError} if `priv` is not a valid seed.
   */
  publicJwk(privateJwk: AkpJwk): AkpJwk {
    const alg = checkJwk(privateJwk, true);
    const seedBytes = fromBase64Url(privateJwk.priv!);
    const seed = SecretBytes.from(seedBytes);
    seedBytes.fill(0);
    try {
      const pub = toBase64Url(call((w) => w.mldsaStandardPublicFromSeed(alg, seed._wasm)));
      return { kty: 'AKP', alg, pub, ...(privateJwk.kid ? { kid: privateJwk.kid } : {}) };
    } finally {
      seed.free();
    }
  },

  /**
   * Signs claims as a compact JWS (`alg` = the key's ML-DSA level).
   *
   * The header is `{ alg, typ: "JWT" }` plus `kid` when the JWK has one. The signature is FIPS 204 ML-DSA with an empty context over
   * `header.payload`.
   * @param claims - Claims to include; they override the generated `iss`, `iat` and `exp`.
   * @param privateJwk - An AKP JWK with `priv`.
   * @param options - `issuer` and `expiresIn` in seconds (default 3600; `0` omits `exp`).
   * @returns The compact token.
   * @throws {InvalidArgumentError} if the JWK is malformed or `expiresIn` is negative or not finite.
   * @throws {UnsupportedAlgorithmError} if the JWK's `alg` is not an ML-DSA JOSE algorithm.
   * @throws {MalformedKeyError} if `priv` does not decode to a 32-byte seed.
   */
  sign(claims: JwtClaims, privateJwk: AkpJwk, options: StandardSignOptions = {}): string {
    const alg = checkJwk(privateJwk, true);
    const header: Record<string, unknown> = { alg, typ: 'JWT' };
    if (privateJwk.kid) header.kid = privateJwk.kid;
    const headerB64 = jsonB64(header);
    const payloadB64 = jsonB64(buildClaims(claims, options.issuer, options.expiresIn ?? 3600));
    const input = utf8(`${headerB64}.${payloadB64}`);
    const seedBytes = fromBase64Url(privateJwk.priv!);
    const seed = SecretBytes.from(seedBytes);
    seedBytes.fill(0);
    try {
      const sig = call((w) => w.mldsaStandardSign(alg, seed._wasm, input, new Uint8Array()));
      return `${headerB64}.${payloadB64}.${toBase64Url(sig)}`;
    } finally {
      seed.free();
    }
  },

  /**
   * Verifies a compact JWS against `publicJwk` and returns the claims. The algorithm is taken from
   * the key and must equal the header `alg`; `crit` headers are rejected.
   *
   * The signature part must be canonical unpadded base64url.
   * @param token - The compact token.
   * @param publicJwk - An AKP JWK with `pub`.
   * @param options - Claim checks (`issuer`, `audience`, `validateExp`, `validateNbf`, `requireExp`, `now`).
   * @returns The payload claims.
   * @throws {VerificationError} for an invalid signature or failed claim check.
   * @throws {AlgorithmMismatchError} if the header `alg` differs from the key's `alg`.
   * @throws {UnsupportedAlgorithmError} if the JWK's `alg` is not an ML-DSA JOSE algorithm, or the header has a `crit` member.
   * @throws {InvalidArgumentError} if the JWK or the token is malformed.
   * @throws {MalformedKeyError} if `pub` decodes to a key of the wrong length.
   */
  verify(token: string, publicJwk: AkpJwk, options: StandardVerifyOptions = {}): JwtClaims {
    const alg = checkJwk(publicJwk, false);
    const [h, p, s] = splitToken(token);
    const header = decodeJson(h, 'header');
    if (header.alg !== alg) {
      throw new AlgorithmMismatchError(`Token algorithm '${String(header.alg)}' does not match the key ('${alg}').`);
    }
    if ('crit' in header) throw new UnsupportedAlgorithmError('JWS "crit" headers are not supported.');
    const claims = decodeJson(p, 'payload');
    let sig: Uint8Array;
    let pub: Uint8Array;
    try {
      sig = fromBase64UrlStrict(s); // one spelling per signature: no padding, no non-canonical trailing bits
      pub = fromBase64Url(publicJwk.pub);
    } catch {
      throw new VerificationError();
    }
    const ok = call((w) => w.mldsaStandardVerify(alg, bytes(pub, 'pub'), utf8(`${h}.${p}`), new Uint8Array(), sig));
    if (!ok) throw new VerificationError();
    checkClaims(claims, options);
    return claims as JwtClaims;
  },
} as const;
