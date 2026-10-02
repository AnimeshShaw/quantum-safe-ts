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
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [claim: string]: unknown;
}

/** Clock-skew tolerance applied to `exp` / `nbf` (seconds), as in quantum-safe-py. */
const CLOCK_SKEW_SECONDS = 30;

const dec = new TextDecoder('utf-8', { fatal: true });

function jsonB64(obj: unknown): string {
  return toBase64Url(utf8(JSON.stringify(obj)));
}

function decodeJson(part: string, what: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(dec.decode(fromBase64Url(part)));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value as Record<string, unknown>;
  } catch {
    throw new InvalidArgumentError(`Malformed JWT: could not decode the ${what}.`);
  }
}

function splitToken(token: string): [string, string, string] {
  if (typeof token !== 'string') throw new InvalidArgumentError('token must be a string.');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new InvalidArgumentError(`Malformed JWT: expected 3 non-empty parts, got ${parts.length}.`);
  }
  return parts as [string, string, string];
}

interface ClaimChecks {
  issuer?: string | undefined;
  audience?: string | undefined;
  validateExp?: boolean | undefined;
  requireExp?: boolean | undefined;
  validateNbf?: boolean | undefined;
  now?: number | undefined;
}

/** Claim validation shared by both modes. Failures are a bare VerificationError (no oracle). */
const CLAIMS_MESSAGE = 'Token verification failed: the signature or a claim check (exp, nbf, iss, aud) did not pass.';

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

/** Signs quantum-safe-py-compatible JWTs. See the module notes: other JOSE libraries cannot verify them. */
export class JWTSigner {
  readonly algorithm: SignatureAlgorithm;
  readonly #secret: SecretKey;
  readonly #issuer: string | undefined;
  readonly #signer: Sign | HybridSign;

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

  /** Signs `claims` and returns `header.payload.signature`. */
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
  validateExp?: boolean;
  validateNbf?: boolean;
  /** Reject tokens that carry no `exp` claim (default false, as in quantum-safe-py). Recommended for anything that should expire. */
  requireExp?: boolean;
  /** Override "now" (Unix seconds), mainly for tests. */
  now?: number;
}

/** Verifies quantum-safe-py-compatible JWTs. */
export class JWTVerifier {
  readonly algorithm: SignatureAlgorithm;
  readonly #public: PublicKey;
  readonly #opts: JwtVerifierOptions;
  readonly #verifier: Sign | HybridSign;

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
  kty: 'AKP';
  alg: MlDsaJoseAlg;
  /** base64url of the FIPS 204 public key. */
  pub: string;
  /** base64url of the 32-byte seed. **Secret.** */
  priv?: string;
  kid?: string;
  use?: 'sig';
  key_ops?: string[];
}

const ML_DSA_ALGS: readonly string[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

function checkAlg(alg: unknown): MlDsaJoseAlg {
  if (typeof alg !== 'string' || !ML_DSA_ALGS.includes(alg)) {
    throw new UnsupportedAlgorithmError(`'${String(alg)}' is not an ML-DSA JOSE algorithm (ML-DSA-44/65/87).`);
  }
  return alg as MlDsaJoseAlg;
}

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
  issuer?: string;
  audience?: string;
  validateExp?: boolean;
  validateNbf?: boolean;
  /** Reject tokens that carry no `exp` claim (default false). Recommended for anything that should expire. */
  requireExp?: boolean;
  now?: number;
}

/** RFC 9964 ML-DSA JWTs: interoperable with any compliant JOSE implementation. */
export const StandardJwt = {
  /**
   * Generates an ML-DSA key pair as AKP JWKs. The private JWK contains the secret seed as a string
   * (inherent to JWK): store it as carefully as any secret key.
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

  /** Derives the public JWK from a private one. */
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

  /** Signs claims as a compact JWS (`alg` = the key's ML-DSA level). */
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
   * @throws {VerificationError} for an invalid signature or failed claim check.
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
