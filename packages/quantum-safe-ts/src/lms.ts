/**
 * LMS / HSS signature **verification** (RFC 8554, SHA-256, n = m = 32), the stateful hash-based scheme
 * CNSA 2.0 requires for software and firmware signing (with XMSS, via NIST SP 800-208).
 *
 * Verification only, deliberately: LMS signing is stateful, and reusing a one-time-signature index
 * destroys the scheme's security. Doing that safely needs a durable, atomic state store that a library
 * cannot provide for an embedding application, and SP 800-208 also requires key generation inside a
 * validated cryptographic module. Verifying a firmware or software signature needs none of that.
 *
 * Supported: `LMS_SHA256_M32_H{5,10,15,20,25}` with `LMOTS_SHA256_N32_W{1,2,4,8}`, HSS with 1 to 8
 * levels (a bare LMS key is HSS with one level). Not supported (rejected explicitly): the 192-bit and
 * SHAKE variants of SP 800-208, and XMSS.
 *
 * Verified against the RFC 8554 Appendix F test vectors and against signatures from an independent
 * implementation (pyhsslms).
 */
import { VerificationError } from './errors.js';
import { call } from './runtime.js';
import { bytes } from './utils.js';

/** Public parameters of an HSS public key. */
export interface HssPublicKeyInfo {
  /** Number of HSS levels (1 to 8). */
  readonly levels: number;
  /** RFC 8554 LMS type code of the top-level tree. */
  readonly lmsType: number;
  /** RFC 8554 LM-OTS type code of the top-level tree. */
  readonly otsType: number;
  readonly treeHeight: number;
  /** Winternitz parameter w (1, 2, 4 or 8). */
  readonly winternitz: number;
  /** Human-readable name, e.g. `LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8`. */
  readonly parameterSet: string;
}

export const Lms = {
  /**
   * Verifies an HSS signature over `message`.
   *
   * @param publicKey HSS public key: `u32(levels) || LMS public key` (60 bytes), as in RFC 8554 §6.3.
   * @param signature HSS signature: `u32(levels - 1) || (LMS signature || LMS public key)* || LMS signature`.
   * @throws {VerificationError} if the signature is well formed but does not verify.
   * @throws {MalformedKeyError} if the public key is structurally invalid.
   * @throws {MalformedSignatureError} if the signature is truncated, has trailing bytes, or its level count disagrees with the key.
   * @throws {UnsupportedAlgorithmError} for parameter sets outside the supported list.
   */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): void {
    if (!Lms.isValid(publicKey, message, signature)) throw new VerificationError();
  },

  /** Like {@link Lms.verify} but returns `false` for a well-formed, invalid signature. Structural problems still throw. */
  isValid(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    return call((w) => w.lmsVerify(bytes(publicKey, 'publicKey'), bytes(message, 'message'), bytes(signature, 'signature')));
  },

  /** Reads the parameter set of an HSS public key without verifying anything. */
  inspectPublicKey(publicKey: Uint8Array): HssPublicKeyInfo {
    return JSON.parse(call((w) => w.lmsInspectPublicKey(bytes(publicKey, 'publicKey')))) as HssPublicKeyInfo;
  },
} as const;
