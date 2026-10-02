import { SecretBytes } from './keys.js';
import { call } from './runtime.js';
import { bytes, utf8 } from './utils.js';

/**
 * Derives a 32-byte master key from a password with Argon2id (19 MiB memory, 2 passes,
 * 1 lane: the OWASP interactive profile). The result stays in WASM memory as {@link SecretBytes};
 * use `deriveKey()` on it to obtain purpose-specific subkeys (for example an auth key and a
 * vault key with different `info` strings).
 *
 * This is **not** part of quantum-safe-py (which has no master-password concept), so there is no
 * cross-library compatibility requirement; the parameters are fixed so the same password and
 * salt always give the same key.
 *
 * Passwords are used as the UTF-8 bytes of the string you pass, with **no Unicode normalisation**.
 * If users may type the same password in different composed forms, normalise it first
 * (for example `password.normalize('NFKC')`) and do so consistently everywhere.
 *
 * The call is CPU- and memory-heavy. It currently runs synchronously on the calling thread inside
 * the returned promise; in a browser, run it in a Web Worker to keep the UI responsive.
 *
 * @param password The password (string, or bytes you control and should wipe afterwards).
 * @param salt At least 8 bytes; use 16+ random bytes per user.
 * @throws {KdfError} for a too-short salt.
 */
export async function deriveMasterKey(password: string | Uint8Array, salt: Uint8Array): Promise<SecretBytes> {
  const pw = typeof password === 'string' ? utf8(password) : bytes(password, 'password');
  const s = bytes(salt, 'salt');
  try {
    return new SecretBytes(call((w) => w.deriveMasterKey(pw, s)));
  } finally {
    if (typeof password === 'string') pw.fill(0);
  }
}
