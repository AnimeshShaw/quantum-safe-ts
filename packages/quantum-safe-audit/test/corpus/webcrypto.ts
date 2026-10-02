// WebCrypto usage (crypto.subtle) in TypeScript.
const subtle = globalThis.crypto.subtle;

async function run(data: Uint8Array) {
  const a = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt']); // expect: QSJ003
  const b = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, hash: 'SHA-256' }, true, ['sign']); // expect: QSJ002
  const c = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 3072, hash: 'SHA-384' }, true, ['sign']); // expect: QSJ001
  const d = await window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']); // expect: QSJ010
  const e = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']); // expect: QSJ011
  const f = await subtle.generateKey('Ed25519', true, ['sign']); // expect: QSJ012
  const g = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']); // expect: QSJ011
  const h = await subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, ['encrypt']); // expect: QSJ020
  const weak = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024, hash: 'SHA-256' }, true, ['encrypt']); // expect: QSJ003,QSJ070
  const i = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data); // expect: QSJ010

  // Post-quantum WebCrypto (Node >= 24.7, Chromium): a positive signal.
  const pq = await subtle.generateKey({ name: 'ML-KEM-768' }, true, ['encapsulateKey']); // expect: QSJ900
  const pqs = await subtle.generateKey('ML-DSA-65', true, ['sign']); // expect: QSJ900

  // ---- Must NOT be flagged ----
  const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const m = await subtle.digest('SHA-256', data);
  const hm = await subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
  const derived = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256);
  const other = { name: 'ECDSA' }; // a plain object that is never passed to subtle
  return [a, b, c, d, e, f, g, h, weak, i, pq, pqs, k, m, hm, derived, other];
}
export { run };
