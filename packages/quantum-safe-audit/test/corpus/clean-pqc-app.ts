// A project that is already post-quantum and uses only safe-today primitives: findings are the
// positive PQC signal only.
import { Envelope, HybridKEM, HybridSign, StandardJwt, utf8 } from 'quantum-safe-ts'; // expect: QSJ900
import { createCipheriv, createHash, createHmac, randomBytes, scryptSync } from 'node:crypto';

export function encrypt(plain: Uint8Array) {
  const kem = new HybridKEM('X25519+ML-KEM-1024');
  const pair = kem.generateKeyPair();
  const sealed = Envelope.seal(plain, pair.publicKey, { aad: utf8('v1') });
  const signer = new HybridSign('Ed25519+ML-DSA-87');
  const key = scryptSync('pw', randomBytes(16), 32);
  const c = createCipheriv('aes-256-gcm', key, randomBytes(12));
  const digest = createHash('sha512').update(plain).digest();
  const mac = createHmac('sha384', key).update(plain).digest();
  const token = StandardJwt.sign({ sub: 'u' }, privateJwk);
  return { sealed, signer, c, digest, mac, token };
}
