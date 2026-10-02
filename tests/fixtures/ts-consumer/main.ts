import {
  Envelope, HybridKEM, HybridSign, JWTSigner, JWTVerifier, QuantumSafeError, StandardJwt, cnsa2, deriveMasterKey,
  utf8, DecryptionAuthenticationError,
} from 'quantum-safe-ts';
import type { KemAlgorithm, SealedMessage } from 'quantum-safe-ts';

const algorithm: KemAlgorithm = 'X25519+ML-KEM-1024';
const kem = new HybridKEM(algorithm);
{
  using pair = kem.generateKeyPair(); // Symbol.dispose typing must work for consumers
  const sealed: SealedMessage = Envelope.seal(utf8('typed'), pair.publicKey, { aad: utf8('x') });
  const plain: Uint8Array = Envelope.open(sealed, pair.secretKey);
  if (new TextDecoder().decode(plain) !== 'typed') throw new Error('roundtrip');
  try {
    Envelope.open(new Uint8Array(3), pair.secretKey);
  } catch (e) {
    if (!(e instanceof QuantumSafeError)) throw e;
    const code: string = e.code;
    if (!code.startsWith('QS_')) throw e;
    if (e instanceof DecryptionAuthenticationError) throw e;
  }
}
const signer = new HybridSign('Ed25519+ML-DSA-87');
const sp = signer.generateKeyPair();
const token = new JWTSigner(sp, { issuer: 'me' }).sign({ sub: 'u' });
const claims = new JWTVerifier(sp.publicKey, { issuer: 'me' }).verify(token);
const s: string | undefined = claims.sub;
const { publicJwk, privateJwk } = StandardJwt.generateKeyPair('ML-DSA-65');
StandardJwt.verify(StandardJwt.sign({ a: 1 }, privateJwk), publicJwk);
void deriveMasterKey('pw', utf8('0123456789abcdef')).then((mk) => {
  console.log(JSON.stringify({ ok: s === 'u' && mk.length === 32 && cnsa2.report({ kem: algorithm }).checks.length > 0 }));
  sp.free();
  mk.free();
});
