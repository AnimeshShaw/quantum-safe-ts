import jwt from 'jsonwebtoken'; // expect: QSJ050
import { SignJWT, importPKCS8, generateKeyPair } from 'jose'; // expect: QSJ050
import forge from 'node-forge'; // expect: QSJ050
import elliptic from 'elliptic'; // expect: QSJ050
import nacl from 'tweetnacl'; // expect: QSJ050
import { secp256k1 } from '@noble/curves/secp256k1'; // expect: QSJ010
import { ed25519 } from '@noble/curves/ed25519.js'; // expect: QSJ012
import { x25519 } from '@noble/curves/x25519'; // expect: QSJ011
import NodeRSA from 'node-rsa'; // expect: QSJ001
import { sha256 } from '@noble/hashes/sha2';
import { ml_kem768 } from '@noble/post-quantum/ml-kem'; // expect: QSJ900
import { HybridKEM } from 'quantum-safe-ts'; // expect: QSJ900

const t1 = jwt.sign(payload, key, { algorithm: 'RS256' }); // expect: QSJ040
const t2 = jwt.sign(payload, key, { algorithm: 'ES384', expiresIn: '1h' }); // expect: QSJ040
const t3 = jwt.verify(token, key, { algorithms: ['RS256', 'ES256'] }); // expect: QSJ040,QSJ040
const t4 = await new SignJWT({ sub: 'u' }).setProtectedHeader({ alg: 'EdDSA' }).sign(key); // expect: QSJ040
const k1 = await importPKCS8(pem, 'RS512'); // expect: QSJ040
const k2 = await generateKeyPair('ES256'); // expect: QSJ040
const hs = jwt.sign(payload, secret, { algorithm: 'HS256' });
const hs2 = jwt.verify(token, secret, { algorithms: ['HS256'] });
const header = { alg: 'HS512', typ: 'JWT' };

const rsa = new NodeRSA({ b: 2048 }); // expect: QSJ001
const pair = forge.pki.rsa.generateKeyPair({ bits: 2048 }); // expect: QSJ001
const weakPair = forge.pki.rsa.generateKeyPair({ bits: 1024 }); // expect: QSJ001,QSJ070
const ec = new elliptic.ec('secp256k1'); // expect: QSJ010
const EC = elliptic.ec;
const ec2 = new EC('secp256k1'); // expect: QSJ010
const kp = nacl.sign.keyPair(); // expect: QSJ012
const bx = nacl.box.keyPair(); // expect: QSJ011
const sm = nacl.sign(message, kp.secretKey); // expect: QSJ012
const rnd = nacl.randomBytes(24);
const sec = nacl.secretbox(msg, nonce, key);
