// Labelled corpus: every line that must produce a finding carries `// expect: <ids>`.
// A line without a marker must produce NO finding. (Markers are the ground truth for precision/recall.)
const crypto = require('node:crypto');
const { createSign, createVerify, createECDH, createHash } = crypto;

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 4096 }); // expect: QSJ001
const weak = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }); // expect: QSJ001,QSJ070
const pss = crypto.generateKeyPair('rsa-pss', { modulusLength: 3072 }, () => {}); // expect: QSJ001
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // expect: QSJ010
const ed = crypto.generateKeyPairSync('ed25519'); // expect: QSJ012
const x = crypto.generateKeyPairSync('x25519'); // expect: QSJ011
const dsa = crypto.generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 }); // expect: QSJ015
const dh = crypto.generateKeyPairSync('dh', { group: 'modp14' }); // expect: QSJ016

const signer = createSign('RSA-SHA256'); // expect: QSJ002
const verifier = crypto.createVerify('RSA-SHA512'); // expect: QSJ002
const ecSigner = crypto.createSign('ecdsa-with-SHA256'); // expect: QSJ010
const ecdh = createECDH('prime256v1'); // expect: QSJ011
const group = crypto.getDiffieHellman('modp15'); // expect: QSJ016
const enc = crypto.publicEncrypt(pem, Buffer.from('x')); // expect: QSJ003
const dec = crypto.privateDecrypt(pem, ciphertext); // expect: QSJ003

const md5 = createHash('md5'); // expect: QSJ031
const sha1 = crypto.createHash('SHA1'); // expect: QSJ030
const sha1b = crypto.createHash('sha-1'); // expect: QSJ030
const aes128 = crypto.createCipheriv('aes-128-gcm', key16, iv); // expect: QSJ020
const aes128cbc = crypto.createDecipheriv('aes-128-cbc', key16, iv); // expect: QSJ020
const des = crypto.createCipheriv('des-ede3-cbc', key24, iv8); // expect: QSJ021
const rc4 = crypto.createCipheriv('rc4', key, null); // expect: QSJ021

// ---- Things that must NOT be flagged ----
const aes256 = crypto.createCipheriv('aes-256-gcm', key32, iv);
const sha256 = createHash('sha256');
const sha512 = createHash('sha512');
const hmac = crypto.createHmac('sha256', secret);
const rnd = crypto.randomBytes(32);
const scrypt = crypto.scryptSync(password, salt, 32);
const hkdf = crypto.hkdfSync('sha256', ikm, salt, info, 32);
// RSA, ECDSA and X25519 are mentioned only in this comment.
const label = 'RSA is mentioned in a string but nothing is called';
const rsaVariableName = 42;
function generateKeyPairSync(kind) { return kind; } // a local helper, not crypto
generateKeyPairSync(kind);

// Algorithm *labels* in data are not JWT settings (no JOSE library imported here).
const catalog = [{ algorithm: 'RSA-OAEP', title: 'a label' }, { algorithm: 'EdDSA' }, { alg: 'ES256' }];
