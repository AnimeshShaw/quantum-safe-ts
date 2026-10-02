//! wasm-bindgen glue over `quantum-safe-core`. This crate is **private**: the public API is the
//! hand-written TypeScript facade in `packages/quantum-safe-ts`, which validates inputs, maps
//! the `kind` tag on thrown errors to typed error classes, and documents everything.
//!
//! Secret-bearing objects (`SecretKey`, `SecretBytes`) live in WASM linear memory and are wiped
//! by the core's `Zeroizing` wrappers when `.free()` is called (or when dropped). Anything the
//! caller explicitly copies out (`exportBytes()`) is a JS-heap copy outside our control.

mod errors;

use errors::Kinded;
use quantum_safe_core::keys::{self, EncodedKey, KeyType, MigrationState};
use quantum_safe_core::suite::KemSuite;
use quantum_safe_core::{aead, envelope, kdf, kem, sig};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn err<E: Kinded>(e: E) -> JsValue {
    err_kind(e.kind(), &e.to_string())
}

fn err_kind(kind: &str, message: &str) -> JsValue {
    let e = js_sys::Error::new(message);
    let _ = js_sys::Reflect::set(&e, &JsValue::from_str("kind"), &JsValue::from_str(kind));
    e.into()
}

fn invalid(message: &str) -> JsValue {
    err_kind("invalid_argument", message)
}

#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ------------------------------------------------------------------------------------------
// Keys
// ------------------------------------------------------------------------------------------

fn parse_ms(s: Option<String>) -> Result<MigrationState, JsValue> {
    match s {
        None => Ok(MigrationState::HybridTransition),
        Some(v) => MigrationState::parse(&v).ok_or_else(|| invalid("unknown migration state")),
    }
}

fn default_ms(algorithm: &str) -> MigrationState {
    if algorithm.contains('+') || algorithm == "X-Wing" {
        MigrationState::HybridTransition
    } else {
        MigrationState::PqcOnly
    }
}

/// A public key (KEM or signature). Safe to share, log and store.
#[wasm_bindgen]
pub struct PublicKey {
    inner: EncodedKey,
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = migrationState)]
    pub fn migration_state(&self) -> String {
        self.inner.migration_state.as_str().to_string()
    }
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.raw.to_vec()
    }
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }
    #[wasm_bindgen(js_name = fingerprintColon)]
    pub fn fingerprint_colon(&self) -> String {
        self.inner.fingerprint_colon()
    }
    #[wasm_bindgen(js_name = toCbor)]
    pub fn to_cbor(&self) -> Vec<u8> {
        self.inner.to_cbor()
    }
    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }
    #[wasm_bindgen(js_name = toJwk)]
    pub fn to_jwk(&self) -> Result<String, JsValue> {
        self.inner.to_jwk().map_err(err)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(
        algorithm: &str,
        raw: &[u8],
        migration_state: Option<String>,
    ) -> Result<PublicKey, JsValue> {
        if raw.is_empty() {
            return Err(invalid("raw key bytes cannot be empty"));
        }
        let ms = match migration_state {
            Some(_) => parse_ms(migration_state)?,
            None => default_ms(algorithm),
        };
        Ok(PublicKey { inner: EncodedKey::new(algorithm, KeyType::Public, raw.to_vec(), ms) })
    }
    #[wasm_bindgen(js_name = fromCbor)]
    pub fn from_cbor(data: &[u8]) -> Result<PublicKey, JsValue> {
        Ok(PublicKey { inner: EncodedKey::from_cbor(data, KeyType::Public).map_err(err)? })
    }
    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: &str) -> Result<PublicKey, JsValue> {
        Ok(PublicKey { inner: EncodedKey::from_pem(pem, KeyType::Public).map_err(err)? })
    }
    #[wasm_bindgen(js_name = fromJwk)]
    pub fn from_jwk(json: &str) -> Result<PublicKey, JsValue> {
        Ok(PublicKey { inner: EncodedKey::from_jwk(json).map_err(err)? })
    }
}

impl PublicKey {
    fn core(&self) -> kem::PublicKey {
        kem::PublicKey { raw: self.inner.raw.to_vec(), algorithm: self.inner.algorithm.clone() }
    }
}

/// A secret key (KEM or signature). Call `.free()` when finished: it wipes the key material
/// held in WASM memory.
#[wasm_bindgen]
pub struct SecretKey {
    inner: EncodedKey,
}

#[wasm_bindgen]
impl SecretKey {
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = migrationState)]
    pub fn migration_state(&self) -> String {
        self.inner.migration_state.as_str().to_string()
    }
    /// Copies the raw key bytes into a JS `Uint8Array`. The caller owns wiping that copy.
    #[wasm_bindgen(js_name = exportBytes)]
    pub fn export_bytes(&self) -> Vec<u8> {
        self.inner.raw.to_vec()
    }
    #[wasm_bindgen(js_name = toCbor)]
    pub fn to_cbor(&self) -> Vec<u8> {
        self.inner.to_cbor()
    }
    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(
        algorithm: &str,
        raw: &[u8],
        migration_state: Option<String>,
    ) -> Result<SecretKey, JsValue> {
        if raw.is_empty() {
            return Err(invalid("raw key bytes cannot be empty"));
        }
        let ms = match migration_state {
            Some(_) => parse_ms(migration_state)?,
            None => default_ms(algorithm),
        };
        Ok(SecretKey { inner: EncodedKey::new(algorithm, KeyType::Secret, raw.to_vec(), ms) })
    }
    #[wasm_bindgen(js_name = fromCbor)]
    pub fn from_cbor(data: &[u8]) -> Result<SecretKey, JsValue> {
        Ok(SecretKey { inner: EncodedKey::from_cbor(data, KeyType::Secret).map_err(err)? })
    }
    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: &str) -> Result<SecretKey, JsValue> {
        Ok(SecretKey { inner: EncodedKey::from_pem(pem, KeyType::Secret).map_err(err)? })
    }
}

impl SecretKey {
    fn core(&self) -> kem::SecretKey {
        kem::SecretKey::new(self.inner.raw.to_vec(), self.inner.algorithm.clone())
    }
}

/// A matched key pair. Both accessors return independent copies; free the pair when done.
#[wasm_bindgen]
pub struct KeyPair {
    public: EncodedKey,
    secret: EncodedKey,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey { inner: self.public.clone() }
    }
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> SecretKey {
        SecretKey { inner: self.secret.clone() }
    }
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.public.algorithm.clone()
    }
    #[wasm_bindgen(js_name = toCborBundle)]
    pub fn to_cbor_bundle(&self) -> Result<Vec<u8>, JsValue> {
        keys::keypair_to_bundle(&self.public, &self.secret).map_err(err)
    }
    #[wasm_bindgen(js_name = fromCborBundle)]
    pub fn from_cbor_bundle(data: &[u8]) -> Result<KeyPair, JsValue> {
        let (public, secret) = keys::keypair_from_bundle(data).map_err(err)?;
        Ok(KeyPair { public, secret })
    }
}

fn keypair_from_core(public: kem::PublicKey, secret: kem::SecretKey, ms: MigrationState) -> KeyPair {
    KeyPair {
        public: EncodedKey::new(public.algorithm, KeyType::Public, public.raw, ms),
        secret: EncodedKey::new(secret.algorithm, KeyType::Secret, secret.raw.to_vec(), ms),
    }
}

// ------------------------------------------------------------------------------------------
// Secret byte strings (shared secrets, derived master keys)
// ------------------------------------------------------------------------------------------

/// 32 bytes of secret material (a KEM shared secret or Argon2id master key) kept in WASM memory.
#[wasm_bindgen]
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl SecretBytes {
    /// Moves a copy of `bytes` into WASM memory (for example a JWK `priv` seed). The caller
    /// should wipe their own JS-side copy.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretBytes, JsValue> {
        if bytes.is_empty() {
            return Err(invalid("secret bytes cannot be empty"));
        }
        Ok(SecretBytes { inner: Zeroizing::new(bytes.to_vec()) })
    }
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.inner.len()
    }
    /// Copies the secret into a JS `Uint8Array`. The caller owns wiping that copy.
    #[wasm_bindgen(js_name = exportBytes)]
    pub fn export_bytes(&self) -> Vec<u8> {
        self.inner.to_vec()
    }
    /// HKDF-SHA256 with no salt, matching `SharedSecret.derive_key` in quantum-safe-py.
    #[wasm_bindgen(js_name = deriveKey)]
    pub fn derive_key(&self, length: usize, info: &[u8]) -> Result<Vec<u8>, JsValue> {
        kdf::derive_key(&self.inner, info, length).map_err(err)
    }
}

// ------------------------------------------------------------------------------------------
// KEM
// ------------------------------------------------------------------------------------------

#[wasm_bindgen(js_name = kemGenerateKeyPair)]
pub fn kem_generate_key_pair(algorithm: &str) -> Result<KeyPair, JsValue> {
    let kp = kem::generate_keypair_for(algorithm).map_err(err)?;
    let ms = default_ms(algorithm);
    Ok(keypair_from_core(kp.public, kp.secret, ms))
}

/// Result of encapsulation. `ciphertext` may be read any number of times; the shared secret
/// can be taken exactly once.
#[wasm_bindgen]
pub struct Encapsulation {
    ciphertext: Vec<u8>,
    shared: Option<Zeroizing<Vec<u8>>>,
}

#[wasm_bindgen]
impl Encapsulation {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    #[wasm_bindgen(js_name = takeSharedSecret)]
    pub fn take_shared_secret(&mut self) -> Result<SecretBytes, JsValue> {
        self.shared
            .take()
            .map(|inner| SecretBytes { inner })
            .ok_or_else(|| invalid("shared secret was already taken"))
    }
}

#[wasm_bindgen(js_name = kemEncapsulate)]
pub fn kem_encapsulate(public_key: &PublicKey) -> Result<Encapsulation, JsValue> {
    let (ciphertext, ss) = kem::encapsulate(&public_key.core()).map_err(err)?;
    Ok(Encapsulation { ciphertext, shared: Some(Zeroizing::new(ss.to_vec())) })
}

#[wasm_bindgen(js_name = kemDecapsulate)]
pub fn kem_decapsulate(secret_key: &SecretKey, ciphertext: &[u8]) -> Result<SecretBytes, JsValue> {
    let ss = kem::decapsulate(&secret_key.core(), ciphertext).map_err(err)?;
    Ok(SecretBytes { inner: Zeroizing::new(ss.to_vec()) })
}

// ------------------------------------------------------------------------------------------
// Envelope
// ------------------------------------------------------------------------------------------

/// Seal `plaintext` to `public_key`; returns the CBOR-encoded `SealedMessage`.
#[wasm_bindgen(js_name = envelopeSeal)]
pub fn envelope_seal(plaintext: &[u8], public_key: &PublicKey, aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sealed = envelope::seal(plaintext, &public_key.core(), aad).map_err(err)?;
    sealed.to_cbor().map_err(err)
}

#[wasm_bindgen(js_name = envelopeOpen)]
pub fn envelope_open(sealed: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, JsValue> {
    let msg = envelope::SealedMessage::from_cbor(sealed).map_err(err)?;
    envelope::open(&msg, &secret_key.core()).map_err(err)
}

/// Non-secret metadata of a sealed message, as JSON.
#[wasm_bindgen(js_name = envelopeInspect)]
pub fn envelope_inspect(sealed: &[u8]) -> Result<String, JsValue> {
    let m = envelope::SealedMessage::from_cbor(sealed).map_err(err)?;
    Ok(json!({
        "version": m.version,
        "algorithm": m.algorithm,
        "kemCiphertextLength": m.kem_ct.len(),
        "nonceLength": m.nonce.len(),
        "ciphertextLength": m.ciphertext.len(),
        "aadLength": m.aad.len(),
    })
    .to_string())
}

/// Parsed fields of a sealed message (all public data).
#[wasm_bindgen]
pub struct SealedParts {
    inner: envelope::SealedMessage,
}

#[wasm_bindgen]
impl SealedParts {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u8 {
        self.inner.version
    }
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = kemCiphertext)]
    pub fn kem_ciphertext(&self) -> Vec<u8> {
        self.inner.kem_ct.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.inner.nonce.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.inner.ciphertext.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn aad(&self) -> Vec<u8> {
        self.inner.aad.clone()
    }
}

#[wasm_bindgen(js_name = sealedMessageParse)]
pub fn sealed_message_parse(data: &[u8]) -> Result<SealedParts, JsValue> {
    Ok(SealedParts { inner: envelope::SealedMessage::from_cbor(data).map_err(err)? })
}

#[wasm_bindgen(js_name = sealedMessageEncode)]
pub fn sealed_message_encode(
    version: u8,
    algorithm: &str,
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    envelope::SealedMessage {
        version,
        algorithm: algorithm.to_string(),
        kem_ct: kem_ciphertext.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
        aad: aad.to_vec(),
    }
    .to_cbor()
    .map_err(err)
}

#[wasm_bindgen(js_name = aesGcmNonceLength)]
pub fn aes_gcm_nonce_length() -> usize {
    aead::NONCE_LEN
}

// ------------------------------------------------------------------------------------------
// Argon2id master key
// ------------------------------------------------------------------------------------------

#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<SecretBytes, JsValue> {
    let key = kdf::derive_master_key(password, salt).map_err(err)?;
    Ok(SecretBytes { inner: Zeroizing::new(key.to_vec()) })
}

// ------------------------------------------------------------------------------------------
// Signatures
// ------------------------------------------------------------------------------------------

#[wasm_bindgen(js_name = sigGenerateKeyPair)]
pub fn sig_generate_key_pair(algorithm: &str) -> Result<KeyPair, JsValue> {
    let kp = sig::generate_keypair(algorithm).map_err(err)?;
    let ms = sig::SigSuite::parse(algorithm).map(|s| s.migration_state()).unwrap_or(MigrationState::PqcOnly);
    Ok(keypair_from_core(kp.public, kp.secret, ms))
}

/// Sign `message`; returns the CBOR-encoded `SignedMessage`.
#[wasm_bindgen(js_name = sigSign)]
pub fn sig_sign(
    secret_key: &SecretKey,
    message: &[u8],
    context: &[u8],
    deterministic: bool,
    signer_fingerprint: &str,
    signed_at: f64,
) -> Result<Vec<u8>, JsValue> {
    let opts = sig::SignOptions { deterministic, signer_fingerprint: signer_fingerprint.to_string(), signed_at };
    sig::sign(&secret_key.core(), message, context, &opts).map(|m| m.to_cbor()).map_err(err)
}

#[wasm_bindgen(js_name = sigVerify)]
pub fn sig_verify(signed_message: &[u8], public_key: &PublicKey) -> Result<(), JsValue> {
    let sm = sig::SignedMessage::from_cbor(signed_message).map_err(err)?;
    sig::verify(&sm, &public_key.core()).map_err(err)
}

#[wasm_bindgen(js_name = sigVerifyParts)]
pub fn sig_verify_parts(
    algorithm: &str,
    message: &[u8],
    signature_blob: &[u8],
    context: &[u8],
    public_key: &PublicKey,
) -> Result<(), JsValue> {
    sig::verify_parts(algorithm, message, signature_blob, context, &public_key.core()).map_err(err)
}

/// Non-secret metadata of a signed message, as JSON (the message itself is not echoed).
#[wasm_bindgen(js_name = signedMessageInspect)]
pub fn signed_message_inspect(signed_message: &[u8]) -> Result<String, JsValue> {
    let m = sig::SignedMessage::from_cbor(signed_message).map_err(err)?;
    Ok(json!({
        "algorithm": m.algorithm,
        "isHybrid": m.is_hybrid,
        "messageLength": m.message.len(),
        "signatureLength": m.signature.len(),
        "contextLength": m.context.len(),
        "signerFingerprint": m.signer_fingerprint,
        "signedAt": m.signed_at,
    })
    .to_string())
}

/// Parsed fields of a signed message (all public data).
#[wasm_bindgen]
pub struct SignedParts {
    inner: sig::SignedMessage,
}

#[wasm_bindgen]
impl SignedParts {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.inner.message.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.inner.signature.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn context(&self) -> Vec<u8> {
        self.inner.context.clone()
    }
    #[wasm_bindgen(getter, js_name = signerFingerprint)]
    pub fn signer_fingerprint(&self) -> String {
        self.inner.signer_fingerprint.clone()
    }
    #[wasm_bindgen(getter, js_name = signedAt)]
    pub fn signed_at(&self) -> f64 {
        self.inner.signed_at
    }
    #[wasm_bindgen(getter, js_name = isHybrid)]
    pub fn is_hybrid(&self) -> bool {
        self.inner.is_hybrid
    }
}

#[wasm_bindgen(js_name = signedMessageParse)]
pub fn signed_message_parse(data: &[u8]) -> Result<SignedParts, JsValue> {
    Ok(SignedParts { inner: sig::SignedMessage::from_cbor(data).map_err(err)? })
}

#[wasm_bindgen(js_name = signedMessageEncode)]
pub fn signed_message_encode(
    message: &[u8],
    signature: &[u8],
    algorithm: &str,
    context: &[u8],
    signer_fingerprint: &str,
    signed_at: f64,
    is_hybrid: bool,
) -> Result<Vec<u8>, JsValue> {
    if message.is_empty() {
        return Err(invalid("message cannot be empty"));
    }
    if signature.is_empty() {
        return Err(invalid("signature cannot be empty"));
    }
    if context.len() > sig::MAX_CONTEXT_LEN {
        return Err(invalid("context must be at most 255 bytes"));
    }
    Ok(sig::SignedMessage {
        message: message.to_vec(),
        signature: signature.to_vec(),
        algorithm: algorithm.to_string(),
        context: context.to_vec(),
        signer_fingerprint: signer_fingerprint.to_string(),
        signed_at,
        is_hybrid,
    }
    .to_cbor())
}

// ------------------------------------------------------------------------------------------
// Standards-mode ML-DSA (FIPS 204 native context, seed keys) for RFC 9964 JOSE
// ------------------------------------------------------------------------------------------

fn level_of(name: &str) -> Result<sig::MlDsaLevel, JsValue> {
    sig::MlDsaLevel::from_name(name).ok_or_else(|| err_kind("unsupported_algorithm", "unsupported ML-DSA parameter set"))
}

/// A standards-mode ML-DSA key pair: public key bytes plus a 32-byte secret seed.
#[wasm_bindgen]
pub struct SeedKeyPair {
    public: Vec<u8>,
    seed: Option<Zeroizing<Vec<u8>>>,
}

#[wasm_bindgen]
impl SeedKeyPair {
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
    #[wasm_bindgen(js_name = takeSeed)]
    pub fn take_seed(&mut self) -> Result<SecretBytes, JsValue> {
        self.seed.take().map(|inner| SecretBytes { inner }).ok_or_else(|| invalid("seed was already taken"))
    }
}

#[wasm_bindgen(js_name = mldsaStandardKeyGen)]
pub fn mldsa_standard_key_gen(level: &str) -> Result<SeedKeyPair, JsValue> {
    let (seed, public) = sig::standard::keygen(level_of(level)?);
    Ok(SeedKeyPair { public, seed: Some(seed) })
}

#[wasm_bindgen(js_name = mldsaStandardPublicFromSeed)]
pub fn mldsa_standard_public_from_seed(level: &str, seed: &SecretBytes) -> Result<Vec<u8>, JsValue> {
    sig::standard::public_from_seed(level_of(level)?, &seed.inner).map_err(err)
}

#[wasm_bindgen(js_name = mldsaStandardSign)]
pub fn mldsa_standard_sign(
    level: &str,
    seed: &SecretBytes,
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    sig::standard::sign(level_of(level)?, &seed.inner, message, context).map_err(err)
}

#[wasm_bindgen(js_name = mldsaStandardVerify)]
pub fn mldsa_standard_verify(
    level: &str,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    sig::standard::verify(level_of(level)?, public_key, message, context, signature).map_err(err)
}

// ------------------------------------------------------------------------------------------
// Registry
// ------------------------------------------------------------------------------------------

/// JSON array describing every KEM suite.
#[wasm_bindgen(js_name = kemSuites)]
pub fn kem_suites() -> String {
    let list: Vec<_> = KemSuite::all()
        .into_iter()
        .map(|s| {
            json!({
                "name": s.name(),
                "hybrid": s.is_hybrid(),
                "nistLevel": s.nist_level().0,
                "meetsCnsa2": s.meets_cnsa2(),
                "pyCompatible": s != KemSuite::XWing,
            })
        })
        .collect();
    serde_json::Value::Array(list).to_string()
}

/// JSON array describing every signature suite.
#[wasm_bindgen(js_name = sigSuites)]
pub fn sig_suites() -> String {
    let list: Vec<_> = sig::SigSuite::all()
        .into_iter()
        .map(|s| {
            let (nist, py) = match s {
                sig::SigSuite::MlDsa(l) | sig::SigSuite::Hybrid(_, l) => (l.nist_level(), true),
                sig::SigSuite::Slh(p) => (p.nist_level(), p.py_compatible()),
            };
            json!({
                "name": s.name(),
                "hybrid": s.is_hybrid(),
                "nistLevel": nist,
                "meetsCnsa2": s.meets_cnsa2(),
                "pyCompatible": py,
            })
        })
        .collect();
    serde_json::Value::Array(list).to_string()
}
