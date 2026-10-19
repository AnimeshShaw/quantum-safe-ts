//! wasm-bindgen glue over `quantum-safe-core`. This crate is **private**: the public API is the
//! hand-written TypeScript facade in `packages/quantum-safe-ts`, which validates inputs, maps
//! the `kind` tag on thrown errors to typed error classes, and documents everything.
//!
//! Secret-bearing objects (`SecretKey`, `SecretBytes`) live in WASM linear memory and are wiped
//! by the core's `Zeroizing` wrappers when `.free()` is called (or when dropped). Anything the
//! caller explicitly copies out (`exportBytes()`) is a JS-heap copy outside our control.
//!
//! JavaScript conventions used by every export below:
//!
//! - byte arguments are `Uint8Array` and byte results are returned as a new `Uint8Array`;
//! - a fallible export throws a JavaScript `Error` with an extra string property `kind` (for example
//!   `"malformed_ciphertext"`, `"decryption_failed"`, `"invalid_argument"`); `errors.rs` lists the tags;
//! - a returned `Option`/`Result<(), _>` unit maps to `undefined`;
//! - class instances own memory inside the WASM module and are released with `.free()`.

mod errors;

use errors::Kinded;
use quantum_safe_core::keys::{self, EncodedKey, KeyType, MigrationState};
use quantum_safe_core::suite::KemSuite;
use quantum_safe_core::{aead, envelope, kdf, kem, lms, sig, stream};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Converts a core error into the JavaScript `Error` that is thrown: its message is the error's `Display`
/// text and its `kind` property is the error's tag.
fn err<E: Kinded>(e: E) -> JsValue {
    err_kind(e.kind(), &e.to_string())
}

/// Builds a JavaScript `Error` with message `message` and a string property `kind`.
fn err_kind(kind: &str, message: &str) -> JsValue {
    let e = js_sys::Error::new(message);
    let _ = js_sys::Reflect::set(&e, &JsValue::from_str("kind"), &JsValue::from_str(kind));
    e.into()
}

/// A thrown `Error` of kind `invalid_argument`.
fn invalid(message: &str) -> JsValue {
    err_kind("invalid_argument", message)
}

/// `version()`: returns the version string of this WASM crate, e.g. `"0.1.0"`.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ------------------------------------------------------------------------------------------
// Keys
// ------------------------------------------------------------------------------------------

/// Parses an optional migration-state name; `None` gives `hybrid_transition` and an unknown name throws
/// `invalid_argument`.
fn parse_ms(s: Option<String>) -> Result<MigrationState, JsValue> {
    match s {
        None => Ok(MigrationState::HybridTransition),
        Some(v) => MigrationState::parse(&v).ok_or_else(|| invalid("unknown migration state")),
    }
}

/// Migration state used when the caller gives none: `hybrid_transition` for an algorithm name containing `+`
/// or equal to `X-Wing`, otherwise `pqc_only`.
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
    /// The canonical algorithm string, e.g. `"X25519+ML-KEM-768"`.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    /// The migration state: `classical_only`, `hybrid_transition`, `pqc_preferred` or `pqc_only`.
    #[wasm_bindgen(getter, js_name = migrationState)]
    pub fn migration_state(&self) -> String {
        self.inner.migration_state.as_str().to_string()
    }
    /// Returns a copy of the raw public key bytes as a `Uint8Array`.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.raw.to_vec()
    }
    /// Returns the SHA-256 fingerprint of the algorithm name and key bytes as lowercase hex.
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }
    /// Returns the fingerprint as colon-separated hex pairs (`aa:bb:...`).
    #[wasm_bindgen(js_name = fingerprintColon)]
    pub fn fingerprint_colon(&self) -> String {
        self.inner.fingerprint_colon()
    }
    /// Returns the key as CBOR bytes (`{v, algo, ms, ktype, key}`).
    #[wasm_bindgen(js_name = toCbor)]
    pub fn to_cbor(&self) -> Vec<u8> {
        self.inner.to_cbor()
    }
    /// Returns the key as PEM text (`QUANTUM SAFE PUBLIC KEY`).
    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }
    /// Returns the key as a JWK JSON string (`kty` `"AKP"`).
    #[wasm_bindgen(js_name = toJwk)]
    pub fn to_jwk(&self) -> Result<String, JsValue> {
        self.inner.to_jwk().map_err(err)
    }

    /// Static `PublicKey.fromBytes(algorithm, raw, migrationState?)`: builds a public key from raw bytes.
    ///
    /// When `migrationState` is omitted it defaults from the algorithm name (see `default_ms`). Throws
    /// `invalid_argument` for empty bytes or an unknown migration state, and `key_parse_error` when `raw` has the
    /// wrong length for a known algorithm.
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
        quantum_safe_core::keys::check_public_len(algorithm, raw).map_err(err)?;
        Ok(PublicKey {
            inner: EncodedKey::new(algorithm, KeyType::Public, raw.to_vec(), ms),
        })
    }
    /// Static `PublicKey.fromCbor(data)`: parses CBOR written by `toCbor`.
    ///
    /// Throws `payload_too_large`, `key_parse_error` (malformed data, wrong key type, version below 1, or a
    /// wrong-length key) or `incompatible_key_version`.
    #[wasm_bindgen(js_name = fromCbor)]
    pub fn from_cbor(data: &[u8]) -> Result<PublicKey, JsValue> {
        Ok(PublicKey {
            inner: EncodedKey::from_cbor(data, KeyType::Public).map_err(err)?,
        })
    }
    /// Static `PublicKey.fromPem(pem)`: parses PEM text written by `toPem`. Throws as `fromCbor` does.
    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: &str) -> Result<PublicKey, JsValue> {
        Ok(PublicKey {
            inner: EncodedKey::from_pem(pem, KeyType::Public).map_err(err)?,
        })
    }
    /// Static `PublicKey.fromJwk(json)`: parses a JWK JSON string (`kty` `"AKP"`, `alg`, `pub`). Throws as
    /// `fromCbor` does.
    #[wasm_bindgen(js_name = fromJwk)]
    pub fn from_jwk(json: &str) -> Result<PublicKey, JsValue> {
        Ok(PublicKey {
            inner: EncodedKey::from_jwk(json).map_err(err)?,
        })
    }
}

// The core-crate view of this key.
impl PublicKey {
    fn core(&self) -> kem::PublicKey {
        kem::PublicKey {
            raw: self.inner.raw.to_vec(),
            algorithm: self.inner.algorithm.clone(),
        }
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
    /// The canonical algorithm string.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    /// The migration state name.
    #[wasm_bindgen(getter, js_name = migrationState)]
    pub fn migration_state(&self) -> String {
        self.inner.migration_state.as_str().to_string()
    }
    /// Copies the raw key bytes into a JS `Uint8Array`. The caller owns wiping that copy.
    #[wasm_bindgen(js_name = exportBytes)]
    pub fn export_bytes(&self) -> Vec<u8> {
        self.inner.raw.to_vec()
    }
    /// Returns the key as CBOR bytes (`{v, algo, ms, ktype, key}`). The result holds the secret key in the clear.
    #[wasm_bindgen(js_name = toCbor)]
    pub fn to_cbor(&self) -> Vec<u8> {
        self.inner.to_cbor()
    }
    /// Returns the key as PEM text (`QUANTUM SAFE SECRET KEY`). The result holds the secret key in the clear.
    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    /// Static `SecretKey.fromBytes(algorithm, raw, migrationState?)`: builds a secret key from raw bytes.
    ///
    /// The bytes and the algorithm name are not checked here; use is checked by the operation that consumes the
    /// key. Throws `invalid_argument` for empty bytes or an unknown migration state.
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
        Ok(SecretKey {
            inner: EncodedKey::new(algorithm, KeyType::Secret, raw.to_vec(), ms),
        })
    }
    /// Static `SecretKey.fromCbor(data)`: parses CBOR written by `toCbor`. Throws `payload_too_large`,
    /// `key_parse_error` or `incompatible_key_version`.
    #[wasm_bindgen(js_name = fromCbor)]
    pub fn from_cbor(data: &[u8]) -> Result<SecretKey, JsValue> {
        Ok(SecretKey {
            inner: EncodedKey::from_cbor(data, KeyType::Secret).map_err(err)?,
        })
    }
    /// Static `SecretKey.fromPem(pem)`: parses PEM text written by `toPem`. Throws as `fromCbor` does.
    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: &str) -> Result<SecretKey, JsValue> {
        Ok(SecretKey {
            inner: EncodedKey::from_pem(pem, KeyType::Secret).map_err(err)?,
        })
    }
}

// The core-crate view of this key (copies the bytes into a wiping buffer).
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
    /// A new `PublicKey` object holding a copy of the public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.public.clone(),
        }
    }
    /// A new `SecretKey` object holding a copy of the secret key; free it when done.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> SecretKey {
        SecretKey {
            inner: self.secret.clone(),
        }
    }
    /// The canonical algorithm string shared by both keys.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.public.algorithm.clone()
    }
    /// Returns the pair as a CBOR bundle (`{v, bundle: "keypair", pub, sec}`), which holds the secret key in the
    /// clear. Throws `key_parse_error` if the two keys name different algorithms.
    #[wasm_bindgen(js_name = toCborBundle)]
    pub fn to_cbor_bundle(&self) -> Result<Vec<u8>, JsValue> {
        keys::keypair_to_bundle(&self.public, &self.secret).map_err(err)
    }
    /// Static `KeyPair.fromCborBundle(data)`: parses a bundle written by `toCborBundle`. Throws
    /// `payload_too_large`, `key_parse_error` or `incompatible_key_version`.
    #[wasm_bindgen(js_name = fromCborBundle)]
    pub fn from_cbor_bundle(data: &[u8]) -> Result<KeyPair, JsValue> {
        let (public, secret) = keys::keypair_from_bundle(data).map_err(err)?;
        Ok(KeyPair { public, secret })
    }
}

// Wraps a core key pair as `EncodedKey`s carrying the migration state `ms`.
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
    /// Static `SecretBytes.fromBytes(bytes)`: moves a copy of `bytes` into WASM memory (for example a JWK
    /// `priv` seed). The caller should wipe their own JS-side copy. Throws `invalid_argument` for an empty array.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretBytes, JsValue> {
        if bytes.is_empty() {
            return Err(invalid("secret bytes cannot be empty"));
        }
        Ok(SecretBytes {
            inner: Zeroizing::new(bytes.to_vec()),
        })
    }
    /// The number of secret bytes.
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
    ///
    /// Returns `length` derived bytes as a `Uint8Array`. Throws `hkdf_output_too_long` when `length` is over 8160.
    #[wasm_bindgen(js_name = deriveKey)]
    pub fn derive_key(&self, length: usize, info: &[u8]) -> Result<Vec<u8>, JsValue> {
        kdf::derive_key(&self.inner, info, length).map_err(err)
    }
}

// ------------------------------------------------------------------------------------------
// KEM
// ------------------------------------------------------------------------------------------

/// `kemGenerateKeyPair(algorithm)`: generates a KEM key pair for a suite name such as
/// `"X25519+ML-KEM-768"`, `"ML-KEM-1024"` or `"X-Wing"`. Returns a `KeyPair`; throws `unsupported_algorithm`
/// for an unknown suite.
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
    /// A copy of the KEM ciphertext as a `Uint8Array`.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// Returns the 32-byte shared secret as a `SecretBytes`. A second call throws `invalid_argument`.
    #[wasm_bindgen(js_name = takeSharedSecret)]
    pub fn take_shared_secret(&mut self) -> Result<SecretBytes, JsValue> {
        self.shared
            .take()
            .map(|inner| SecretBytes { inner })
            .ok_or_else(|| invalid("shared secret was already taken"))
    }
}

/// `kemEncapsulate(publicKey)`: encapsulates to a KEM public key and returns an `Encapsulation`.
///
/// Throws `unsupported_algorithm`, `malformed_key` or `classical_failure`.
#[wasm_bindgen(js_name = kemEncapsulate)]
pub fn kem_encapsulate(public_key: &PublicKey) -> Result<Encapsulation, JsValue> {
    let (ciphertext, ss) = kem::encapsulate(&public_key.core()).map_err(err)?;
    Ok(Encapsulation {
        ciphertext,
        shared: Some(Zeroizing::new(ss.to_vec())),
    })
}

/// `kemDecapsulate(secretKey, ciphertext)`: returns the 32-byte shared secret as a `SecretBytes`.
///
/// A ciphertext of the right length made for another key does not throw; it yields a different secret. Throws
/// `unsupported_algorithm`, `malformed_key`, `malformed_ciphertext` or `classical_failure`.
#[wasm_bindgen(js_name = kemDecapsulate)]
pub fn kem_decapsulate(secret_key: &SecretKey, ciphertext: &[u8]) -> Result<SecretBytes, JsValue> {
    let ss = kem::decapsulate(&secret_key.core(), ciphertext).map_err(err)?;
    Ok(SecretBytes {
        inner: Zeroizing::new(ss.to_vec()),
    })
}

// ------------------------------------------------------------------------------------------
// Envelope
// ------------------------------------------------------------------------------------------

/// `envelopeSeal(plaintext, publicKey, aad)`: seals `plaintext` to `public_key`; returns the CBOR-encoded
/// `SealedMessage` as a `Uint8Array`. `aad` is authenticated and stored in the message in the clear.
///
/// Throws `unsupported_algorithm` (the key is not a hybrid KEM or `ML-KEM-1024`), `malformed_key` or
/// `classical_failure`.
#[wasm_bindgen(js_name = envelopeSeal)]
pub fn envelope_seal(plaintext: &[u8], public_key: &PublicKey, aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sealed = envelope::seal(plaintext, &public_key.core(), aad).map_err(err)?;
    sealed.to_cbor().map_err(err)
}

/// `envelopeOpen(sealed, secretKey)`: opens a CBOR-encoded `SealedMessage` and returns the plaintext as a
/// `Uint8Array`.
///
/// Throws `malformed_ciphertext` (bad CBOR, missing field, wrong nonce length), `unsupported_algorithm`,
/// `algorithm_mismatch` (the message was sealed for another suite than the key's), `malformed_key`,
/// `decryption_failed` (wrong key, wrong AAD or tampered data) or `classical_failure`.
#[wasm_bindgen(js_name = envelopeOpen)]
pub fn envelope_open(sealed: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, JsValue> {
    let msg = envelope::SealedMessage::from_cbor(sealed).map_err(err)?;
    envelope::open(&msg, &secret_key.core()).map_err(err)
}

/// The key step of `envelopeSeal`, for a caller that runs AES-256-GCM itself (Node's native crypto): the KEM
/// ciphertext, nonce and AAD are public; `takeKey()` returns a copy of the one-time AES key (each call gives a
/// new `SecretBytes`). Free it when done.
///
/// `finish()` can be called any number of times; free the plan when done so the key is wiped.
#[wasm_bindgen]
pub struct SealPlan {
    inner: envelope::SealPlan,
}

#[wasm_bindgen]
impl SealPlan {
    // The plan's data.
    fn plan(&self) -> &envelope::SealPlan {
        &self.inner
    }
    /// The envelope version: 1 or 2.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u8 {
        self.plan().version
    }
    /// The KEM suite name of the recipient key.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.plan().algorithm.clone()
    }
    /// The KEM ciphertext for the recipient.
    #[wasm_bindgen(getter, js_name = kemCiphertext)]
    pub fn kem_ciphertext(&self) -> Vec<u8> {
        self.plan().kem_ct.clone()
    }
    /// The random 12-byte AES-GCM nonce.
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.plan().nonce.to_vec()
    }
    /// The AAD that AES-GCM authenticates (version, algorithm and the caller's AAD).
    #[wasm_bindgen(getter, js_name = builtAad)]
    pub fn built_aad(&self) -> Vec<u8> {
        self.plan().built_aad.clone()
    }
    /// The caller's own AAD, which the message stores.
    #[wasm_bindgen(getter)]
    pub fn aad(&self) -> Vec<u8> {
        self.plan().aad.clone()
    }
    /// A copy of the one-time AES-256 key as a `SecretBytes`, wipeable from JavaScript. Each call returns a new copy.
    #[wasm_bindgen(js_name = takeKey)]
    pub fn take_key(&self) -> SecretBytes {
        SecretBytes {
            inner: Zeroizing::new(self.plan().key.to_vec()),
        }
    }
    /// Encodes the sealed message, given the AES-GCM output (`ciphertext || tag`). Returns the CBOR bytes as a
    /// `Uint8Array`.
    pub fn finish(&self, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.to_message(ciphertext.to_vec()).to_cbor().map_err(err)
    }
}

/// `envelopeSealPlan(publicKey, aad)`: runs the key step of `envelopeSeal` and returns a `SealPlan`.
///
/// Throws `unsupported_algorithm`, `malformed_key` or `classical_failure`.
#[wasm_bindgen(js_name = envelopeSealPlan)]
pub fn envelope_seal_plan(public_key: &PublicKey, aad: &[u8]) -> Result<SealPlan, JsValue> {
    Ok(SealPlan {
        inner: envelope::seal_plan(&public_key.core(), aad).map_err(err)?,
    })
}

/// The key step of `envelopeOpen`: nonce and AAD are public; `takeKey()` returns a copy of the one-time AES key.
#[wasm_bindgen]
pub struct OpenPlan {
    inner: envelope::OpenPlan,
}

#[wasm_bindgen]
impl OpenPlan {
    /// The 12-byte AES-GCM nonce of the message.
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.inner.nonce.to_vec()
    }
    /// The AAD that AES-GCM authenticates (version, algorithm and the message's AAD).
    #[wasm_bindgen(getter, js_name = builtAad)]
    pub fn built_aad(&self) -> Vec<u8> {
        self.inner.built_aad.clone()
    }
    /// A copy of the one-time AES-256 key as a `SecretBytes`. Each call returns a new copy.
    #[wasm_bindgen(js_name = takeKey)]
    pub fn take_key(&self) -> SecretBytes {
        SecretBytes {
            inner: Zeroizing::new(self.inner.key.to_vec()),
        }
    }
}

/// `envelopeOpenPlan(sealed, secretKey)`: runs the key step of `envelopeOpen` and returns an `OpenPlan`; the
/// caller then decrypts `ciphertext` with AES-256-GCM.
///
/// Throws as `envelopeOpen` does, except `decryption_failed`, which arises in the caller's decryption.
#[wasm_bindgen(js_name = envelopeOpenPlan)]
pub fn envelope_open_plan(sealed: &[u8], secret_key: &SecretKey) -> Result<OpenPlan, JsValue> {
    let msg = envelope::SealedMessage::from_cbor(sealed).map_err(err)?;
    Ok(OpenPlan {
        inner: envelope::open_plan(&msg, &secret_key.core()).map_err(err)?,
    })
}

/// `envelopeInspect(sealed)`: non-secret metadata of a sealed message, as a JSON string with `version`,
/// `algorithm`, `kemCiphertextLength`, `nonceLength`, `ciphertextLength` and `aadLength`.
///
/// Throws `malformed_ciphertext` when the CBOR does not parse.
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
    /// The envelope version.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u8 {
        self.inner.version
    }
    /// The KEM suite name.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    /// The KEM ciphertext.
    #[wasm_bindgen(getter, js_name = kemCiphertext)]
    pub fn kem_ciphertext(&self) -> Vec<u8> {
        self.inner.kem_ct.clone()
    }
    /// The AES-GCM nonce as stored in the message.
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.inner.nonce.clone()
    }
    /// The AES-GCM output (`ciphertext || tag`).
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.inner.ciphertext.clone()
    }
    /// The caller's AAD as stored in the message.
    #[wasm_bindgen(getter)]
    pub fn aad(&self) -> Vec<u8> {
        self.inner.aad.clone()
    }
}

/// `sealedMessageParse(data)`: parses a CBOR `SealedMessage` into a `SealedParts`. Throws
/// `malformed_ciphertext`.
#[wasm_bindgen(js_name = sealedMessageParse)]
pub fn sealed_message_parse(data: &[u8]) -> Result<SealedParts, JsValue> {
    Ok(SealedParts {
        inner: envelope::SealedMessage::from_cbor(data).map_err(err)?,
    })
}

/// `sealedMessageEncode(version, algorithm, kemCiphertext, nonce, ciphertext, aad)`: encodes the six fields as a
/// CBOR `SealedMessage` and returns it as a `Uint8Array`. The fields are not validated here.
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

/// `aesGcmNonceLength()`: the AES-GCM nonce length in bytes (12).
#[wasm_bindgen(js_name = aesGcmNonceLength)]
pub fn aes_gcm_nonce_length() -> usize {
    aead::NONCE_LEN
}

// ------------------------------------------------------------------------------------------
// Argon2id master key
// ------------------------------------------------------------------------------------------

/// `deriveMasterKey(password, salt)`: stretches a password with Argon2id (19 MiB, 2 passes, 1 lane) into a
/// 32-byte `SecretBytes`. Throws `kdf_failed` when Argon2 rejects the input (for example a salt under 8 bytes).
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<SecretBytes, JsValue> {
    let key = kdf::derive_master_key(password, salt).map_err(err)?;
    Ok(SecretBytes {
        inner: Zeroizing::new(key.to_vec()),
    })
}

// ------------------------------------------------------------------------------------------
// Signatures
// ------------------------------------------------------------------------------------------

/// `sigGenerateKeyPair(algorithm)`: generates a signature key pair for a suite name such as `"ML-DSA-65"`,
/// `"Ed25519+ML-DSA-65"`, `"SLH-DSA-SHAKE-128f"` or a `-v2` identifier. Returns a `KeyPair`; throws
/// `unsupported_algorithm` for an unknown suite.
#[wasm_bindgen(js_name = sigGenerateKeyPair)]
pub fn sig_generate_key_pair(algorithm: &str) -> Result<KeyPair, JsValue> {
    let kp = sig::generate_keypair(algorithm).map_err(err)?;
    let ms = sig::SigSuite::parse(sig::v2::base_of(algorithm).unwrap_or(algorithm))
        .map(|s| s.migration_state())
        .unwrap_or(MigrationState::PqcOnly);
    Ok(keypair_from_core(kp.public, kp.secret, ms))
}

/// `sigSign(secretKey, message, context, deterministic, signerFingerprint, signedAt)`: signs `message`; returns
/// the CBOR-encoded `SignedMessage` as a `Uint8Array`.
///
/// `context` is at most 255 bytes. `deterministic` omits the random prefix of the quantum-safe-py format.
/// `signerFingerprint` (string) and `signedAt` (Unix seconds, a number) are stored unsigned.
///
/// Throws `unsupported_algorithm`, `invalid_argument` (empty message or context over 255 bytes),
/// `malformed_key` or `signing_failed`.
#[wasm_bindgen(js_name = sigSign)]
pub fn sig_sign(
    secret_key: &SecretKey,
    message: &[u8],
    context: &[u8],
    deterministic: bool,
    signer_fingerprint: &str,
    signed_at: f64,
) -> Result<Vec<u8>, JsValue> {
    let opts = sig::SignOptions {
        deterministic,
        signer_fingerprint: signer_fingerprint.to_string(),
        signed_at,
    };
    sig::sign(&secret_key.core(), message, context, &opts)
        .map(|m| m.to_cbor())
        .map_err(err)
}

/// `sigVerify(signedMessage, publicKey)`: verifies a CBOR-encoded `SignedMessage`. Returns `undefined` on success.
///
/// Throws `verification_failed` when the signature is invalid, `algorithm_mismatch` when the key's algorithm
/// differs from the message's, `malformed_key`, `unsupported_algorithm`, and `key_parse_error` or
/// `invalid_argument` when the container does not parse.
#[wasm_bindgen(js_name = sigVerify)]
pub fn sig_verify(signed_message: &[u8], public_key: &PublicKey) -> Result<(), JsValue> {
    let sm = sig::SignedMessage::from_cbor(signed_message).map_err(err)?;
    sig::verify(&sm, &public_key.core()).map_err(err)
}

/// `sigVerifyParts(algorithm, message, signatureBlob, context, publicKey)`: verifies the raw parts of a
/// signature. Returns `undefined` on success and throws as `sigVerify` does.
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

/// `signedMessageInspect(data)`: non-secret metadata of a signed message, as a JSON string with `algorithm`,
/// `isHybrid`, `messageLength`, `signatureLength`, `contextLength`, `signerFingerprint` and `signedAt` (the
/// message itself is not echoed). Throws as `signedMessageParse` does.
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
    /// The signed message.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.inner.message.clone()
    }
    /// The signature blob.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.inner.signature.clone()
    }
    /// The algorithm string.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }
    /// The signing context.
    #[wasm_bindgen(getter)]
    pub fn context(&self) -> Vec<u8> {
        self.inner.context.clone()
    }
    /// The signer fingerprint stored in the message (unsigned metadata).
    #[wasm_bindgen(getter, js_name = signerFingerprint)]
    pub fn signer_fingerprint(&self) -> String {
        self.inner.signer_fingerprint.clone()
    }
    /// The Unix timestamp in seconds stored in the message (unsigned metadata).
    #[wasm_bindgen(getter, js_name = signedAt)]
    pub fn signed_at(&self) -> f64 {
        self.inner.signed_at
    }
    /// Whether the message says its algorithm is a hybrid suite (unsigned metadata).
    #[wasm_bindgen(getter, js_name = isHybrid)]
    pub fn is_hybrid(&self) -> bool {
        self.inner.is_hybrid
    }
}

/// `signedMessageParse(data)`: parses a CBOR `SignedMessage` into a `SignedParts`. Throws `key_parse_error`
/// (malformed container), `invalid_argument` (empty message or context over 255 bytes).
#[wasm_bindgen(js_name = signedMessageParse)]
pub fn signed_message_parse(data: &[u8]) -> Result<SignedParts, JsValue> {
    Ok(SignedParts {
        inner: sig::SignedMessage::from_cbor(data).map_err(err)?,
    })
}

/// `signedMessageEncode(message, signature, algorithm, context, signerFingerprint, signedAt, isHybrid)`: encodes
/// the fields as a CBOR `SignedMessage` and returns it as a `Uint8Array`.
///
/// Throws `invalid_argument` for an empty message, an empty signature or a context over 255 bytes. Nothing is
/// signed or verified.
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

// Parses an ML-DSA level name (`ML-DSA-44`, `-65` or `-87`); anything else throws `unsupported_algorithm`.
fn level_of(name: &str) -> Result<sig::MlDsaLevel, JsValue> {
    sig::MlDsaLevel::from_name(name)
        .ok_or_else(|| err_kind("unsupported_algorithm", "unsupported ML-DSA parameter set"))
}

/// A standards-mode ML-DSA key pair: public key bytes plus a 32-byte secret seed.
#[wasm_bindgen]
pub struct SeedKeyPair {
    public: Vec<u8>,
    seed: Option<Zeroizing<Vec<u8>>>,
}

#[wasm_bindgen]
impl SeedKeyPair {
    /// A copy of the public key as a `Uint8Array`.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
    /// Returns the 32-byte secret seed as a `SecretBytes`. A second call throws `invalid_argument`.
    #[wasm_bindgen(js_name = takeSeed)]
    pub fn take_seed(&mut self) -> Result<SecretBytes, JsValue> {
        self.seed
            .take()
            .map(|inner| SecretBytes { inner })
            .ok_or_else(|| invalid("seed was already taken"))
    }
}

/// `mldsaStandardKeyGen(level)`: generates a standards-mode ML-DSA key pair (`level` is `"ML-DSA-44"`,
/// `"ML-DSA-65"` or `"ML-DSA-87"`). Returns a `SeedKeyPair`; throws `unsupported_algorithm` for another level.
#[wasm_bindgen(js_name = mldsaStandardKeyGen)]
pub fn mldsa_standard_key_gen(level: &str) -> Result<SeedKeyPair, JsValue> {
    let (seed, public) = sig::standard::keygen(level_of(level)?);
    Ok(SeedKeyPair {
        public,
        seed: Some(seed),
    })
}

/// `mldsaStandardPublicFromSeed(level, seed)`: the public key for a 32-byte seed. Throws `malformed_key` when the
/// seed is not 32 bytes, `unsupported_algorithm` for an unknown level.
#[wasm_bindgen(js_name = mldsaStandardPublicFromSeed)]
pub fn mldsa_standard_public_from_seed(level: &str, seed: &SecretBytes) -> Result<Vec<u8>, JsValue> {
    sig::standard::public_from_seed(level_of(level)?, &seed.inner).map_err(err)
}

/// `mldsaStandardSign(level, seed, message, context)`: signs with FIPS 204 `ML-DSA.Sign`, passing `context` (at
/// most 255 bytes) as the native context. Returns the signature as a `Uint8Array`.
///
/// Throws `invalid_argument` (context too long), `malformed_key` (seed not 32 bytes), `signing_failed` or
/// `unsupported_algorithm`.
#[wasm_bindgen(js_name = mldsaStandardSign)]
pub fn mldsa_standard_sign(
    level: &str,
    seed: &SecretBytes,
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    sig::standard::sign(level_of(level)?, &seed.inner, message, context).map_err(err)
}

/// `mldsaStandardVerify(level, publicKey, message, context, signature)`: returns `true` if the signature is valid.
///
/// Returns `false` for a signature of the wrong length or one that does not verify. Throws `malformed_key` when
/// the public key has the wrong length and `unsupported_algorithm` for an unknown level.
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
// LMS / HSS (RFC 8554) signature verification. Verification only: signing is stateful and unsafe to
// offer without a durable state store; SP 800-208 also requires key generation in a validated module.
// ------------------------------------------------------------------------------------------

/// `lmsVerify(publicKey, message, signature)`: verifies an HSS signature. Returns `false` for a well-formed but
/// invalid signature and throws (kind `malformed_key` / `malformed_signature` / `unsupported_algorithm`) for
/// structural problems.
#[wasm_bindgen(js_name = lmsVerify)]
pub fn lms_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    lms::verify_hss(public_key, message, signature).map_err(err)
}

/// `lmsInspectPublicKey(publicKey)`: public parameters of an HSS public key, as a JSON string with `levels`,
/// `lmsType`, `otsType`, `treeHeight`, `winternitz` and `parameterSet`. Throws as `lmsVerify` does for a bad key.
#[wasm_bindgen(js_name = lmsInspectPublicKey)]
pub fn lms_inspect_public_key(public_key: &[u8]) -> Result<String, JsValue> {
    let i = lms::inspect_hss_public_key(public_key).map_err(err)?;
    Ok(json!({
        "levels": i.levels,
        "lmsType": i.lms_type,
        "otsType": i.ots_type,
        "treeHeight": i.tree_height,
        "winternitz": i.winternitz,
        "parameterSet": format!("LMS_SHA256_M32_H{}/LMOTS_SHA256_N32_W{}", i.tree_height, i.winternitz),
    })
    .to_string())
}

// ------------------------------------------------------------------------------------------
// Registry
// ------------------------------------------------------------------------------------------

/// `kemSuites()`: a JSON array string describing every KEM suite. Each entry has `name`, `hybrid`, `nistLevel`,
/// `meetsCnsa2` and `pyCompatible` (false for the suites quantum-safe-py 0.3.0 lacks).
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
                // quantum-safe-py 0.3.0 has neither X-Wing nor the P-384 hybrid (both are in 0.4.0).
                "pyCompatible": !matches!(
                    s,
                    KemSuite::XWing | KemSuite::Hybrid(quantum_safe_core::suite::Classical::P384, _)
                ),
            })
        })
        .collect();
    serde_json::Value::Array(list).to_string()
}

/// `sigSuites()`: a JSON array string describing every signature suite. Each entry has `name`, `hybrid`,
/// `nistLevel`, `meetsCnsa2` and `pyCompatible`; the `-v2` identifiers also carry `format: "v2"`.
#[wasm_bindgen(js_name = sigSuites)]
pub fn sig_suites() -> String {
    let list: Vec<_> = sig::SigSuite::all()
        .into_iter()
        .map(|s| {
            let (nist, py) = match s {
                sig::SigSuite::Hybrid(sig::ClassicalSig::P384, l) => (l.nist_level(), false),
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
        .chain(sig::v2::all().into_iter().map(|name| {
            let base = sig::SigSuite::parse(sig::v2::base_of(&name).unwrap_or(&name))
                .expect("v2 names have a base suite");
            let nist = match base {
                sig::SigSuite::MlDsa(l) | sig::SigSuite::Hybrid(_, l) => l.nist_level(),
                sig::SigSuite::Slh(p) => p.nist_level(),
            };
            json!({
                "name": name,
                "hybrid": base.is_hybrid(),
                "nistLevel": nist,
                "meetsCnsa2": base.meets_cnsa2(),
                "pyCompatible": false,
                "format": "v2",
            })
        }))
        .collect();
    serde_json::Value::Array(list).to_string()
}

// ------------------------------------------------------------------------------------------
// Streaming envelope (format v3)
// ------------------------------------------------------------------------------------------

/// Seals or opens the chunks of one stream, in order. Owns the key and the chunk counter (a nonce can never be reused by a caller).
/// Free it (or let the TypeScript `using` scope do so) when done: the key is wiped.
#[wasm_bindgen]
pub struct StreamCipher {
    inner: stream::StreamCipher,
    header: Vec<u8>,
}

#[wasm_bindgen]
impl StreamCipher {
    /// Static `StreamCipher.startSealing(publicKey, aad, chunkSize)`: starts a stream to `public_key` (a hybrid KEM
    /// key or `ML-KEM-1024`). The header is available as `.header`. `chunkSize` is 1024 to 16 MiB.
    ///
    /// Throws `invalid_argument` (chunk size out of range), `unsupported_algorithm`, `malformed_key` or
    /// `classical_failure`.
    #[wasm_bindgen(js_name = startSealing)]
    pub fn start_sealing(
        public_key: &PublicKey,
        aad: &[u8],
        chunk_size: usize,
    ) -> Result<StreamCipher, JsValue> {
        let (header, inner) =
            stream::StreamCipher::start_sealing(&public_key.core(), aad, chunk_size).map_err(err)?;
        Ok(StreamCipher { inner, header })
    }

    /// Static `StreamCipher.startOpening(secretKey, header, aad)`: starts opening the stream whose header bytes
    /// are `header`; `aad` must equal the sealer's.
    ///
    /// Throws `malformed_ciphertext` (bad header), `invalid_argument` (chunk size out of range),
    /// `unsupported_algorithm`, `algorithm_mismatch`, `malformed_key` or `classical_failure`.
    #[wasm_bindgen(js_name = startOpening)]
    pub fn start_opening(secret_key: &SecretKey, header: &[u8], aad: &[u8]) -> Result<StreamCipher, JsValue> {
        let inner = stream::StreamCipher::start_opening(&secret_key.core(), header, aad).map_err(err)?;
        Ok(StreamCipher {
            inner,
            header: header.to_vec(),
        })
    }

    /// The stream header bytes, to be sent before the first chunk.
    #[wasm_bindgen(getter)]
    pub fn header(&self) -> Vec<u8> {
        self.header.clone()
    }

    /// The chunk size in plaintext bytes.
    #[wasm_bindgen(getter, js_name = chunkSize)]
    pub fn chunk_size(&self) -> usize {
        self.inner.chunk_size()
    }

    /// Seals the next chunk and returns `ciphertext || tag` (`plaintext.length + 16` bytes). Every chunk but the last
    /// must be exactly `chunkSize` bytes; `last = true` finishes the stream.
    ///
    /// Throws `invalid_argument` (stream finished, plaintext length not allowed, or too many chunks).
    #[wasm_bindgen(js_name = sealChunk)]
    pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>, JsValue> {
        self.inner.seal_chunk(plaintext, last).map_err(err)
    }

    /// Opens the next chunk and returns the plaintext. `last` says whether this is the final chunk. Any failure
    /// ends the stream.
    ///
    /// Throws `invalid_argument` (stream already finished), `malformed_ciphertext` (length not allowed) or
    /// `decryption_failed` (wrong key or AAD, or a modified, reordered, dropped or truncated chunk).
    #[wasm_bindgen(js_name = openChunk)]
    pub fn open_chunk(&mut self, ciphertext: &[u8], last: bool) -> Result<Vec<u8>, JsValue> {
        self.inner.open_chunk(ciphertext, last).map_err(err)
    }

    /// For a caller that runs AES-256-GCM itself: the checks and the nonce of the next sealed chunk. Returns the
    /// 12-byte nonce; throws `invalid_argument` (stream finished or length not allowed).
    #[wasm_bindgen(js_name = prepareSeal)]
    pub fn prepare_seal(&mut self, plaintext_len: usize, last: bool) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .prepare_seal(plaintext_len, last)
            .map_err(err)?
            .to_vec())
    }

    /// For a caller that runs AES-256-GCM itself: the checks and the nonce of the next opened chunk. Returns the
    /// 12-byte nonce; throws `invalid_argument` (stream finished) or `malformed_ciphertext` (length not allowed,
    /// which also ends the stream).
    #[wasm_bindgen(js_name = prepareOpen)]
    pub fn prepare_open(&mut self, ciphertext_len: usize, last: bool) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .prepare_open(ciphertext_len, last)
            .map_err(err)?
            .to_vec())
    }

    /// Moves to the next chunk after the caller's AES-256-GCM step succeeded. Throws `invalid_argument` when the
    /// chunk counter would overflow.
    pub fn commit(&mut self, last: bool) -> Result<(), JsValue> {
        self.inner.commit(last).map_err(err)
    }

    /// Ends the stream (call it when a chunk fails authentication).
    pub fn abort(&mut self) {
        self.inner.abort();
    }

    /// A copy of the stream's one-time AES-256 key as a `SecretBytes`, wipeable from JavaScript. Each call returns a
    /// new copy.
    #[wasm_bindgen(js_name = takeKey)]
    pub fn take_key(&self) -> SecretBytes {
        SecretBytes {
            inner: Zeroizing::new(self.inner.key().to_vec()),
        }
    }

    /// The AAD every chunk authenticates.
    #[wasm_bindgen(getter)]
    pub fn aad(&self) -> Vec<u8> {
        self.inner.aad().to_vec()
    }
}

/// `streamHeaderInspect(header)`: parses and validates a stream header; returns its non-secret fields as a JSON
/// string with `algorithm`, `kemCiphertextLength` and `chunkSize`. Throws `malformed_ciphertext`,
/// `unsupported_algorithm` or `invalid_argument` (chunk size out of range).
#[wasm_bindgen(js_name = streamHeaderInspect)]
pub fn stream_header_inspect(header: &[u8]) -> Result<String, JsValue> {
    let h = stream::StreamHeader::from_cbor(header).map_err(err)?;
    Ok(json!({
        "algorithm": h.algorithm,
        "kemCiphertextLength": h.kem_ct.len(),
        "chunkSize": h.chunk_size,
    })
    .to_string())
}
