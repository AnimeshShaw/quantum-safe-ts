//! Authenticated-encryption envelope, matching
//! `quantum_safe.protocols.envelope` exactly.
//!
//! [`seal`] encapsulates to a recipient KEM public key, derives a one-time AES-256 key from the shared
//! secret, and encrypts with AES-256-GCM; [`open`] reverses it. Two versions exist:
//!
//! - v1 (quantum-safe-py compatible): any hybrid KEM suite, key derived with HKDF-SHA256;
//! - v2 (CNSA 2.0 profile): pure ML-KEM-1024, key derived with HKDF-SHA384.
//!
//! The AES-GCM associated data binds the version, the algorithm name and the caller's AAD (see
//! [`build_aad`]). [`SealedMessage`] is the CBOR-encoded result. [`seal_plan`] and [`open_plan`] expose
//! the steps before the AES-GCM call so a caller can run the cipher itself.

use crate::aead::{self, AeadError};
use crate::kdf;
use crate::kdf::KdfError;
use crate::kem;
use crate::kem::KemError;
use crate::suite::KemSuite;
use ciborium::value::Value;
use thiserror::Error;
use zeroize::Zeroizing;

/// Version byte of the quantum-safe-py compatible envelope (hybrid KEM suites, HKDF-SHA256).
pub const ENVELOPE_VERSION: u8 = 1;
/// Envelope v2: the CNSA 2.0 profile (pure ML-KEM-1024, HKDF-SHA384, AES-256-GCM). quantum-safe-py (0.3.2 or later) reads and writes it too.
pub const ENVELOPE_VERSION_CNSA2: u8 = 2;
/// The only KEM suite v2 envelopes use.
pub const CNSA2_ENVELOPE_ALGORITHM: &str = "ML-KEM-1024";
/// HKDF `info` for the v1 AES key.
const ENC_KEY_INFO: &[u8] = b"qs-envelope-enc-v1";
/// HKDF `info` for the v2 AES key.
const ENC_KEY_INFO_V2: &[u8] = b"qs-envelope-enc-v2-cnsa2";

/// Errors returned by sealing, opening and the CBOR encoding of a [`SealedMessage`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The algorithm name is longer than 255 bytes, so its length does not fit the AAD's length byte.
    #[error("algorithm name of {len} bytes is too long to encode in a single length byte (max 255)")]
    AlgorithmNameTooLong { len: usize },
    /// Writing the CBOR failed; the field holds the encoder's message.
    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),
    /// The input is over 10 MB, has a shape the CBOR guard refuses, is not valid CBOR, or is not a map;
    /// the field holds the reason.
    #[error("CBOR decoding failed: {0}")]
    CborDecode(String),
    /// A required field (`v`, `algo`, `kct`, `n` or `ct`) is absent or has the wrong CBOR type; the field
    /// holds its name.
    #[error("sealed message is missing required field '{0}'")]
    MissingField(&'static str),
    /// The KEM step failed (see [`KemError`]).
    #[error("KEM operation failed: {0}")]
    Kem(#[from] KemError),
    /// Deriving the AES key failed (see [`KdfError`]).
    #[error("key derivation failed: {0}")]
    Kdf(#[from] KdfError),
    /// AES-GCM decryption failed (see [`AeadError`]): wrong key, wrong AAD or tampered data.
    #[error("AEAD operation failed: {0}")]
    Aead(#[from] AeadError),
    /// The message nonce is not 12 bytes.
    #[error("nonce must be exactly {expected} bytes, got {actual}")]
    BadNonceLength { expected: usize, actual: usize },
    /// The CBOR version is outside 0 to 255.
    #[error("envelope version {0} is out of range for a single byte (0-255)")]
    InvalidVersion(i64),
    /// The algorithm is neither a hybrid KEM suite (v1) nor ML-KEM-1024 (v2), or the message's version
    /// does not match its algorithm.
    #[error("envelope suite '{0}' is not supported (v1 needs a hybrid KEM; v2 needs ML-KEM-1024)")]
    UnsupportedSuite(String),
    /// The version byte is neither 1 nor 2.
    #[error("envelope version {0} is not supported")]
    UnsupportedVersion(u8),
    /// The message's algorithm differs from the secret key's.
    #[error("sealed message algorithm does not match the secret key algorithm")]
    AlgorithmMismatch,
}

/// Build the AAD passed to AES-GCM, matching `Envelope._build_aad` exactly:
///   aad = byte(version) || byte(len(algorithm_bytes)) || algorithm_bytes || extra
/// `algorithm` must be ASCII (as quantum-safe-py encodes it with
/// `.encode("ascii")`) and no longer than 255 bytes, since its length is
/// encoded in a single byte.
///
/// # Errors
///
/// [`EnvelopeError::AlgorithmNameTooLong`] when `algorithm` is longer than 255 bytes. ASCII is not
/// checked here.
pub fn build_aad(version: u8, algorithm: &str, extra: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let algo_bytes = algorithm.as_bytes();
    if algo_bytes.len() > 255 {
        return Err(EnvelopeError::AlgorithmNameTooLong {
            len: algo_bytes.len(),
        });
    }
    let mut aad = Vec::with_capacity(2 + algo_bytes.len() + extra.len());
    aad.push(version);
    aad.push(algo_bytes.len() as u8);
    aad.extend_from_slice(algo_bytes);
    aad.extend_from_slice(extra);
    Ok(aad)
}

/// A sealed message: everything the recipient needs to open it, other than the secret key.
pub struct SealedMessage {
    /// Envelope version: 1 or 2.
    pub version: u8,
    /// KEM suite name, e.g. `"X25519+ML-KEM-768"`.
    pub algorithm: String,
    /// KEM ciphertext in the suite's wire layout.
    pub kem_ct: Vec<u8>,
    /// AES-GCM nonce; 12 bytes in a valid message.
    pub nonce: Vec<u8>,
    /// AES-GCM output, `ciphertext || 16-byte tag`.
    pub ciphertext: Vec<u8>,
    /// The caller's AAD, authenticated but stored in the clear. Empty when the CBOR has no `aad` field.
    pub aad: Vec<u8>,
}

impl SealedMessage {
    /// CBOR map with keys "v","algo","kct","n","ct","aad" — matching
    /// `SealedMessage.to_bytes()` in quantum-safe-py (`cbor2.dumps` of a
    /// dict with the same six keys).
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::CborEncode`] if the CBOR writer fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EnvelopeError> {
        let value = Value::Map(vec![
            (
                Value::Text("v".into()),
                Value::Integer((self.version as i64).into()),
            ),
            (Value::Text("algo".into()), Value::Text(self.algorithm.clone())),
            (Value::Text("kct".into()), Value::Bytes(self.kem_ct.clone())),
            (Value::Text("n".into()), Value::Bytes(self.nonce.clone())),
            (Value::Text("ct".into()), Value::Bytes(self.ciphertext.clone())),
            (Value::Text("aad".into()), Value::Bytes(self.aad.clone())),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).map_err(|e| EnvelopeError::CborEncode(e.to_string()))?;
        Ok(out)
    }

    /// Parses the CBOR written by [`SealedMessage::to_cbor`].
    ///
    /// The size limit and the CBOR guard run before decoding. A missing `aad` becomes an empty vector;
    /// every other field is required. The nonce length is not checked here ([`open_plan`] checks it).
    ///
    /// # Errors
    ///
    /// - [`EnvelopeError::CborDecode`] for input over 10 MB, a shape the CBOR guard refuses, invalid CBOR,
    ///   or a top-level value that is not a map.
    /// - [`EnvelopeError::MissingField`] for an absent or mistyped `v`, `algo`, `kct`, `n` or `ct`.
    /// - [`EnvelopeError::InvalidVersion`] when `v` does not fit in one byte.
    pub fn from_cbor(data: &[u8]) -> Result<Self, EnvelopeError> {
        if data.len() > crate::keys::MAX_PAYLOAD_BYTES {
            return Err(EnvelopeError::CborDecode(
                "payload exceeds the 10 MB limit".into(),
            ));
        }
        crate::cbor_guard::validate_shape(data).map_err(|e| EnvelopeError::CborDecode(e.to_string()))?;
        let value: Value =
            ciborium::from_reader(data).map_err(|e| EnvelopeError::CborDecode(e.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(EnvelopeError::CborDecode(
                "top-level CBOR value is not a map".into(),
            ));
        };
        let get_bytes = |key: &str| -> Option<Vec<u8>> {
            entries.iter().find_map(|(k, v)| match (k, v) {
                (Value::Text(t), Value::Bytes(b)) if t == key => Some(b.clone()),
                _ => None,
            })
        };
        let get_text = |key: &str| -> Option<String> {
            entries.iter().find_map(|(k, v)| match (k, v) {
                (Value::Text(t), Value::Text(s)) if t == key => Some(s.clone()),
                _ => None,
            })
        };
        let get_int = |key: &str| -> Option<i64> {
            entries.iter().find_map(|(k, v)| match (k, v) {
                (Value::Text(t), Value::Integer(i)) if t == key => (*i).try_into().ok(),
                _ => None,
            })
        };

        let raw_version = get_int("v").ok_or(EnvelopeError::MissingField("v"))?;
        let version = u8::try_from(raw_version).map_err(|_| EnvelopeError::InvalidVersion(raw_version))?;

        Ok(SealedMessage {
            version,
            algorithm: get_text("algo").ok_or(EnvelopeError::MissingField("algo"))?,
            kem_ct: get_bytes("kct").ok_or(EnvelopeError::MissingField("kct"))?,
            nonce: get_bytes("n").ok_or(EnvelopeError::MissingField("n"))?,
            ciphertext: get_bytes("ct").ok_or(EnvelopeError::MissingField("ct"))?,
            aad: get_bytes("aad").unwrap_or_default(),
        })
    }
}

/// Everything `seal` decides before the AES-256-GCM step: the KEM ciphertext, the one-time AES key,
/// the nonce and the AAD that GCM authenticates. `seal` uses it and then encrypts; a caller with a
/// faster AES-256-GCM (Node's native crypto) can encrypt with these values itself and get the same
/// bytes, then assemble the message with [`SealPlan::into_message`].
pub struct SealPlan {
    /// KEM suite name of the recipient key.
    pub algorithm: String,
    /// KEM ciphertext for the recipient.
    pub kem_ct: Vec<u8>,
    /// Random 12-byte nonce.
    pub nonce: [u8; aead::NONCE_LEN],
    /// The AAD passed to AES-GCM: version || algorithm length || algorithm || caller AAD.
    pub built_aad: Vec<u8>,
    /// The caller's own AAD, stored unchanged in the message.
    pub aad: Vec<u8>,
    /// The one-time AES-256 key. Wiped when dropped.
    pub key: Zeroizing<[u8; 32]>,
}

impl SealPlan {
    /// The envelope version, 1 (hybrid suites) or 2 (ML-KEM-1024), derived from the suite. It is not stored in the plan, so the plan
    /// holds nothing but the secret values and the message fields that depend on them.
    pub fn version(&self) -> u8 {
        version_for(&self.algorithm).expect("the suite was validated when the plan was made")
    }

    /// The finished message for the AES-GCM output (`ciphertext || tag`), leaving the plan intact (the
    /// public fields are copied; the key stays in the plan and is wiped when it is dropped).
    pub fn to_message(&self, ciphertext: Vec<u8>) -> SealedMessage {
        SealedMessage {
            version: self.version(),
            algorithm: self.algorithm.clone(),
            kem_ct: self.kem_ct.clone(),
            nonce: self.nonce.to_vec(),
            ciphertext,
            aad: self.aad.clone(),
        }
    }

    /// The finished message, given the AES-GCM output (`ciphertext || tag`).
    pub fn into_message(self, ciphertext: Vec<u8>) -> SealedMessage {
        SealedMessage {
            version: self.version(),
            algorithm: self.algorithm,
            kem_ct: self.kem_ct,
            nonce: self.nonce.to_vec(),
            ciphertext,
            aad: self.aad,
        }
    }
}

/// The key step of [`seal`]: KEM-encapsulate to the recipient, derive the AES key from the shared
/// secret, generate a random 12-byte nonce and build the AAD.
///
/// # Errors
///
/// - [`EnvelopeError::UnsupportedSuite`] when the key's algorithm is not a hybrid KEM suite or
///   ML-KEM-1024.
/// - [`EnvelopeError::Kem`] when encapsulation fails, e.g. a malformed public key.
/// - [`EnvelopeError::Kdf`] if key derivation fails.
/// - [`EnvelopeError::AlgorithmNameTooLong`] if the algorithm name exceeds 255 bytes.
///
/// # Panics
///
/// Panics if the operating system RNG is unavailable.
pub fn seal_plan(recipient_public_key: &kem::PublicKey, aad: &[u8]) -> Result<SealPlan, EnvelopeError> {
    let version = version_for(&recipient_public_key.algorithm)?;
    let (kem_ct, shared_secret) = kem::encapsulate(recipient_public_key)?;
    let key = derive_enc_key(version, &shared_secret[..])?;

    let mut nonce = [0u8; aead::NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS RNG must be available to generate a nonce");

    let built_aad = build_aad(version, &recipient_public_key.algorithm, aad)?;
    Ok(SealPlan {
        algorithm: recipient_public_key.algorithm.clone(),
        kem_ct,
        nonce,
        built_aad,
        aad: aad.to_vec(),
        key,
    })
}

/// Matches `Envelope.seal`: KEM-encapsulate to the recipient, derive the AES
/// key from the shared secret, generate a random 12-byte nonce, and
/// AES-256-GCM-encrypt with the version+algorithm+caller-aad bound in as AAD.
///
/// The `aad` is stored in the message and authenticated, not encrypted.
///
/// # Errors
///
/// The errors of [`seal_plan`]. Encryption itself does not fail.
///
/// # Panics
///
/// Panics if the operating system RNG is unavailable.
pub fn seal(
    plaintext: &[u8],
    recipient_public_key: &kem::PublicKey,
    aad: &[u8],
) -> Result<SealedMessage, EnvelopeError> {
    let plan = seal_plan(recipient_public_key, aad)?;
    let ciphertext = aead::encrypt(&plan.key, &plan.nonce, plaintext, &plan.built_aad);
    Ok(plan.into_message(ciphertext))
}

/// Which envelope version a KEM suite uses. v1 (quantum-safe-py compatible): any hybrid suite.
/// v2 (CNSA 2.0 profile): pure ML-KEM-1024 only. Everything else is rejected, including the other
/// pure KEMs (pure ML-KEM-512/768 envelopes are neither recommended nor produced).
fn version_for(algorithm: &str) -> Result<u8, EnvelopeError> {
    match KemSuite::parse(algorithm) {
        Some(s) if s.is_hybrid() => Ok(ENVELOPE_VERSION),
        Some(KemSuite::Pure(crate::suite::Pqc::MlKem1024)) => Ok(ENVELOPE_VERSION_CNSA2),
        _ => Err(EnvelopeError::UnsupportedSuite(algorithm.to_string())),
    }
}

// Derives the 32-byte AES key: HKDF-SHA256 with the v1 info for version 1, HKDF-SHA384 with the v2 info
// for version 2. Any other version is `UnsupportedVersion`.
fn derive_enc_key(version: u8, shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let okm = Zeroizing::new(if version == ENVELOPE_VERSION {
        kdf::derive_key(shared_secret, ENC_KEY_INFO, aead::KEY_LEN)?
    } else if version == ENVELOPE_VERSION_CNSA2 {
        kdf::derive_key_sha384(shared_secret, ENC_KEY_INFO_V2, aead::KEY_LEN)?
    } else {
        return Err(EnvelopeError::UnsupportedVersion(version));
    });
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    Ok(key)
}

/// What `open` needs for the AES-256-GCM step: the one-time key, the nonce and the AAD to authenticate.
pub struct OpenPlan {
    /// The message's 12-byte nonce.
    pub nonce: [u8; aead::NONCE_LEN],
    /// The AAD passed to AES-GCM: version || algorithm length || algorithm || the message's AAD.
    pub built_aad: Vec<u8>,
    /// The one-time AES-256 key. Wiped when dropped.
    pub key: Zeroizing<[u8; 32]>,
}

/// The key step of [`open`]: checks the message against the key, decapsulates, re-derives the AES key
/// and rebuilds the AAD. The caller (or [`open`]) then decrypts `sealed.ciphertext` with them.
///
/// The checks run in this order: nonce length, version and suite agreement, algorithm against the secret
/// key, then decapsulation.
///
/// # Errors
///
/// - [`EnvelopeError::BadNonceLength`] when the nonce is not 12 bytes.
/// - [`EnvelopeError::UnsupportedSuite`] when the algorithm is not a hybrid KEM suite or ML-KEM-1024, or
///   when the version is 1 or 2 but not the one that suite uses.
/// - [`EnvelopeError::UnsupportedVersion`] when the version is neither 1 nor 2 (for a supported suite).
/// - [`EnvelopeError::AlgorithmMismatch`] when the message's algorithm differs from the secret key's.
/// - [`EnvelopeError::Kem`] when decapsulation fails, e.g. a wrong-length KEM ciphertext.
/// - [`EnvelopeError::Kdf`] if key derivation fails.
/// - [`EnvelopeError::AlgorithmNameTooLong`] if the algorithm name exceeds 255 bytes.
pub fn open_plan(
    sealed: &SealedMessage,
    recipient_secret_key: &kem::SecretKey,
) -> Result<OpenPlan, EnvelopeError> {
    if sealed.nonce.len() != aead::NONCE_LEN {
        return Err(EnvelopeError::BadNonceLength {
            expected: aead::NONCE_LEN,
            actual: sealed.nonce.len(),
        });
    }
    // The version must agree with the suite: a message cannot be relabelled into another profile.
    let expected_version = version_for(&sealed.algorithm)?;
    if sealed.version != expected_version {
        return Err(
            if sealed.version == ENVELOPE_VERSION || sealed.version == ENVELOPE_VERSION_CNSA2 {
                EnvelopeError::UnsupportedSuite(sealed.algorithm.clone())
            } else {
                EnvelopeError::UnsupportedVersion(sealed.version)
            },
        );
    }
    if sealed.algorithm != recipient_secret_key.algorithm {
        return Err(EnvelopeError::AlgorithmMismatch);
    }
    let shared_secret = kem::decapsulate(recipient_secret_key, &sealed.kem_ct)?;
    let enc_key = derive_enc_key(sealed.version, &shared_secret[..])?;

    let built_aad = build_aad(sealed.version, &sealed.algorithm, &sealed.aad)?;
    let nonce: [u8; aead::NONCE_LEN] = sealed
        .nonce
        .as_slice()
        .try_into()
        .expect("length already checked above");
    Ok(OpenPlan {
        nonce,
        built_aad,
        key: enc_key,
    })
}

/// Matches `Envelope.open`: KEM-decapsulate, re-derive the same AES key,
/// rebuild the same AAD, then AES-256-GCM-decrypt+verify.
///
/// # Errors
///
/// The errors of [`open_plan`], plus [`EnvelopeError::Aead`] when the GCM tag does not verify (wrong
/// key, modified ciphertext, nonce or AAD).
pub fn open(sealed: &SealedMessage, recipient_secret_key: &kem::SecretKey) -> Result<Vec<u8>, EnvelopeError> {
    let plan = open_plan(sealed, recipient_secret_key)?;
    Ok(aead::decrypt(
        &plan.key,
        &plan.nonce,
        &sealed.ciphertext,
        &plan.built_aad,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;

    #[derive(Deserialize)]
    struct AadVector {
        version: u8,
        algorithm: String,
        extra: String,
        expected_aad: String,
    }

    #[derive(Deserialize)]
    struct VectorFile {
        aad_construction: AadVector,
        aad_construction_with_extra: AadVector,
    }

    fn load_vectors() -> VectorFile {
        let raw = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/glue_vectors.json"
        ))
        .expect("run scripts/generate_vectors.py first (see Task 2 of the implementation plan)");
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn build_aad_matches_python_reference_no_extra() {
        let v = load_vectors().aad_construction;
        let result = build_aad(v.version, &v.algorithm, &[]).unwrap();
        assert_eq!(hex::encode(result), v.expected_aad);
    }

    #[test]
    fn build_aad_matches_python_reference_with_extra() {
        let v = load_vectors().aad_construction_with_extra;
        let extra = hex::decode(&v.extra).unwrap();
        let result = build_aad(v.version, &v.algorithm, &extra).unwrap();
        assert_eq!(hex::encode(result), v.expected_aad);
    }

    #[test]
    fn build_aad_rejects_algorithm_name_over_255_bytes() {
        let long_algo = "A".repeat(256);
        let err = build_aad(1, &long_algo, &[]).unwrap_err();
        assert_eq!(err, EnvelopeError::AlgorithmNameTooLong { len: 256 });
    }

    #[test]
    fn build_aad_accepts_algorithm_name_at_255_bytes() {
        let max_algo = "A".repeat(255);
        assert!(build_aad(1, &max_algo, &[]).is_ok());
    }

    #[test]
    fn cnsa2_profile_roundtrips_and_is_isolated_from_v1() {
        let kp = kem::generate_keypair_for("ML-KEM-1024").unwrap();
        let sealed = seal(b"cnsa2 payload", &kp.public, b"aad").unwrap();
        assert_eq!(sealed.version, ENVELOPE_VERSION_CNSA2);
        assert_eq!(sealed.algorithm, CNSA2_ENVELOPE_ALGORITHM);
        assert_eq!(sealed.kem_ct.len(), 1568);
        assert_eq!(open(&sealed, &kp.secret).unwrap(), b"cnsa2 payload");

        // Relabelling the version must fail (the profile is checked and the version is bound into the AAD).
        let mut relabelled = SealedMessage::from_cbor(&sealed.to_cbor().unwrap()).unwrap();
        relabelled.version = ENVELOPE_VERSION;
        assert!(open(&relabelled, &kp.secret).is_err());
        let mut v3 = SealedMessage::from_cbor(&sealed.to_cbor().unwrap()).unwrap();
        v3.version = 3;
        assert_eq!(open(&v3, &kp.secret), Err(EnvelopeError::UnsupportedVersion(3)));

        // A hybrid envelope relabelled v2 must fail too.
        let hk = kem::generate_keypair();
        let mut hybrid = seal(b"x", &hk.public, b"").unwrap();
        hybrid.version = ENVELOPE_VERSION_CNSA2;
        assert!(open(&hybrid, &hk.secret).is_err());

        // Other pure KEMs are not valid envelope suites.
        for pure in ["ML-KEM-512", "ML-KEM-768"] {
            let k = kem::generate_keypair_for(pure).unwrap();
            assert!(matches!(
                seal(b"x", &k.public, b""),
                Err(EnvelopeError::UnsupportedSuite(_))
            ));
        }
    }

    #[test]
    fn cnsa2_profile_authenticates_everything() {
        let kp = kem::generate_keypair_for("ML-KEM-1024").unwrap();
        let sealed = seal(b"hello", &kp.public, b"aad").unwrap();
        let mut c = SealedMessage::from_cbor(&sealed.to_cbor().unwrap()).unwrap();
        c.ciphertext[0] ^= 1;
        assert!(open(&c, &kp.secret).is_err());
        let mut a = SealedMessage::from_cbor(&sealed.to_cbor().unwrap()).unwrap();
        a.aad = b"other".to_vec();
        assert!(open(&a, &kp.secret).is_err());
        let other = kem::generate_keypair_for("ML-KEM-1024").unwrap();
        assert!(open(&sealed, &other.secret).is_err());
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let kp = kem::generate_keypair();
        let plaintext = b"correct horse battery staple";
        let sealed = seal(plaintext, &kp.public, b"vault-item-42").unwrap();
        let opened = open(&sealed, &kp.secret).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn sealed_message_roundtrips_through_cbor() {
        let kp = kem::generate_keypair();
        let sealed = seal(b"hello", &kp.public, b"").unwrap();
        let cbor = sealed.to_cbor().unwrap();
        let decoded = SealedMessage::from_cbor(&cbor).unwrap();
        let opened = open(&decoded, &kp.secret).unwrap();
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let kp = kem::generate_keypair();
        let mut sealed = seal(b"hello", &kp.public, b"").unwrap();
        sealed.ciphertext[0] ^= 0xFF;
        assert!(open(&sealed, &kp.secret).is_err());
    }

    #[test]
    fn from_cbor_rejects_missing_field() {
        let value = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            // "algo" deliberately omitted
        ]);
        let mut data = Vec::new();
        ciborium::into_writer(&value, &mut data).unwrap();
        // `assert_eq!` here would require `SealedMessage: PartialEq` (Rust
        // checks the trait bound on the whole `Result<SealedMessage, _>`
        // type even though only the `Err` arm is exercised) — SealedMessage
        // deliberately doesn't derive PartialEq (it holds key-derived
        // secrets transiently; no reason to enable content comparison), so
        // `matches!` is used instead.
        assert!(matches!(
            SealedMessage::from_cbor(&data),
            Err(EnvelopeError::MissingField("algo"))
        ));
    }

    #[test]
    fn from_cbor_rejects_non_map_input() {
        let mut data = Vec::new();
        ciborium::into_writer(&Value::Integer(42.into()), &mut data).unwrap();
        assert!(SealedMessage::from_cbor(&data).is_err());
    }

    /// Code-review finding: `get_int("v") ... as u8` silently truncates an
    /// out-of-range version instead of rejecting it (e.g. 257 wraps to 1).
    /// quantum-safe-py's `Envelope._build_aad` runs `bytes([version, ...])`,
    /// which raises `ValueError` for the same out-of-range value, so a
    /// version Python rejects must not be silently accepted here — accepting
    /// it makes the wire format ambiguous/malleable (many different "v"
    /// bytes decoding to the same effective version).
    #[test]
    fn from_cbor_rejects_version_above_u8_range() {
        let value = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(257.into())),
            (
                Value::Text("algo".into()),
                Value::Text("X25519+ML-KEM-768".into()),
            ),
            (Value::Text("kct".into()), Value::Bytes(vec![0u8; 4])),
            (Value::Text("n".into()), Value::Bytes(vec![0u8; 12])),
            (Value::Text("ct".into()), Value::Bytes(vec![0u8; 4])),
        ]);
        let mut data = Vec::new();
        ciborium::into_writer(&value, &mut data).unwrap();
        assert!(matches!(
            SealedMessage::from_cbor(&data),
            Err(EnvelopeError::InvalidVersion(257))
        ));
    }

    #[test]
    fn from_cbor_rejects_negative_version() {
        let value = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer((-1i64).into())),
            (
                Value::Text("algo".into()),
                Value::Text("X25519+ML-KEM-768".into()),
            ),
            (Value::Text("kct".into()), Value::Bytes(vec![0u8; 4])),
            (Value::Text("n".into()), Value::Bytes(vec![0u8; 12])),
            (Value::Text("ct".into()), Value::Bytes(vec![0u8; 4])),
        ]);
        let mut data = Vec::new();
        ciborium::into_writer(&value, &mut data).unwrap();
        assert!(matches!(
            SealedMessage::from_cbor(&data),
            Err(EnvelopeError::InvalidVersion(-1))
        ));
    }

    /// Code-review finding: the "wire-compatible with quantum-safe-py" claim
    /// was only backed by isolated glue-function vectors (combiner, AAD),
    /// not by a real Python-generated keypair + sealed envelope. This test
    /// closes that gap: it parses and opens an envelope that real
    /// quantum-safe-py (via its liboqs backend) actually produced, using a
    /// secret key it actually produced -- proving the 2400-byte *expanded*
    /// ML-KEM secret-key format quantum-safe-core deliberately uses (see
    /// kem.rs's module doc) is the same format quantum-safe-py's liboqs
    /// backend emits, and that our CBOR/AAD/AEAD pipeline opens a real
    /// Python-sealed envelope correctly end to end.
    #[test]
    fn opens_envelope_sealed_by_real_quantum_safe_py() {
        #[derive(serde::Deserialize)]
        struct EnvelopeRoundtripVector {
            secret_key: String,
            algorithm: String,
            plaintext: String,
            sealed: String,
        }
        #[derive(serde::Deserialize)]
        struct VectorFile {
            envelope_roundtrip: EnvelopeRoundtripVector,
        }
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/glue_vectors.json"
        ))
        .expect("run scripts/generate_vectors.py first (see Task 2 of the implementation plan)");
        let file: VectorFile = serde_json::from_str(&raw).unwrap();
        let v = file.envelope_roundtrip;

        let secret_key = kem::SecretKey::new(hex::decode(&v.secret_key).unwrap(), v.algorithm.clone());
        let sealed_bytes = hex::decode(&v.sealed).unwrap();
        let sealed = SealedMessage::from_cbor(&sealed_bytes).unwrap();

        let opened = open(&sealed, &secret_key).unwrap();
        assert_eq!(hex::encode(opened), v.plaintext);
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn plan_then_encrypt_equals_seal_and_opens() {
        for algo in ["X25519+ML-KEM-768", "P-384+ML-KEM-1024", "ML-KEM-1024"] {
            let pair = kem::generate_keypair_for(algo).unwrap();
            for len in [0usize, 1, 100, 70_000] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let plan = seal_plan(&pair.public, b"extra").unwrap();
                let ct = aead::encrypt(&plan.key, &plan.nonce, &data, &plan.built_aad);
                let msg = plan.into_message(ct);
                assert_eq!(open(&msg, &pair.secret).unwrap(), data, "{algo} {len}");
                // the key step of open gives the values that decrypt the same message
                let op = open_plan(&msg, &pair.secret).unwrap();
                let plain = aead::decrypt(&op.key, &op.nonce, &msg.ciphertext, &op.built_aad).unwrap();
                assert_eq!(plain, data);
            }
        }
    }

    #[test]
    fn open_plan_keeps_every_check_of_open() {
        let a = kem::generate_keypair_for("X25519+ML-KEM-768").unwrap();
        let b = kem::generate_keypair_for("X25519+ML-KEM-1024").unwrap();
        let msg = seal(b"hello", &a.public, b"").unwrap();
        assert!(matches!(
            open_plan(&msg, &b.secret),
            Err(EnvelopeError::AlgorithmMismatch)
        ));
        let mut bad = seal(b"hello", &a.public, b"").unwrap();
        bad.nonce.pop();
        assert!(matches!(
            open_plan(&bad, &a.secret),
            Err(EnvelopeError::BadNonceLength { .. })
        ));
        let mut relabelled = seal(b"hello", &a.public, b"").unwrap();
        relabelled.version = ENVELOPE_VERSION_CNSA2;
        assert!(open_plan(&relabelled, &a.secret).is_err());
    }
}
