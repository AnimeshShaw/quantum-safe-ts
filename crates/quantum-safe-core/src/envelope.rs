//! Authenticated-encryption envelope, matching
//! `quantum_safe.protocols.envelope` exactly. This file is built in two
//! passes: AAD construction here (Task 5), then `SealedMessage` + CBOR +
//! `seal`/`open` in Task 6.

use crate::aead::{self, AeadError};
use crate::kdf;
use crate::kdf::KdfError;
use crate::kem;
use crate::kem::KemError;
use crate::suite::KemSuite;
use ciborium::value::Value;
use thiserror::Error;
use zeroize::Zeroizing;

pub const ENVELOPE_VERSION: u8 = 1;
/// Envelope v2: the CNSA 2.0 profile (pure ML-KEM-1024, HKDF-SHA384, AES-256-GCM). TypeScript-only.
pub const ENVELOPE_VERSION_CNSA2: u8 = 2;
/// The only KEM suite v2 envelopes use.
pub const CNSA2_ENVELOPE_ALGORITHM: &str = "ML-KEM-1024";
const ENC_KEY_INFO: &[u8] = b"qs-envelope-enc-v1";
const ENC_KEY_INFO_V2: &[u8] = b"qs-envelope-enc-v2-cnsa2";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("algorithm name of {len} bytes is too long to encode in a single length byte (max 255)")]
    AlgorithmNameTooLong { len: usize },
    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),
    #[error("CBOR decoding failed: {0}")]
    CborDecode(String),
    #[error("sealed message is missing required field '{0}'")]
    MissingField(&'static str),
    #[error("KEM operation failed: {0}")]
    Kem(#[from] KemError),
    #[error("key derivation failed: {0}")]
    Kdf(#[from] KdfError),
    #[error("AEAD operation failed: {0}")]
    Aead(#[from] AeadError),
    #[error("nonce must be exactly {expected} bytes, got {actual}")]
    BadNonceLength { expected: usize, actual: usize },
    #[error("envelope version {0} is out of range for a single byte (0-255)")]
    InvalidVersion(i64),
    #[error("envelope suite '{0}' is not supported (v1 needs a hybrid KEM; v2 needs ML-KEM-1024)")]
    UnsupportedSuite(String),
    #[error("envelope version {0} is not supported")]
    UnsupportedVersion(u8),
    #[error("sealed message algorithm does not match the secret key algorithm")]
    AlgorithmMismatch,
}

/// Build the AAD passed to AES-GCM, matching `Envelope._build_aad` exactly:
///   aad = byte(version) || byte(len(algorithm_bytes)) || algorithm_bytes || extra
/// `algorithm` must be ASCII (as quantum-safe-py encodes it with
/// `.encode("ascii")`) and no longer than 255 bytes, since its length is
/// encoded in a single byte.
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

pub struct SealedMessage {
    pub version: u8,
    pub algorithm: String,
    pub kem_ct: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

impl SealedMessage {
    /// CBOR map with keys "v","algo","kct","n","ct","aad" — matching
    /// `SealedMessage.to_bytes()` in quantum-safe-py (`cbor2.dumps` of a
    /// dict with the same five keys).
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

    pub fn from_cbor(data: &[u8]) -> Result<Self, EnvelopeError> {
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

/// Matches `Envelope.seal`: KEM-encapsulate to the recipient, derive the AES
/// key from the shared secret, generate a random 12-byte nonce, and
/// AES-256-GCM-encrypt with the version+algorithm+caller-aad bound in as AAD.
pub fn seal(
    plaintext: &[u8],
    recipient_public_key: &kem::PublicKey,
    aad: &[u8],
) -> Result<SealedMessage, EnvelopeError> {
    let version = version_for(&recipient_public_key.algorithm)?;
    let (kem_ct, shared_secret) = kem::encapsulate(recipient_public_key)?;
    let enc_key = derive_enc_key(version, &shared_secret[..])?;

    let mut nonce_bytes = [0u8; aead::NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).expect("OS RNG must be available to generate a nonce");

    let built_aad = build_aad(version, &recipient_public_key.algorithm, aad)?;
    let ciphertext = aead::encrypt(&enc_key, &nonce_bytes, plaintext, &built_aad);

    Ok(SealedMessage {
        version,
        algorithm: recipient_public_key.algorithm.clone(),
        kem_ct,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        aad: aad.to_vec(),
    })
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

fn derive_enc_key(version: u8, shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let okm = Zeroizing::new(match version {
        ENVELOPE_VERSION => kdf::derive_key(shared_secret, ENC_KEY_INFO, aead::KEY_LEN)?,
        ENVELOPE_VERSION_CNSA2 => kdf::derive_key_sha384(shared_secret, ENC_KEY_INFO_V2, aead::KEY_LEN)?,
        v => return Err(EnvelopeError::UnsupportedVersion(v)),
    });
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    Ok(key)
}

/// Matches `Envelope.open`: KEM-decapsulate, re-derive the same AES key,
/// rebuild the same AAD, then AES-256-GCM-decrypt+verify.
pub fn open(sealed: &SealedMessage, recipient_secret_key: &kem::SecretKey) -> Result<Vec<u8>, EnvelopeError> {
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
    Ok(aead::decrypt(&enc_key, &nonce, &sealed.ciphertext, &built_aad)?)
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
