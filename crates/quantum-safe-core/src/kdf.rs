//! HKDF-SHA256-based key derivation, matching two constructions from
//! quantum-safe-py exactly:
//!   - the hybrid KEM combiner: `quantum_safe.types.kem.combine_shared_secrets`
//!   - the envelope's per-message key derivation: `SharedSecret.derive_key`
//! Both use `cryptography.hazmat.primitives.kdf.hkdf.HKDF`, which follows
//! RFC 5869 exactly — including substituting a zero-filled salt of the
//! hash's output length when `salt=None`, which the Rust `hkdf` crate's
//! `Hkdf::new(None, ikm)` also does. This is why `derive_key` below passes
//! `None` rather than an explicit zero buffer: both sides apply the same
//! RFC 5869 substitution, so they still agree.

use thiserror::Error;

const HYBRID_COMBINER_INFO: &[u8] = b"quantum-safe hybrid KEM v1";
const SHARED_SECRET_LEN: usize = 32;
/// RFC 5869 §2.3: HKDF-Expand output is capped at 255 * HashLen.
const MAX_HKDF_OUTPUT_SHA256: usize = 255 * 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KdfError {
    #[error("requested HKDF output of {requested} bytes exceeds the maximum of {max} for SHA-256")]
    OutputTooLong { requested: usize, max: usize },
    #[error("Argon2id derivation failed: {0}")]
    Argon2(String),
}

use hkdf::Hkdf;
use sha2::Sha256;

/// Combine a classical and a PQC KEM shared secret into one 32-byte key,
/// matching `quantum_safe.types.kem.combine_shared_secrets` exactly:
///   ikm  = classical_ss || pqc_ss
///   salt = classical_ct || pqc_ct
///   info = b"quantum-safe hybrid KEM v1" || 0x00 || algorithm.encode("ascii")
///   combined = HKDF-SHA256(ikm, salt, info, length=32)
pub fn combine_shared_secrets(
    classical_ss: &[u8],
    pqc_ss: &[u8],
    algorithm: &str,
    classical_ct: &[u8],
    pqc_ct: &[u8],
) -> [u8; SHARED_SECRET_LEN] {
    let mut ikm = Vec::with_capacity(classical_ss.len() + pqc_ss.len());
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pqc_ss);

    let mut salt = Vec::with_capacity(classical_ct.len() + pqc_ct.len());
    salt.extend_from_slice(classical_ct);
    salt.extend_from_slice(pqc_ct);

    let mut info = Vec::with_capacity(HYBRID_COMBINER_INFO.len() + 1 + algorithm.len());
    info.extend_from_slice(HYBRID_COMBINER_INFO);
    info.push(0x00);
    info.extend_from_slice(algorithm.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; SHARED_SECRET_LEN];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is always <= the SHA-256 HKDF output cap");
    okm
}

/// Derive a key from a shared secret via HKDF-SHA256 with no salt, matching
/// `SharedSecret.derive_key(length, salt=None, info)` in quantum-safe-py.
/// `length` is caller-controlled (it will eventually come from the WASM
/// binding, i.e. from JS callers), so this returns `Result` rather than
/// panicking on an out-of-range request.
pub fn derive_key(shared_secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, KdfError> {
    if length > MAX_HKDF_OUTPUT_SHA256 {
        return Err(KdfError::OutputTooLong { requested: length, max: MAX_HKDF_OUTPUT_SHA256 });
    }
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("length was already checked against the HKDF output cap above");
    Ok(okm)
}

use argon2::{Algorithm, Argon2, Params, Version};

/// OWASP-recommended Argon2id parameters for interactive, client-side use
/// (memory-hard master-password stretching): 19 MiB memory, 2 iterations,
/// 1 degree of parallelism, 32-byte output. This is the application's own
/// choice — quantum-safe-py has no master-password concept, so there is no
/// upstream construction to match here.
const ARGON2ID_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2ID_ITERATIONS: u32 = 2;
const ARGON2ID_PARALLELISM: u32 = 1;

pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], KdfError> {
    let params = Params::new(ARGON2ID_MEMORY_KIB, ARGON2ID_ITERATIONS, ARGON2ID_PARALLELISM, Some(32))
        .map_err(|e| KdfError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| KdfError::Argon2(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;

    #[derive(Deserialize)]
    struct CombinerVector {
        classical_ss: String,
        pqc_ss: String,
        classical_ct: String,
        pqc_ct: String,
        algorithm: String,
        expected_shared_secret: String,
    }

    #[derive(Deserialize)]
    struct EncKeyVector {
        shared_secret: String,
        info: String,
        expected_enc_key: String,
    }

    #[derive(Deserialize)]
    struct VectorFile {
        combiner: CombinerVector,
        enc_key_derivation: EncKeyVector,
    }

    fn load_vectors() -> VectorFile {
        let raw = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/glue_vectors.json"
        ))
        .expect("run scripts/generate_vectors.py first (see Task 2 of the implementation plan)");
        serde_json::from_str(&raw).expect("glue_vectors.json must match the expected shape")
    }

    fn from_hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("vector fixture field must be valid hex")
    }

    #[test]
    fn combiner_matches_python_reference() {
        let v = load_vectors().combiner;
        let result = combine_shared_secrets(
            &from_hex(&v.classical_ss),
            &from_hex(&v.pqc_ss),
            &v.algorithm,
            &from_hex(&v.classical_ct),
            &from_hex(&v.pqc_ct),
        );
        assert_eq!(hex::encode(result), v.expected_shared_secret);
    }

    #[test]
    fn enc_key_derivation_matches_python_reference() {
        let v = load_vectors().enc_key_derivation;
        let result = derive_key(&from_hex(&v.shared_secret), v.info.as_bytes(), 32).unwrap();
        assert_eq!(hex::encode(result), v.expected_enc_key);
    }

    #[test]
    fn derive_key_rejects_output_longer_than_hkdf_cap() {
        let err = derive_key(&[0u8; 32], b"info", MAX_HKDF_OUTPUT_SHA256 + 1).unwrap_err();
        assert_eq!(
            err,
            KdfError::OutputTooLong { requested: MAX_HKDF_OUTPUT_SHA256 + 1, max: MAX_HKDF_OUTPUT_SHA256 }
        );
    }

    #[test]
    fn derive_master_key_is_deterministic_given_same_password_and_salt() {
        let a = derive_master_key(b"correct horse battery staple", b"a-16-byte-salt!!").unwrap();
        let b = derive_master_key(b"correct horse battery staple", b"a-16-byte-salt!!").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_master_key_differs_for_different_passwords() {
        let a = derive_master_key(b"password one", b"a-16-byte-salt!!").unwrap();
        let b = derive_master_key(b"password two", b"a-16-byte-salt!!").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_master_key_differs_for_different_salts() {
        let a = derive_master_key(b"same password", b"salt-number-one!").unwrap();
        let b = derive_master_key(b"same password", b"salt-number-two!").unwrap();
        assert_ne!(a, b);
    }
}
