//! Authenticated-encryption envelope, matching
//! `quantum_safe.protocols.envelope` exactly. This file is built in two
//! passes: AAD construction here (Task 5), then `SealedMessage` + CBOR +
//! `seal`/`open` in Task 6.

use thiserror::Error;

pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("algorithm name of {len} bytes is too long to encode in a single length byte (max 255)")]
    AlgorithmNameTooLong { len: usize },
}

/// Build the AAD passed to AES-GCM, matching `Envelope._build_aad` exactly:
///   aad = byte(version) || byte(len(algorithm_bytes)) || algorithm_bytes || extra
/// `algorithm` must be ASCII (as quantum-safe-py encodes it with
/// `.encode("ascii")`) and no longer than 255 bytes, since its length is
/// encoded in a single byte.
pub fn build_aad(version: u8, algorithm: &str, extra: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let algo_bytes = algorithm.as_bytes();
    if algo_bytes.len() > 255 {
        return Err(EnvelopeError::AlgorithmNameTooLong { len: algo_bytes.len() });
    }
    let mut aad = Vec::with_capacity(2 + algo_bytes.len() + extra.len());
    aad.push(version);
    aad.push(algo_bytes.len() as u8);
    aad.extend_from_slice(algo_bytes);
    aad.extend_from_slice(extra);
    Ok(aad)
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
}
