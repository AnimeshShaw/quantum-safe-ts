//! AES-256-GCM encryption, matching `AESGCM` from Python's `cryptography`
//! library as used in `quantum_safe.protocols.envelope.Envelope.seal`/`open`:
//! a 12-byte nonce, and `encrypt()` returns `ciphertext || 16-byte tag`
//! concatenated (not returned as a separate field).

use thiserror::Error;

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AeadError {
    #[error("AES-GCM authentication failed: wrong key, wrong AAD, or tampered ciphertext")]
    AuthenticationFailed,
}

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

/// Encrypt `plaintext` under `key`/`nonce`, authenticating `aad`. Returns
/// `ciphertext || tag` (tag is the trailing 16 bytes), matching
/// `cryptography.hazmat.primitives.ciphers.aead.AESGCM.encrypt`'s output shape.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(nonce.as_slice()).expect("NONCE_LEN-sized array always converts");
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("AES-256-GCM encryption with a valid 12-byte nonce cannot fail")
}

/// Decrypt+verify `ciphertext_with_tag` under `key`/`nonce`/`aad`. Returns
/// `Err(AeadError::AuthenticationFailed)` — never panics — on a wrong key,
/// wrong AAD, or any tampering, so a caller decrypting attacker-supplied
/// envelopes never crashes the process on bad input.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(nonce.as_slice()).expect("NONCE_LEN-sized array always converts");
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext_with_tag, aad })
        .map_err(|_| AeadError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;

    #[derive(Deserialize)]
    struct AesGcmVector {
        key: String,
        nonce: String,
        plaintext: String,
        aad: String,
        expected_ciphertext_with_tag: String,
    }

    #[derive(Deserialize)]
    struct VectorFile {
        aes_gcm: AesGcmVector,
    }

    fn load_vector() -> AesGcmVector {
        let raw = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/glue_vectors.json"
        ))
        .expect("run scripts/generate_vectors.py first (see Task 2 of the implementation plan)");
        let file: VectorFile = serde_json::from_str(&raw).unwrap();
        file.aes_gcm
    }

    fn from_hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn encrypt_matches_python_reference() {
        let v = load_vector();
        let key: [u8; 32] = from_hex(&v.key).try_into().unwrap();
        let nonce: [u8; 12] = from_hex(&v.nonce).try_into().unwrap();
        let plaintext = from_hex(&v.plaintext);
        let aad = from_hex(&v.aad);

        let result = encrypt(&key, &nonce, &plaintext, &aad);
        assert_eq!(hex::encode(result), v.expected_ciphertext_with_tag);
    }

    #[test]
    fn decrypt_matches_python_reference_and_roundtrips() {
        let v = load_vector();
        let key: [u8; 32] = from_hex(&v.key).try_into().unwrap();
        let nonce: [u8; 12] = from_hex(&v.nonce).try_into().unwrap();
        let ciphertext = from_hex(&v.expected_ciphertext_with_tag);
        let aad = from_hex(&v.aad);

        let plaintext = decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(hex::encode(plaintext), v.plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let v = load_vector();
        let key: [u8; 32] = from_hex(&v.key).try_into().unwrap();
        let nonce: [u8; 12] = from_hex(&v.nonce).try_into().unwrap();
        let mut ciphertext = from_hex(&v.expected_ciphertext_with_tag);
        ciphertext[0] ^= 0xFF;
        let aad = from_hex(&v.aad);

        assert_eq!(decrypt(&key, &nonce, &ciphertext, &aad), Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn decrypt_rejects_wrong_aad() {
        let v = load_vector();
        let key: [u8; 32] = from_hex(&v.key).try_into().unwrap();
        let nonce: [u8; 12] = from_hex(&v.nonce).try_into().unwrap();
        let ciphertext = from_hex(&v.expected_ciphertext_with_tag);

        assert_eq!(
            decrypt(&key, &nonce, &ciphertext, b"wrong aad"),
            Err(AeadError::AuthenticationFailed)
        );
    }
}
