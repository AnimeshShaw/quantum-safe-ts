//! Hybrid KEM: X25519 (classical) + ML-KEM-768 (post-quantum), matching
//! `quantum_safe.kem.hybrid.HybridKEM` with `classical="X25519"`,
//! `pqc="ML-KEM-768"` — the only combination quantum-safe-ts v0.1 supports.
//! Key and ciphertext byte layouts match `_pack_components`/
//! `HybridCipherText.to_bytes()` in quantum-safe-py exactly (see the spec's
//! "Exact wire format" section for the byte-offset table). Secret-key wire
//! bytes use ML-KEM's *expanded* form (2400 bytes for ML-KEM-768), matching
//! quantum-safe-py's `secret_key_bytes=2400` — not the newer, more compact
//! 64-byte seed form this crate now prefers by default (see the
//! `#[allow(deprecated)]` calls below: the "deprecated" expanded encoding is
//! the one we need for wire compatibility, so we use it deliberately).

use crate::kdf::combine_shared_secrets;
use crate::wire::{pack_components, unpack_components};
use thiserror::Error;

pub const ALGORITHM: &str = "X25519+ML-KEM-768";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KemError {
    #[error("key/ciphertext algorithm does not match the configured hybrid algorithm {ALGORITHM}")]
    AlgorithmMismatch,
    #[error("key bytes are malformed or truncated")]
    MalformedKey,
    #[error("ciphertext bytes are malformed or truncated")]
    MalformedCiphertext,
}

pub struct PublicKey {
    pub raw: Vec<u8>,
    pub algorithm: String,
}

pub struct SecretKey {
    pub raw: Vec<u8>,
    pub algorithm: String,
}

pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

pub struct HybridCiphertext {
    pub classical_ct: Vec<u8>,
    pub pqc_ct: Vec<u8>,
}

impl HybridCiphertext {
    /// Matches `HybridCipherText.to_bytes()`: 2-byte BE length prefix of
    /// `classical_ct`, then `classical_ct`, then `pqc_ct` (no prefix — it's
    /// everything remaining).
    pub fn to_bytes(&self) -> Vec<u8> {
        pack_components(&self.classical_ct, &self.pqc_ct)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, KemError> {
        let (classical_ct, pqc_ct) = unpack_components(data).map_err(|_| KemError::MalformedCiphertext)?;
        if pqc_ct.is_empty() {
            return Err(KemError::MalformedCiphertext);
        }
        Ok(Self {
            classical_ct: classical_ct.to_vec(),
            pqc_ct: pqc_ct.to_vec(),
        })
    }
}

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{Decapsulate, Encapsulate, ExpandedDecapsulationKey, Kem as _, KeyExport, MlKem768};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

pub fn generate_keypair() -> KeyPair {
    // Classical half — StaticSecret::random() uses OsRng internally.
    let x25519_secret = X25519SecretKey::random();
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // PQC half. `getrandom` feature enables the no-arg convenience form.
    let (dk, ek) = MlKem768::generate_keypair();
    #[allow(deprecated)]
    let dk_expanded = dk.to_expanded_bytes(); // 2400 bytes — see module doc
    let ek_bytes = ek.to_bytes(); // via KeyExport — 1184 bytes

    let combined_pub = pack_components(x25519_public.as_bytes(), ek_bytes.as_slice());
    let combined_sec = pack_components(&x25519_secret.to_bytes(), dk_expanded.as_slice());

    KeyPair {
        public: PublicKey {
            raw: combined_pub,
            algorithm: ALGORITHM.to_string(),
        },
        secret: SecretKey {
            raw: combined_sec,
            algorithm: ALGORITHM.to_string(),
        },
    }
}

pub fn encapsulate(public_key: &PublicKey) -> Result<(HybridCiphertext, [u8; 32]), KemError> {
    if public_key.algorithm != ALGORITHM {
        return Err(KemError::AlgorithmMismatch);
    }
    let (classical_pub_bytes, pqc_pub_bytes) =
        unpack_components(&public_key.raw).map_err(|_| KemError::MalformedKey)?;

    // Classical half: ephemeral X25519, "ciphertext" is our ephemeral public key
    let classical_pub_arr: [u8; 32] = classical_pub_bytes
        .try_into()
        .map_err(|_| KemError::MalformedKey)?;
    let recipient_x25519_pub = X25519PublicKey::from(classical_pub_arr);
    let ephemeral_secret = X25519SecretKey::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let classical_ss = ephemeral_secret.diffie_hellman(&recipient_x25519_pub);
    let classical_ct = ephemeral_public.as_bytes().to_vec();

    // PQC half
    let ek_key_bytes = ml_kem::Key::<ml_kem::EncapsulationKey<MlKem768>>::try_from(pqc_pub_bytes)
        .map_err(|_| KemError::MalformedKey)?;
    let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&ek_key_bytes).map_err(|_| KemError::MalformedKey)?;
    let (pqc_ct, pqc_ss) = ek.encapsulate(); // infallible; getrandom feature

    let combined = combine_shared_secrets(
        classical_ss.as_bytes(),
        pqc_ss.as_slice(),
        ALGORITHM,
        &classical_ct,
        pqc_ct.as_slice(),
    );

    Ok((
        HybridCiphertext {
            classical_ct,
            pqc_ct: pqc_ct.as_slice().to_vec(),
        },
        combined,
    ))
}

pub fn decapsulate(secret_key: &SecretKey, ciphertext: &HybridCiphertext) -> Result<[u8; 32], KemError> {
    if secret_key.algorithm != ALGORITHM {
        return Err(KemError::AlgorithmMismatch);
    }
    let (classical_sec_bytes, pqc_sec_bytes) =
        unpack_components(&secret_key.raw).map_err(|_| KemError::MalformedKey)?;

    let classical_sec_arr: [u8; 32] = classical_sec_bytes
        .try_into()
        .map_err(|_| KemError::MalformedKey)?;
    let our_secret = X25519SecretKey::from(classical_sec_arr);
    let sender_ephemeral_arr: [u8; 32] = ciphertext
        .classical_ct
        .as_slice()
        .try_into()
        .map_err(|_| KemError::MalformedCiphertext)?;
    let sender_ephemeral_pub = X25519PublicKey::from(sender_ephemeral_arr);
    let classical_ss = our_secret.diffie_hellman(&sender_ephemeral_pub);

    let dk_expanded =
        ExpandedDecapsulationKey::<MlKem768>::try_from(pqc_sec_bytes).map_err(|_| KemError::MalformedKey)?;
    #[allow(deprecated)]
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_expanded(&dk_expanded)
        .map_err(|_| KemError::MalformedKey)?;

    let pqc_ct_typed = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext.pqc_ct.as_slice())
        .map_err(|_| KemError::MalformedCiphertext)?;
    // ML-KEM uses implicit rejection (FIPS 203): a malformed/attacker-crafted
    // ciphertext still returns *a* shared secret (pseudorandom, not an
    // error) rather than failing — matching quantum-safe-py's own
    // documented behavior, and this crate's decapsulate() is infallible.
    let pqc_ss = dk.decapsulate(&pqc_ct_typed);

    Ok(combine_shared_secrets(
        classical_ss.as_bytes(),
        pqc_ss.as_slice(),
        ALGORITHM,
        &ciphertext.classical_ct,
        &ciphertext.pqc_ct,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_then_decapsulate_agree() {
        let kp = generate_keypair();
        assert_eq!(kp.public.raw.len(), 2 + 32 + 1184); // spec: 1218 bytes
        assert_eq!(kp.secret.raw.len(), 2 + 32 + 2400); // spec: 2434 bytes

        let (ct, ss_sender) = encapsulate(&kp.public).unwrap();
        assert_eq!(ct.classical_ct.len(), 32);
        assert_eq!(ct.pqc_ct.len(), 1088);

        let ss_receiver = decapsulate(&kp.secret, &ct).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn ciphertext_roundtrips_through_bytes() {
        let kp = generate_keypair();
        let (ct, _ss) = encapsulate(&kp.public).unwrap();
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), 2 + 32 + 1088); // spec: 1122 bytes
        let ct2 = HybridCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct.classical_ct, ct2.classical_ct);
        assert_eq!(ct.pqc_ct, ct2.pqc_ct);
    }

    #[test]
    fn decapsulate_rejects_algorithm_mismatch() {
        let kp = generate_keypair();
        let (ct, _ss) = encapsulate(&kp.public).unwrap();
        let mut wrong_secret = kp.secret;
        wrong_secret.algorithm = "P-256+ML-KEM-512".to_string();
        assert_eq!(decapsulate(&wrong_secret, &ct), Err(KemError::AlgorithmMismatch));
    }
}
