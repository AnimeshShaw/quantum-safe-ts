//! Key encapsulation for every suite in [`crate::suite`]:
//!
//! - hybrid `X25519+ML-KEM-{512,768,1024}`, `P-256+ML-KEM-{512,768}` and `P-384+ML-KEM-1024`, matching
//!   `quantum_safe.kem.hybrid.HybridKEM` byte for byte;
//! - pure `ML-KEM-{512,768,1024}`, matching `quantum_safe.kem.core.KEM`;
//! - `X-Wing` (draft-connolly-cfrg-xwing-kem; quantum-safe-py 0.4.0 has the same suite).
//!
//! Wire layouts (all verified against quantum-safe-py 0.3.0):
//!
//! - hybrid public/secret key: `u16_be(len(classical)) || classical || pqc`
//! - hybrid ciphertext: `u16_be(len(classical_ct)) || classical_ct || pqc_ct`
//! - X25519: public 32 B, secret 32 B, "ciphertext" = sender's ephemeral public key
//! - P-256: public 65 B uncompressed SEC1, secret = **PKCS#8 PEM text bytes** (a
//!   quantum-safe-py quirk reproduced for compatibility), ciphertext = 65 B ephemeral
//!   public key, classical shared secret = ECDH x-coordinate (32 B)
//! - ML-KEM secret keys use the *expanded* FIPS 203 decapsulation key (1632/2400/3168 B),
//!   as liboqs emits, not the newer 64-byte seed form (see the `allow(deprecated)` uses:
//!   the "deprecated" encoding is the one wire compatibility requires)
//!
//! All secret-bearing values are wrapped in [`zeroize::Zeroizing`].

use crate::kdf::combine_shared_secrets;
use crate::suite::{Classical, KemSuite, Pqc};
use crate::wire::{pack_components, unpack_components};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Algorithm name of the default suite.
pub const ALGORITHM: &str = crate::suite::DEFAULT_KEM;

/// A 32-byte KEM shared secret, wiped on drop.
pub type SharedSecret = Zeroizing<[u8; 32]>;

/// Errors returned by key generation, encapsulation and decapsulation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KemError {
    /// The algorithm string is not a suite in [`crate::suite`]; the field holds the string.
    #[error("unsupported or unapproved KEM algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    /// A key and a ciphertext (or two keys) name different algorithms. No function in this module
    /// returns it; callers that compare algorithm strings use it.
    #[error("key/ciphertext algorithm does not match the algorithm of the key in use")]
    AlgorithmMismatch,
    /// A key has the wrong length for its suite, fails to parse, or (for hybrid keys) lacks the
    /// 2-byte length prefix or a component.
    #[error("key bytes are malformed or truncated")]
    MalformedKey,
    /// A ciphertext has the wrong length for its suite, or a hybrid ciphertext lacks the 2-byte length
    /// prefix or a component.
    #[error("ciphertext bytes are malformed or truncated")]
    MalformedCiphertext,
    /// The X25519 shared secret was all zeros, which a low-order peer point produces.
    #[error("classical key-agreement component failed (invalid or low-order point)")]
    ClassicalFailure,
}

/// A KEM public key: the raw bytes and the canonical algorithm string of its suite.
///
/// For a hybrid suite `raw` is `u16_be(len(classical)) || classical || pqc`.
#[derive(Clone)]
pub struct PublicKey {
    /// Public key bytes in the suite's wire layout.
    pub raw: Vec<u8>,
    /// Canonical suite name, e.g. `"X25519+ML-KEM-768"`.
    pub algorithm: String,
}

/// A KEM secret key: the raw bytes (wiped on drop) and the canonical algorithm string of its suite.
///
/// Its `Debug` output shows the algorithm and hides the bytes.
pub struct SecretKey {
    /// Secret key bytes in the suite's wire layout.
    pub raw: Zeroizing<Vec<u8>>,
    /// Canonical suite name, e.g. `"X25519+ML-KEM-768"`.
    pub algorithm: String,
}

impl SecretKey {
    /// Wraps `raw` so it is wiped on drop; the bytes and the algorithm string are not validated here.
    pub fn new(raw: Vec<u8>, algorithm: impl Into<String>) -> Self {
        Self {
            raw: Zeroizing::new(raw),
            algorithm: algorithm.into(),
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}, {} B)", self.algorithm, self.raw.len())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({}, <redacted>)", self.algorithm)
    }
}

/// A matching public and secret key for one suite.
pub struct KeyPair {
    /// The public key.
    pub public: PublicKey,
    /// The secret key.
    pub secret: SecretKey,
}

/// The two halves of a hybrid-suite ciphertext.
pub struct HybridCiphertext {
    /// Classical half: the sender's ephemeral public key (32 bytes for X25519, 65 for P-256, 97 for P-384).
    pub classical_ct: Vec<u8>,
    /// ML-KEM ciphertext.
    pub pqc_ct: Vec<u8>,
}

impl HybridCiphertext {
    /// Matches `HybridCipherText.to_bytes()`: 2-byte BE length prefix of
    /// `classical_ct`, then `classical_ct`, then `pqc_ct` (no prefix: it's
    /// everything remaining).
    pub fn to_bytes(&self) -> Vec<u8> {
        pack_components(&self.classical_ct, &self.pqc_ct)
    }

    /// Parses the layout written by [`HybridCiphertext::to_bytes`].
    ///
    /// # Errors
    ///
    /// [`KemError::MalformedCiphertext`] when the 2-byte prefix or the classical component is missing, or
    /// when nothing follows the classical component.
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

// ---------------------------------------------------------------------------
// ML-KEM (three parameter sets via one macro)
// ---------------------------------------------------------------------------

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{Decapsulate, Encapsulate, ExpandedDecapsulationKey, Kem as _, KeyExport};

// Expands to a module `$m` with `keygen`, `encaps` and `decaps` for the ML-KEM parameter set `$ty`.
// Keys and ciphertexts cross this boundary as plain byte vectors in the expanded FIPS 203 encoding;
// a parse failure maps to `MalformedKey` or `MalformedCiphertext`.
macro_rules! mlkem_level {
    ($m:ident, $ty:ty) => {
        mod $m {
            use super::*;

            pub fn keygen() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
                let (dk, ek) = <$ty>::generate_keypair();
                #[allow(deprecated)]
                let dk_expanded = dk.to_expanded_bytes();
                (
                    Zeroizing::new(dk_expanded.as_slice().to_vec()),
                    ek.to_bytes().as_slice().to_vec(),
                )
            }

            pub fn encaps(ek_bytes: &[u8]) -> Result<(Vec<u8>, SharedSecret), KemError> {
                let key = ml_kem::Key::<ml_kem::EncapsulationKey<$ty>>::try_from(ek_bytes)
                    .map_err(|_| KemError::MalformedKey)?;
                let ek = ml_kem::EncapsulationKey::<$ty>::new(&key).map_err(|_| KemError::MalformedKey)?;
                let (ct, ss) = ek.encapsulate();
                let mut out = [0u8; 32];
                out.copy_from_slice(ss.as_slice());
                Ok((ct.as_slice().to_vec(), Zeroizing::new(out)))
            }

            pub fn decaps(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<SharedSecret, KemError> {
                let expanded = ExpandedDecapsulationKey::<$ty>::try_from(dk_bytes)
                    .map_err(|_| KemError::MalformedKey)?;
                #[allow(deprecated)]
                let dk = ml_kem::DecapsulationKey::<$ty>::from_expanded(&expanded)
                    .map_err(|_| KemError::MalformedKey)?;
                let ct = ml_kem::Ciphertext::<$ty>::try_from(ct_bytes)
                    .map_err(|_| KemError::MalformedCiphertext)?;
                // FIPS 203 implicit rejection: a wrong ciphertext yields a pseudorandom
                // secret, not an error. Decapsulation here is infallible by design.
                let ss = dk.decapsulate(&ct);
                let mut out = [0u8; 32];
                out.copy_from_slice(ss.as_slice());
                Ok(Zeroizing::new(out))
            }
        }
    };
}

mlkem_level!(mlkem512, ml_kem::MlKem512);
mlkem_level!(mlkem768, ml_kem::MlKem768);
mlkem_level!(mlkem1024, ml_kem::MlKem1024);

/// Generates an ML-KEM key pair, returning `(expanded secret key, public key)`.
fn pqc_keygen(p: Pqc) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    match p {
        Pqc::MlKem512 => mlkem512::keygen(),
        Pqc::MlKem768 => mlkem768::keygen(),
        Pqc::MlKem1024 => mlkem1024::keygen(),
    }
}

/// ML-KEM encapsulation; a public key whose length is not the parameter set's gives `MalformedKey`.
fn pqc_encaps(p: Pqc, ek: &[u8]) -> Result<(Vec<u8>, SharedSecret), KemError> {
    if ek.len() != p.sizes().0 {
        return Err(KemError::MalformedKey);
    }
    match p {
        Pqc::MlKem512 => mlkem512::encaps(ek),
        Pqc::MlKem768 => mlkem768::encaps(ek),
        Pqc::MlKem1024 => mlkem1024::encaps(ek),
    }
}

/// ML-KEM decapsulation; the key and ciphertext lengths are checked against the parameter set before
/// decoding. A well-formed but wrong ciphertext yields a pseudorandom secret (FIPS 203 implicit rejection).
fn pqc_decaps(p: Pqc, dk: &[u8], ct: &[u8]) -> Result<SharedSecret, KemError> {
    let (_, sk_len, ct_len) = p.sizes();
    if dk.len() != sk_len {
        return Err(KemError::MalformedKey);
    }
    if ct.len() != ct_len {
        return Err(KemError::MalformedCiphertext);
    }
    match p {
        Pqc::MlKem512 => mlkem512::decaps(dk, ct),
        Pqc::MlKem768 => mlkem768::decaps(dk, ct),
        Pqc::MlKem1024 => mlkem1024::decaps(dk, ct),
    }
}

// ---------------------------------------------------------------------------
// Classical halves
// ---------------------------------------------------------------------------

use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Draws a random valid P-256 secret scalar from the OS RNG, retrying on out-of-range values.
pub(crate) fn p256_random_secret() -> p256::SecretKey {
    loop {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut b[..]).expect("OS RNG must be available");
        // Rejects zero and values >= the group order (probability ~2^-32); loop until valid.
        if let Ok(sk) = p256::SecretKey::from_slice(&b[..]) {
            return sk;
        }
    }
}

/// Uncompressed SEC1 encoding (65 bytes) of a P-256 public key.
pub(crate) fn p256_public_bytes(pk: &p256::PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    pk.to_sec1_point(false).as_bytes().to_vec()
}

/// Draws a random valid P-384 secret scalar from the OS RNG, retrying on out-of-range values.
pub(crate) fn p384_random_secret() -> p384::SecretKey {
    loop {
        let mut b = Zeroizing::new([0u8; 48]);
        getrandom::fill(&mut b[..]).expect("OS RNG must be available");
        // Rejects zero and values >= the group order; loop until valid.
        if let Ok(sk) = p384::SecretKey::from_slice(&b[..]) {
            return sk;
        }
    }
}

/// Uncompressed SEC1 encoding (97 bytes) of a P-384 public key.
pub(crate) fn p384_public_bytes(pk: &p384::PublicKey) -> Vec<u8> {
    use p384::elliptic_curve::sec1::ToSec1Point;
    pk.to_sec1_point(false).as_bytes().to_vec()
}

/// Generates a classical key pair, returning `(secret, public)`. X25519 secrets are 32 raw bytes; P-256
/// and P-384 secrets are PKCS#8 PEM text bytes, as quantum-safe-py stores them.
fn classical_keygen(c: Classical) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    match c {
        Classical::X25519 => {
            let sk = X25519SecretKey::random();
            let pk = X25519PublicKey::from(&sk);
            (Zeroizing::new(sk.to_bytes().to_vec()), pk.as_bytes().to_vec())
        }
        Classical::P256 => {
            let sk = p256_random_secret();
            let pem = sk
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .expect("P-256 PKCS#8 PEM encoding is infallible for a valid key");
            (
                Zeroizing::new(pem.as_bytes().to_vec()),
                p256_public_bytes(&sk.public_key()),
            )
        }
        Classical::P384 => {
            let sk = p384_random_secret();
            let pem = sk
                .to_pkcs8_pem(p384::pkcs8::LineEnding::LF)
                .expect("P-384 PKCS#8 PEM encoding is infallible for a valid key");
            (
                Zeroizing::new(pem.as_bytes().to_vec()),
                p384_public_bytes(&sk.public_key()),
            )
        }
    }
}

/// Returns `(classical_ct, classical_shared_secret)`. The recipient key must be exactly `c.public_len()`
/// bytes; X25519 additionally rejects an all-zero shared secret.
fn classical_encaps(c: Classical, recipient_pub: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), KemError> {
    if recipient_pub.len() != c.public_len() {
        return Err(KemError::MalformedKey);
    }
    match c {
        Classical::X25519 => {
            let arr: [u8; 32] = recipient_pub.try_into().map_err(|_| KemError::MalformedKey)?;
            let eph = X25519SecretKey::random();
            let ss = eph.diffie_hellman(&X25519PublicKey::from(arr));
            nonzero(ss.as_bytes())?;
            Ok((
                X25519PublicKey::from(&eph).as_bytes().to_vec(),
                Zeroizing::new(ss.as_bytes().to_vec()),
            ))
        }
        Classical::P256 => {
            let recipient =
                p256::PublicKey::from_sec1_bytes(recipient_pub).map_err(|_| KemError::MalformedKey)?;
            let eph = p256_random_secret();
            let ss = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), recipient.as_affine());
            Ok((
                p256_public_bytes(&eph.public_key()),
                Zeroizing::new(ss.raw_secret_bytes().as_slice().to_vec()),
            ))
        }
        Classical::P384 => {
            let recipient =
                p384::PublicKey::from_sec1_bytes(recipient_pub).map_err(|_| KemError::MalformedKey)?;
            let eph = p384_random_secret();
            let ss = p384::ecdh::diffie_hellman(eph.to_nonzero_scalar(), recipient.as_affine());
            // The whole ECDH x-coordinate (48 bytes), as quantum-safe-py uses it.
            Ok((
                p384_public_bytes(&eph.public_key()),
                Zeroizing::new(ss.raw_secret_bytes().as_slice().to_vec()),
            ))
        }
    }
}

/// Classical half of decapsulation. The ciphertext must be exactly `c.public_len()` bytes; X25519
/// additionally rejects an all-zero shared secret.
fn classical_decaps(c: Classical, secret: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, KemError> {
    if ct.len() != c.public_len() {
        return Err(KemError::MalformedCiphertext);
    }
    match c {
        Classical::X25519 => {
            let sk: [u8; 32] = secret.try_into().map_err(|_| KemError::MalformedKey)?;
            let peer: [u8; 32] = ct.try_into().map_err(|_| KemError::MalformedCiphertext)?;
            let ss = X25519SecretKey::from(sk).diffie_hellman(&X25519PublicKey::from(peer));
            nonzero(ss.as_bytes())?;
            Ok(Zeroizing::new(ss.as_bytes().to_vec()))
        }
        Classical::P256 => {
            let pem = std::str::from_utf8(secret).map_err(|_| KemError::MalformedKey)?;
            let sk = p256::SecretKey::from_pkcs8_pem(pem).map_err(|_| KemError::MalformedKey)?;
            let peer = p256::PublicKey::from_sec1_bytes(ct).map_err(|_| KemError::MalformedCiphertext)?;
            let ss = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(ss.raw_secret_bytes().as_slice().to_vec()))
        }
        Classical::P384 => {
            let pem = std::str::from_utf8(secret).map_err(|_| KemError::MalformedKey)?;
            let sk = p384::SecretKey::from_pkcs8_pem(pem).map_err(|_| KemError::MalformedKey)?;
            let peer = p384::PublicKey::from_sec1_bytes(ct).map_err(|_| KemError::MalformedCiphertext)?;
            let ss = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(ss.raw_secret_bytes().as_slice().to_vec()))
        }
    }
}

/// Reject an all-zero X25519 output (low-order point), as `cryptography` does.
fn nonzero(ss: &[u8]) -> Result<(), KemError> {
    // Fold instead of `all()`: no early exit on the first non-zero byte of a secret DH output.
    if ss.iter().fold(0u8, |acc, b| acc | b) == 0 {
        Err(KemError::ClassicalFailure)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// X-Wing
// ---------------------------------------------------------------------------

// X-Wing wrappers around the `x_wing` crate: the public key, secret key and ciphertext are the crate's
// fixed-size byte encodings, and the shared secret is 32 bytes.
mod xwing {
    use super::*;
    use x_wing::KeyInit as _;

    pub const PUBLIC_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
    pub const SECRET_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
    pub const CT_LEN: usize = x_wing::CIPHERTEXT_SIZE;

    pub fn keygen() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let (dk, ek) = x_wing::XWingKem::generate_keypair();
        (
            Zeroizing::new(dk.as_bytes().to_vec()),
            ek.to_bytes().as_slice().to_vec(),
        )
    }

    pub fn encaps(pk: &[u8]) -> Result<(Vec<u8>, SharedSecret), KemError> {
        let ek = x_wing::EncapsulationKey::try_from(pk).map_err(|_| KemError::MalformedKey)?;
        let (ct, ss) = ek.encapsulate();
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_slice());
        Ok((ct.as_slice().to_vec(), Zeroizing::new(out)))
    }

    pub fn decaps(sk: &[u8], ct: &[u8]) -> Result<SharedSecret, KemError> {
        let dk = x_wing::DecapsulationKey::new_from_slice(sk).map_err(|_| KemError::MalformedKey)?;
        let ct = x_wing::Ciphertext::try_from(ct).map_err(|_| KemError::MalformedCiphertext)?;
        let ss = dk.decapsulate(&ct);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_slice());
        Ok(Zeroizing::new(out))
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolves an algorithm string to a suite or `UnsupportedAlgorithm`.
fn suite_of(algorithm: &str) -> Result<KemSuite, KemError> {
    KemSuite::parse(algorithm).ok_or_else(|| KemError::UnsupportedAlgorithm(algorithm.to_string()))
}

/// Generate a key pair for the default suite (`X25519+ML-KEM-768`).
///
/// # Panics
///
/// Does not panic in practice: the default suite name always parses.
pub fn generate_keypair() -> KeyPair {
    generate_keypair_for(ALGORITHM).expect("default suite is always supported")
}

/// Generate a key pair for any supported suite.
///
/// Hybrid secret and public keys are `u16_be(len(classical)) || classical || pqc`.
///
/// # Errors
///
/// [`KemError::UnsupportedAlgorithm`] when `algorithm` is not a suite in [`crate::suite`].
pub fn generate_keypair_for(algorithm: &str) -> Result<KeyPair, KemError> {
    let suite = suite_of(algorithm)?;
    let (sec, public) = match suite {
        KemSuite::Pure(p) => pqc_keygen(p),
        KemSuite::XWing => xwing::keygen(),
        KemSuite::Hybrid(c, p) => {
            let (c_sec, c_pub) = classical_keygen(c);
            let (p_sec, p_pub) = pqc_keygen(p);
            (
                Zeroizing::new(pack_components(&c_sec, &p_sec)),
                pack_components(&c_pub, &p_pub),
            )
        }
    };
    let name = suite.name();
    Ok(KeyPair {
        public: PublicKey {
            raw: public,
            algorithm: name.clone(),
        },
        secret: SecretKey {
            raw: sec,
            algorithm: name,
        },
    })
}

/// Encapsulate to `public_key`. Returns `(ciphertext_wire_bytes, shared_secret)`.
///
/// The ciphertext is the bare ML-KEM or X-Wing ciphertext for those suites, and
/// `u16_be(len(classical_ct)) || classical_ct || pqc_ct` for hybrids; the shared secret is 32 bytes.
///
/// # Errors
///
/// - [`KemError::UnsupportedAlgorithm`] when `public_key.algorithm` is not a known suite.
/// - [`KemError::MalformedKey`] when the key has the wrong length or does not parse.
/// - [`KemError::ClassicalFailure`] when an X25519 hybrid's classical shared secret is all zeros.
pub fn encapsulate(public_key: &PublicKey) -> Result<(Vec<u8>, SharedSecret), KemError> {
    let suite = suite_of(&public_key.algorithm)?;
    match suite {
        KemSuite::Pure(p) => pqc_encaps(p, &public_key.raw),
        KemSuite::XWing => {
            if public_key.raw.len() != xwing::PUBLIC_LEN {
                return Err(KemError::MalformedKey);
            }
            xwing::encaps(&public_key.raw)
        }
        KemSuite::Hybrid(c, p) => {
            let (c_pub, p_pub) = unpack_components(&public_key.raw).map_err(|_| KemError::MalformedKey)?;
            let (classical_ct, classical_ss) = classical_encaps(c, c_pub)?;
            let (pqc_ct, pqc_ss) = pqc_encaps(p, p_pub)?;
            let combined =
                combine_shared_secrets(&classical_ss, &pqc_ss[..], &suite.name(), &classical_ct, &pqc_ct);
            let ct = HybridCiphertext { classical_ct, pqc_ct }.to_bytes();
            Ok((ct, Zeroizing::new(combined)))
        }
    }
}

/// Decapsulate wire-format ciphertext bytes with `secret_key`.
///
/// A ciphertext of the right length that was not made for this key does not raise an error: ML-KEM and
/// X-Wing return a pseudorandom secret (implicit rejection), and a hybrid suite returns a secret that
/// differs from the sender's.
///
/// # Errors
///
/// - [`KemError::UnsupportedAlgorithm`] when `secret_key.algorithm` is not a known suite.
/// - [`KemError::MalformedKey`] when the secret key has the wrong length or does not parse.
/// - [`KemError::MalformedCiphertext`] when the ciphertext has the wrong length or layout.
/// - [`KemError::ClassicalFailure`] when an X25519 hybrid's classical shared secret is all zeros.
pub fn decapsulate(secret_key: &SecretKey, ciphertext: &[u8]) -> Result<SharedSecret, KemError> {
    let suite = suite_of(&secret_key.algorithm)?;
    match suite {
        KemSuite::Pure(p) => pqc_decaps(p, &secret_key.raw, ciphertext),
        KemSuite::XWing => {
            if secret_key.raw.len() != xwing::SECRET_LEN {
                return Err(KemError::MalformedKey);
            }
            if ciphertext.len() != xwing::CT_LEN {
                return Err(KemError::MalformedCiphertext);
            }
            xwing::decaps(&secret_key.raw, ciphertext)
        }
        KemSuite::Hybrid(c, p) => {
            let (c_sec, p_sec) = unpack_components(&secret_key.raw).map_err(|_| KemError::MalformedKey)?;
            let ct = HybridCiphertext::from_bytes(ciphertext)?;
            let classical_ss = classical_decaps(c, c_sec, &ct.classical_ct)?;
            let pqc_ss = pqc_decaps(p, p_sec, &ct.pqc_ct)?;
            let combined = combine_shared_secrets(
                &classical_ss,
                &pqc_ss[..],
                &suite.name(),
                &ct.classical_ct,
                &ct.pqc_ct,
            );
            Ok(Zeroizing::new(combined))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_suite_sizes_match_spec() {
        let kp = generate_keypair();
        assert_eq!(kp.public.raw.len(), 2 + 32 + 1184); // 1218 bytes
        assert_eq!(kp.secret.raw.len(), 2 + 32 + 2400); // 2434 bytes
        let (ct, ss_sender) = encapsulate(&kp.public).unwrap();
        assert_eq!(ct.len(), 2 + 32 + 1088); // 1122 bytes
        let ss_receiver = decapsulate(&kp.secret, &ct).unwrap();
        assert_eq!(*ss_sender, *ss_receiver);
    }

    #[test]
    fn every_suite_roundtrips() {
        for suite in KemSuite::all() {
            let name = suite.name();
            let kp = generate_keypair_for(&name).unwrap();
            assert_eq!(kp.public.algorithm, name);
            let (ct, a) = encapsulate(&kp.public).unwrap();
            let b = decapsulate(&kp.secret, &ct).unwrap();
            assert_eq!(*a, *b, "{name}");
        }
    }

    #[test]
    fn expected_wire_sizes_per_suite() {
        let sizes = |n: &str| {
            let kp = generate_keypair_for(n).unwrap();
            let (ct, _) = encapsulate(&kp.public).unwrap();
            (kp.public.raw.len(), kp.secret.raw.len(), ct.len())
        };
        assert_eq!(sizes("ML-KEM-512"), (800, 1632, 768));
        assert_eq!(sizes("ML-KEM-768"), (1184, 2400, 1088));
        assert_eq!(sizes("ML-KEM-1024"), (1568, 3168, 1568));
        assert_eq!(
            sizes("X25519+ML-KEM-1024"),
            (2 + 32 + 1568, 2 + 32 + 3168, 2 + 32 + 1568)
        );
        // Verified against quantum-safe-py: X25519+ML-KEM-1024 ciphertext is 1602 bytes.
        assert_eq!(sizes("X25519+ML-KEM-1024").2, 1602);
        assert_eq!(sizes("X-Wing"), (1216, 32, 1120));
        let (p, _, c) = sizes("P-256+ML-KEM-768");
        assert_eq!((p, c), (2 + 65 + 1184, 2 + 65 + 1088));
    }

    #[test]
    fn ciphertext_roundtrips_through_bytes() {
        let kp = generate_keypair();
        let (bytes, _ss) = encapsulate(&kp.public).unwrap();
        let ct = HybridCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct.classical_ct.len(), 32);
        assert_eq!(ct.pqc_ct.len(), 1088);
        assert_eq!(ct.to_bytes(), bytes);
    }

    #[test]
    fn decapsulate_rejects_algorithm_mismatch() {
        let kp = generate_keypair();
        let (ct, _ss) = encapsulate(&kp.public).unwrap();
        let wrong = SecretKey::new(kp.secret.raw.to_vec(), "P-256+ML-KEM-512");
        assert!(decapsulate(&wrong, &ct).is_err());
        let unknown = SecretKey::new(kp.secret.raw.to_vec(), "Nope");
        assert_eq!(
            decapsulate(&unknown, &ct),
            Err(KemError::UnsupportedAlgorithm("Nope".into()))
        );
    }

    #[test]
    fn malformed_inputs_fail_closed_without_panicking() {
        for suite in KemSuite::all() {
            let name = suite.name();
            let kp = generate_keypair_for(&name).unwrap();
            let (ct, _) = encapsulate(&kp.public).unwrap();
            for cut in [0usize, 1, 2, 31, 33, 100, ct.len() - 1] {
                let _ = decapsulate(&kp.secret, &ct[..cut]);
            }
            let bad_pub = PublicKey {
                raw: kp.public.raw[..kp.public.raw.len() / 2].to_vec(),
                algorithm: name,
            };
            assert!(encapsulate(&bad_pub).is_err());
        }
    }

    #[test]
    fn x25519_low_order_point_is_rejected() {
        let kp = generate_keypair();
        // All-zero ephemeral key is a low-order point; the shared secret would be zero.
        let mut forged = HybridCiphertext::from_bytes(&encapsulate(&kp.public).unwrap().0).unwrap();
        forged.classical_ct = vec![0u8; 32];
        assert_eq!(
            decapsulate(&kp.secret, &forged.to_bytes()),
            Err(KemError::ClassicalFailure)
        );
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let kp = generate_keypair();
        let dbg = format!("{:?}", kp.secret);
        assert!(dbg.contains("redacted"));
        assert!(dbg.len() < 64);
    }
}
