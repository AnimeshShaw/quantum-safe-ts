//! Digital signatures, matching `quantum_safe.signatures` byte for byte:
//!
//! - pure ML-DSA-44/65/87 (`Sign`) and SLH-DSA (FIPS 205);
//! - hybrid `Ed25519+ML-DSA-{44,65,87}`, `P-256+ML-DSA-{44,65}` and `P-384+ML-DSA-87` (`HybridSign`).
//!
//! **Construction (verified against quantum-safe-py 0.3.0 with liboqs).** quantum-safe-py does
//! *not* use FIPS 204/205's native context parameter. Every sub-signature is a plain
//! signature with an **empty** FIPS context over
//!
//! ```text
//! len(context) (1 byte) || context || rand_prefix || message
//! ```
//!
//! where `rand_prefix` is 32 random bytes when hedged (the default) and empty otherwise.
//! The signature blob is `len(rand_prefix) (1 byte) || rand_prefix || payload`; for hybrids the
//! payload is CBOR `{classical_sig, pqc_sig, classical_algo, pqc_algo}`. Both halves of a
//! hybrid are always verified before the result is combined.
//!
//! Key layouts: ML-DSA secret keys are the *expanded* FIPS 204 encoding (2560/4032/4896 B, as
//! liboqs emits). Hybrid keys use `u16_be(len(classical)) || classical || pqc`. Ed25519:
//! 32 B keys. P-256 signing: public key = raw `x || y` (64 B, no 0x04 tag), secret key =
//! PKCS#8 PEM text bytes, signature = DER ECDSA-SHA256. P-384 follows the same layout (96 B public
//! key) with ECDSA-SHA384.
//!
//! [`v2`] holds the `<suite>-v2` format and [`standard`] the plain FIPS 204 ML-DSA mode.

use crate::kem::{PublicKey, SecretKey};
use crate::keys::MigrationState;
use crate::wire::{pack_components, unpack_components};
use ciborium::value::Value;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Number of random bytes prepended in hedged mode (`HEDGED_RANDOMNESS_BYTES`).
pub const HEDGE_BYTES: usize = 32;
/// Longest signing context in bytes; its length is stored in one byte.
pub const MAX_CONTEXT_LEN: usize = 255;
/// Value of the `v` field in a [`SignedMessage`]'s CBOR.
pub const SIGNED_MESSAGE_VERSION: i64 = 1;
/// Mirrors the 10 MB cap in quantum-safe-py's serialization layer.
pub const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

/// Default hybrid signature suite.
pub const DEFAULT_HYBRID_SIG: &str = "Ed25519+ML-DSA-65";
/// Default pure signature suite.
pub const DEFAULT_SIG: &str = "ML-DSA-65";
/// The hybrid at CNSA 2.0's ML-DSA parameter set, kept for quantum-safe-py compatibility. CNSA 2.0 does not prescribe hybrids; pure `ML-DSA-87` is the compliant choice.
pub const CNSA2_SIG: &str = "Ed25519+ML-DSA-87";

/// Errors returned by key generation, signing, verification and [`SignedMessage`] parsing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigError {
    /// The algorithm string is not a signature suite (or `-v2` identifier) this library supports; the
    /// field holds the string.
    #[error("unsupported or unapproved signature algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    /// The public key's algorithm differs from the message's.
    #[error("key algorithm does not match the signed message / expected algorithm")]
    AlgorithmMismatch,
    /// A key has the wrong length for its suite or fails to parse.
    #[error("key bytes are malformed or have the wrong length")]
    MalformedKey,
    /// The context is longer than [`MAX_CONTEXT_LEN`]; the field is its length.
    #[error("context must be at most {MAX_CONTEXT_LEN} bytes, got {0}")]
    ContextTooLong(usize),
    /// The message to sign (or in a parsed [`SignedMessage`]) is empty.
    #[error("message cannot be empty")]
    EmptyMessage,
    /// The OS RNG failed or the signing primitive returned an error.
    #[error("signing failed")]
    SigningFailed,
    /// The signature does not verify, or its blob is malformed.
    #[error("signature verification failed")]
    VerificationFailed,
    /// A [`SignedMessage`] CBOR payload is invalid; the field says how, and the message reads
    /// "SignedMessage" followed by that text.
    #[error("SignedMessage {0}")]
    Format(String),
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// ML-DSA parameter sets (FIPS 204).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MlDsaLevel {
    /// ML-DSA-44.
    L44,
    /// ML-DSA-65.
    L65,
    /// ML-DSA-87.
    L87,
}

/// The twelve SLH-DSA parameter sets (FIPS 205): SHAKE and SHA2 variants at 128, 192 and 256 bits, each
/// in a small-signature (`s`) and a fast-signing (`f`) form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlhParam {
    Shake128s,
    Shake128f,
    Shake192s,
    Shake192f,
    Shake256s,
    Shake256f,
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
}

/// Classical halves of a hybrid signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassicalSig {
    /// Ed25519.
    Ed25519,
    /// ECDSA over P-256 with SHA-256.
    P256,
    /// ECDSA over P-384 with SHA-384.
    P384,
}

/// A complete signature suite as addressed by its canonical algorithm string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigSuite {
    /// Pure ML-DSA, e.g. `"ML-DSA-65"`.
    MlDsa(MlDsaLevel),
    /// Pure SLH-DSA, e.g. `"SLH-DSA-SHAKE-128f"`.
    Slh(SlhParam),
    /// Classical + ML-DSA, e.g. `"Ed25519+ML-DSA-65"`.
    Hybrid(ClassicalSig, MlDsaLevel),
}

/// Per SLH-DSA parameter set: `(param, canonical name, public key bytes, secret key bytes, signature bytes)`.
const SLH_TABLE: [(SlhParam, &str, usize, usize, usize); 12] = [
    (SlhParam::Shake128s, "SLH-DSA-SHAKE-128s", 32, 64, 7856),
    (SlhParam::Shake128f, "SLH-DSA-SHAKE-128f", 32, 64, 17088),
    (SlhParam::Shake192s, "SLH-DSA-SHAKE-192s", 48, 96, 16224),
    (SlhParam::Shake192f, "SLH-DSA-SHAKE-192f", 48, 96, 35664),
    (SlhParam::Shake256s, "SLH-DSA-SHAKE-256s", 64, 128, 29792),
    (SlhParam::Shake256f, "SLH-DSA-SHAKE-256f", 64, 128, 49856),
    (SlhParam::Sha2_128s, "SLH-DSA-SHA2-128s", 32, 64, 7856),
    (SlhParam::Sha2_128f, "SLH-DSA-SHA2-128f", 32, 64, 17088),
    (SlhParam::Sha2_192s, "SLH-DSA-SHA2-192s", 48, 96, 16224),
    (SlhParam::Sha2_192f, "SLH-DSA-SHA2-192f", 48, 96, 35664),
    (SlhParam::Sha2_256s, "SLH-DSA-SHA2-256s", 64, 128, 29792),
    (SlhParam::Sha2_256f, "SLH-DSA-SHA2-256f", 64, 128, 49856),
];

impl MlDsaLevel {
    /// Canonical name, e.g. `"ML-DSA-65"`.
    pub fn name(self) -> &'static str {
        match self {
            MlDsaLevel::L44 => "ML-DSA-44",
            MlDsaLevel::L65 => "ML-DSA-65",
            MlDsaLevel::L87 => "ML-DSA-87",
        }
    }
    /// Parses a canonical name; `None` for anything else.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "ML-DSA-44" => Some(Self::L44),
            "ML-DSA-65" => Some(Self::L65),
            "ML-DSA-87" => Some(Self::L87),
            _ => None,
        }
    }
    /// (public key, expanded secret key, signature) sizes in bytes (FIPS 204 Table 2).
    pub fn sizes(self) -> (usize, usize, usize) {
        match self {
            MlDsaLevel::L44 => (1312, 2560, 2420),
            MlDsaLevel::L65 => (1952, 4032, 3309),
            MlDsaLevel::L87 => (2592, 4896, 4627),
        }
    }
    /// NIST category of the parameter set: 2, 3 or 5.
    pub fn nist_level(self) -> u8 {
        match self {
            MlDsaLevel::L44 => 2,
            MlDsaLevel::L65 => 3,
            MlDsaLevel::L87 => 5,
        }
    }
}

impl SlhParam {
    /// Canonical name, e.g. `"SLH-DSA-SHAKE-128s"`.
    pub fn name(self) -> &'static str {
        SLH_TABLE
            .iter()
            .find(|r| r.0 == self)
            .map(|r| r.1)
            .expect("table covers every variant")
    }
    /// Parses a canonical name; `None` for anything else.
    pub fn from_name(s: &str) -> Option<Self> {
        SLH_TABLE.iter().find(|r| r.1 == s).map(|r| r.0)
    }
    /// (public key, secret key, signature) sizes in bytes (FIPS 205 Table 2).
    pub fn sizes(self) -> (usize, usize, usize) {
        let r = SLH_TABLE
            .iter()
            .find(|r| r.0 == self)
            .expect("table covers every variant");
        (r.2, r.3, r.4)
    }
    /// quantum-safe-py's high-level `Sign` accepts only these three SLH-DSA names; the other
    /// nine FIPS 205 parameter sets are TypeScript-only additions.
    pub fn py_compatible(self) -> bool {
        matches!(
            self,
            SlhParam::Shake128s | SlhParam::Shake128f | SlhParam::Shake256s
        )
    }
    /// NIST category of the parameter set: 1 (128-bit), 3 (192-bit) or 5 (256-bit).
    pub fn nist_level(self) -> u8 {
        match self.sizes().0 {
            32 => 1,
            48 => 3,
            _ => 5,
        }
    }
    /// Security parameter `n` in bytes: half the public key size (16, 24 or 32). It is also the length of the
    /// optional randomness passed when signing.
    fn n(self) -> usize {
        self.sizes().0 / 2
    }
}

impl ClassicalSig {
    /// Canonical name: `"Ed25519"`, `"P-256"` or `"P-384"`.
    pub fn name(self) -> &'static str {
        match self {
            ClassicalSig::Ed25519 => "Ed25519",
            ClassicalSig::P256 => "P-256",
            ClassicalSig::P384 => "P-384",
        }
    }
    /// Parses a canonical name; `None` for anything else.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Ed25519" => Some(Self::Ed25519),
            "P-256" => Some(Self::P256),
            "P-384" => Some(Self::P384),
            _ => None,
        }
    }
}

/// Approved hybrid pairings, mirroring `HYBRID_SIGNATURE_COMBINATIONS`.
///
/// Ed25519 pairs with every ML-DSA level, P-256 with ML-DSA-44 and ML-DSA-65, and P-384 with ML-DSA-87.
pub fn is_approved_hybrid(c: ClassicalSig, l: MlDsaLevel) -> bool {
    match c {
        ClassicalSig::Ed25519 => true,
        ClassicalSig::P256 => matches!(l, MlDsaLevel::L44 | MlDsaLevel::L65),
        ClassicalSig::P384 => matches!(l, MlDsaLevel::L87),
    }
}

impl SigSuite {
    /// Parses a canonical algorithm string. `None` for anything unknown, for an unapproved hybrid pairing,
    /// and for a `-v2` identifier (see [`v2::base_of`]).
    pub fn parse(name: &str) -> Option<Self> {
        if let Some((c, p)) = name.split_once('+') {
            let (c, l) = (ClassicalSig::from_name(c)?, MlDsaLevel::from_name(p)?);
            return is_approved_hybrid(c, l).then_some(SigSuite::Hybrid(c, l));
        }
        if let Some(l) = MlDsaLevel::from_name(name) {
            return Some(SigSuite::MlDsa(l));
        }
        SlhParam::from_name(name).map(SigSuite::Slh)
    }

    /// Canonical algorithm string.
    pub fn name(self) -> String {
        match self {
            SigSuite::MlDsa(l) => l.name().to_string(),
            SigSuite::Slh(p) => p.name().to_string(),
            SigSuite::Hybrid(c, l) => format!("{}+{}", c.name(), l.name()),
        }
    }

    /// True for classical + ML-DSA suites.
    pub fn is_hybrid(self) -> bool {
        matches!(self, SigSuite::Hybrid(..))
    }

    /// `HybridTransition` for hybrid suites, `PqcOnly` for pure ones.
    pub fn migration_state(self) -> MigrationState {
        if self.is_hybrid() {
            MigrationState::HybridTransition
        } else {
            MigrationState::PqcOnly
        }
    }

    /// CNSA 2.0 requires ML-DSA-87 for general signatures (LMS/XMSS for firmware, separately).
    pub fn meets_cnsa2(self) -> bool {
        matches!(
            self,
            SigSuite::MlDsa(MlDsaLevel::L87) | SigSuite::Hybrid(_, MlDsaLevel::L87)
        )
    }

    /// All suites this library can instantiate (without `-v2` identifiers): the pure ML-DSA sets, the approved
    /// hybrids, then the twelve SLH-DSA sets.
    pub fn all() -> Vec<SigSuite> {
        let mut v = Vec::new();
        for l in [MlDsaLevel::L44, MlDsaLevel::L65, MlDsaLevel::L87] {
            v.push(SigSuite::MlDsa(l));
        }
        for c in [ClassicalSig::Ed25519, ClassicalSig::P256, ClassicalSig::P384] {
            for l in [MlDsaLevel::L44, MlDsaLevel::L65, MlDsaLevel::L87] {
                if is_approved_hybrid(c, l) {
                    v.push(SigSuite::Hybrid(c, l));
                }
            }
        }
        for r in SLH_TABLE {
            v.push(SigSuite::Slh(r.0));
        }
        v
    }
}

impl fmt::Display for SigSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

// ---------------------------------------------------------------------------
// ML-DSA
// ---------------------------------------------------------------------------

/// FIPS 204 expanded secret key layout: rho(32) K(32) tr(64) s1 s2 t0. The ml-dsa crate's
/// expanded-key decoder is documented to be able to panic on malformed input, so the
/// packed `s1`/`s2` coefficient fields are validated here first; a fuzz target covers this.
fn validate_expanded_mldsa_sk(level: MlDsaLevel, sk: &[u8]) -> bool {
    let (k, l, eta_bits, max): (usize, usize, usize, u8) = match level {
        MlDsaLevel::L44 => (4, 4, 3, 4),
        MlDsaLevel::L65 => (6, 5, 4, 8),
        MlDsaLevel::L87 => (8, 7, 3, 4),
    };
    if sk.len() != level.sizes().1 {
        return false;
    }
    let poly_bytes = 32 * eta_bits;
    let s_region = &sk[128..128 + (l + k) * poly_bytes];
    if eta_bits == 4 {
        s_region.iter().all(|b| (b & 0x0f) <= max && (b >> 4) <= max)
    } else {
        // 3-bit coefficients packed little-endian, 8 coefficients per 3 bytes.
        s_region.as_chunks::<3>().0.iter().all(|c| {
            let v = u32::from(c[0]) | (u32::from(c[1]) << 8) | (u32::from(c[2]) << 16);
            (0..8).all(|i| ((v >> (3 * i)) & 0x7) as u8 <= max)
        })
    }
}

// Expands to a module `$m` for one ML-DSA level (`$ty`, `$level`) with two groups of functions:
// the quantum-safe-py construction (`keygen`, `sign`, `sign_ctx`, `verify`, `verify_ctx`: expanded secret
// keys) and standards mode (`std_*`: 32-byte seeds). Callers check key and signature lengths first;
// signing always draws 32 fresh random bytes (hedged), and verification returns `Ok(false)` for an
// unparsable signature or an over-long context.
macro_rules! mldsa_level {
    ($m:ident, $ty:ty, $level:expr) => {
        mod $m {
            use super::*;
            use ml_dsa::{ExpandedSigningKey, Signature, VerifyingKey};

            /// Generates a key pair from a random seed, returning `(expanded secret key, public key)`.
            pub fn keygen() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
                let mut seed_bytes = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut seed_bytes[..]).expect("OS RNG must be available");
                let seed = ml_dsa::Seed::from(*seed_bytes);
                let esk = ExpandedSigningKey::<$ty>::from_seed(&seed);
                #[allow(deprecated)]
                let sk = esk.to_expanded();
                let pk = esk.verifying_key().encode();
                (
                    Zeroizing::new(sk.as_slice().to_vec()),
                    pk.as_slice().to_vec(),
                )
            }

            /// ML-DSA.Sign (hedged) with an empty FIPS 204 context over `msg`.
            pub fn sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, SigError> {
                sign_ctx(sk, msg, &[])
            }

            /// ML-DSA.Sign (hedged) with FIPS 204 context `ctx` (at most 255 bytes) over `msg`, from an expanded secret key.
            pub fn sign_ctx(sk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SigError> {
                if ctx.len() > MAX_CONTEXT_LEN {
                    return Err(SigError::ContextTooLong(ctx.len()));
                }
                if !validate_expanded_mldsa_sk($level, sk) {
                    return Err(SigError::MalformedKey);
                }
                let enc = ml_dsa::ExpandedSigningKeyBytes::<$ty>::try_from(sk)
                    .map_err(|_| SigError::MalformedKey)?;
                #[allow(deprecated)]
                let esk = ExpandedSigningKey::<$ty>::from_expanded(&enc);
                let mut rnd = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut rnd[..]).map_err(|_| SigError::SigningFailed)?;
                // M' = 0x00 || len(ctx) || ctx || M  (FIPS 204 Algorithm 2; the quantum-safe-py construction uses an empty ctx)
                let prefix: Vec<u8> = [&[0u8, ctx.len() as u8][..], ctx].concat();
                let sig = esk.sign_internal(&[&prefix, msg], &ml_dsa::B32::from(*rnd));
                Ok(sig.encode().as_slice().to_vec())
            }

            /// Verifies with an empty context; see `verify_ctx`.
            pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SigError> {
                verify_ctx(pk, msg, &[], sig)
            }

            /// Verifies `sig` over `msg` with FIPS 204 context `ctx`. `MalformedKey` for an unusable public key;
            /// an unparsable signature or a context over 255 bytes gives `Ok(false)`.
            pub fn verify_ctx(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<bool, SigError> {
                let enc =
                    ml_dsa::EncodedVerifyingKey::<$ty>::try_from(pk).map_err(|_| SigError::MalformedKey)?;
                let vk = VerifyingKey::<$ty>::decode(&enc);
                let Ok(sig) = Signature::<$ty>::try_from(sig) else {
                    return Ok(false);
                };
                if ctx.len() > MAX_CONTEXT_LEN {
                    return Ok(false);
                }
                Ok(vk.verify_with_context(msg, ctx, &sig))
            }

            // --- standards mode (FIPS 204 / RFC 9964): seed keys, native context, no prefix ---

            /// Generates a random 32-byte seed and its public key, returning `(seed, public key)`.
            pub fn std_keygen() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
                let mut seed = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut seed[..]).expect("OS RNG must be available");
                let pk = std_public(&seed[..]).expect("a 32-byte seed is always valid");
                (Zeroizing::new(seed.to_vec()), pk)
            }

            /// The public key for a 32-byte seed; `MalformedKey` if the seed is not 32 bytes.
            pub fn std_public(seed: &[u8]) -> Result<Vec<u8>, SigError> {
                let seed: [u8; 32] = seed.try_into().map_err(|_| SigError::MalformedKey)?;
                let esk = ExpandedSigningKey::<$ty>::from_seed(&ml_dsa::Seed::from(seed));
                Ok(esk.verifying_key().encode().as_slice().to_vec())
            }

            /// Signs `msg` with FIPS 204 context `ctx` (at most 255 bytes) from a 32-byte seed.
            pub fn std_sign(seed: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SigError> {
                if ctx.len() > MAX_CONTEXT_LEN {
                    return Err(SigError::ContextTooLong(ctx.len()));
                }
                let seed: [u8; 32] = seed.try_into().map_err(|_| SigError::MalformedKey)?;
                let esk = ExpandedSigningKey::<$ty>::from_seed(&ml_dsa::Seed::from(seed));
                let mut rnd = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut rnd[..]).map_err(|_| SigError::SigningFailed)?;
                // M' = 0x00 || len(ctx) || ctx || M  (FIPS 204 Algorithm 2)
                let prefix: Vec<u8> = [&[0u8, ctx.len() as u8][..], ctx].concat();
                let sig = esk.sign_internal(&[&prefix, msg], &ml_dsa::B32::from(*rnd));
                Ok(sig.encode().as_slice().to_vec())
            }

            /// Verifies a standards-mode signature; failure modes as for `verify_ctx`.
            pub fn std_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<bool, SigError> {
                let enc =
                    ml_dsa::EncodedVerifyingKey::<$ty>::try_from(pk).map_err(|_| SigError::MalformedKey)?;
                let vk = VerifyingKey::<$ty>::decode(&enc);
                let Ok(sig) = Signature::<$ty>::try_from(sig) else {
                    return Ok(false);
                };
                if ctx.len() > MAX_CONTEXT_LEN {
                    return Ok(false);
                }
                Ok(vk.verify_with_context(msg, ctx, &sig))
            }
        }
    };
}

mldsa_level!(mldsa44, ml_dsa::MlDsa44, MlDsaLevel::L44);
mldsa_level!(mldsa65, ml_dsa::MlDsa65, MlDsaLevel::L65);
mldsa_level!(mldsa87, ml_dsa::MlDsa87, MlDsaLevel::L87);

/// Generates an ML-DSA key pair, returning `(expanded secret key, public key)`.
fn mldsa_keygen(l: MlDsaLevel) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    match l {
        MlDsaLevel::L44 => mldsa44::keygen(),
        MlDsaLevel::L65 => mldsa65::keygen(),
        MlDsaLevel::L87 => mldsa87::keygen(),
    }
}

/// Signs `msg` with an empty FIPS 204 context.
fn mldsa_sign(l: MlDsaLevel, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, SigError> {
    match l {
        MlDsaLevel::L44 => mldsa44::sign(sk, msg),
        MlDsaLevel::L65 => mldsa65::sign(sk, msg),
        MlDsaLevel::L87 => mldsa87::sign(sk, msg),
    }
}

/// Signs `msg` with FIPS 204 context `ctx`.
fn mldsa_sign_ctx(l: MlDsaLevel, sk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SigError> {
    match l {
        MlDsaLevel::L44 => mldsa44::sign_ctx(sk, msg, ctx),
        MlDsaLevel::L65 => mldsa65::sign_ctx(sk, msg, ctx),
        MlDsaLevel::L87 => mldsa87::sign_ctx(sk, msg, ctx),
    }
}

/// Verifies with FIPS 204 context `ctx`. A public key of the wrong length is `MalformedKey`; a signature of
/// the wrong length is `Ok(false)`.
fn mldsa_verify_ctx(l: MlDsaLevel, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<bool, SigError> {
    if pk.len() != l.sizes().0 {
        return Err(SigError::MalformedKey);
    }
    if sig.len() != l.sizes().2 {
        return Ok(false);
    }
    match l {
        MlDsaLevel::L44 => mldsa44::verify_ctx(pk, msg, ctx, sig),
        MlDsaLevel::L65 => mldsa65::verify_ctx(pk, msg, ctx, sig),
        MlDsaLevel::L87 => mldsa87::verify_ctx(pk, msg, ctx, sig),
    }
}

/// Verifies with an empty FIPS 204 context; length handling as for `mldsa_verify_ctx`.
fn mldsa_verify(l: MlDsaLevel, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SigError> {
    if pk.len() != l.sizes().0 {
        return Err(SigError::MalformedKey);
    }
    if sig.len() != l.sizes().2 {
        return Ok(false);
    }
    match l {
        MlDsaLevel::L44 => mldsa44::verify(pk, msg, sig),
        MlDsaLevel::L65 => mldsa65::verify(pk, msg, sig),
        MlDsaLevel::L87 => mldsa87::verify(pk, msg, sig),
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA
// ---------------------------------------------------------------------------

/// `rand_core` 0.6 adapter over the OS RNG (slh-dsa still targets the 0.6 traits).
struct SysRng06;

impl rand_core06::RngCore for SysRng06 {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS RNG must be available");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core06::Error> {
        getrandom::fill(dest).map_err(|_| rand_core06::Error::from(std::num::NonZeroU32::new(1).unwrap()))
    }
}
impl rand_core06::CryptoRng for SysRng06 {}

// Expands to a module `$m` with `keygen`, `sign` and `verify` for one SLH-DSA parameter set `$ty`. Signing
// uses an empty FIPS 205 context and `n` fresh random bytes as the optional randomness.
macro_rules! slh_param {
    ($m:ident, $ty:ty) => {
        mod $m {
            use super::*;
            use slh_dsa::signature::Keypair as _;

            pub fn keygen() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
                let sk = slh_dsa::SigningKey::<$ty>::new(&mut SysRng06);
                (Zeroizing::new(sk.to_vec()), sk.verifying_key().to_vec())
            }

            pub fn sign(sk: &[u8], msg: &[u8], n: usize) -> Result<Vec<u8>, SigError> {
                let sk = slh_dsa::SigningKey::<$ty>::try_from(sk).map_err(|_| SigError::MalformedKey)?;
                let mut opt_rand = vec![0u8; n];
                getrandom::fill(&mut opt_rand).map_err(|_| SigError::SigningFailed)?;
                let sig = sk
                    .try_sign_with_context(msg, &[], Some(&opt_rand))
                    .map_err(|_| SigError::SigningFailed)?;
                Ok(sig.to_vec())
            }

            pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SigError> {
                let vk = slh_dsa::VerifyingKey::<$ty>::try_from(pk).map_err(|_| SigError::MalformedKey)?;
                let Ok(sig) = slh_dsa::Signature::<$ty>::try_from(sig) else {
                    return Ok(false);
                };
                Ok(vk.try_verify_with_context(msg, &[], &sig).is_ok())
            }
        }
    };
}

slh_param!(shake128s, slh_dsa::Shake128s);
slh_param!(shake128f, slh_dsa::Shake128f);
slh_param!(shake192s, slh_dsa::Shake192s);
slh_param!(shake192f, slh_dsa::Shake192f);
slh_param!(shake256s, slh_dsa::Shake256s);
slh_param!(shake256f, slh_dsa::Shake256f);
slh_param!(sha2_128s, slh_dsa::Sha2_128s);
slh_param!(sha2_128f, slh_dsa::Sha2_128f);
slh_param!(sha2_192s, slh_dsa::Sha2_192s);
slh_param!(sha2_192f, slh_dsa::Sha2_192f);
slh_param!(sha2_256s, slh_dsa::Sha2_256s);
slh_param!(sha2_256f, slh_dsa::Sha2_256f);

/// Generates an SLH-DSA key pair, returning `(secret key, public key)`.
fn slh_keygen(p: SlhParam) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    match p {
        SlhParam::Shake128s => shake128s::keygen(),
        SlhParam::Shake128f => shake128f::keygen(),
        SlhParam::Shake192s => shake192s::keygen(),
        SlhParam::Shake192f => shake192f::keygen(),
        SlhParam::Shake256s => shake256s::keygen(),
        SlhParam::Shake256f => shake256f::keygen(),
        SlhParam::Sha2_128s => sha2_128s::keygen(),
        SlhParam::Sha2_128f => sha2_128f::keygen(),
        SlhParam::Sha2_192s => sha2_192s::keygen(),
        SlhParam::Sha2_192f => sha2_192f::keygen(),
        SlhParam::Sha2_256s => sha2_256s::keygen(),
        SlhParam::Sha2_256f => sha2_256f::keygen(),
    }
}

/// Signs `msg`; a secret key of the wrong length is `MalformedKey`.
fn slh_sign(p: SlhParam, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, SigError> {
    if sk.len() != p.sizes().1 {
        return Err(SigError::MalformedKey);
    }
    let n = p.n();
    match p {
        SlhParam::Shake128s => shake128s::sign(sk, msg, n),
        SlhParam::Shake128f => shake128f::sign(sk, msg, n),
        SlhParam::Shake192s => shake192s::sign(sk, msg, n),
        SlhParam::Shake192f => shake192f::sign(sk, msg, n),
        SlhParam::Shake256s => shake256s::sign(sk, msg, n),
        SlhParam::Shake256f => shake256f::sign(sk, msg, n),
        SlhParam::Sha2_128s => sha2_128s::sign(sk, msg, n),
        SlhParam::Sha2_128f => sha2_128f::sign(sk, msg, n),
        SlhParam::Sha2_192s => sha2_192s::sign(sk, msg, n),
        SlhParam::Sha2_192f => sha2_192f::sign(sk, msg, n),
        SlhParam::Sha2_256s => sha2_256s::sign(sk, msg, n),
        SlhParam::Sha2_256f => sha2_256f::sign(sk, msg, n),
    }
}

/// Verifies `sig`; a public key of the wrong length is `MalformedKey`, a signature of the wrong length is
/// `Ok(false)`.
fn slh_verify(p: SlhParam, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SigError> {
    if pk.len() != p.sizes().0 {
        return Err(SigError::MalformedKey);
    }
    if sig.len() != p.sizes().2 {
        return Ok(false);
    }
    match p {
        SlhParam::Shake128s => shake128s::verify(pk, msg, sig),
        SlhParam::Shake128f => shake128f::verify(pk, msg, sig),
        SlhParam::Shake192s => shake192s::verify(pk, msg, sig),
        SlhParam::Shake192f => shake192f::verify(pk, msg, sig),
        SlhParam::Shake256s => shake256s::verify(pk, msg, sig),
        SlhParam::Shake256f => shake256f::verify(pk, msg, sig),
        SlhParam::Sha2_128s => sha2_128s::verify(pk, msg, sig),
        SlhParam::Sha2_128f => sha2_128f::verify(pk, msg, sig),
        SlhParam::Sha2_192s => sha2_192s::verify(pk, msg, sig),
        SlhParam::Sha2_192f => sha2_192f::verify(pk, msg, sig),
        SlhParam::Sha2_256s => sha2_256s::verify(pk, msg, sig),
        SlhParam::Sha2_256f => sha2_256f::verify(pk, msg, sig),
    }
}

// ---------------------------------------------------------------------------
// Classical signature halves
// ---------------------------------------------------------------------------

use ed25519_dalek::{Signer as _, Verifier as _};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

/// Generates the classical half of a hybrid key, returning `(secret, public)`. Ed25519 secrets are 32-byte
/// seeds; P-256 and P-384 secrets are PKCS#8 PEM text bytes and their public keys are raw `x || y`.
fn classical_sig_keygen(c: ClassicalSig) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    match c {
        ClassicalSig::Ed25519 => {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut seed[..]).expect("OS RNG must be available");
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            (
                Zeroizing::new(seed.to_vec()),
                sk.verifying_key().to_bytes().to_vec(),
            )
        }
        ClassicalSig::P256 => {
            let sk = crate::kem::p256_random_secret();
            let pem = sk
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .expect("valid P-256 key encodes");
            let point = crate::kem::p256_public_bytes(&sk.public_key());
            // quantum-safe-py stores the signing public key as raw x || y (drops the 0x04 tag).
            (Zeroizing::new(pem.as_bytes().to_vec()), point[1..].to_vec())
        }
        ClassicalSig::P384 => {
            let sk = crate::kem::p384_random_secret();
            let pem = sk
                .to_pkcs8_pem(p384::pkcs8::LineEnding::LF)
                .expect("valid P-384 key encodes");
            let point = crate::kem::p384_public_bytes(&sk.public_key());
            (Zeroizing::new(pem.as_bytes().to_vec()), point[1..].to_vec())
        }
    }
}

/// Signs `msg` with the classical half: Ed25519, or DER-encoded ECDSA (SHA-256 for P-256, SHA-384 for P-384).
fn classical_sign(c: ClassicalSig, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, SigError> {
    match c {
        ClassicalSig::Ed25519 => {
            let arr: [u8; 32] = sk.try_into().map_err(|_| SigError::MalformedKey)?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&arr)
                .sign(msg)
                .to_bytes()
                .to_vec())
        }
        ClassicalSig::P256 => {
            let pem = std::str::from_utf8(sk).map_err(|_| SigError::MalformedKey)?;
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| SigError::MalformedKey)?;
            let sig: p256::ecdsa::Signature = key.try_sign(msg).map_err(|_| SigError::SigningFailed)?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
        ClassicalSig::P384 => {
            // ECDSA P-384 with SHA-384, DER, as quantum-safe-py (cryptography ECDSA(SHA384)).
            let pem = std::str::from_utf8(sk).map_err(|_| SigError::MalformedKey)?;
            let key = p384::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| SigError::MalformedKey)?;
            let sig: p384::ecdsa::Signature = key.try_sign(msg).map_err(|_| SigError::SigningFailed)?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }
}

/// Verifies the classical half. A public key of the wrong length or off the curve is `MalformedKey`; a
/// signature that does not parse is `Ok(false)`. Ed25519 uses strict verification.
fn classical_verify(c: ClassicalSig, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SigError> {
    match c {
        ClassicalSig::Ed25519 => {
            let arr: [u8; 32] = pk.try_into().map_err(|_| SigError::MalformedKey)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| SigError::MalformedKey)?;
            let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
                return Ok(false);
            };
            Ok(vk
                .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .is_ok())
        }
        ClassicalSig::P256 => {
            if pk.len() != 64 {
                return Err(SigError::MalformedKey);
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(pk);
            let vk =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| SigError::MalformedKey)?;
            let Ok(sig) = p256::ecdsa::Signature::from_der(sig) else {
                return Ok(false);
            };
            Ok(vk.verify(msg, &sig).is_ok())
        }
        ClassicalSig::P384 => {
            if pk.len() != 96 {
                return Err(SigError::MalformedKey);
            }
            let mut point = Vec::with_capacity(97);
            point.push(0x04);
            point.extend_from_slice(pk);
            let vk =
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| SigError::MalformedKey)?;
            let Ok(sig) = p384::ecdsa::Signature::from_der(sig) else {
                return Ok(false);
            };
            Ok(vk.verify(msg, &sig).is_ok())
        }
    }
}

// ---------------------------------------------------------------------------
// Signed message
// ---------------------------------------------------------------------------

/// `quantum_safe.types.signatures.SignedMessage`.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedMessage {
    /// The signed message.
    pub message: Vec<u8>,
    /// The signature blob in the format of `algorithm`.
    pub signature: Vec<u8>,
    /// Canonical algorithm string, including the `-v2` tag for v2 signatures.
    pub algorithm: String,
    /// The signing context, at most 255 bytes; part of the signed input.
    pub context: Vec<u8>,
    /// Fingerprint of the signer's key, as supplied at signing time. Metadata only; not covered by the signature.
    pub signer_fingerprint: String,
    /// Unix timestamp (seconds). Metadata only; not covered by the signature.
    pub signed_at: f64,
    /// True when the algorithm is a hybrid suite. Metadata only; verification uses `algorithm`.
    pub is_hybrid: bool,
}

/// Looks up a text key in a decoded CBOR map; the first match wins.
fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

impl SignedMessage {
    /// Serializes as the CBOR map `{v, msg, sig, algo, ctx, fp, ts, hybrid}`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let value = Value::Map(vec![
            (
                Value::Text("v".into()),
                Value::Integer(SIGNED_MESSAGE_VERSION.into()),
            ),
            (Value::Text("msg".into()), Value::Bytes(self.message.clone())),
            (Value::Text("sig".into()), Value::Bytes(self.signature.clone())),
            (Value::Text("algo".into()), Value::Text(self.algorithm.clone())),
            (Value::Text("ctx".into()), Value::Bytes(self.context.clone())),
            (
                Value::Text("fp".into()),
                Value::Text(self.signer_fingerprint.clone()),
            ),
            (Value::Text("ts".into()), Value::Float(self.signed_at)),
            (Value::Text("hybrid".into()), Value::Bool(self.is_hybrid)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("writing CBOR to a Vec cannot fail");
        out
    }

    /// Parses the CBOR written by [`SignedMessage::to_cbor`]. Nothing here verifies the signature.
    ///
    /// `ctx`, `fp`, `ts` and `hybrid` are optional and default to empty, empty, 0.0 and false.
    ///
    /// # Errors
    ///
    /// - [`SigError::Format`] for input over 10 MB, a shape the CBOR guard refuses, undecodable CBOR, a
    ///   top-level value that is not a map, a version other than 1, a missing `algo`, `msg` or `sig`, an
    ///   empty signature, or a mistyped `ctx`.
    /// - [`SigError::EmptyMessage`] when `msg` is empty.
    /// - [`SigError::ContextTooLong`] when `ctx` is over 255 bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, SigError> {
        let fmt = |s: &str| SigError::Format(s.to_string());
        if data.len() > MAX_PAYLOAD_BYTES {
            return Err(fmt("payload exceeds the 10 MB limit"));
        }
        crate::cbor_guard::validate_shape(data).map_err(|e| SigError::Format(e.to_string()))?;
        let value: Value =
            ciborium::from_reader(data).map_err(|e| SigError::Format(format!("decode failed: {e}")))?;
        let Value::Map(entries) = value else {
            return Err(fmt("is not a CBOR map"));
        };
        match map_get(&entries, "v") {
            Some(Value::Integer(i)) if i128::from(*i) == i128::from(SIGNED_MESSAGE_VERSION) => {}
            _ => return Err(fmt("has an unsupported or missing version")),
        }
        let bytes = |k: &str| match map_get(&entries, k) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(SigError::Format(format!("is missing byte field '{k}'"))),
        };
        let algorithm = match map_get(&entries, "algo") {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(fmt("is missing 'algo'")),
        };
        let message = bytes("msg")?;
        let signature = bytes("sig")?;
        if message.is_empty() {
            return Err(SigError::EmptyMessage);
        }
        if signature.is_empty() {
            return Err(fmt("signature cannot be empty"));
        }
        let context = match map_get(&entries, "ctx") {
            Some(Value::Bytes(b)) => b.clone(),
            None => Vec::new(),
            _ => return Err(fmt("has a malformed 'ctx'")),
        };
        if context.len() > MAX_CONTEXT_LEN {
            return Err(SigError::ContextTooLong(context.len()));
        }
        let signer_fingerprint = match map_get(&entries, "fp") {
            Some(Value::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let signed_at = match map_get(&entries, "ts") {
            Some(Value::Float(f)) => *f,
            Some(Value::Integer(i)) => i128::from(*i) as f64,
            _ => 0.0,
        };
        let is_hybrid = matches!(map_get(&entries, "hybrid"), Some(Value::Bool(true)));
        Ok(Self {
            message,
            signature,
            algorithm,
            context,
            signer_fingerprint,
            signed_at,
            is_hybrid,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SignOptions {
    /// When `false` (the default), 32 random bytes are prepended to the signed input and stored in the
    /// signature blob, as quantum-safe-py does by default. When `true`, that prefix is omitted. Only the
    /// prefix is affected: ML-DSA and SLH-DSA signing still draw fresh randomness. `-v2` signatures have
    /// no prefix and ignore this field.
    pub deterministic: bool,
    /// Stored in the [`SignedMessage`]; not signed.
    pub signer_fingerprint: String,
    /// Unix timestamp in seconds stored in the [`SignedMessage`]; not signed.
    pub signed_at: f64,
}

/// A matching signature public key and secret key.
pub struct SigKeyPair {
    /// The public key.
    pub public: PublicKey,
    /// The secret key.
    pub secret: SecretKey,
}

/// Resolves an algorithm string to a suite or `UnsupportedAlgorithm`.
fn suite_of(algorithm: &str) -> Result<SigSuite, SigError> {
    SigSuite::parse(algorithm).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))
}

/// Generate a key pair for `algorithm`, a signature suite or a `-v2` identifier.
///
/// Hybrid keys are `u16_be(len(classical)) || classical || pqc`. A `-v2` pair holds the same key bytes as
/// its base suite with the algorithm string tagged `-v2`.
///
/// # Errors
///
/// [`SigError::UnsupportedAlgorithm`] when `algorithm` is not a supported suite.
pub fn generate_keypair(algorithm: &str) -> Result<SigKeyPair, SigError> {
    if v2::base_of(algorithm).is_some() {
        return v2::generate_keypair(algorithm);
    }
    let suite = suite_of(algorithm)?;
    let (sec, public) = match suite {
        SigSuite::MlDsa(l) => mldsa_keygen(l),
        SigSuite::Slh(p) => slh_keygen(p),
        SigSuite::Hybrid(c, l) => {
            let (c_sec, c_pub) = classical_sig_keygen(c);
            let (p_sec, p_pub) = mldsa_keygen(l);
            (
                Zeroizing::new(pack_components(&c_sec, &p_sec)),
                pack_components(&c_pub, &p_pub),
            )
        }
    };
    let name = suite.name();
    Ok(SigKeyPair {
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

/// Builds the v1 signature blob `len(rand_prefix) (1 byte) || rand_prefix || payload`.
fn pack_sig_blob(rand_prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + rand_prefix.len() + payload.len());
    v.push(rand_prefix.len() as u8);
    v.extend_from_slice(rand_prefix);
    v.extend_from_slice(payload);
    v
}

/// Splits a v1 signature blob into `(rand_prefix, payload)`; `None` if it is empty or shorter than its
/// prefix length says.
fn unpack_sig_blob(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&n, rest) = blob.split_first()?;
    let n = n as usize;
    if rest.len() < n {
        return None;
    }
    Some(rest.split_at(n))
}

/// `len(context) || context || rand_prefix || message`
fn signing_input(context: &[u8], rand_prefix: &[u8], message: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + context.len() + rand_prefix.len() + message.len());
    v.push(context.len() as u8);
    v.extend_from_slice(context);
    v.extend_from_slice(rand_prefix);
    v.extend_from_slice(message);
    v
}

/// CBOR payload of a v1 hybrid signature: `{classical_sig, pqc_sig, classical_algo, pqc_algo}`.
fn hybrid_payload(classical_sig: &[u8], pqc_sig: &[u8], c: ClassicalSig, l: MlDsaLevel) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("classical_sig".into()),
            Value::Bytes(classical_sig.to_vec()),
        ),
        (Value::Text("pqc_sig".into()), Value::Bytes(pqc_sig.to_vec())),
        (Value::Text("classical_algo".into()), Value::Text(c.name().into())),
        (Value::Text("pqc_algo".into()), Value::Text(l.name().into())),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

/// Parses a v1 hybrid payload into `(classical_sig, pqc_sig, classical_algo, pqc_algo)`. `None` unless it
/// is a map of exactly those four entries with the right types; the size limit and CBOR guard apply first.
fn parse_hybrid_payload(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, String, String)> {
    if data.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    crate::cbor_guard::validate_shape(data).ok()?;
    let value: Value = ciborium::from_reader(data).ok()?;
    let Value::Map(entries) = value else { return None };
    // Exactly the four entries quantum-safe-py writes: unknown extra entries would be unsigned, mutable bytes (malleability).
    if entries.len() != 4 {
        return None;
    }
    let b = |k: &str| match map_get(&entries, k) {
        Some(Value::Bytes(v)) => Some(v.clone()),
        _ => None,
    };
    let t = |k: &str| match map_get(&entries, k) {
        Some(Value::Text(v)) => Some(v.clone()),
        _ => None,
    };
    Some((
        b("classical_sig")?,
        b("pqc_sig")?,
        t("classical_algo")?,
        t("pqc_algo")?,
    ))
}

/// Sign `message` with `secret`. Both `Sign` and `HybridSign` semantics, selected by the
/// key's algorithm.
///
/// A `-v2` secret key produces a v2 signature (see [`v2`]). Otherwise the signature blob is
/// `len(rand_prefix) || rand_prefix || payload`; for a hybrid the payload is CBOR holding both
/// signatures, and both halves sign the same input. `signed_at` and `signer_fingerprint` are copied from
/// `opts` into the result unsigned.
///
/// # Errors
///
/// - [`SigError::UnsupportedAlgorithm`] when the key's algorithm is not a supported suite.
/// - [`SigError::ContextTooLong`] when `context` is over 255 bytes.
/// - [`SigError::EmptyMessage`] when `message` is empty.
/// - [`SigError::MalformedKey`] when the secret key has the wrong length or does not parse.
/// - [`SigError::SigningFailed`] when the OS RNG or the signing primitive fails.
pub fn sign(
    secret: &SecretKey,
    message: &[u8],
    context: &[u8],
    opts: &SignOptions,
) -> Result<SignedMessage, SigError> {
    if v2::base_of(&secret.algorithm).is_some() {
        return v2::sign(secret, message, context, opts);
    }
    let suite = suite_of(&secret.algorithm)?;
    if context.len() > MAX_CONTEXT_LEN {
        return Err(SigError::ContextTooLong(context.len()));
    }
    if message.is_empty() {
        return Err(SigError::EmptyMessage);
    }
    let mut rand_prefix = Vec::new();
    if !opts.deterministic {
        rand_prefix = vec![0u8; HEDGE_BYTES];
        getrandom::fill(&mut rand_prefix).map_err(|_| SigError::SigningFailed)?;
    }
    let input = signing_input(context, &rand_prefix, message);

    let payload = match suite {
        SigSuite::MlDsa(l) => mldsa_sign(l, &secret.raw, &input)?,
        SigSuite::Slh(p) => slh_sign(p, &secret.raw, &input)?,
        SigSuite::Hybrid(c, l) => {
            let (c_sec, p_sec) = unpack_components(&secret.raw).map_err(|_| SigError::MalformedKey)?;
            let classical_sig = classical_sign(c, c_sec, &input)?;
            let pqc_sig = mldsa_sign(l, p_sec, &input)?;
            hybrid_payload(&classical_sig, &pqc_sig, c, l)
        }
    };
    Ok(SignedMessage {
        message: message.to_vec(),
        signature: pack_sig_blob(&rand_prefix, &payload),
        algorithm: suite.name(),
        context: context.to_vec(),
        signer_fingerprint: opts.signer_fingerprint.clone(),
        signed_at: opts.signed_at,
        is_hybrid: suite.is_hybrid(),
    })
}

/// Verify raw parts. All failure modes of the *signature* collapse to `VerificationFailed`
/// (no oracle); an unusable *public key* is reported as `MalformedKey`.
///
/// For a hybrid, both halves are verified before the results are combined, and the algorithm names inside
/// the payload must match the suite.
///
/// # Errors
///
/// - [`SigError::UnsupportedAlgorithm`] when `algorithm` is not a supported suite.
/// - [`SigError::AlgorithmMismatch`] when `public.algorithm` differs from `algorithm`.
/// - [`SigError::MalformedKey`] when the public key has the wrong length or does not parse.
/// - [`SigError::VerificationFailed`] when the context is over 255 bytes, the blob is malformed, or the
///   signature does not verify.
pub fn verify_parts(
    algorithm: &str,
    message: &[u8],
    signature_blob: &[u8],
    context: &[u8],
    public: &PublicKey,
) -> Result<(), SigError> {
    if v2::base_of(algorithm).is_some() {
        return v2::verify_parts(algorithm, message, signature_blob, context, public);
    }
    let suite = suite_of(algorithm)?;
    if public.algorithm != algorithm {
        return Err(SigError::AlgorithmMismatch);
    }
    if context.len() > MAX_CONTEXT_LEN {
        return Err(SigError::VerificationFailed);
    }
    let Some((rand_prefix, payload)) = unpack_sig_blob(signature_blob) else {
        return Err(SigError::VerificationFailed);
    };
    let input = signing_input(context, rand_prefix, message);

    let ok = match suite {
        SigSuite::MlDsa(l) => mldsa_verify(l, &public.raw, &input, payload)?,
        SigSuite::Slh(p) => slh_verify(p, &public.raw, &input, payload)?,
        SigSuite::Hybrid(c, l) => {
            let (c_pub, p_pub) = unpack_components(&public.raw).map_err(|_| SigError::MalformedKey)?;
            let Some((classical_sig, pqc_sig, c_algo, p_algo)) = parse_hybrid_payload(payload) else {
                return Err(SigError::VerificationFailed);
            };
            // Evaluate BOTH halves unconditionally before combining (no timing/oracle on which failed).
            let classical_ok = classical_verify(c, c_pub, &input, &classical_sig);
            let pqc_ok = mldsa_verify(l, p_pub, &input, &pqc_sig);
            let algos_ok = c_algo == c.name() && p_algo == l.name();
            let (classical_ok, pqc_ok) = (classical_ok?, pqc_ok?);
            classical_ok & pqc_ok & algos_ok
        }
    };
    if ok {
        Ok(())
    } else {
        Err(SigError::VerificationFailed)
    }
}

/// Verify a [`SignedMessage`] against `public`; shorthand for [`verify_parts`] on its fields.
///
/// # Errors
///
/// As for [`verify_parts`].
pub fn verify(signed: &SignedMessage, public: &PublicKey) -> Result<(), SigError> {
    verify_parts(
        &signed.algorithm,
        &signed.message,
        &signed.signature,
        &signed.context,
        public,
    )
}

pub mod v2;

/// Standards-mode ML-DSA (FIPS 204 pure signing with the native context parameter, keys as
/// 32-byte seeds). This is the construction RFC 9964 (ML-DSA for JOSE/COSE) uses, and is what any
/// third-party ML-DSA library verifies. It is **not** the quantum-safe-py construction above.
pub mod standard {
    use super::*;

    /// Generates a random 32-byte seed (the secret key) and its public key, returning `(seed, public key)`.
    pub fn keygen(level: MlDsaLevel) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        match level {
            MlDsaLevel::L44 => mldsa44::std_keygen(),
            MlDsaLevel::L65 => mldsa65::std_keygen(),
            MlDsaLevel::L87 => mldsa87::std_keygen(),
        }
    }

    /// The public key for a 32-byte seed.
    ///
    /// # Errors
    ///
    /// [`SigError::MalformedKey`] when `seed` is not 32 bytes.
    pub fn public_from_seed(level: MlDsaLevel, seed: &[u8]) -> Result<Vec<u8>, SigError> {
        match level {
            MlDsaLevel::L44 => mldsa44::std_public(seed),
            MlDsaLevel::L65 => mldsa65::std_public(seed),
            MlDsaLevel::L87 => mldsa87::std_public(seed),
        }
    }

    /// Signs `msg` with FIPS 204 `ML-DSA.Sign`, passing `ctx` as the native context. Signing is hedged.
    ///
    /// # Errors
    ///
    /// - [`SigError::ContextTooLong`] when `ctx` is over 255 bytes.
    /// - [`SigError::MalformedKey`] when `seed` is not 32 bytes.
    /// - [`SigError::SigningFailed`] when the OS RNG fails.
    pub fn sign(level: MlDsaLevel, seed: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SigError> {
        match level {
            MlDsaLevel::L44 => mldsa44::std_sign(seed, msg, ctx),
            MlDsaLevel::L65 => mldsa65::std_sign(seed, msg, ctx),
            MlDsaLevel::L87 => mldsa87::std_sign(seed, msg, ctx),
        }
    }

    /// Verifies a signature made by [`sign`] (or any FIPS 204 signer using context `ctx`).
    ///
    /// Returns `Ok(false)` for a signature of the wrong length or one that does not verify, including a
    /// context over 255 bytes.
    ///
    /// # Errors
    ///
    /// [`SigError::MalformedKey`] when the public key has the wrong length.
    pub fn verify(
        level: MlDsaLevel,
        pk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<bool, SigError> {
        if pk.len() != level.sizes().0 {
            return Err(SigError::MalformedKey);
        }
        if sig.len() != level.sizes().2 {
            return Ok(false);
        }
        match level {
            MlDsaLevel::L44 => mldsa44::std_verify(pk, msg, ctx, sig),
            MlDsaLevel::L65 => mldsa65::std_verify(pk, msg, ctx, sig),
            MlDsaLevel::L87 => mldsa87::std_verify(pk, msg, ctx, sig),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SignOptions {
        SignOptions {
            deterministic: false,
            signer_fingerprint: String::new(),
            signed_at: 1.0,
        }
    }

    // SLH-DSA "s" sets are slow; keep the round-trip suite to the fast sets plus one "s".
    fn fast_suites() -> Vec<SigSuite> {
        SigSuite::all()
            .into_iter()
            .filter(|s| match s {
                SigSuite::Slh(p) => {
                    matches!(p, SlhParam::Shake128f | SlhParam::Sha2_128f | SlhParam::Shake128s)
                }
                _ => true,
            })
            .collect()
    }

    #[test]
    fn registry_sizes_and_names() {
        assert_eq!(MlDsaLevel::L87.sizes().1, 4896); // liboqs / FIPS 204 (quantum-safe-py's registry said 4864 before its 0.3.1 fix)
        assert_eq!(SigSuite::all().len(), 3 + 5 + 1 + 12); // + P-384+ML-DSA-87
        for s in SigSuite::all() {
            assert_eq!(SigSuite::parse(&s.name()), Some(s));
        }
        assert_eq!(SigSuite::parse("P-256+ML-DSA-87"), None);
        assert_eq!(SigSuite::parse("P-384+ML-DSA-65"), None);
        assert_eq!(SigSuite::parse("P-384+ML-DSA-44"), None);
        assert!(SigSuite::parse("P-384+ML-DSA-87").unwrap().meets_cnsa2());
        assert_eq!(SigSuite::parse("Ed25519+ML-DSA-65+x"), None);
        assert!(SigSuite::parse("Ed25519+ML-DSA-87").unwrap().meets_cnsa2());
        assert!(!SigSuite::parse(DEFAULT_HYBRID_SIG).unwrap().meets_cnsa2());
    }

    #[test]
    fn every_fast_suite_signs_and_verifies() {
        for s in fast_suites() {
            let name = s.name();
            let kp = generate_keypair(&name).unwrap();
            let sm = sign(&kp.secret, b"hello world", b"ctx", &opts()).unwrap();
            assert_eq!(sm.is_hybrid, s.is_hybrid());
            assert_eq!(sm.signature[0] as usize, HEDGE_BYTES, "{name}");
            verify(&sm, &kp.public).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn key_and_signature_sizes() {
        let kp = generate_keypair("ML-DSA-65").unwrap();
        assert_eq!((kp.public.raw.len(), kp.secret.raw.len()), (1952, 4032));
        let kp = generate_keypair("ML-DSA-87").unwrap();
        assert_eq!((kp.public.raw.len(), kp.secret.raw.len()), (2592, 4896));
        let kp = generate_keypair("Ed25519+ML-DSA-65").unwrap();
        assert_eq!((kp.public.raw.len(), kp.secret.raw.len()), (1986, 4066)); // matches quantum-safe-py
        let sm = sign(&kp.secret, b"m", b"c", &opts()).unwrap();
        assert_eq!(sm.signature.len(), 3476); // matches quantum-safe-py probe
    }

    #[test]
    fn tampering_with_message_context_or_signature_fails() {
        let kp = generate_keypair(DEFAULT_HYBRID_SIG).unwrap();
        let sm = sign(&kp.secret, b"payload", b"app-v1", &opts()).unwrap();
        let mut bad = sm.clone();
        bad.message[0] ^= 1;
        assert_eq!(verify(&bad, &kp.public), Err(SigError::VerificationFailed));
        let mut bad = sm.clone();
        bad.context = b"app-v2".to_vec();
        assert_eq!(verify(&bad, &kp.public), Err(SigError::VerificationFailed));
        let mut bad = sm.clone();
        let n = bad.signature.len();
        bad.signature[n - 1] ^= 1;
        assert_eq!(verify(&bad, &kp.public), Err(SigError::VerificationFailed));
        let other = generate_keypair(DEFAULT_HYBRID_SIG).unwrap();
        assert_eq!(verify(&sm, &other.public), Err(SigError::VerificationFailed));
    }

    #[test]
    fn hedged_signatures_differ_and_deterministic_prefix_is_empty() {
        let kp = generate_keypair("ML-DSA-44").unwrap();
        let a = sign(&kp.secret, b"same", b"", &opts()).unwrap();
        let b = sign(&kp.secret, b"same", b"", &opts()).unwrap();
        assert_ne!(a.signature, b.signature);
        let d = sign(
            &kp.secret,
            b"same",
            b"",
            &SignOptions {
                deterministic: true,
                ..opts()
            },
        )
        .unwrap();
        assert_eq!(d.signature[0], 0);
        verify(&d, &kp.public).unwrap();
    }

    #[test]
    fn input_validation() {
        let kp = generate_keypair("ML-DSA-44").unwrap();
        assert_eq!(
            sign(&kp.secret, b"", b"", &opts()).unwrap_err(),
            SigError::EmptyMessage
        );
        let long = vec![0u8; 256];
        assert_eq!(
            sign(&kp.secret, b"m", &long, &opts()).unwrap_err(),
            SigError::ContextTooLong(256)
        );
        let wrong = SecretKey::new(kp.secret.raw.to_vec(), "Nope");
        assert!(matches!(
            sign(&wrong, b"m", b"", &opts()),
            Err(SigError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn algorithm_mismatch_is_rejected() {
        let a = generate_keypair("ML-DSA-44").unwrap();
        let b = generate_keypair("ML-DSA-65").unwrap();
        let sm = sign(&a.secret, b"m", b"", &opts()).unwrap();
        assert_eq!(verify(&sm, &b.public), Err(SigError::AlgorithmMismatch));
    }

    #[test]
    fn signed_message_cbor_roundtrip() {
        let kp = generate_keypair("ML-DSA-65").unwrap();
        let sm = sign(&kp.secret, b"msg", b"ctx", &opts()).unwrap();
        let back = SignedMessage::from_cbor(&sm.to_cbor()).unwrap();
        assert_eq!(back, sm);
        verify(&back, &kp.public).unwrap();
        assert!(SignedMessage::from_cbor(b"garbage").is_err());
    }

    #[test]
    fn malformed_secret_keys_never_panic() {
        for l in [MlDsaLevel::L44, MlDsaLevel::L65, MlDsaLevel::L87] {
            let len = l.sizes().1;
            for fill in [0x00u8, 0x55, 0xff, 0x07, 0x09] {
                let sk = SecretKey::new(vec![fill; len], l.name());
                let _ = sign(&sk, b"m", b"", &opts());
            }
            let _ = sign(&SecretKey::new(vec![1; len - 1], l.name()), b"m", b"", &opts());
        }
    }

    #[test]
    fn malformed_signatures_fail_closed() {
        let kp = generate_keypair(DEFAULT_HYBRID_SIG).unwrap();
        let sm = sign(&kp.secret, b"m", b"", &opts()).unwrap();
        for cut in [0usize, 1, 2, 33, 34, 100, sm.signature.len() - 1] {
            let mut bad = sm.clone();
            bad.signature.truncate(cut);
            assert!(verify(&bad, &kp.public).is_err());
        }
        let mut bad = sm.clone();
        bad.signature[0] = 255;
        assert!(verify(&bad, &kp.public).is_err());
    }

    #[test]
    fn standard_mode_roundtrips_and_binds_context() {
        for l in [MlDsaLevel::L44, MlDsaLevel::L65, MlDsaLevel::L87] {
            let (seed, pk) = standard::keygen(l);
            assert_eq!(pk.len(), l.sizes().0);
            assert_eq!(standard::public_from_seed(l, &seed).unwrap(), pk);
            let sig = standard::sign(l, &seed, b"jws input", b"").unwrap();
            assert_eq!(sig.len(), l.sizes().2);
            assert!(standard::verify(l, &pk, b"jws input", b"", &sig).unwrap());
            assert!(!standard::verify(l, &pk, b"jws input!", b"", &sig).unwrap());
            assert!(!standard::verify(l, &pk, b"jws input", b"ctx", &sig).unwrap());
            let sig2 = standard::sign(l, &seed, b"jws input", b"ctx").unwrap();
            assert!(standard::verify(l, &pk, b"jws input", b"ctx", &sig2).unwrap());
        }
    }
}
