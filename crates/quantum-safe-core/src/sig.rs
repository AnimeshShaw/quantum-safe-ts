//! Digital signatures, matching `quantum_safe.signatures` byte for byte:
//!
//! - pure ML-DSA-44/65/87 (`Sign`) and SLH-DSA (FIPS 205);
//! - hybrid `Ed25519+ML-DSA-{44,65,87}` and `P-256+ML-DSA-{44,65}` (`HybridSign`).
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
//! PKCS#8 PEM text bytes, signature = DER ECDSA-SHA256.

use crate::kem::{PublicKey, SecretKey};
use crate::keys::MigrationState;
use crate::wire::{pack_components, unpack_components};
use ciborium::value::Value;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Number of random bytes prepended in hedged mode (`HEDGED_RANDOMNESS_BYTES`).
pub const HEDGE_BYTES: usize = 32;
pub const MAX_CONTEXT_LEN: usize = 255;
pub const SIGNED_MESSAGE_VERSION: i64 = 1;
/// Mirrors the 10 MB cap in quantum-safe-py's serialization layer.
pub const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

pub const DEFAULT_HYBRID_SIG: &str = "Ed25519+ML-DSA-65";
pub const DEFAULT_SIG: &str = "ML-DSA-65";
/// CNSA 2.0 signature suite (ML-DSA-87).
pub const CNSA2_SIG: &str = "Ed25519+ML-DSA-87";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigError {
    #[error("unsupported or unapproved signature algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("key algorithm does not match the signed message / expected algorithm")]
    AlgorithmMismatch,
    #[error("key bytes are malformed or have the wrong length")]
    MalformedKey,
    #[error("context must be at most {MAX_CONTEXT_LEN} bytes, got {0}")]
    ContextTooLong(usize),
    #[error("message cannot be empty")]
    EmptyMessage,
    #[error("signing failed")]
    SigningFailed,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("SignedMessage {0}")]
    Format(String),
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MlDsaLevel {
    L44,
    L65,
    L87,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassicalSig {
    Ed25519,
    P256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigSuite {
    MlDsa(MlDsaLevel),
    Slh(SlhParam),
    Hybrid(ClassicalSig, MlDsaLevel),
}

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
    pub fn name(self) -> &'static str {
        match self {
            MlDsaLevel::L44 => "ML-DSA-44",
            MlDsaLevel::L65 => "ML-DSA-65",
            MlDsaLevel::L87 => "ML-DSA-87",
        }
    }
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
    pub fn nist_level(self) -> u8 {
        match self {
            MlDsaLevel::L44 => 2,
            MlDsaLevel::L65 => 3,
            MlDsaLevel::L87 => 5,
        }
    }
}

impl SlhParam {
    pub fn name(self) -> &'static str {
        SLH_TABLE
            .iter()
            .find(|r| r.0 == self)
            .map(|r| r.1)
            .expect("table covers every variant")
    }
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
    pub fn nist_level(self) -> u8 {
        match self.sizes().0 {
            32 => 1,
            48 => 3,
            _ => 5,
        }
    }
    fn n(self) -> usize {
        self.sizes().0 / 2
    }
}

impl ClassicalSig {
    pub fn name(self) -> &'static str {
        match self {
            ClassicalSig::Ed25519 => "Ed25519",
            ClassicalSig::P256 => "P-256",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Ed25519" => Some(Self::Ed25519),
            "P-256" => Some(Self::P256),
            _ => None,
        }
    }
}

/// Approved hybrid pairings, mirroring `HYBRID_SIGNATURE_COMBINATIONS`.
pub fn is_approved_hybrid(c: ClassicalSig, l: MlDsaLevel) -> bool {
    match c {
        ClassicalSig::Ed25519 => true,
        ClassicalSig::P256 => matches!(l, MlDsaLevel::L44 | MlDsaLevel::L65),
    }
}

impl SigSuite {
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

    pub fn name(self) -> String {
        match self {
            SigSuite::MlDsa(l) => l.name().to_string(),
            SigSuite::Slh(p) => p.name().to_string(),
            SigSuite::Hybrid(c, l) => format!("{}+{}", c.name(), l.name()),
        }
    }

    pub fn is_hybrid(self) -> bool {
        matches!(self, SigSuite::Hybrid(..))
    }

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

    pub fn all() -> Vec<SigSuite> {
        let mut v = Vec::new();
        for l in [MlDsaLevel::L44, MlDsaLevel::L65, MlDsaLevel::L87] {
            v.push(SigSuite::MlDsa(l));
        }
        for c in [ClassicalSig::Ed25519, ClassicalSig::P256] {
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

macro_rules! mldsa_level {
    ($m:ident, $ty:ty, $level:expr) => {
        mod $m {
            use super::*;
            use ml_dsa::{ExpandedSigningKey, Signature, VerifyingKey};

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

            pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SigError> {
                verify_ctx(pk, msg, &[], sig)
            }

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

            pub fn std_keygen() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
                let mut seed = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut seed[..]).expect("OS RNG must be available");
                let pk = std_public(&seed[..]).expect("a 32-byte seed is always valid");
                (Zeroizing::new(seed.to_vec()), pk)
            }

            pub fn std_public(seed: &[u8]) -> Result<Vec<u8>, SigError> {
                let seed: [u8; 32] = seed.try_into().map_err(|_| SigError::MalformedKey)?;
                let esk = ExpandedSigningKey::<$ty>::from_seed(&ml_dsa::Seed::from(seed));
                Ok(esk.verifying_key().encode().as_slice().to_vec())
            }

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

fn mldsa_keygen(l: MlDsaLevel) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    match l {
        MlDsaLevel::L44 => mldsa44::keygen(),
        MlDsaLevel::L65 => mldsa65::keygen(),
        MlDsaLevel::L87 => mldsa87::keygen(),
    }
}

fn mldsa_sign(l: MlDsaLevel, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, SigError> {
    match l {
        MlDsaLevel::L44 => mldsa44::sign(sk, msg),
        MlDsaLevel::L65 => mldsa65::sign(sk, msg),
        MlDsaLevel::L87 => mldsa87::sign(sk, msg),
    }
}

fn mldsa_sign_ctx(l: MlDsaLevel, sk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SigError> {
    match l {
        MlDsaLevel::L44 => mldsa44::sign_ctx(sk, msg, ctx),
        MlDsaLevel::L65 => mldsa65::sign_ctx(sk, msg, ctx),
        MlDsaLevel::L87 => mldsa87::sign_ctx(sk, msg, ctx),
    }
}

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
    }
}

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
    }
}

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
    }
}

// ---------------------------------------------------------------------------
// Signed message
// ---------------------------------------------------------------------------

/// `quantum_safe.types.signatures.SignedMessage`.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub algorithm: String,
    pub context: Vec<u8>,
    pub signer_fingerprint: String,
    /// Unix timestamp (seconds). Metadata only; not covered by the signature.
    pub signed_at: f64,
    pub is_hybrid: bool,
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

impl SignedMessage {
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
    /// Prepend 32 random bytes (default in quantum-safe-py). Set `false` for deterministic input.
    pub deterministic: bool,
    pub signer_fingerprint: String,
    pub signed_at: f64,
}

pub struct SigKeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

fn suite_of(algorithm: &str) -> Result<SigSuite, SigError> {
    SigSuite::parse(algorithm).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))
}

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

fn pack_sig_blob(rand_prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + rand_prefix.len() + payload.len());
    v.push(rand_prefix.len() as u8);
    v.extend_from_slice(rand_prefix);
    v.extend_from_slice(payload);
    v
}

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

    pub fn keygen(level: MlDsaLevel) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        match level {
            MlDsaLevel::L44 => mldsa44::std_keygen(),
            MlDsaLevel::L65 => mldsa65::std_keygen(),
            MlDsaLevel::L87 => mldsa87::std_keygen(),
        }
    }

    pub fn public_from_seed(level: MlDsaLevel, seed: &[u8]) -> Result<Vec<u8>, SigError> {
        match level {
            MlDsaLevel::L44 => mldsa44::std_public(seed),
            MlDsaLevel::L65 => mldsa65::std_public(seed),
            MlDsaLevel::L87 => mldsa87::std_public(seed),
        }
    }

    pub fn sign(level: MlDsaLevel, seed: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SigError> {
        match level {
            MlDsaLevel::L44 => mldsa44::std_sign(seed, msg, ctx),
            MlDsaLevel::L65 => mldsa65::std_sign(seed, msg, ctx),
            MlDsaLevel::L87 => mldsa87::std_sign(seed, msg, ctx),
        }
    }

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
        assert_eq!(MlDsaLevel::L87.sizes().1, 4896); // liboqs / FIPS 204 (quantum-safe-py's registry says 4864)
        assert_eq!(SigSuite::all().len(), 3 + 5 + 12);
        for s in SigSuite::all() {
            assert_eq!(SigSuite::parse(&s.name()), Some(s));
        }
        assert_eq!(SigSuite::parse("P-256+ML-DSA-87"), None);
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
