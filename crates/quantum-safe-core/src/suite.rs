//! Algorithm registry for key encapsulation, mirroring
//! `quantum_safe.kem.algorithms` in quantum-safe-py (names, sizes, NIST levels,
//! approved hybrid combinations) plus the TypeScript-only `X-Wing` suite.
//!
//! Identifiers are **wire-visible** (they are bound into the envelope AAD and the
//! hybrid combiner `info`), so they must never change meaning once released.

use std::fmt;

/// Post-quantum KEM parameter sets (FIPS 203).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pqc {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// Classical halves of a hybrid KEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Classical {
    X25519,
    P256,
}

/// A complete KEM suite as addressed by its canonical algorithm string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KemSuite {
    /// Pure ML-KEM, e.g. `"ML-KEM-768"` (quantum-safe-py `KEM`). Not recommended for new
    /// deployments during the transition period.
    Pure(Pqc),
    /// Hybrid classical + ML-KEM, e.g. `"X25519+ML-KEM-768"` (quantum-safe-py `HybridKEM`).
    Hybrid(Classical, Pqc),
    /// X-Wing (draft-connolly-cfrg-xwing-kem): ML-KEM-768 + X25519 with the X-Wing combiner.
    /// TypeScript-only; **not** readable by quantum-safe-py.
    XWing,
}

/// NIST PQC security category (FIPS 203 §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NistLevel(pub u8);

/// Default hybrid suite name (quantum-safe-py default).
pub const DEFAULT_KEM: &str = "X25519+ML-KEM-768";
/// CNSA 2.0 key-establishment hybrid suite (ML-KEM-1024).
pub const CNSA2_KEM: &str = "X25519+ML-KEM-1024";
pub const XWING_NAME: &str = "X-Wing";

impl Pqc {
    pub fn name(self) -> &'static str {
        match self {
            Pqc::MlKem512 => "ML-KEM-512",
            Pqc::MlKem768 => "ML-KEM-768",
            Pqc::MlKem1024 => "ML-KEM-1024",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "ML-KEM-512" => Some(Pqc::MlKem512),
            "ML-KEM-768" => Some(Pqc::MlKem768),
            "ML-KEM-1024" => Some(Pqc::MlKem1024),
            _ => None,
        }
    }
    /// (public key, expanded secret key, ciphertext) sizes in bytes (FIPS 203 Table 3).
    pub fn sizes(self) -> (usize, usize, usize) {
        match self {
            Pqc::MlKem512 => (800, 1632, 768),
            Pqc::MlKem768 => (1184, 2400, 1088),
            Pqc::MlKem1024 => (1568, 3168, 1568),
        }
    }
    pub fn nist_level(self) -> NistLevel {
        match self {
            Pqc::MlKem512 => NistLevel(1),
            Pqc::MlKem768 => NistLevel(3),
            Pqc::MlKem1024 => NistLevel(5),
        }
    }
}

impl Classical {
    pub fn name(self) -> &'static str {
        match self {
            Classical::X25519 => "X25519",
            Classical::P256 => "P-256",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "X25519" => Some(Classical::X25519),
            "P-256" => Some(Classical::P256),
            _ => None,
        }
    }
    /// Length of the classical public key and of the classical "ciphertext"
    /// (the sender's ephemeral public key).
    pub fn public_len(self) -> usize {
        match self {
            Classical::X25519 => 32,
            Classical::P256 => 65,
        }
    }
}

/// Approved classical/PQC pairings, mirroring `HYBRID_COMBINATIONS` in quantum-safe-py.
pub fn is_approved_hybrid(c: Classical, p: Pqc) -> bool {
    match c {
        Classical::X25519 => true,
        Classical::P256 => matches!(p, Pqc::MlKem512 | Pqc::MlKem768),
    }
}

impl KemSuite {
    /// Parse a canonical algorithm string. Returns `None` for anything unknown or for a
    /// hybrid pairing quantum-safe-py does not approve.
    pub fn parse(name: &str) -> Option<Self> {
        if name == XWING_NAME {
            return Some(KemSuite::XWing);
        }
        if let Some((c, p)) = name.split_once('+') {
            let (c, p) = (Classical::from_name(c)?, Pqc::from_name(p)?);
            return is_approved_hybrid(c, p).then_some(KemSuite::Hybrid(c, p));
        }
        Pqc::from_name(name).map(KemSuite::Pure)
    }

    /// Canonical algorithm string (wire-visible).
    pub fn name(self) -> String {
        match self {
            KemSuite::Pure(p) => p.name().to_string(),
            KemSuite::Hybrid(c, p) => format!("{}+{}", c.name(), p.name()),
            KemSuite::XWing => XWING_NAME.to_string(),
        }
    }

    pub fn is_hybrid(self) -> bool {
        !matches!(self, KemSuite::Pure(_))
    }

    /// NIST category of the post-quantum component (X-Wing is ML-KEM-768 based).
    pub fn nist_level(self) -> NistLevel {
        match self {
            KemSuite::Pure(p) | KemSuite::Hybrid(_, p) => p.nist_level(),
            KemSuite::XWing => Pqc::MlKem768.nist_level(),
        }
    }

    /// True if the suite meets the CNSA 2.0 key-establishment requirement (ML-KEM-1024).
    /// CNSA 2.0 itself mandates ML-KEM-1024; a hybrid still satisfies it when its PQC half
    /// is ML-KEM-1024. X-Wing (ML-KEM-768) does not.
    pub fn meets_cnsa2(self) -> bool {
        matches!(
            self,
            KemSuite::Pure(Pqc::MlKem1024) | KemSuite::Hybrid(_, Pqc::MlKem1024)
        )
    }

    /// All suites this library can instantiate, in a stable order.
    pub fn all() -> Vec<KemSuite> {
        let mut v = Vec::new();
        for p in [Pqc::MlKem512, Pqc::MlKem768, Pqc::MlKem1024] {
            v.push(KemSuite::Pure(p));
        }
        for c in [Classical::X25519, Classical::P256] {
            for p in [Pqc::MlKem512, Pqc::MlKem768, Pqc::MlKem1024] {
                if is_approved_hybrid(c, p) {
                    v.push(KemSuite::Hybrid(c, p));
                }
            }
        }
        v.push(KemSuite::XWing);
        v
    }
}

impl fmt::Display for KemSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_roundtrip_for_every_suite() {
        for s in KemSuite::all() {
            assert_eq!(KemSuite::parse(&s.name()), Some(s), "{s}");
        }
    }

    #[test]
    fn rejects_unapproved_and_unknown() {
        assert_eq!(KemSuite::parse("P-256+ML-KEM-1024"), None);
        assert_eq!(KemSuite::parse("RSA+ML-KEM-768"), None);
        assert_eq!(KemSuite::parse("ML-KEM-999"), None);
        assert_eq!(KemSuite::parse(""), None);
        assert_eq!(KemSuite::parse("X25519+ML-KEM-768+extra"), None);
    }

    #[test]
    fn cnsa2_classification() {
        assert!(KemSuite::parse("X25519+ML-KEM-1024").unwrap().meets_cnsa2());
        assert!(KemSuite::parse("ML-KEM-1024").unwrap().meets_cnsa2());
        assert!(!KemSuite::parse(DEFAULT_KEM).unwrap().meets_cnsa2());
        assert!(!KemSuite::XWing.meets_cnsa2());
    }

    #[test]
    fn suite_count_matches_quantum_safe_py_plus_xwing() {
        // 3 pure + 3 X25519 hybrids + 2 P-256 hybrids + X-Wing
        assert_eq!(KemSuite::all().len(), 9);
    }
}
