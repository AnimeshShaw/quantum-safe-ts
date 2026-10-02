//! Key serialization, matching `quantum_safe.types.keys` byte for byte:
//! CBOR (`{v, algo, ms, ktype, key}`), PEM (`QUANTUM SAFE PUBLIC/SECRET KEY` with `qs-*`
//! headers around base64 CBOR), public-key JWK (`kty: "AKP"`), SHA-256 fingerprints, and
//! the `KeyPair` CBOR bundle.
//!
//! Hardening carried over from quantum-safe-py: payloads over 10 MB are refused before
//! parsing, key versions below 1 are rejected as rollback attempts, versions above the
//! supported maximum are reported as incompatible, and a secret key is never emitted as JWK.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const CURRENT_KEY_VERSION: i64 = 1;
pub const MAX_SUPPORTED_KEY_VERSION: i64 = 1;
/// Mirrors `_MAX_PAYLOAD_BYTES` in quantum-safe-py's serialization layer.
pub const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

const PEM_PUBLIC_LABEL: &str = "QUANTUM SAFE PUBLIC KEY";
const PEM_SECRET_LABEL: &str = "QUANTUM SAFE SECRET KEY";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("payload of {0} bytes exceeds the {MAX_PAYLOAD_BYTES}-byte limit")]
    TooLarge(usize),
    #[error("{format} parse error: {reason}")]
    Parse { format: &'static str, reason: String },
    #[error("invalid key version {0}: minimum is 1")]
    VersionRollback(i64),
    #[error("key version {found} is newer than the maximum supported version {max}")]
    IncompatibleVersion { found: i64, max: i64 },
    #[error("data contains a {found} key, but a {expected} key was expected")]
    WrongKeyType {
        expected: &'static str,
        found: &'static str,
    },
    #[error("secret keys are never serialized as JWK")]
    JwkSecretForbidden,
}

fn parse_err(format: &'static str, reason: impl Into<String>) -> KeyError {
    KeyError::Parse {
        format,
        reason: reason.into(),
    }
}

/// Mirrors `quantum_safe.types.keys.MigrationState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationState {
    ClassicalOnly,
    HybridTransition,
    PqcPreferred,
    PqcOnly,
}

impl MigrationState {
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationState::ClassicalOnly => "classical_only",
            MigrationState::HybridTransition => "hybrid_transition",
            MigrationState::PqcPreferred => "pqc_preferred",
            MigrationState::PqcOnly => "pqc_only",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "classical_only" => Some(Self::ClassicalOnly),
            "hybrid_transition" => Some(Self::HybridTransition),
            "pqc_preferred" => Some(Self::PqcPreferred),
            "pqc_only" => Some(Self::PqcOnly),
            _ => None,
        }
    }
    /// quantum-safe-py silently falls back to `hybrid_transition` for unknown values.
    fn parse_lenient(s: Option<&str>) -> Self {
        s.and_then(Self::parse).unwrap_or(Self::HybridTransition)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Public,
    Secret,
}

impl KeyType {
    fn tag(self) -> &'static str {
        match self {
            KeyType::Public => "pub",
            KeyType::Secret => "sec",
        }
    }
    fn word(self) -> &'static str {
        match self {
            KeyType::Public => "public",
            KeyType::Secret => "secret",
        }
    }
}

/// A key plus the metadata quantum-safe-py serializes with it.
#[derive(Clone)]
pub struct EncodedKey {
    pub algorithm: String,
    pub migration_state: MigrationState,
    pub key_type: KeyType,
    pub raw: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EncodedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.key_type {
            KeyType::Public => write!(f, "EncodedKey(public, {}, {} B)", self.algorithm, self.raw.len()),
            KeyType::Secret => write!(f, "EncodedKey(secret, {}, <redacted>)", self.algorithm),
        }
    }
}

fn cbor_to_vec(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

fn cbor_from_slice(data: &[u8], format: &'static str) -> Result<Value, KeyError> {
    if data.len() > MAX_PAYLOAD_BYTES {
        return Err(KeyError::TooLarge(data.len()));
    }
    crate::cbor_guard::validate_shape(data).map_err(|e| parse_err(format, e))?;
    ciborium::from_reader(data).map_err(|e| parse_err(format, format!("CBOR decode failed: {e}")))
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

/// Exact length of a public key for the algorithms this library implements (`None` for names it does not know).
/// Used to refuse a "public key" that is really a secret key (or anything else of the wrong size).
pub fn expected_public_len(algorithm: &str) -> Option<usize> {
    use crate::{sig, suite};
    if let Some(kem) = suite::KemSuite::parse(algorithm) {
        return Some(match kem {
            suite::KemSuite::Pure(p) => p.sizes().0,
            suite::KemSuite::Hybrid(c, p) => 2 + c.public_len() + p.sizes().0,
            suite::KemSuite::XWing => 1216,
        });
    }
    sig::SigSuite::parse(algorithm).map(|s| match s {
        sig::SigSuite::MlDsa(l) => l.sizes().0,
        sig::SigSuite::Slh(p) => p.sizes().0,
        sig::SigSuite::Hybrid(c, l) => {
            2 + match c {
                sig::ClassicalSig::Ed25519 => 32,
                sig::ClassicalSig::P256 => 64,
            } + l.sizes().0
        }
    })
}

/// Errors unless `raw` has the exact public-key length for a known `algorithm`.
pub fn check_public_len(algorithm: &str, raw: &[u8]) -> Result<(), KeyError> {
    match expected_public_len(algorithm) {
        Some(n) if raw.len() != n => Err(parse_err(
            "key",
            format!("a {algorithm} public key is {n} bytes, got {}", raw.len()),
        )),
        _ => Ok(()),
    }
}

impl EncodedKey {
    pub fn new(
        algorithm: impl Into<String>,
        key_type: KeyType,
        raw: Vec<u8>,
        migration_state: MigrationState,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            migration_state,
            key_type,
            raw: Zeroizing::new(raw),
        }
    }

    /// `sha256(algorithm_ascii || 0x00 || raw)` as lowercase hex (quantum-safe-py `fingerprint()`).
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.algorithm.as_bytes());
        h.update([0u8]);
        h.update(&*self.raw);
        hex_lower(&h.finalize())
    }

    /// Colon-separated variant: `aa:bb:cc:...`.
    pub fn fingerprint_colon(&self) -> String {
        let fp = self.fingerprint();
        fp.as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":")
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Text("v".into()),
                Value::Integer(CURRENT_KEY_VERSION.into()),
            ),
            (Value::Text("algo".into()), Value::Text(self.algorithm.clone())),
            (
                Value::Text("ms".into()),
                Value::Text(self.migration_state.as_str().into()),
            ),
            (
                Value::Text("ktype".into()),
                Value::Text(self.key_type.tag().into()),
            ),
            (Value::Text("key".into()), Value::Bytes(self.raw.to_vec())),
        ])
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        cbor_to_vec(&self.to_value())
    }

    fn from_value(value: &Value, expected: KeyType, format: &'static str) -> Result<Self, KeyError> {
        let Value::Map(entries) = value else {
            return Err(parse_err(format, "top-level CBOR value is not a map"));
        };
        let version: i64 = match map_get(entries, "v") {
            Some(Value::Integer(i)) => (*i)
                .try_into()
                .map_err(|_| parse_err(format, "missing or non-integer 'v' field"))?,
            _ => return Err(parse_err(format, "missing or non-integer 'v' field")),
        };
        if version < 1 {
            return Err(KeyError::VersionRollback(version));
        }
        if version > MAX_SUPPORTED_KEY_VERSION {
            return Err(KeyError::IncompatibleVersion {
                found: version,
                max: MAX_SUPPORTED_KEY_VERSION,
            });
        }
        let algorithm = match map_get(entries, "algo") {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(parse_err(format, "missing 'algo' field")),
        };
        let raw = match map_get(entries, "key") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => return Err(parse_err(format, "missing 'key' field")),
        };
        if raw.is_empty() {
            return Err(parse_err(format, "raw key bytes cannot be empty"));
        }
        // Fail closed: the key type must be present and must match. (quantum-safe-py always writes it; accepting an absent one would let
        // secret-key bytes be loaded as a "public" key and then exported.)
        let found = match map_get(entries, "ktype") {
            Some(Value::Text(kt)) if kt == "pub" => KeyType::Public,
            Some(Value::Text(kt)) if kt == "sec" => KeyType::Secret,
            _ => return Err(parse_err(format, "missing or unknown 'ktype' field")),
        };
        if found != expected {
            return Err(KeyError::WrongKeyType {
                expected: expected.word(),
                found: found.word(),
            });
        }
        if expected == KeyType::Public {
            check_public_len(&algorithm, &raw)?;
        }
        let ms = MigrationState::parse_lenient(match map_get(entries, "ms") {
            Some(Value::Text(t)) => Some(t.as_str()),
            _ => None,
        });
        Ok(Self::new(algorithm, expected, raw, ms))
    }

    pub fn from_cbor(data: &[u8], expected: KeyType) -> Result<Self, KeyError> {
        Self::from_value(&cbor_from_slice(data, "cbor")?, expected, "cbor")
    }

    /// PEM text: 64-column base64 of the key CBOR with `qs-version`, `qs-algo`,
    /// `qs-migration` headers (RFC 7468-style blank line before the body).
    pub fn to_pem(&self) -> String {
        let label = match self.key_type {
            KeyType::Public => PEM_PUBLIC_LABEL,
            KeyType::Secret => PEM_SECRET_LABEL,
        };
        let b64 = STANDARD.encode(self.to_cbor());
        let wrapped = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "-----BEGIN {label}-----\nqs-version: {CURRENT_KEY_VERSION}\nqs-algo: {}\nqs-migration: {}\n\n{wrapped}\n-----END {label}-----\n",
            self.algorithm,
            self.migration_state.as_str()
        )
    }

    pub fn from_pem(pem: &str, expected: KeyType) -> Result<Self, KeyError> {
        if pem.len() > MAX_PAYLOAD_BYTES * 2 {
            return Err(KeyError::TooLarge(pem.len()));
        }
        let trimmed = pem.trim();
        let lines: Vec<&str> = trimmed.lines().collect();
        let (first, last) = match (lines.first(), lines.last()) {
            (Some(f), Some(l)) if lines.len() >= 2 => (*f, *l),
            _ => return Err(parse_err("pem", "missing BEGIN/END markers")),
        };
        if !first.starts_with("-----BEGIN") || !last.starts_with("-----END") {
            return Err(parse_err("pem", "missing BEGIN/END markers"));
        }
        // Label sanity check, as in quantum-safe-py (first line must not name the other type).
        let (other_label, other) = match expected {
            KeyType::Public => (PEM_SECRET_LABEL, KeyType::Secret),
            KeyType::Secret => (PEM_PUBLIC_LABEL, KeyType::Public),
        };
        if first.contains(other_label) {
            return Err(KeyError::WrongKeyType {
                expected: expected.word(),
                found: other.word(),
            });
        }
        let mut in_body = false;
        let mut body = String::new();
        for line in &lines[1..lines.len() - 1] {
            if in_body {
                body.push_str(line);
            } else if line.is_empty() {
                in_body = true;
            }
        }
        if body.is_empty() {
            return Err(parse_err("pem", "empty key body"));
        }
        let cbor = STANDARD
            .decode(body.as_bytes())
            .map_err(|e| parse_err("pem", format!("base64 decode failed: {e}")))?;
        let value = cbor_from_slice(&cbor, "pem")?;
        Self::from_value(&value, expected, "pem")
    }

    /// Public-key JWK as a JSON string (`kty: "AKP"`). Secret keys are refused.
    pub fn to_jwk(&self) -> Result<String, KeyError> {
        if self.key_type == KeyType::Secret {
            return Err(KeyError::JwkSecretForbidden);
        }
        let jwk = serde_json::json!({
            "kty": "AKP",
            "alg": self.algorithm,
            "pub": URL_SAFE_NO_PAD.encode(&*self.raw),
            "qs-version": CURRENT_KEY_VERSION,
            "qs-migration": self.migration_state.as_str(),
            "key_ops": ["encapsulate", "verify"],
        });
        Ok(jwk.to_string())
    }

    pub fn from_jwk(json: &str) -> Result<Self, KeyError> {
        if json.len() > MAX_PAYLOAD_BYTES {
            return Err(KeyError::TooLarge(json.len()));
        }
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|e| parse_err("jwk", format!("invalid JSON: {e}")))?;
        if v.get("kty").and_then(|x| x.as_str()) != Some("AKP") {
            return Err(parse_err("jwk", "'kty' must be \"AKP\""));
        }
        let pub_b64 = v
            .get("pub")
            .and_then(|x| x.as_str())
            .ok_or_else(|| parse_err("jwk", "missing 'pub' field"))?;
        let alg = v
            .get("alg")
            .and_then(|x| x.as_str())
            .ok_or_else(|| parse_err("jwk", "missing 'alg' field"))?;
        // py restores padding then urlsafe-decodes; accept padded or unpadded input.
        let raw = URL_SAFE_NO_PAD
            .decode(pub_b64.trim_end_matches('='))
            .map_err(|e| parse_err("jwk", format!("base64url decode failed: {e}")))?;
        if raw.is_empty() {
            return Err(parse_err("jwk", "raw key bytes cannot be empty"));
        }
        check_public_len(alg, &raw)?;
        let ms = MigrationState::parse_lenient(v.get("qs-migration").and_then(|x| x.as_str()));
        Ok(Self::new(alg, KeyType::Public, raw, ms))
    }
}

/// `KeyPair.to_cbor_bundle()`: `{v, bundle: "keypair", pub: {...}, sec: {...}}`.
pub fn keypair_to_bundle(public: &EncodedKey, secret: &EncodedKey) -> Result<Vec<u8>, KeyError> {
    if public.algorithm != secret.algorithm {
        return Err(parse_err("cbor", "public and secret key algorithms differ"));
    }
    Ok(cbor_to_vec(&Value::Map(vec![
        (
            Value::Text("v".into()),
            Value::Integer(CURRENT_KEY_VERSION.into()),
        ),
        (Value::Text("bundle".into()), Value::Text("keypair".into())),
        (Value::Text("pub".into()), public.to_value()),
        (Value::Text("sec".into()), secret.to_value()),
    ])))
}

pub fn keypair_from_bundle(data: &[u8]) -> Result<(EncodedKey, EncodedKey), KeyError> {
    let Value::Map(entries) = cbor_from_slice(data, "cbor")? else {
        return Err(parse_err("cbor", "bundle is not a map"));
    };
    match map_get(&entries, "bundle") {
        Some(Value::Text(t)) if t == "keypair" => {}
        _ => return Err(parse_err("cbor", "not a keypair bundle")),
    }
    let public = EncodedKey::from_value(
        map_get(&entries, "pub").ok_or_else(|| parse_err("cbor", "missing 'pub'"))?,
        KeyType::Public,
        "cbor",
    )?;
    let secret = EncodedKey::from_value(
        map_get(&entries, "sec").ok_or_else(|| parse_err("cbor", "missing 'sec'"))?,
        KeyType::Secret,
        "cbor",
    )?;
    if public.algorithm != secret.algorithm {
        return Err(parse_err("cbor", "public and secret key algorithms differ"));
    }
    Ok((public, secret))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kt: KeyType) -> EncodedKey {
        EncodedKey::new(
            "X25519+ML-KEM-768",
            kt,
            (0..=255u8).cycle().take(1218).collect(),
            MigrationState::HybridTransition,
        )
    }

    #[test]
    fn cbor_roundtrip() {
        let k = sample(KeyType::Public);
        let back = EncodedKey::from_cbor(&k.to_cbor(), KeyType::Public).unwrap();
        assert_eq!(back.algorithm, k.algorithm);
        assert_eq!(*back.raw, *k.raw);
        assert_eq!(back.migration_state, k.migration_state);
    }

    #[test]
    fn pem_roundtrip_and_shape() {
        let k = sample(KeyType::Secret);
        let pem = k.to_pem();
        assert!(pem.starts_with("-----BEGIN QUANTUM SAFE SECRET KEY-----\nqs-version: 1\nqs-algo: X25519+ML-KEM-768\nqs-migration: hybrid_transition\n\n"));
        assert!(pem.ends_with("-----END QUANTUM SAFE SECRET KEY-----\n"));
        assert!(pem
            .lines()
            .all(|l| l.len() <= 64 || l.starts_with("-----") || l.starts_with("qs-")));
        let back = EncodedKey::from_pem(&pem, KeyType::Secret).unwrap();
        assert_eq!(*back.raw, *k.raw);
    }

    #[test]
    fn key_type_confusion_is_rejected() {
        let public = sample(KeyType::Public);
        let secret = sample(KeyType::Secret);
        assert!(matches!(
            EncodedKey::from_cbor(&secret.to_cbor(), KeyType::Public),
            Err(KeyError::WrongKeyType { .. })
        ));
        assert!(matches!(
            EncodedKey::from_cbor(&public.to_cbor(), KeyType::Secret),
            Err(KeyError::WrongKeyType { .. })
        ));
        assert!(matches!(
            EncodedKey::from_pem(&secret.to_pem(), KeyType::Public),
            Err(KeyError::WrongKeyType { .. })
        ));
        assert!(matches!(
            EncodedKey::from_pem(&public.to_pem(), KeyType::Secret),
            Err(KeyError::WrongKeyType { .. })
        ));
    }

    #[test]
    fn jwk_roundtrip_public_only() {
        let public = sample(KeyType::Public);
        let jwk = public.to_jwk().unwrap();
        let v: serde_json::Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(v["kty"], "AKP");
        assert_eq!(v["alg"], "X25519+ML-KEM-768");
        assert_eq!(v["key_ops"], serde_json::json!(["encapsulate", "verify"]));
        assert_eq!(*EncodedKey::from_jwk(&jwk).unwrap().raw, *public.raw);
        assert_eq!(
            sample(KeyType::Secret).to_jwk(),
            Err(KeyError::JwkSecretForbidden)
        );
    }

    #[test]
    fn version_rollback_and_future_versions_are_rejected() {
        let mk = |v: i64| {
            cbor_to_vec(&Value::Map(vec![
                (Value::Text("v".into()), Value::Integer(v.into())),
                (Value::Text("algo".into()), Value::Text("ML-KEM-768".into())),
                (Value::Text("ktype".into()), Value::Text("pub".into())),
                (Value::Text("key".into()), Value::Bytes(vec![1; 1184])),
            ]))
        };
        assert_eq!(
            EncodedKey::from_cbor(&mk(0), KeyType::Public).unwrap_err(),
            KeyError::VersionRollback(0)
        );
        assert_eq!(
            EncodedKey::from_cbor(&mk(-5), KeyType::Public).unwrap_err(),
            KeyError::VersionRollback(-5)
        );
        assert_eq!(
            EncodedKey::from_cbor(&mk(2), KeyType::Public).unwrap_err(),
            KeyError::IncompatibleVersion { found: 2, max: 1 }
        );
        assert!(EncodedKey::from_cbor(&mk(1), KeyType::Public).is_ok());
    }

    #[test]
    fn oversize_payload_is_refused_before_parsing() {
        let big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            EncodedKey::from_cbor(&big, KeyType::Public).unwrap_err(),
            KeyError::TooLarge(MAX_PAYLOAD_BYTES + 1)
        );
    }

    #[test]
    fn garbage_never_panics() {
        for data in [&b""[..], b"\xff", b"\xa1", b"not cbor at all", &[0x9f; 64]] {
            assert!(EncodedKey::from_cbor(data, KeyType::Public).is_err());
        }
        for pem in [
            "",
            "-----BEGIN X-----",
            "x\ny",
            "-----BEGIN A-----\n\n-----END A-----",
        ] {
            assert!(EncodedKey::from_pem(pem, KeyType::Public).is_err());
        }
        assert!(EncodedKey::from_jwk("{").is_err());
        assert!(EncodedKey::from_jwk("{\"alg\":\"x\"}").is_err());
    }

    #[test]
    fn bundle_roundtrip() {
        let (p, s) = (sample(KeyType::Public), sample(KeyType::Secret));
        let (p2, s2) = keypair_from_bundle(&keypair_to_bundle(&p, &s).unwrap()).unwrap();
        assert_eq!(*p2.raw, *p.raw);
        assert_eq!(*s2.raw, *s.raw);
    }

    #[test]
    fn fingerprint_shape() {
        let fp = sample(KeyType::Public).fingerprint();
        assert_eq!(fp.len(), 64);
        let colon = sample(KeyType::Public).fingerprint_colon();
        assert_eq!(colon.len(), 64 + 31);
        assert_eq!(colon.replace(':', ""), fp);
    }
}
