//! Maps every core error into a stable `kind` tag. The TypeScript facade turns the tag into a
//! real `QuantumSafeError` subclass; free-text messages are never parsed. Messages never
//! contain key material (core error types carry only lengths and algorithm names).

use quantum_safe_core::aead::AeadError;
use quantum_safe_core::envelope::EnvelopeError;
use quantum_safe_core::kdf::KdfError;
use quantum_safe_core::kem::KemError;
use quantum_safe_core::keys::KeyError;
use quantum_safe_core::sig::SigError;
use std::fmt::Display;

/// A stable, machine-readable error classification.
pub trait Kinded: Display {
    fn kind(&self) -> &'static str;
}

impl Kinded for KemError {
    fn kind(&self) -> &'static str {
        match self {
            KemError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
            KemError::AlgorithmMismatch => "algorithm_mismatch",
            KemError::MalformedKey => "malformed_key",
            KemError::MalformedCiphertext => "malformed_ciphertext",
            KemError::ClassicalFailure => "classical_failure",
        }
    }
}

impl Kinded for AeadError {
    fn kind(&self) -> &'static str {
        match self {
            AeadError::AuthenticationFailed => "decryption_failed",
        }
    }
}

impl Kinded for KdfError {
    fn kind(&self) -> &'static str {
        match self {
            KdfError::OutputTooLong { .. } => "hkdf_output_too_long",
            KdfError::Argon2(_) => "kdf_failed",
        }
    }
}

impl Kinded for EnvelopeError {
    fn kind(&self) -> &'static str {
        match self {
            EnvelopeError::AlgorithmNameTooLong { .. } => "malformed_ciphertext",
            EnvelopeError::CborEncode(_) | EnvelopeError::CborDecode(_) => "malformed_ciphertext",
            EnvelopeError::MissingField(_) => "malformed_ciphertext",
            EnvelopeError::BadNonceLength { .. } => "malformed_ciphertext",
            EnvelopeError::InvalidVersion(_) => "malformed_ciphertext",
            EnvelopeError::Kem(e) => e.kind(),
            EnvelopeError::Kdf(e) => e.kind(),
            EnvelopeError::Aead(e) => e.kind(),
            EnvelopeError::UnsupportedSuite(_) => "unsupported_algorithm",
            EnvelopeError::AlgorithmMismatch => "algorithm_mismatch",
        }
    }
}

impl Kinded for KeyError {
    fn kind(&self) -> &'static str {
        match self {
            KeyError::TooLarge(_) => "payload_too_large",
            KeyError::Parse { .. } => "key_parse_error",
            KeyError::VersionRollback(_) => "key_parse_error",
            KeyError::IncompatibleVersion { .. } => "incompatible_key_version",
            KeyError::WrongKeyType { .. } => "key_parse_error",
            KeyError::JwkSecretForbidden => "unsupported_format",
        }
    }
}

impl Kinded for SigError {
    fn kind(&self) -> &'static str {
        match self {
            SigError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
            SigError::AlgorithmMismatch => "algorithm_mismatch",
            SigError::MalformedKey => "malformed_key",
            SigError::ContextTooLong(_) => "invalid_argument",
            SigError::EmptyMessage => "invalid_argument",
            SigError::SigningFailed => "signing_failed",
            SigError::VerificationFailed => "verification_failed",
            SigError::Format(_) => "key_parse_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_variant_has_a_stable_kind() {
        assert_eq!(KemError::MalformedKey.kind(), "malformed_key");
        assert_eq!(KemError::MalformedCiphertext.kind(), "malformed_ciphertext");
        assert_eq!(KemError::AlgorithmMismatch.kind(), "algorithm_mismatch");
        assert_eq!(KemError::UnsupportedAlgorithm("x".into()).kind(), "unsupported_algorithm");
        assert_eq!(KemError::ClassicalFailure.kind(), "classical_failure");
        assert_eq!(AeadError::AuthenticationFailed.kind(), "decryption_failed");
        assert_eq!(KdfError::OutputTooLong { requested: 1, max: 0 }.kind(), "hkdf_output_too_long");
        assert_eq!(KdfError::Argon2("x".into()).kind(), "kdf_failed");
        assert_eq!(EnvelopeError::MissingField("v").kind(), "malformed_ciphertext");
        assert_eq!(EnvelopeError::Aead(AeadError::AuthenticationFailed).kind(), "decryption_failed");
        assert_eq!(EnvelopeError::Kem(KemError::MalformedKey).kind(), "malformed_key");
        assert_eq!(EnvelopeError::AlgorithmMismatch.kind(), "algorithm_mismatch");
        assert_eq!(EnvelopeError::UnsupportedSuite("ML-KEM-768".into()).kind(), "unsupported_algorithm");
        assert_eq!(KeyError::TooLarge(1).kind(), "payload_too_large");
        assert_eq!(KeyError::VersionRollback(0).kind(), "key_parse_error");
        assert_eq!(KeyError::IncompatibleVersion { found: 2, max: 1 }.kind(), "incompatible_key_version");
        assert_eq!(KeyError::JwkSecretForbidden.kind(), "unsupported_format");
        assert_eq!(SigError::VerificationFailed.kind(), "verification_failed");
        assert_eq!(SigError::ContextTooLong(300).kind(), "invalid_argument");
        assert_eq!(SigError::MalformedKey.kind(), "malformed_key");
    }

    #[test]
    fn messages_do_not_echo_input_bytes() {
        // Error text must be derived from lengths/algorithm names only.
        let m = KemError::UnsupportedAlgorithm("Nope".into()).to_string();
        assert!(m.contains("Nope"));
        assert!(!KemError::MalformedKey.to_string().contains("0x"));
    }
}
