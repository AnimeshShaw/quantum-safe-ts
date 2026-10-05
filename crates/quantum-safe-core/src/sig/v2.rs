//! Signature format v2 (`<suite>-v2`). quantum-safe-py (0.3.2 or later) reads and writes it too; versions before that fail closed on the identifier. It never touches the py v1 wire formats.
//!
//! It fixes the structural problems of the quantum-safe-py construction (kept unchanged under its own identifiers):
//! - no random prefix and no prefix length in the blob, so there is no message/prefix boundary for anyone to move;
//! - the ML-DSA half is FIPS 204 `ML-DSA.Sign` with a non-empty native context ([`LABEL`]) over the wrapped message `M2`, so a standard FIPS 204
//!   library can verify it only by rebuilding `M2` and passing `LABEL` (it is not a standard signature over the caller's message);
//! - the algorithm identifier and the caller's context are inside the signed bytes (`M2`), and both halves of a hybrid sign the same `M2`;
//! - the signature blob has one fixed-length encoding (no CBOR wrapper around the halves, raw low-S P-256). The `SignedMessage` container around it is
//!   the same CBOR container as in v1 and is NOT canonical (extra keys, order, and the `fp`/`ts`/`hybrid` metadata are not authenticated), so do not
//!   use the hash of a container as an identity; the blob and the verified message are not malleable;
//! - keys carry the `-v2` tag. The tag is advisory metadata, not a technical barrier: v1 and v2 keys have identical bytes. **Never use the same key
//!   material in both formats.** The ML-DSA halves are domain-separated by FIPS 204's context anyway (empty in v1, `LABEL` here), but the classical
//!   halves are not (their inputs are different byte strings, and a v1 signing oracle that signs attacker-chosen contexts could be made to emit a v2 half).
//!
//! `M2 = u8(len(algo)) || algo || u8(len(ctx)) || ctx || message`, where `algo` is the full v2 identifier (for example `ML-DSA-65-v2`).
//! ML-DSA signs `M2` with FIPS 204 context [`LABEL`]. The classical half signs `LABEL || 0x00 || M2` (Ed25519, or ECDSA P-256 with SHA-256,
//! raw `r || s`, low-S only). A hybrid signature is `classical signature || ML-DSA signature`, both of fixed length. ML-DSA signing is always
//! hedged (32 fresh random bytes inside ML-DSA, per FIPS 204).

use super::*;

pub const SUFFIX: &str = "-v2";
pub const LABEL: &[u8] = b"quantum-safe-sig-v2";

/// `Some(base suite name)` when `algorithm` is a supported v2 identifier (ML-DSA and the approved hybrids; SLH-DSA has no v2).
pub fn base_of(algorithm: &str) -> Option<&str> {
    let base = algorithm.strip_suffix(SUFFIX)?;
    match SigSuite::parse(base)? {
        SigSuite::MlDsa(_) | SigSuite::Hybrid(..) => Some(base),
        SigSuite::Slh(_) => None,
    }
}

/// Every supported v2 identifier.
pub fn all() -> Vec<String> {
    SigSuite::all()
        .into_iter()
        .filter(|s| !matches!(s, SigSuite::Slh(_)))
        .map(|s| format!("{}{SUFFIX}", s.name()))
        .collect()
}

/// `M2`: the bytes both halves sign (the classical half adds a label in front).
pub(crate) fn signed_input(algorithm: &str, context: &[u8], message: &[u8]) -> Vec<u8> {
    debug_assert!(
        algorithm.len() <= 255 && context.len() <= 255,
        "the one-byte length prefixes would truncate"
    );
    let mut v = Vec::with_capacity(2 + algorithm.len() + context.len() + message.len());
    v.push(algorithm.len() as u8);
    v.extend_from_slice(algorithm.as_bytes());
    v.push(context.len() as u8);
    v.extend_from_slice(context);
    v.extend_from_slice(message);
    v
}

fn classical_input(m2: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(LABEL.len() + 1 + m2.len());
    v.extend_from_slice(LABEL);
    v.push(0);
    v.extend_from_slice(m2);
    v
}

fn classical_sign_v2(c: ClassicalSig, sk: &[u8], input: &[u8]) -> Result<Vec<u8>, SigError> {
    match c {
        ClassicalSig::Ed25519 => classical_sign(c, sk, input),
        ClassicalSig::P256 => {
            let pem = std::str::from_utf8(sk).map_err(|_| SigError::MalformedKey)?;
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| SigError::MalformedKey)?;
            let sig: p256::ecdsa::Signature = key.try_sign(input).map_err(|_| SigError::SigningFailed)?;
            Ok(sig.normalize_s().to_bytes().to_vec()) // raw r || s, low-S
        }
    }
}

fn classical_verify_v2(c: ClassicalSig, pk: &[u8], input: &[u8], sig: &[u8]) -> Result<bool, SigError> {
    match c {
        ClassicalSig::Ed25519 => classical_verify(c, pk, input, sig),
        ClassicalSig::P256 => {
            if pk.len() != 64 {
                return Err(SigError::MalformedKey);
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(pk);
            let vk =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| SigError::MalformedKey)?;
            let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
                return Ok(false);
            };
            if sig.normalize_s() != sig {
                return Ok(false); // the high-S twin is a second valid encoding of the same signature: refuse it
            }
            Ok(vk.verify(input, &sig).is_ok())
        }
    }
}

/// Both classical signature encodings used here are 64 bytes (Ed25519, raw P-256 `r || s`).
const CLASSICAL_SIG_LEN: usize = 64;

pub fn generate_keypair(algorithm: &str) -> Result<SigKeyPair, SigError> {
    let base = base_of(algorithm).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))?;
    // The same key material as the base suite, tagged `<base>-v2`.
    let mut kp = super::generate_keypair(base)?;
    kp.public.algorithm = algorithm.to_string();
    kp.secret.algorithm = algorithm.to_string();
    Ok(kp)
}

pub fn sign(
    secret: &SecretKey,
    message: &[u8],
    context: &[u8],
    opts: &SignOptions,
) -> Result<SignedMessage, SigError> {
    let algorithm = secret.algorithm.as_str();
    let base = base_of(algorithm).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))?;
    let suite = SigSuite::parse(base).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))?;
    if context.len() > MAX_CONTEXT_LEN {
        return Err(SigError::ContextTooLong(context.len()));
    }
    if message.is_empty() {
        return Err(SigError::EmptyMessage);
    }
    let m2 = signed_input(algorithm, context, message);
    let blob = match suite {
        SigSuite::MlDsa(l) => mldsa_sign_ctx(l, &secret.raw, &m2, LABEL)?,
        SigSuite::Hybrid(c, l) => {
            let (c_sec, p_sec) = unpack_components(&secret.raw).map_err(|_| SigError::MalformedKey)?;
            let mut blob = classical_sign_v2(c, c_sec, &classical_input(&m2))?;
            blob.extend_from_slice(&mldsa_sign_ctx(l, p_sec, &m2, LABEL)?);
            blob
        }
        SigSuite::Slh(_) => return Err(SigError::UnsupportedAlgorithm(algorithm.to_string())),
    };
    Ok(SignedMessage {
        message: message.to_vec(),
        signature: blob,
        algorithm: algorithm.to_string(),
        context: context.to_vec(),
        signer_fingerprint: opts.signer_fingerprint.clone(),
        signed_at: opts.signed_at,
        is_hybrid: suite.is_hybrid(),
    })
}

/// Failures of the signature collapse to `VerificationFailed`; an unusable public key is `MalformedKey`.
pub fn verify_parts(
    algorithm: &str,
    message: &[u8],
    blob: &[u8],
    context: &[u8],
    public: &PublicKey,
) -> Result<(), SigError> {
    let base = base_of(algorithm).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))?;
    let suite = SigSuite::parse(base).ok_or_else(|| SigError::UnsupportedAlgorithm(algorithm.to_string()))?;
    if public.algorithm != algorithm {
        return Err(SigError::AlgorithmMismatch);
    }
    if context.len() > MAX_CONTEXT_LEN || message.is_empty() {
        return Err(SigError::VerificationFailed);
    }
    let m2 = signed_input(algorithm, context, message);
    let ok = match suite {
        SigSuite::MlDsa(l) => mldsa_verify_ctx(l, &public.raw, &m2, LABEL, blob)?,
        SigSuite::Hybrid(c, l) => {
            let (c_pub, p_pub) = unpack_components(&public.raw).map_err(|_| SigError::MalformedKey)?;
            if blob.len() != CLASSICAL_SIG_LEN + l.sizes().2 {
                return Err(SigError::VerificationFailed);
            }
            let (c_sig, p_sig) = blob.split_at(CLASSICAL_SIG_LEN);
            // Both halves are always evaluated before they are combined.
            let classical_ok = classical_verify_v2(c, c_pub, &classical_input(&m2), c_sig);
            let pqc_ok = mldsa_verify_ctx(l, p_pub, &m2, LABEL, p_sig);
            let (classical_ok, pqc_ok) = (classical_ok?, pqc_ok?);
            classical_ok & pqc_ok
        }
        SigSuite::Slh(_) => return Err(SigError::UnsupportedAlgorithm(algorithm.to_string())),
    };
    if ok {
        Ok(())
    } else {
        Err(SigError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SignOptions {
        SignOptions {
            deterministic: false,
            signer_fingerprint: String::new(),
            signed_at: 0.0,
        }
    }

    #[test]
    fn identifiers() {
        assert_eq!(all().len(), 3 + 5);
        assert_eq!(base_of("ML-DSA-65-v2"), Some("ML-DSA-65"));
        assert_eq!(base_of("Ed25519+ML-DSA-87-v2"), Some("Ed25519+ML-DSA-87"));
        assert_eq!(base_of("SLH-DSA-SHAKE-128f-v2"), None);
        assert_eq!(base_of("ML-DSA-65"), None);
        assert_eq!(base_of("P-256+ML-DSA-87-v2"), None);
        assert_eq!(base_of("ML-DSA-65-v3"), None);
    }

    #[test]
    fn roundtrip_for_every_v2_suite_with_tamper_checks() {
        for name in all() {
            let kp = super::super::generate_keypair(&name).unwrap();
            assert_eq!(kp.public.algorithm, name);
            let sm = sign(&kp.secret, b"hello v2", b"ctx", &opts()).unwrap();
            // via the generic entry points
            super::super::verify(&sm, &kp.public).unwrap();
            assert!(
                super::super::verify_parts(&name, b"hello v2!", &sm.signature, b"ctx", &kp.public).is_err()
            );
            assert!(
                super::super::verify_parts(&name, b"hello v2", &sm.signature, b"other", &kp.public).is_err()
            );
            let mut bad = sm.signature.clone();
            let mid = bad.len() / 2;
            bad[mid] ^= 1;
            assert!(super::super::verify_parts(&name, b"hello v2", &bad, b"ctx", &kp.public).is_err());
            // a truncated or extended blob never verifies
            let mut longer = sm.signature.clone();
            longer.push(0);
            assert!(super::super::verify_parts(&name, b"hello v2", &longer, b"ctx", &kp.public).is_err());
            assert!(
                super::super::verify_parts(&name, b"hello v2", &sm.signature[1..], b"ctx", &kp.public)
                    .is_err()
            );
        }
    }

    #[test]
    fn no_prefix_boundary_to_move() {
        // The v1 forgery moved bytes from the message into the prefix. In v2 the blob has no prefix, so a suffix of the message must not verify.
        let kp = super::super::generate_keypair("Ed25519+ML-DSA-44-v2").unwrap();
        let sm = sign(&kp.secret, b"PAY alice 5\nPAY mallory 1000\n", b"", &opts()).unwrap();
        for k in 1..sm.message.len() {
            assert!(super::super::verify_parts(
                &sm.algorithm,
                &sm.message[k..],
                &sm.signature,
                b"",
                &kp.public
            )
            .is_err());
        }
    }

    #[test]
    fn v1_and_v2_tagged_keys_and_signatures_do_not_cross() {
        let v1 = super::super::generate_keypair("ML-DSA-44").unwrap();
        let v2 = super::super::generate_keypair("ML-DSA-44-v2").unwrap();
        // a v2 secret key cannot be used through the v1 dispatcher's key check, and vice versa
        let s1 = super::super::sign(&v1.secret, b"m", b"", &opts()).unwrap();
        assert_eq!(
            super::super::verify_parts("ML-DSA-44-v2", b"m", &s1.signature, b"", &v2.public),
            Err(SigError::VerificationFailed)
        );
        assert_eq!(
            super::super::verify_parts("ML-DSA-44-v2", b"m", &s1.signature, b"", &v1.public),
            Err(SigError::AlgorithmMismatch)
        );
        let s2 = sign(&v2.secret, b"m", b"", &opts()).unwrap();
        assert!(super::super::verify_parts("ML-DSA-44", b"m", &s2.signature, b"", &v1.public).is_err());
    }

    #[test]
    fn ml_dsa_half_is_plain_fips_204_with_the_label_as_context() {
        // Rebuild M2 and verify the signature with the standards-mode verifier (native FIPS 204 context = LABEL).
        let kp = super::super::generate_keypair("ML-DSA-65-v2").unwrap();
        let sm = sign(&kp.secret, b"interop", b"app-ctx", &opts()).unwrap();
        let m2 = signed_input("ML-DSA-65-v2", b"app-ctx", b"interop");
        assert!(
            super::super::standard::verify(MlDsaLevel::L65, &kp.public.raw, &m2, LABEL, &sm.signature)
                .unwrap()
        );
        assert!(
            !super::super::standard::verify(MlDsaLevel::L65, &kp.public.raw, &m2, b"", &sm.signature)
                .unwrap()
        );
    }

    #[test]
    fn p256_high_s_twin_is_rejected() {
        use p256::ecdsa::Signature;
        let kp = super::super::generate_keypair("P-256+ML-DSA-44-v2").unwrap();
        let sm = sign(&kp.secret, b"low-s only", b"", &opts()).unwrap();
        let (c_sig, p_sig) = sm.signature.split_at(CLASSICAL_SIG_LEN);
        let sig = Signature::from_slice(c_sig).unwrap();
        // build the high-S twin: s' = n - s
        let (r, s) = sig.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        assert_ne!(high, sig);
        let mut twin = high.to_bytes().to_vec();
        twin.extend_from_slice(p_sig);
        super::super::verify_parts(&sm.algorithm, b"low-s only", &sm.signature, b"", &kp.public).unwrap();
        assert!(super::super::verify_parts(&sm.algorithm, b"low-s only", &twin, b"", &kp.public).is_err());
    }
}
