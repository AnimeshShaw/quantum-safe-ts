//! Deterministic mutation-fuzzing of every function that parses caller-controlled bytes.
//! The contract: **never panic** (a panic becomes a WASM trap and takes the host with it);
//! always return a typed error. These run on every `cargo test`; `fuzz/` holds the
//! coverage-guided cargo-fuzz targets for the same entry points (run in CI on Linux).

use quantum_safe_core::keys::{keypair_from_bundle, keypair_to_bundle, EncodedKey, KeyType, MigrationState};
use quantum_safe_core::sig::{self, SigSuite, SignOptions, SignedMessage};
use quantum_safe_core::suite::KemSuite;
use quantum_safe_core::{envelope, kem, wire};

/// xorshift64*: tiny, deterministic, good enough to drive mutation.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
    /// Mutates a valid buffer: bit flips, truncation, extension, byte splices, zeroing.
    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        for _ in 0..1 + self.below(4) {
            match self.below(7) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] ^= 1 << self.below(8);
                }
                1 if !v.is_empty() => {
                    let n = self.below(v.len());
                    v.truncate(n);
                }
                2 => {
                    let extra = self.below(64);
                    v.extend(self.bytes(extra));
                }
                3 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = self.next() as u8;
                }
                4 if v.len() > 2 => {
                    let i = self.below(v.len() - 1);
                    let j = self.below(v.len() - 1);
                    v.swap(i, j);
                }
                5 if !v.is_empty() => {
                    let i = self.below(v.len());
                    let n = self.below(v.len() - i).min(32);
                    v[i..i + n].fill(0);
                }
                _ => {
                    let i = self.below(v.len() + 1);
                    let b = self.next() as u8;
                    v.insert(i, b);
                }
            }
        }
        v
    }
}

const ITERS: usize = 400;

#[test]
fn random_bytes_never_panic_any_parser() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let kp = kem::generate_keypair();
    for _ in 0..ITERS * 5 {
        let len = rng.below(1500);
        let data = rng.bytes(len);
        let _ = wire::unpack_components(&data);
        let _ = kem::HybridCiphertext::from_bytes(&data);
        let _ = envelope::SealedMessage::from_cbor(&data);
        let _ = SignedMessage::from_cbor(&data);
        let _ = EncodedKey::from_cbor(&data, KeyType::Public);
        let _ = EncodedKey::from_cbor(&data, KeyType::Secret);
        let _ = keypair_from_bundle(&data);
        let _ = kem::decapsulate(&kp.secret, &data);
        if let Ok(text) = std::str::from_utf8(&data) {
            let _ = EncodedKey::from_pem(text, KeyType::Public);
            let _ = EncodedKey::from_jwk(text);
        }
    }
}

#[test]
fn mutated_kem_inputs_never_panic_for_every_suite() {
    let mut rng = Rng(0xA5A5_1234_5678_9ABC);
    for suite in KemSuite::all() {
        let name = suite.name();
        let kp = kem::generate_keypair_for(&name).unwrap();
        let (ct, _) = kem::encapsulate(&kp.public).unwrap();
        for _ in 0..ITERS / 4 {
            let bad_ct = rng.mutate(&ct);
            let _ = kem::decapsulate(&kp.secret, &bad_ct);
            let bad_pub = kem::PublicKey {
                raw: rng.mutate(&kp.public.raw),
                algorithm: name.clone(),
            };
            let _ = kem::encapsulate(&bad_pub);
            let bad_sec = kem::SecretKey::new(rng.mutate(&kp.secret.raw), name.clone());
            let _ = kem::decapsulate(&bad_sec, &ct);
        }
    }
}

#[test]
fn mutated_envelopes_never_panic_and_never_open_wrongly() {
    let mut rng = Rng(0x0BAD_C0DE_F00D_FACE);
    let kp = kem::generate_keypair();
    let plaintext = b"integrity check plaintext".to_vec();
    let sealed = envelope::seal(&plaintext, &kp.public, b"aad")
        .unwrap()
        .to_cbor()
        .unwrap();
    for _ in 0..ITERS * 2 {
        let bad = rng.mutate(&sealed);
        if let Ok(msg) = envelope::SealedMessage::from_cbor(&bad) {
            if let Ok(opened) = envelope::open(&msg, &kp.secret) {
                // Only mutations that change no authenticated data may open, and must give the original.
                assert_eq!(
                    opened, plaintext,
                    "a mutated envelope opened to a different plaintext"
                );
            }
        }
    }
}

#[test]
fn mutated_keys_never_panic() {
    let mut rng = Rng(0x1357_9BDF_2468_ACE0);
    let public = EncodedKey::new(
        "X25519+ML-KEM-768",
        KeyType::Public,
        vec![7u8; 300],
        MigrationState::HybridTransition,
    );
    let secret = EncodedKey::new(
        "X25519+ML-KEM-768",
        KeyType::Secret,
        vec![9u8; 300],
        MigrationState::HybridTransition,
    );
    let cbor = public.to_cbor();
    let pem = public.to_pem().into_bytes();
    let jwk = public.to_jwk().unwrap().into_bytes();
    let bundle = keypair_to_bundle(&public, &secret).unwrap();
    for _ in 0..ITERS * 3 {
        let _ = EncodedKey::from_cbor(&rng.mutate(&cbor), KeyType::Public);
        let _ = keypair_from_bundle(&rng.mutate(&bundle));
        if let Ok(t) = String::from_utf8(rng.mutate(&pem)) {
            let _ = EncodedKey::from_pem(&t, KeyType::Public);
        }
        if let Ok(t) = String::from_utf8(rng.mutate(&jwk)) {
            let _ = EncodedKey::from_jwk(&t);
        }
    }
}

#[test]
fn mutated_signature_inputs_never_panic_for_every_fast_suite() {
    let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
    let opts = SignOptions {
        deterministic: false,
        signer_fingerprint: String::new(),
        signed_at: 1.0,
    };
    for suite in SigSuite::all() {
        if let SigSuite::Slh(p) = suite {
            if !matches!(p, sig::SlhParam::Shake128f | sig::SlhParam::Sha2_128f) {
                continue; // slow parameter sets add no new parsing code
            }
        }
        let name = suite.name();
        let kp = sig::generate_keypair(&name).unwrap();
        let sm = sig::sign(&kp.secret, b"message", b"ctx", &opts).unwrap();
        let iters = if matches!(suite, SigSuite::Slh(_)) {
            6
        } else {
            ITERS / 8
        };
        for _ in 0..iters {
            // Mutated signature blob / public key must fail closed.
            let mut bad = sm.clone();
            bad.signature = rng.mutate(&sm.signature);
            let _ = sig::verify(&bad, &kp.public);
            let bad_pub = kem::PublicKey {
                raw: rng.mutate(&kp.public.raw),
                algorithm: name.clone(),
            };
            let _ = sig::verify(&sm, &bad_pub);
            // Mutated secret keys (the ml-dsa expanded-key decoder can panic on malformed input).
            let bad_sec = kem::SecretKey::new(rng.mutate(&kp.secret.raw), name.clone());
            let _ = sig::sign(&bad_sec, b"m", b"", &opts);
            let _ = SignedMessage::from_cbor(&rng.mutate(&sm.to_cbor()));
        }
    }
}

#[test]
fn random_full_length_mldsa_secret_keys_never_panic() {
    // Fully random keys of exactly the right length hit the coefficient-range validation hardest.
    let mut rng = Rng(0xFEED_FACE_CAFE_BEEF);
    let opts = SignOptions::default();
    for level in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        let len = sig::MlDsaLevel::from_name(level).unwrap().sizes().1;
        for _ in 0..300 {
            let sk = kem::SecretKey::new(rng.bytes(len), level);
            let _ = sig::sign(&sk, b"m", b"", &opts);
        }
        // Keys whose s1/s2 region is within range but otherwise random.
        let kp = sig::generate_keypair(level).unwrap();
        for _ in 0..300 {
            let mut raw = kp.secret.raw.to_vec();
            for b in raw.iter_mut().skip(128).take(64) {
                *b = rng.next() as u8;
            }
            let _ = sig::sign(&kem::SecretKey::new(raw, level), b"m", b"", &opts);
        }
    }
}

#[test]
fn p256_pem_secret_keys_never_panic() {
    let mut rng = Rng(0x7777_8888_9999_AAAA);
    let kp = kem::generate_keypair_for("P-256+ML-KEM-512").unwrap();
    let (ct, _) = kem::encapsulate(&kp.public).unwrap();
    for _ in 0..ITERS {
        let bad = kem::SecretKey::new(rng.mutate(&kp.secret.raw), "P-256+ML-KEM-512");
        let _ = kem::decapsulate(&bad, &ct);
    }
}
