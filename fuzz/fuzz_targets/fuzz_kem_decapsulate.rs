#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::{kem, suite::KemSuite};
use std::sync::OnceLock;

static KEYS: OnceLock<Vec<kem::KeyPair>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let keys = KEYS.get_or_init(|| {
        KemSuite::all().into_iter().map(|s| kem::generate_keypair_for(&s.name()).unwrap()).collect()
    });
    // First byte selects the suite; the rest is the ciphertext. Also feed the rest as a public key.
    let Some((&sel, rest)) = data.split_first() else { return };
    let kp = &keys[sel as usize % keys.len()];
    let _ = kem::decapsulate(&kp.secret, rest);
    let _ = kem::encapsulate(&kem::PublicKey { raw: rest.to_vec(), algorithm: kp.public.algorithm.clone() });
});
