#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::kem::SecretKey;
use quantum_safe_core::sig::{self, SigSuite, SignOptions, SlhParam};

fuzz_target!(|data: &[u8]| {
    // Attacker-controlled secret-key bytes must never panic (ml-dsa's expanded-key decoder can).
    let Some((&sel, rest)) = data.split_first() else { return };
    let fast: Vec<SigSuite> = SigSuite::all()
        .into_iter()
        .filter(|s| !matches!(s, SigSuite::Slh(p) if !matches!(p, SlhParam::Shake128f)))
        .collect();
    let suite = fast[sel as usize % fast.len()];
    let _ = sig::sign(&SecretKey::new(rest.to_vec(), suite.name()), b"m", b"", &SignOptions::default());
});
