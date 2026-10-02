#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::{kem::HybridCiphertext, wire};

fuzz_target!(|data: &[u8]| {
    let _ = wire::unpack_components(data);
    let _ = HybridCiphertext::from_bytes(data);
});
