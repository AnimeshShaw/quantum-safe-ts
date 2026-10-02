#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::lms;

// LMS/HSS public keys and signatures are caller-controlled bytes: any split of the input must give a typed result, never a panic.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let cut = (data[0] as usize) % data.len();
    let (pk, sig) = data[1..].split_at(cut.min(data.len() - 1));
    let _ = lms::inspect_hss_public_key(pk);
    let _ = lms::verify_hss(pk, b"fuzz message", sig);
    let _ = lms::verify_hss(data, b"", data);
});
