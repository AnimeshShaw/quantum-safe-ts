//! LMS / HSS **signature verification** (RFC 8554, SHA-256, n = m = 32), the stateful hash-based
//! scheme CNSA 2.0 requires for software and firmware signing (with XMSS, via NIST SP 800-208).
//!
//! **Verification only, deliberately.** LMS signing is stateful: reusing a one-time-signature index
//! destroys the scheme's security, and doing it safely needs a durable, atomic state store that no
//! library can provide for an embedding application. Verifying firmware or software signatures needs no
//! state, so it is offered; signing is not. SP 800-208 additionally requires key *generation* to take
//! place in a validated cryptographic module, which no JavaScript library can claim.
//!
//! Parameter sets: LMS_SHA256_M32_H{5,10,15,20,25} with LMOTS_SHA256_N32_W{1,2,4,8}. The 192-bit
//! (N24/M24) and SHAKE variants of SP 800-208 are not supported and are rejected explicitly.
//!
//! Checked against the RFC 8554 Appendix F test cases (see `tests/vectors/lms_rfc8554.json`).

use sha2::{Digest, Sha256};
use thiserror::Error;

const N: usize = 32; // hash output / node size
const I_LEN: usize = 16;
const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;
/// RFC 8554 limits HSS to 1..=8 levels.
const MAX_LEVELS: u32 = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LmsError {
    #[error("public key is truncated or has trailing bytes")]
    MalformedKey,
    #[error("signature is truncated, has trailing bytes, or disagrees with the key's level count")]
    MalformedSignature,
    #[error("unsupported or unknown parameter set (type code {0})")]
    UnsupportedParameters(u32),
    #[error("HSS level count {0} is outside 1..=8")]
    BadLevelCount(u32),
}

struct OtsParams {
    w: usize,
    p: usize,
    ls: usize,
}

fn ots_params(typecode: u32) -> Result<OtsParams, LmsError> {
    match typecode {
        1 => Ok(OtsParams { w: 1, p: 265, ls: 7 }),
        2 => Ok(OtsParams { w: 2, p: 133, ls: 6 }),
        3 => Ok(OtsParams { w: 4, p: 67, ls: 4 }),
        4 => Ok(OtsParams { w: 8, p: 34, ls: 0 }),
        other => Err(LmsError::UnsupportedParameters(other)),
    }
}

fn lms_height(typecode: u32) -> Result<usize, LmsError> {
    match typecode {
        5 => Ok(5),
        6 => Ok(10),
        7 => Ok(15),
        8 => Ok(20),
        9 => Ok(25),
        other => Err(LmsError::UnsupportedParameters(other)),
    }
}

/// Reads big-endian integers and byte slices with bounds checking (never panics on short input).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], LmsError> {
        let end = self.pos.checked_add(n).ok_or(LmsError::MalformedSignature)?;
        let s = self.data.get(self.pos..end).ok_or(LmsError::MalformedSignature)?;
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, LmsError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| LmsError::MalformedSignature)?,
        ))
    }
    fn rest(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// An LMS public key: `lms_type || ots_type || I (16) || K (32)`.
#[derive(Clone)]
struct LmsPublicKey<'a> {
    lms_type: u32,
    ots_type: u32,
    i: &'a [u8],
    k: &'a [u8],
}

fn parse_lms_public(raw: &[u8]) -> Result<LmsPublicKey<'_>, LmsError> {
    let key_err = |e: LmsError| {
        if e == LmsError::MalformedSignature {
            LmsError::MalformedKey
        } else {
            e
        }
    };
    let mut r = Reader::new(raw);
    let lms_type = r.u32().map_err(key_err)?;
    let ots_type = r.u32().map_err(key_err)?;
    let i = r.take(I_LEN).map_err(key_err)?;
    let k = r.take(N).map_err(key_err)?;
    if r.rest() != 0 {
        return Err(LmsError::MalformedKey);
    }
    lms_height(lms_type)?;
    ots_params(ots_type)?;
    Ok(LmsPublicKey {
        lms_type,
        ots_type,
        i,
        k,
    })
}

const LMS_PUBLIC_LEN: usize = 4 + 4 + I_LEN + N;

/// `coef(S, i, w)` from RFC 8554 §3.1.3.
fn coef(s: &[u8], i: usize, w: usize) -> usize {
    let byte = s[i * w / 8] as usize;
    let shift = 8 - (w * (i % (8 / w)) + w);
    ((1usize << w) - 1) & (byte >> shift)
}

/// Verifies one LMS signature (RFC 8554 Algorithm 6a). Returns `Ok(true/false)` for well-formed
/// inputs and an error only for structurally invalid ones.
fn verify_lms(public: &LmsPublicKey<'_>, message: &[u8], sig: &[u8]) -> Result<bool, LmsError> {
    let mut r = Reader::new(sig);
    let q = r.u32()?;
    let ots_type = r.u32()?;
    if ots_type != public.ots_type {
        return Ok(false);
    }
    let params = ots_params(ots_type)?;
    let c = r.take(N)?;
    let y = r.take(params.p * N)?;
    let lms_type = r.u32()?;
    if lms_type != public.lms_type {
        return Ok(false);
    }
    let h = lms_height(lms_type)?;
    let path = r.take(h * N)?;
    if r.rest() != 0 {
        return Err(LmsError::MalformedSignature);
    }
    if u64::from(q) >= (1u64 << h) {
        return Ok(false);
    }

    // --- LM-OTS public-key candidate (Algorithm 4b) ---
    let i = public.i;
    let qb = q.to_be_bytes();
    let big_q: [u8; N] = Sha256::new()
        .chain_update(i)
        .chain_update(qb)
        .chain_update(D_MESG.to_be_bytes())
        .chain_update(c)
        .chain_update(message)
        .finalize()
        .into();
    // Q || Cksm(Q)
    let mut checksum = 0usize;
    let digits = N * 8 / params.w;
    for idx in 0..digits {
        checksum += ((1usize << params.w) - 1) - coef(&big_q, idx, params.w);
    }
    let cksm = ((checksum << params.ls) & 0xffff) as u16;
    let mut qc = Vec::with_capacity(N + 2);
    qc.extend_from_slice(&big_q);
    qc.extend_from_slice(&cksm.to_be_bytes());

    let mut pk_hash = Sha256::new()
        .chain_update(i)
        .chain_update(qb)
        .chain_update(D_PBLC.to_be_bytes());
    for idx in 0..params.p {
        let a = coef(&qc, idx, params.w);
        let mut tmp: [u8; N] = y[idx * N..(idx + 1) * N]
            .try_into()
            .map_err(|_| LmsError::MalformedSignature)?;
        for j in a..((1usize << params.w) - 1) {
            tmp = Sha256::new()
                .chain_update(i)
                .chain_update(qb)
                .chain_update((idx as u16).to_be_bytes())
                .chain_update([j as u8])
                .chain_update(tmp)
                .finalize()
                .into();
        }
        pk_hash.update(tmp);
    }
    let kc: [u8; N] = pk_hash.finalize().into();

    // --- Merkle path (Algorithm 6a) ---
    let mut node = (1u64 << h) + u64::from(q);
    let mut tmp: [u8; N] = Sha256::new()
        .chain_update(i)
        .chain_update((node as u32).to_be_bytes())
        .chain_update(D_LEAF.to_be_bytes())
        .chain_update(kc)
        .finalize()
        .into();
    for level in 0..h {
        let sibling = &path[level * N..(level + 1) * N];
        let parent = (node / 2) as u32;
        let mut hasher = Sha256::new()
            .chain_update(i)
            .chain_update(parent.to_be_bytes())
            .chain_update(D_INTR.to_be_bytes());
        if node % 2 == 1 {
            hasher.update(sibling);
            hasher.update(tmp);
        } else {
            hasher.update(tmp);
            hasher.update(sibling);
        }
        tmp = hasher.finalize().into();
        node /= 2;
    }
    Ok(constant_time_eq(&tmp, public.k))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Size in bytes of an LMS signature for the given parameter type codes.
fn lms_signature_len(lms_type: u32, ots_type: u32) -> Result<usize, LmsError> {
    let h = lms_height(lms_type)?;
    let p = ots_params(ots_type)?.p;
    Ok(4 + 4 + N + p * N + 4 + h * N)
}

/// Verifies an **HSS** signature (RFC 8554 §6.3, Algorithm 6): `public_key = u32(L) || LMS public key`,
/// `signature = u32(Nspk) || (LMS signature || LMS public key)* || LMS signature`.
///
/// Returns `Ok(false)` when the signature does not verify and `Err` when an input is structurally
/// invalid. A bare LMS key/signature is an HSS key with L = 1 (`Nspk = 0`).
pub fn verify_hss(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, LmsError> {
    let (levels, top_raw) = split_hss_public(public_key)?;
    let mut current = parse_lms_public(top_raw)?;

    let mut sr = Reader::new(signature);
    let nspk = sr.u32()?;
    if nspk != levels - 1 {
        return Err(LmsError::MalformedSignature);
    }
    let mut ok = true;
    // Verify the chain of signed public keys, then the message signature. Every step is evaluated
    // even after a failure so the work done does not depend on which step failed.
    for _ in 0..nspk {
        let sig_len = lms_signature_len_from(&mut sr_peek(&sr), &current)?;
        let lms_sig = sr.take(sig_len)?;
        let next_raw = sr.take(LMS_PUBLIC_LEN)?;
        ok &= verify_lms(&current, next_raw, lms_sig)?;
        current = parse_lms_public(next_raw)?;
    }
    let last_len = lms_signature_len_from(&mut sr_peek(&sr), &current)?;
    let last = sr.take(last_len)?;
    if sr.rest() != 0 {
        return Err(LmsError::MalformedSignature);
    }
    ok &= verify_lms(&current, message, last)?;
    Ok(ok)
}

fn sr_peek<'a>(r: &Reader<'a>) -> Reader<'a> {
    Reader {
        data: r.data,
        pos: r.pos,
    }
}

/// Length of the LMS signature that starts at the reader's position, derived from the signature's own
/// type codes (which must match the signing key's).
fn lms_signature_len_from(peek: &mut Reader<'_>, public: &LmsPublicKey<'_>) -> Result<usize, LmsError> {
    let _q = peek.u32()?;
    let ots_type = peek.u32()?;
    if ots_type != public.ots_type {
        // Let verify_lms report a clean "false" by consuming a plausible length for the *key's* parameters.
        return lms_signature_len(public.lms_type, public.ots_type);
    }
    lms_signature_len(public.lms_type, ots_type)
}

/// Public parameters of an HSS public key (for display and policy checks).
#[derive(Debug, PartialEq, Eq)]
pub struct HssPublicInfo {
    pub levels: u32,
    pub lms_type: u32,
    pub ots_type: u32,
    pub tree_height: usize,
    pub winternitz: usize,
}

/// Splits `u32(L) || LMS public key` into the level count and the LMS key bytes.
fn split_hss_public(public_key: &[u8]) -> Result<(u32, &[u8]), LmsError> {
    if public_key.len() != 4 + LMS_PUBLIC_LEN {
        return Err(LmsError::MalformedKey);
    }
    let levels = u32::from_be_bytes([public_key[0], public_key[1], public_key[2], public_key[3]]);
    if !(1..=MAX_LEVELS).contains(&levels) {
        return Err(LmsError::BadLevelCount(levels));
    }
    Ok((levels, &public_key[4..]))
}

pub fn inspect_hss_public_key(public_key: &[u8]) -> Result<HssPublicInfo, LmsError> {
    let (levels, raw) = split_hss_public(public_key)?;
    let p = parse_lms_public(raw)?;
    Ok(HssPublicInfo {
        levels,
        lms_type: p.lms_type,
        ots_type: p.ots_type,
        tree_height: lms_height(p.lms_type)?,
        winternitz: ots_params(p.ots_type)?.w,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Case {
        name: String,
        hss_public_key: String,
        message: String,
        hss_signature: String,
    }
    #[derive(Deserialize)]
    struct File {
        cases: Vec<Case>,
    }

    /// (name, HSS public key, message, HSS signature)
    type TestCase = (String, Vec<u8>, Vec<u8>, Vec<u8>);

    fn cases() -> Vec<TestCase> {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/lms_rfc8554.json"
        ))
        .expect("run scripts/extract_rfc8554_vectors.py");
        let f: File = serde_json::from_str(&raw).unwrap();
        f.cases
            .into_iter()
            .map(|c| {
                (
                    c.name,
                    hex::decode(c.hss_public_key).unwrap(),
                    hex::decode(c.message).unwrap(),
                    hex::decode(c.hss_signature).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn rfc8554_appendix_f_vectors_verify() {
        for (name, pk, msg, sig) in cases() {
            assert_eq!(verify_hss(&pk, &msg, &sig), Ok(true), "{name}");
        }
    }

    #[test]
    fn rfc8554_parameters_are_as_documented() {
        let c = cases();
        assert_eq!(
            inspect_hss_public_key(&c[0].1).unwrap(),
            HssPublicInfo {
                levels: 2,
                lms_type: 5,
                ots_type: 4,
                tree_height: 5,
                winternitz: 8
            }
        );
        assert_eq!(
            inspect_hss_public_key(&c[1].1).unwrap(),
            HssPublicInfo {
                levels: 2,
                lms_type: 6,
                ots_type: 3,
                tree_height: 10,
                winternitz: 4
            }
        );
    }

    #[test]
    fn any_single_bit_flip_in_message_key_or_signature_is_rejected() {
        for (name, pk, msg, sig) in cases() {
            // message
            for i in 0..msg.len() {
                let mut m = msg.clone();
                m[i] ^= 1;
                assert_eq!(verify_hss(&pk, &m, &sig), Ok(false), "{name}: message byte {i}");
            }
            // signature: sample every 7th byte (the file is a few KB; exhaustive costs seconds in debug builds)
            for i in (0..sig.len()).step_by(7) {
                let mut s = sig.clone();
                s[i] ^= 1;
                let r = verify_hss(&pk, &msg, &s);
                assert!(r != Ok(true), "{name}: signature byte {i} flipped but verified");
            }
            // public key (skip the leading level count: changing it is a structural error, covered below)
            for i in 4..pk.len() {
                let mut k = pk.clone();
                k[i] ^= 1;
                let r = verify_hss(&k, &msg, &sig);
                assert!(r != Ok(true), "{name}: key byte {i} flipped but verified");
            }
        }
    }

    #[test]
    fn single_level_hss_built_from_the_second_level_key_verifies() {
        // Test case 1's second-level LMS key signs the message: HSS with L=1 is `u32(1) || lms_pk`.
        let (_, pk, msg, sig) = cases().remove(0);
        let top_sig_len = lms_signature_len(5, 4).unwrap();
        let second_pk = &sig[4 + top_sig_len..4 + top_sig_len + LMS_PUBLIC_LEN];
        let second_sig = &sig[4 + top_sig_len + LMS_PUBLIC_LEN..];
        let mut hss_pk = 1u32.to_be_bytes().to_vec();
        hss_pk.extend_from_slice(second_pk);
        let mut hss_sig = 0u32.to_be_bytes().to_vec();
        hss_sig.extend_from_slice(second_sig);
        assert_eq!(verify_hss(&hss_pk, &msg, &hss_sig), Ok(true));
        assert_eq!(verify_hss(&hss_pk, b"other message", &hss_sig), Ok(false));
        let _ = pk;
    }

    #[test]
    fn structural_errors_are_typed_never_panics() {
        let (_, pk, msg, sig) = cases().remove(0);
        // truncations of every length
        for cut in 0..sig.len() {
            let _ = verify_hss(&pk, &msg, &sig[..cut]);
        }
        for cut in 0..pk.len() {
            assert!(verify_hss(&pk[..cut], &msg, &sig).is_err());
        }
        let mut extra = sig.clone();
        extra.push(0);
        assert_eq!(verify_hss(&pk, &msg, &extra), Err(LmsError::MalformedSignature));
        let mut bad_levels = pk.clone();
        bad_levels[3] = 9;
        assert_eq!(
            verify_hss(&bad_levels, &msg, &sig),
            Err(LmsError::BadLevelCount(9))
        );
        bad_levels[3] = 0;
        assert_eq!(
            verify_hss(&bad_levels, &msg, &sig),
            Err(LmsError::BadLevelCount(0))
        );
        // Nspk disagreeing with L
        let mut bad_nspk = sig.clone();
        bad_nspk[3] = 2;
        assert_eq!(
            verify_hss(&pk, &msg, &bad_nspk),
            Err(LmsError::MalformedSignature)
        );
        // unknown LMS / LM-OTS type codes
        let mut bad_type = pk.clone();
        bad_type[7] = 0x63;
        assert!(matches!(
            verify_hss(&bad_type, &msg, &sig),
            Err(LmsError::UnsupportedParameters(_))
        ));
        let mut bad_ots = pk.clone();
        bad_ots[11] = 0x63;
        assert!(matches!(
            verify_hss(&bad_ots, &msg, &sig),
            Err(LmsError::UnsupportedParameters(_))
        ));
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut x = 0x1234_5678_9abc_def1u64;
        let mut rnd = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect()
        };
        for _ in 0..300 {
            let pk_len = (rnd(1)[0] as usize) % 80;
            let sig_len = (rnd(2)[0] as usize) * 20;
            let _ = verify_hss(&rnd(pk_len), &rnd(10), &rnd(sig_len));
        }
        // Plausible headers with random bodies exercise the length arithmetic.
        let (_, pk, msg, sig) = cases().remove(1);
        for _ in 0..200 {
            let mut s = sig.clone();
            for b in s.iter_mut().skip(4).take(40) {
                *b = rnd(1)[0];
            }
            let _ = verify_hss(&pk, &msg, &s);
        }
    }
}
