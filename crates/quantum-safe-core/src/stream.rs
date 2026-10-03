//! Streaming envelope (format v3): authenticated public-key encryption of data that does not fit in memory, or arrives in pieces.
//! TypeScript-only; quantum-safe-py cannot read it. Experimental until reviewed.
//!
//! One KEM encapsulation per stream. The data is cut into chunks of a fixed size (the last chunk may be shorter or empty), and each chunk is
//! sealed with AES-256-GCM under a key derived from the KEM shared secret and the stream header. This is the STREAM construction (Hoang,
//! Reyhanitabar, Rogaway, Vizar 2015): the 96-bit nonce of chunk `i` is `prefix (7 random bytes) || i (u32, big endian) || last (1 byte, 0 or 1)`,
//! so chunks cannot be reordered, dropped from the middle, or duplicated, and truncating the stream fails because the final chunk present
//! was not sealed with `last = 1`.
//!
//! Header (CBOR map, exactly these five entries): `{"v": 3, "algo": <KEM suite>, "kct": <KEM ciphertext>, "np": <7-byte nonce prefix>, "cs": <chunk size>}`.
//! Key: `HKDF(shared secret, info = "qs-envelope-stream-v3" || 0x00 || H(header))`, with H and HKDF using SHA-256 for hybrid suites and SHA-384 for pure `ML-KEM-1024`
//! (the same suite rule as the single-message envelope). Every chunk's AAD is `u32(len(header)) || header || u32(len(caller aad)) || caller aad`.

use crate::aead::{self, AeadError};
use crate::cbor_guard;
use crate::kdf::{self, KdfError};
use crate::kem::{self, KemError};
use crate::suite::{KemSuite, Pqc};
use ciborium::value::Value;
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use zeroize::Zeroizing;

pub const STREAM_VERSION: u8 = 3;
pub const NONCE_PREFIX_LEN: usize = 7;
pub const TAG_LEN: usize = 16;
pub const MIN_CHUNK_SIZE: usize = 1024;
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
/// A header is a KEM ciphertext plus a few fixed fields; anything much larger is not a header.
pub const MAX_HEADER_LEN: usize = 64 * 1024;
const KEY_INFO: &[u8] = b"qs-envelope-stream-v3";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamError {
    #[error("stream header is malformed: {0}")]
    Header(&'static str),
    #[error(
        "stream suite '{0}' is not supported (hybrid suites (including X-Wing) and pure ML-KEM-1024 only)"
    )]
    UnsupportedSuite(String),
    #[error("stream algorithm does not match the secret key algorithm")]
    AlgorithmMismatch,
    #[error("chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes")]
    BadChunkSize,
    #[error("plaintext chunk has the wrong length: every chunk except the last must be exactly the chunk size, and none may exceed it")]
    BadPlaintextLength,
    #[error("encrypted chunk has the wrong length for its position in the stream")]
    BadChunkLength,
    #[error("stream is finished or has failed; no further chunks are accepted")]
    Finished,
    #[error("stream has too many chunks")]
    TooManyChunks,
    #[error("KEM operation failed: {0}")]
    Kem(#[from] KemError),
    #[error("key derivation failed: {0}")]
    Kdf(#[from] KdfError),
    #[error("chunk failed authentication: wrong key, wrong associated data, or a modified, reordered, dropped or truncated stream")]
    Authentication,
}

impl From<AeadError> for StreamError {
    fn from(_: AeadError) -> Self {
        StreamError::Authentication
    }
}

/// Which hash the key derivation uses for a suite, or an error for suites streams do not support.
fn uses_sha384(algorithm: &str) -> Result<bool, StreamError> {
    match KemSuite::parse(algorithm) {
        Some(s) if s.is_hybrid() => Ok(false),
        Some(KemSuite::Pure(Pqc::MlKem1024)) => Ok(true),
        _ => Err(StreamError::UnsupportedSuite(algorithm.to_string())),
    }
}

/// The parsed, validated header of a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    pub algorithm: String,
    pub kem_ct: Vec<u8>,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub chunk_size: usize,
}

impl StreamHeader {
    pub fn to_cbor(&self) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(STREAM_VERSION.into())),
            (Value::Text("algo".into()), Value::Text(self.algorithm.clone())),
            (Value::Text("kct".into()), Value::Bytes(self.kem_ct.clone())),
            (Value::Text("np".into()), Value::Bytes(self.nonce_prefix.to_vec())),
            (
                Value::Text("cs".into()),
                Value::Integer((self.chunk_size as u64).into()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("writing CBOR to a Vec cannot fail");
        out
    }

    /// Strict parser: exactly the five entries, correct types, a supported suite, a chunk size in range. Never panics.
    pub fn from_cbor(data: &[u8]) -> Result<Self, StreamError> {
        if data.len() > MAX_HEADER_LEN {
            return Err(StreamError::Header("is too large"));
        }
        cbor_guard::validate_shape(data).map_err(|_| StreamError::Header("is not well-formed CBOR"))?;
        let value: Value =
            ciborium::from_reader(data).map_err(|_| StreamError::Header("is not decodable CBOR"))?;
        let Value::Map(entries) = value else {
            return Err(StreamError::Header("is not a map"));
        };
        if entries.len() != 5 {
            return Err(StreamError::Header("must have exactly five entries"));
        }
        let get = |k: &str| {
            entries.iter().find_map(|(key, v)| match key {
                Value::Text(t) if t == k => Some(v),
                _ => None,
            })
        };
        match get("v") {
            Some(Value::Integer(i)) if i128::from(*i) == i128::from(STREAM_VERSION) => {}
            _ => return Err(StreamError::Header("has an unsupported or missing version")),
        }
        let Some(Value::Text(algorithm)) = get("algo") else {
            return Err(StreamError::Header("is missing 'algo'"));
        };
        uses_sha384(algorithm)?;
        let Some(Value::Bytes(kem_ct)) = get("kct") else {
            return Err(StreamError::Header("is missing 'kct'"));
        };
        let Some(Value::Bytes(np)) = get("np") else {
            return Err(StreamError::Header("is missing 'np'"));
        };
        let nonce_prefix: [u8; NONCE_PREFIX_LEN] = np
            .as_slice()
            .try_into()
            .map_err(|_| StreamError::Header("has a nonce prefix of the wrong length"))?;
        let chunk_size = match get("cs") {
            Some(Value::Integer(i)) => {
                usize::try_from(i128::from(*i)).map_err(|_| StreamError::BadChunkSize)?
            }
            _ => return Err(StreamError::Header("is missing 'cs'")),
        };
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(StreamError::BadChunkSize);
        }
        Ok(Self {
            algorithm: algorithm.clone(),
            kem_ct: kem_ct.clone(),
            nonce_prefix,
            chunk_size,
        })
    }
}

/// Seals or opens the chunks of one stream, in order. It owns the key and the chunk counter, so a nonce can never be reused or skipped
/// by a caller. After the last chunk, or after any authentication failure, it refuses everything (fail closed).
pub struct StreamCipher {
    key: Zeroizing<[u8; 32]>,
    prefix: [u8; NONCE_PREFIX_LEN],
    aad: Vec<u8>,
    chunk_size: usize,
    counter: u32,
    finished: bool,
}

fn derive_key(shared_secret: &[u8], header: &[u8], sha384: bool) -> Result<Zeroizing<[u8; 32]>, StreamError> {
    // info = label || 0x00 || H(header), with H = the KDF's own hash: binds the whole header (KEM ciphertext, nonce prefix, chunk size) to the key
    // while keeping the HKDF info short (some HKDF implementations cap it at 1,024 bytes; a KEM ciphertext alone can be longer).
    let digest: Vec<u8> = if sha384 {
        Sha384::digest(header).to_vec()
    } else {
        Sha256::digest(header).to_vec()
    };
    let mut info = Vec::with_capacity(KEY_INFO.len() + 1 + digest.len());
    info.extend_from_slice(KEY_INFO);
    info.push(0);
    info.extend_from_slice(&digest);
    let okm = Zeroizing::new(if sha384 {
        kdf::derive_key_sha384(shared_secret, &info, aead::KEY_LEN)?
    } else {
        kdf::derive_key(shared_secret, &info, aead::KEY_LEN)?
    });
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    Ok(key)
}

fn build_aad(header: &[u8], caller_aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + header.len() + caller_aad.len());
    v.extend_from_slice(&(header.len() as u32).to_be_bytes());
    v.extend_from_slice(header);
    v.extend_from_slice(&(caller_aad.len() as u32).to_be_bytes());
    v.extend_from_slice(caller_aad);
    v
}

impl StreamCipher {
    /// Starts a stream to `recipient`: encapsulates, writes the header, derives the key. Returns the header bytes to send first.
    pub fn start_sealing(
        recipient: &kem::PublicKey,
        caller_aad: &[u8],
        chunk_size: usize,
    ) -> Result<(Vec<u8>, Self), StreamError> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(StreamError::BadChunkSize);
        }
        let sha384 = uses_sha384(&recipient.algorithm)?;
        let (kem_ct, shared_secret) = kem::encapsulate(recipient)?;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        getrandom::fill(&mut nonce_prefix).expect("OS RNG must be available to generate a nonce prefix");
        let header = StreamHeader {
            algorithm: recipient.algorithm.clone(),
            kem_ct,
            nonce_prefix,
            chunk_size,
        }
        .to_cbor();
        let key = derive_key(&shared_secret[..], &header, sha384)?;
        let cipher = Self {
            key,
            prefix: nonce_prefix,
            aad: build_aad(&header, caller_aad),
            chunk_size,
            counter: 0,
            finished: false,
        };
        Ok((header, cipher))
    }

    /// Starts opening a stream: parses and validates the header, decapsulates, derives the key.
    pub fn start_opening(
        recipient_secret: &kem::SecretKey,
        header_bytes: &[u8],
        caller_aad: &[u8],
    ) -> Result<Self, StreamError> {
        let header = StreamHeader::from_cbor(header_bytes)?;
        if header.algorithm != recipient_secret.algorithm {
            return Err(StreamError::AlgorithmMismatch);
        }
        let sha384 = uses_sha384(&header.algorithm)?;
        let shared_secret = kem::decapsulate(recipient_secret, &header.kem_ct)?;
        let key = derive_key(&shared_secret[..], header_bytes, sha384)?;
        Ok(Self {
            key,
            prefix: header.nonce_prefix,
            aad: build_aad(header_bytes, caller_aad),
            chunk_size: header.chunk_size,
            counter: 0,
            finished: false,
        })
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn nonce(&self, last: bool) -> [u8; aead::NONCE_LEN] {
        let mut n = [0u8; aead::NONCE_LEN];
        n[..NONCE_PREFIX_LEN].copy_from_slice(&self.prefix);
        n[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&self.counter.to_be_bytes());
        n[aead::NONCE_LEN - 1] = u8::from(last);
        n
    }

    /// Seals the next chunk. Every chunk except the last must be exactly `chunk_size` bytes; the last may be 0..=`chunk_size`.
    pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>, StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        if plaintext.len() > self.chunk_size || (!last && plaintext.len() != self.chunk_size) {
            return Err(StreamError::BadPlaintextLength);
        }
        let out = aead::encrypt(&self.key, &self.nonce(last), plaintext, &self.aad);
        self.advance(last)?;
        Ok(out)
    }

    /// Opens the next chunk. `last` says whether the transport reached its end after this chunk. Any failure ends the stream.
    pub fn open_chunk(&mut self, ciphertext: &[u8], last: bool) -> Result<Vec<u8>, StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        let ok_len = if last {
            (TAG_LEN..=self.chunk_size + TAG_LEN).contains(&ciphertext.len())
        } else {
            ciphertext.len() == self.chunk_size + TAG_LEN
        };
        if !ok_len {
            self.finished = true;
            return Err(StreamError::BadChunkLength);
        }
        match aead::decrypt(&self.key, &self.nonce(last), ciphertext, &self.aad) {
            Ok(pt) => {
                self.advance(last)?;
                Ok(pt)
            }
            Err(_) => {
                self.finished = true;
                Err(StreamError::Authentication)
            }
        }
    }

    fn advance(&mut self, last: bool) -> Result<(), StreamError> {
        if last {
            self.finished = true;
        } else {
            self.counter = self.counter.checked_add(1).ok_or_else(|| {
                self.finished = true;
                StreamError::TooManyChunks
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(algorithm: &str) -> kem::KeyPair {
        kem::generate_keypair_for(algorithm).unwrap()
    }

    fn seal_all(public: &kem::PublicKey, data: &[u8], aad: &[u8], cs: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let (header, mut c) = StreamCipher::start_sealing(public, aad, cs).unwrap();
        let mut frames = Vec::new();
        let mut chunks: Vec<&[u8]> = data.chunks(cs).collect();
        if chunks.is_empty() || chunks.last().unwrap().len() == cs {
            chunks.push(&[]); // a final (possibly empty) chunk is always sealed with last = 1
        }
        let n = chunks.len();
        for (i, ch) in chunks.into_iter().enumerate() {
            frames.push(c.seal_chunk(ch, i + 1 == n).unwrap());
        }
        (header, frames)
    }

    fn open_all(
        secret: &kem::SecretKey,
        header: &[u8],
        frames: &[Vec<u8>],
        aad: &[u8],
    ) -> Result<Vec<u8>, StreamError> {
        let mut c = StreamCipher::start_opening(secret, header, aad)?;
        let mut out = Vec::new();
        for (i, f) in frames.iter().enumerate() {
            out.extend(c.open_chunk(f, i + 1 == frames.len())?);
        }
        Ok(out)
    }

    #[test]
    fn roundtrip_for_hybrid_and_cnsa_suites_with_various_lengths() {
        for algo in ["X25519+ML-KEM-768", "P-256+ML-KEM-512", "X-Wing", "ML-KEM-1024"] {
            let kp = pair(algo);
            for len in [0usize, 1, 1023, 1024, 1025, 3 * 1024, 5000] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let (h, frames) = seal_all(&kp.public, &data, b"aad", 1024);
                assert_eq!(
                    open_all(&kp.secret, &h, &frames, b"aad").unwrap(),
                    data,
                    "{algo} {len}"
                );
            }
        }
    }

    #[test]
    fn unsupported_suites_are_refused() {
        for algo in ["ML-KEM-512", "ML-KEM-768"] {
            let kp = pair(algo);
            let r = StreamCipher::start_sealing(&kp.public, b"", 1024);
            assert!(matches!(r, Err(StreamError::UnsupportedSuite(_))), "{algo}");
        }
    }

    #[test]
    fn truncation_reordering_duplication_extension_and_tampering_all_fail() {
        let kp = pair("X25519+ML-KEM-512");
        let data = vec![0x42u8; 4 * 1024 + 10];
        let (h, frames) = seal_all(&kp.public, &data, b"", 1024);
        assert_eq!(frames.len(), 5);
        // truncation: drop the last frame, or the last two
        assert!(open_all(&kp.secret, &h, &frames[..4], b"").is_err());
        assert!(open_all(&kp.secret, &h, &frames[..2], b"").is_err());
        // dropping from the middle
        let mut cut = frames.clone();
        cut.remove(1);
        assert!(open_all(&kp.secret, &h, &cut, b"").is_err());
        // reordering
        let mut swapped = frames.clone();
        swapped.swap(0, 1);
        assert!(open_all(&kp.secret, &h, &swapped, b"").is_err());
        // duplication
        let mut dup = frames.clone();
        dup.insert(1, frames[0].clone());
        assert!(open_all(&kp.secret, &h, &dup, b"").is_err());
        // extension: a copy of a middle frame appended after the real last frame
        let mut ext = frames.clone();
        ext.push(frames[0].clone());
        assert!(open_all(&kp.secret, &h, &ext, b"").is_err());
        // bit flips in every frame and in the header
        for i in 0..frames.len() {
            let mut bad = frames.clone();
            bad[i][0] ^= 1;
            assert!(open_all(&kp.secret, &h, &bad, b"").is_err());
        }
        let mut bad_header = h.clone();
        let at = bad_header.len() - 3;
        bad_header[at] ^= 1;
        assert!(open_all(&kp.secret, &bad_header, &frames, b"").is_err());
        // wrong associated data
        assert!(open_all(&kp.secret, &h, &frames, b"other").is_err());
        // the honest stream still opens
        assert_eq!(open_all(&kp.secret, &h, &frames, b"").unwrap(), data);
    }

    #[test]
    fn a_failure_ends_the_stream() {
        let kp = pair("X25519+ML-KEM-512");
        let (h, frames) = seal_all(&kp.public, &vec![1u8; 2048], b"", 1024);
        let mut c = StreamCipher::start_opening(&kp.secret, &h, b"").unwrap();
        let mut bad = frames[0].clone();
        bad[3] ^= 1;
        assert_eq!(c.open_chunk(&bad, false), Err(StreamError::Authentication));
        assert_eq!(c.open_chunk(&frames[0], false), Err(StreamError::Finished));
    }

    #[test]
    fn sealer_enforces_chunk_discipline() {
        let kp = pair("X25519+ML-KEM-512");
        let (_, mut c) = StreamCipher::start_sealing(&kp.public, b"", 1024).unwrap();
        assert_eq!(
            c.seal_chunk(&[0u8; 10], false),
            Err(StreamError::BadPlaintextLength)
        ); // short non-final chunk
        assert_eq!(
            c.seal_chunk(&[0u8; 2000], true),
            Err(StreamError::BadPlaintextLength)
        ); // too long
        c.seal_chunk(&[0u8; 1024], false).unwrap();
        c.seal_chunk(&[], true).unwrap();
        assert_eq!(c.seal_chunk(&[], true), Err(StreamError::Finished));
        assert_eq!(
            StreamCipher::start_sealing(&kp.public, b"", 10).err(),
            Some(StreamError::BadChunkSize)
        );
    }

    #[test]
    fn header_parser_is_strict_and_never_panics() {
        let kp = pair("X25519+ML-KEM-512");
        let (h, _) = StreamCipher::start_sealing(&kp.public, b"", 1024).unwrap();
        let parsed = StreamHeader::from_cbor(&h).unwrap();
        assert_eq!(parsed.to_cbor(), h);
        // every prefix and every single-byte mutation either parses to something sensible or is a typed error
        for n in 0..h.len() {
            let _ = StreamHeader::from_cbor(&h[..n]);
        }
        for i in 0..h.len() {
            let mut m = h.clone();
            m[i] ^= 0xff;
            let _ = StreamHeader::from_cbor(&m);
        }
        assert!(StreamHeader::from_cbor(&[]).is_err());
        assert!(StreamHeader::from_cbor(&vec![0u8; MAX_HEADER_LEN + 1]).is_err());
        let mut extra = h.clone();
        extra.push(0);
        assert!(StreamHeader::from_cbor(&extra).is_err()); // trailing bytes
    }

    #[test]
    fn algorithm_mismatch_is_refused() {
        let a = pair("X25519+ML-KEM-512");
        let b = pair("X25519+ML-KEM-768");
        let (h, _) = StreamCipher::start_sealing(&a.public, b"", 1024).unwrap();
        assert!(matches!(
            StreamCipher::start_opening(&b.secret, &h, b""),
            Err(StreamError::AlgorithmMismatch)
        ));
    }
}
