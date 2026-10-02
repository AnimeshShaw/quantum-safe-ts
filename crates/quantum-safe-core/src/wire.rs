//! Length-prefixed byte packing, matching
//! `quantum_safe.kem.hybrid._pack_components` /
//! `_unpack_components` in quantum-safe-py exactly:
//! a 2-byte big-endian uint16 length prefix on the first component,
//! followed by that component, followed by the second component
//! (which needs no prefix — it's "everything that's left").

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("wire data too short: need at least 2 bytes for the length prefix")]
    TooShortForPrefix,
    #[error("wire data too short: length prefix claims {claimed} bytes, only {available} available")]
    TooShortForComponent { claimed: usize, available: usize },
}

/// Pack two byte strings with a 2-byte big-endian length prefix on `a`.
pub fn pack_components(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + a.len() + b.len());
    out.extend_from_slice(&(a.len() as u16).to_be_bytes());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Unpack two byte strings packed by [`pack_components`].
pub fn unpack_components(data: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    if data.len() < 2 {
        return Err(WireError::TooShortForPrefix);
    }
    let a_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + a_len {
        return Err(WireError::TooShortForComponent {
            claimed: a_len,
            available: data.len().saturating_sub(2),
        });
    }
    Ok((&data[2..2 + a_len], &data[2 + a_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_then_unpack_roundtrip() {
        let a = b"hello";
        let b = b"world!!";
        let packed = pack_components(a, b);
        let (ua, ub) = unpack_components(&packed).unwrap();
        assert_eq!(ua, a);
        assert_eq!(ub, b);
    }

    #[test]
    fn pack_matches_known_byte_layout() {
        // a = [0xAA, 0xBB] (2 bytes) -> length prefix 0x0002
        let packed = pack_components(&[0xAA, 0xBB], &[0xCC]);
        assert_eq!(packed, vec![0x00, 0x02, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn unpack_rejects_missing_prefix() {
        assert_eq!(unpack_components(&[]), Err(WireError::TooShortForPrefix));
        assert_eq!(unpack_components(&[0x00]), Err(WireError::TooShortForPrefix));
    }

    #[test]
    fn unpack_rejects_truncated_component() {
        // claims a_len = 5 but only 2 bytes follow the prefix
        let data = [0x00, 0x05, 0x01, 0x02];
        assert_eq!(
            unpack_components(&data),
            Err(WireError::TooShortForComponent {
                claimed: 5,
                available: 2
            })
        );
    }
}
