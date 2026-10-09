//! SHA-256 multihashes (profile §1).

use crate::encoding::{base58btc_decode, base58btc_encode};
use sha2::{Digest, Sha256};

/// Multihash code and digest length for SHA-256, the only algorithm `vh-log:1.0` permits.
const SHA256_CODE: u8 = 0x12;
const SHA256_LENGTH: u8 = 32;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `base58btc(multihash(data, SHA-256))` — the encoding of SCIDs, entry hashes and key hashes.
pub fn hash_b58(data: &[u8]) -> String {
    let mut bytes = vec![SHA256_CODE, SHA256_LENGTH];
    bytes.extend_from_slice(&sha256(data));
    base58btc_encode(&bytes)
}

/// Classification of a base58btc string as a multihash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultihashCheck {
    /// A SHA-256 multihash.
    Ok,
    /// Not base58btc, or empty.
    NotBase58,
    /// Valid base58btc, but not a SHA-256 multihash.
    UnsupportedAlgorithm,
}

pub fn check_sha256_multihash(value: &str) -> MultihashCheck {
    match base58btc_decode(value) {
        None => MultihashCheck::NotBase58,
        Some(bytes) if bytes.is_empty() => MultihashCheck::NotBase58,
        Some(bytes)
            if bytes.len() != 2 + SHA256_LENGTH as usize
                || bytes[0] != SHA256_CODE
                || bytes[1] != SHA256_LENGTH =>
        {
            MultihashCheck::UnsupportedAlgorithm
        }
        Some(_) => MultihashCheck::Ok,
    }
}

/// Pre-rotation key hash: the multikey string itself is hashed.
pub fn key_hash(multikey: &str) -> String {
    hash_b58(multikey.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multihash_classification() {
        let h = hash_b58(b"abc");
        assert_eq!(h, "QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY");
        assert_eq!(check_sha256_multihash(&h), MultihashCheck::Ok);
        assert_eq!(check_sha256_multihash(""), MultihashCheck::NotBase58);
        assert_eq!(check_sha256_multihash("Qm0"), MultihashCheck::NotBase58);
        assert_eq!(
            check_sha256_multihash("2"),
            MultihashCheck::UnsupportedAlgorithm
        );
    }
}
