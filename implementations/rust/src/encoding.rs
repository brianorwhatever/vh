//! base58btc, hex and Ed25519 multikey helpers (profile §1).

use crate::error::GenerateError;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Ed25519 public key multicodec prefix (0xed, varint-encoded).
const ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// Encodes bytes as base58btc (Bitcoin alphabet, no multibase prefix).
pub fn base58btc_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u32> = Vec::new();
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += *digit << 8;
            *digit = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// Decodes base58btc; returns `None` if `s` contains a character outside the alphabet.
pub fn base58btc_decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s[zeros..].chars() {
        let value = ALPHABET.iter().position(|&a| a as char == c)? as u32;
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

/// `"z" + base58btc(0xed 0x01 ‖ pubkey)`.
pub fn multikey_from_public_key(public_key: &[u8; 32]) -> String {
    let mut bytes = ED25519_PUB.to_vec();
    bytes.extend_from_slice(public_key);
    format!("z{}", base58btc_encode(&bytes))
}

/// Returns the raw Ed25519 public key, or `None` if `multikey` is not an Ed25519 multikey.
pub fn public_key_from_multikey(multikey: &str) -> Option<[u8; 32]> {
    let bytes = base58btc_decode(multikey.strip_prefix('z')?)?;
    if bytes.len() != 34 || bytes[..2] != ED25519_PUB {
        return None;
    }
    bytes[2..].try_into().ok()
}

/// Decodes hex (either case).
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, GenerateError> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GenerateError::InvalidSeed(format!("invalid hex: {hex}")));
    }
    Ok((0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
        .collect())
}

/// Encodes bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trip_with_leading_zeros() {
        for bytes in [
            vec![],
            vec![0],
            vec![0, 0, 1, 2, 255],
            (0..=255).collect::<Vec<u8>>(),
        ] {
            assert_eq!(base58btc_decode(&base58btc_encode(&bytes)).unwrap(), bytes);
        }
        assert_eq!(base58btc_encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58btc_decode("0OIl"), None);
    }

    #[test]
    fn multikey_round_trip() {
        let pk = [7u8; 32];
        let mk = multikey_from_public_key(&pk);
        assert!(mk.starts_with("z6Mk"));
        assert_eq!(public_key_from_multikey(&mk), Some(pk));
        assert_eq!(public_key_from_multikey(&mk[1..]), None);
    }

    #[test]
    fn hex() {
        assert_eq!(hex_decode("00ffAB").unwrap(), vec![0, 255, 171]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
        assert_eq!(hex_encode(&[0, 255]), "00ff");
    }
}
