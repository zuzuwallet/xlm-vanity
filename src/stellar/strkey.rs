//! Stellar StrKey for Ed25519 accounts (`G...`) and seeds (`S...`).
//!
//! SEP-23 v1.3.0:
//! account version byte `(6 << 3) | 0 = 0x30`,
//! seed version byte `(18 << 3) | 0 = 0x90`.
//! The payload is version || 32 bytes || CRC-16/XMODEM, low byte first.
//! Those 35 bytes are RFC 4648 Base32 with no padding: 56 characters.

use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::{SecretBytes, SecretString};
use crate::stellar::crc::{checksum, checksum_matches};

/// SEP-23 `STRKEY_PUBKEY` with `STRKEY_ALG_ED25519`.
pub(crate) const ACCOUNT_VERSION: u8 = 6 << 3;
/// SEP-23 `STRKEY_PRIVKEY` with `STRKEY_ALG_ED25519`.
pub(crate) const SEED_VERSION: u8 = 18 << 3;
pub(crate) const STRKEY_BYTES: usize = 35;
pub(crate) const STRKEY_TEXT_LEN: usize = 56;
pub(crate) const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode_account(public_key: &[u8; 32]) -> String {
    let mut raw = [0u8; STRKEY_BYTES];
    fill_payload(ACCOUNT_VERSION, public_key, &mut raw);
    let mut text = [0u8; STRKEY_TEXT_LEN];
    base32_encode_into(&raw, &mut text);
    ascii_from_fixed(&text)
}

/// Encode a seed as an `S...` StrKey.
///
/// The 35-byte payload and the 56-byte text are wiped when they drop. The
/// returned `SecretString` is the copy that remains. A compiler spill, a
/// register, or an allocator copy of those bytes is outside that wipe.
pub fn encode_seed(seed: &[u8; 32]) -> SecretString {
    let mut raw = Zeroizing::new([0u8; STRKEY_BYTES]);
    fill_payload(SEED_VERSION, seed, &mut raw);
    let mut text = Zeroizing::new([0u8; STRKEY_TEXT_LEN]);
    base32_encode_into(&raw, &mut text);
    SecretString::new(ascii_from_fixed(&text))
}

pub fn decode_account(text: &str) -> Result<[u8; 32], Error> {
    let mut raw = [0u8; STRKEY_BYTES];
    base32_decode_into(text, &mut raw)?;
    require_canonical(&raw, text)?;
    check_version_and_crc(&raw, ACCOUNT_VERSION)?;
    let mut payload = [0u8; 32];
    payload.copy_from_slice(&raw[1..33]);
    Ok(payload)
}

/// Decode an `S...` StrKey.
///
/// The decoded payload and the canonical-text buffer are wiped on drop. The
/// returned `SecretBytes` is the copy that remains. This does not wipe a
/// compiler spill or the caller's own copy of `text`.
pub fn decode_seed(text: &str) -> Result<SecretBytes<32>, Error> {
    let mut raw = Zeroizing::new([0u8; STRKEY_BYTES]);
    base32_decode_into(text, &mut raw)?;
    require_canonical(&raw, text)?;
    check_version_and_crc(&raw, SEED_VERSION)?;
    let mut payload = Zeroizing::new([0u8; 32]);
    payload.copy_from_slice(&raw[1..33]);
    Ok(SecretBytes::new(*payload))
}

fn fill_payload(version: u8, payload: &[u8; 32], raw: &mut [u8; STRKEY_BYTES]) {
    raw[0] = version;
    raw[1..33].copy_from_slice(payload);
    let crc = checksum(&raw[..33]);
    raw[33] = crc[0];
    raw[34] = crc[1];
}

fn check_version_and_crc(raw: &[u8; STRKEY_BYTES], version: u8) -> Result<(), Error> {
    if raw[0] != version {
        return Err(Error::StrKey);
    }
    let expect = checksum(&raw[..33]);
    let got = [raw[33], raw[34]];
    if !checksum_matches(got, expect) {
        return Err(Error::Checksum);
    }
    Ok(())
}

fn ascii_from_fixed(bytes: &[u8; STRKEY_TEXT_LEN]) -> String {
    let mut out = String::with_capacity(STRKEY_TEXT_LEN);
    for &byte in bytes {
        out.push(char::from(byte));
    }
    out
}

/// Write 56 Base32 characters. The shift register is wiped on drop.
fn base32_encode_into(data: &[u8; STRKEY_BYTES], out: &mut [u8; STRKEY_TEXT_LEN]) {
    let mut buffer = Zeroizing::new(0u16);
    let mut bits: u32 = 0;
    let mut written = 0usize;
    for &byte in data {
        *buffer = (*buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((*buffer >> bits) & 0x1f) as usize;
            out[written] = ALPHABET[index];
            written += 1;
        }
    }
    debug_assert_eq!(bits, 0);
    debug_assert_eq!(written, STRKEY_TEXT_LEN);
}

fn base32_decode_into(text: &str, raw: &mut [u8; STRKEY_BYTES]) -> Result<(), Error> {
    if text.len() != STRKEY_TEXT_LEN {
        return Err(Error::StrKey);
    }
    let mut buffer = Zeroizing::new(0u16);
    let mut bits: u32 = 0;
    let mut produced = 0usize;
    for byte in text.bytes() {
        let index = alphabet_index(byte).ok_or(Error::StrKey)?;
        *buffer = (*buffer << 5) | u16::from(index);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if produced >= STRKEY_BYTES {
                return Err(Error::StrKey);
            }
            raw[produced] = ((*buffer >> bits) & 0xff) as u8;
            produced += 1;
        }
    }
    if produced != STRKEY_BYTES || bits != 0 {
        return Err(Error::StrKey);
    }
    Ok(())
}

fn require_canonical(raw: &[u8; STRKEY_BYTES], text: &str) -> Result<(), Error> {
    let mut again = Zeroizing::new([0u8; STRKEY_TEXT_LEN]);
    base32_encode_into(raw, &mut again);
    if again.as_slice() == text.as_bytes() {
        Ok(())
    } else {
        Err(Error::StrKey)
    }
}

pub(crate) fn alphabet_index(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_account, encode_account, ACCOUNT_VERSION};
    use crate::error::Error;

    const SEP23_PUBLIC: [u8; 32] = [
        0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x05,
        0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03, 0xfc, 0x7f,
        0xe8, 0x9a,
    ];
    const SEP23_ACCOUNT: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

    #[test]
    fn version_bytes_match_sep23() {
        assert_eq!(ACCOUNT_VERSION, 0x30);
        assert_eq!(super::SEED_VERSION, 0x90);
    }

    #[test]
    fn sep23_account_round_trip() {
        assert_eq!(encode_account(&SEP23_PUBLIC), SEP23_ACCOUNT);
        let decoded = decode_account(SEP23_ACCOUNT).unwrap();
        assert_eq!(decoded, SEP23_PUBLIC);
    }

    #[test]
    fn swapped_checksum_bytes_are_rejected() {
        let mut chars: Vec<u8> = SEP23_ACCOUNT.as_bytes().to_vec();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == b'A' { b'B' } else { b'A' };
        let text = String::from_utf8(chars).unwrap();
        assert_eq!(decode_account(&text), Err(Error::Checksum));
    }

    #[test]
    fn sep23_invalid_account_strings_are_rejected() {
        let invalid = [
            "GAAAAAAAACGC6",
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA",
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI",
            "G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I",
        ];
        for text in invalid {
            assert!(decode_account(text).is_err(), "{text}");
        }
    }

    #[test]
    fn zero_public_key_matches_the_published_account() {
        let account = encode_account(&[0u8; 32]);
        assert_eq!(
            account,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
    }

    #[test]
    fn canonical_check_rejects_a_different_public_string() {
        let mut raw = [0u8; super::STRKEY_BYTES];
        super::fill_payload(ACCOUNT_VERSION, &SEP23_PUBLIC, &mut raw);
        assert!(super::require_canonical(&raw, SEP23_ACCOUNT).is_ok());
        let mut other = SEP23_ACCOUNT.to_owned();
        let index = 10;
        let replacement = if other.as_bytes()[index] == b'A' {
            "B"
        } else {
            "A"
        };
        other.replace_range(index..index + 1, replacement);
        assert_eq!(super::require_canonical(&raw, &other), Err(Error::StrKey));
    }
}
