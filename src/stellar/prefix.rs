// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vanity prefix checks for Stellar account StrKeys.
//!
//! Base32 consumes the version byte from its high bit. Version `0x30` is
//! `00110000`, so character 1 is always `G` and character 2 is `000` plus the
//! top two bits of the public key: only `A`, `B`, `C`, or `D`.
//!
//! A 56-character account is 280 bits. Bits 0..7 are the version byte, bits
//! 8..263 are the public key, and bits 264..279 are the checksum. Checksum
//! bits begin at character 53 (index 52). Shorter prefixes do not depend on
//! the checksum.

use crate::error::Error;
use crate::stellar::crc::checksum;
use crate::stellar::strkey::{alphabet_index, ACCOUNT_VERSION};

pub(crate) const SEARCH_COUNTER_HEADROOM: u64 = 1_048_576;
pub const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000;
pub const MAX_PREFIX_LEN: usize = 56;

const ERR_EMPTY: &str = "prefix is empty";
const ERR_LOWER: &str = "Stellar StrKey uses uppercase Base32. Lowercase letters are not valid";
const ERR_NEEDS_G: &str = "Stellar account IDs begin with G";
const ERR_ALPHABET: &str = "prefix contains a character that is not in Stellar's Base32 alphabet";
const ERR_LONG: &str = "prefix is longer than a Stellar account ID (56 characters)";
const ERR_SECOND: &str = "an Ed25519 account StrKey's second character can only be A, B, C, or D. Characters E through Z and 2 through 7 cannot occur there. GAZUZU, GBZUZU, GCZUZU, and GDZUZU are reachable";
const ERR_IMPOSSIBLE: &str = "prefix cannot occur in any Ed25519 account ID";
const ERR_RANGE: &str = "prefix search exceeds this implementation's supported attempt range";

/// A prefix that can appear, plus the fair-bit attempt estimate.
///
/// `expected` counts candidates whose constrained public-key bits match, under
/// a model that those bits are independent and fair. Ed25519 stores `y`
/// little-endian, so a short prefix constrains low bits of `y`. This is an
/// estimate, not a proof of uniformity and not a promise of wall-clock time.
#[derive(Clone, PartialEq, Eq)]
pub struct PrefixEstimate {
    prefix: String,
    pub second_character: Option<char>,
    pub pubkey_bits: u32,
    pub checksum_bits: u32,
    pub expected: u64,
    pub median: u64,
    masks: [u8; 32],
    values: [u8; 32],
}

impl PrefixEstimate {
    pub fn as_str(&self) -> &str {
        &self.prefix
    }

    pub fn needs_large_search_confirmation(&self) -> bool {
        self.expected >= CONFIRMATION_THRESHOLD
    }

    /// Compare the public-key bits that this prefix constrains.
    ///
    /// For a prefix of at most 52 characters this is the same question as
    /// `encode_account(public_key).starts_with(prefix)`, because those
    /// characters do not include checksum bits.
    pub fn matches_public_key(&self, public_key: &[u8; 32]) -> bool {
        public_key
            .iter()
            .zip(self.masks)
            .zip(self.values)
            .all(|((byte, mask), value)| byte & mask == value)
    }

    pub fn display_attempts(&self) -> String {
        group_digits(&self.expected.to_string())
    }

    pub fn display_median(&self) -> String {
        group_digits(&self.median.to_string())
    }
}

impl std::fmt::Debug for PrefixEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixEstimate")
            .field("prefix", &self.prefix)
            .field("second_character", &self.second_character)
            .field("pubkey_bits", &self.pubkey_bits)
            .field("checksum_bits", &self.checksum_bits)
            .field("expected", &self.expected)
            .field("median", &self.median)
            .finish()
    }
}

pub fn validate_prefix(prefix: &str) -> Result<PrefixEstimate, Error> {
    if prefix.is_empty() {
        return Err(Error::Prefix(ERR_EMPTY));
    }
    if prefix.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err(Error::Prefix(ERR_LOWER));
    }
    if !prefix.starts_with('G') {
        return Err(Error::Prefix(ERR_NEEDS_G));
    }
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(Error::Prefix(ERR_LONG));
    }
    if prefix.bytes().any(|byte| alphabet_index(byte).is_none()) {
        return Err(Error::Prefix(ERR_ALPHABET));
    }
    if prefix.len() >= 2 {
        let second = prefix.as_bytes()[1];
        if !matches!(second, b'A' | b'B' | b'C' | b'D') {
            return Err(Error::Prefix(ERR_SECOND));
        }
    }

    let bits = prefix_bits(prefix);
    let version = version_bits();
    let compared = bits.len().min(version.len());
    if bits[..compared] != version[..compared] {
        return Err(Error::Prefix(ERR_IMPOSSIBLE));
    }
    if bits.len() >= 264 && checksum_conflicts(&bits) {
        return Err(Error::Prefix(ERR_IMPOSSIBLE));
    }

    let pubkey_bits = bits.len().saturating_sub(8).min(256) as u32;
    let checksum_bits = bits.len().saturating_sub(264) as u32;
    let total_bits = pubkey_bits + checksum_bits;
    // 62 bits (`2^62`) is the widest search accepted below. The counter stops
    // near `2^64`. Under the fair-bit model the chance of still having no
    // match is about `e^-4`, roughly 1.8%, and the search then fails with no
    // wallet. Running `2^64` derivations is not a practical outcome.
    if total_bits >= 64 {
        return Err(Error::Prefix(ERR_RANGE));
    }
    let expected = 1u64 << total_bits;
    if expected > u64::MAX - SEARCH_COUNTER_HEADROOM {
        return Err(Error::Prefix(ERR_RANGE));
    }
    let (masks, values) = masks_from_bits(&bits);
    Ok(PrefixEstimate {
        second_character: prefix.chars().nth(1),
        pubkey_bits,
        checksum_bits,
        expected,
        median: median_attempts(expected),
        masks,
        values,
        prefix: prefix.to_owned(),
    })
}

/// `ln(2) * expected`, rounded to the nearest integer.
///
/// Powers of two through `2^62` are exact in `f64`. The product with `ln(2)`
/// is the displayed median, not an exact rational.
pub fn median_attempts(expected: u64) -> u64 {
    if expected <= 1 {
        return expected;
    }
    let median = (expected as f64) * std::f64::consts::LN_2;
    median.round() as u64
}

/// `1 - (1 - 1/expected)^attempts`, using the fair-bit model.
pub fn probability_after(expected: u64, attempts: u64) -> f64 {
    if expected == 0 {
        return 1.0;
    }
    let miss = 1.0 - (1.0 / expected as f64);
    1.0 - miss.powf(attempts as f64)
}

pub fn group_digits(digits: &str) -> String {
    if digits.is_empty() {
        return String::new();
    }
    if digits.len() > 15 {
        let exponent = digits.len() - 1;
        let mut mantissa = String::new();
        mantissa.push(digits.as_bytes()[0] as char);
        mantissa.push('.');
        let fraction: String = digits.chars().skip(1).take(3).collect();
        mantissa.push_str(&fraction);
        return format!("{mantissa}e{exponent}");
    }
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped.chars().rev().collect()
}

fn version_bits() -> [u8; 8] {
    let mut bits = [0u8; 8];
    for (index, bit) in bits.iter_mut().enumerate() {
        *bit = (ACCOUNT_VERSION >> (7 - index)) & 1;
    }
    bits
}

fn prefix_bits(prefix: &str) -> Vec<u8> {
    let mut bits = Vec::with_capacity(prefix.len() * 5);
    for byte in prefix.bytes() {
        let index = alphabet_index(byte).expect("alphabet was checked");
        for shift in (0..5).rev() {
            bits.push((index >> shift) & 1);
        }
    }
    bits
}

fn masks_from_bits(bits: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut masks = [0u8; 32];
    let mut values = [0u8; 32];
    for (stream_bit, &bit) in bits.iter().enumerate().skip(8) {
        if stream_bit >= 264 {
            break;
        }
        let pubkey_bit = stream_bit - 8;
        let byte = pubkey_bit / 8;
        let shift = 7 - (pubkey_bit % 8);
        masks[byte] |= 1 << shift;
        if bit == 1 {
            values[byte] |= 1 << shift;
        }
    }
    (masks, values)
}

fn checksum_conflicts(bits: &[u8]) -> bool {
    let mut public_key = [0u8; 32];
    for pubkey_bit in 0..256 {
        let stream_bit = 8 + pubkey_bit;
        if stream_bit >= bits.len() {
            return true;
        }
        if bits[stream_bit] == 1 {
            let shift = 7 - (pubkey_bit % 8);
            public_key[pubkey_bit / 8] |= 1 << shift;
        }
    }
    let mut payload = [0u8; 33];
    payload[0] = ACCOUNT_VERSION;
    payload[1..].copy_from_slice(&public_key);
    let crc = checksum(&payload);
    let mut crc_bits = [0u8; 16];
    for (index, bit) in crc_bits.iter_mut().enumerate() {
        let byte = crc[index / 8];
        let shift = 7 - (index % 8);
        *bit = (byte >> shift) & 1;
    }
    for (offset, crc_bit) in crc_bits.iter().enumerate() {
        let stream_bit = 264 + offset;
        if stream_bit >= bits.len() {
            break;
        }
        if bits[stream_bit] != *crc_bit {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        group_digits, median_attempts, validate_prefix, CONFIRMATION_THRESHOLD, ERR_ALPHABET,
        ERR_LONG, ERR_LOWER, ERR_NEEDS_G, ERR_RANGE, ERR_SECOND,
    };
    use crate::error::Error;
    use crate::stellar::strkey::encode_account;

    #[test]
    fn gazuzu_is_22_public_key_bits() {
        let estimate = validate_prefix("GAZUZU").unwrap();
        assert_eq!(estimate.second_character, Some('A'));
        assert_eq!(estimate.pubkey_bits, 22);
        assert_eq!(estimate.checksum_bits, 0);
        assert_eq!(estimate.expected, 4_194_304);
        // 4_194_304 * ln(2), rounded. f64 prints this as 2907269.992..., so
        // the nearest integer is 2_907_270.
        assert_eq!(estimate.median, 2_907_270);
        assert_eq!(median_attempts(4_194_304), 2_907_270);
        assert!(!estimate.needs_large_search_confirmation());
        assert_eq!(estimate.display_attempts(), "4,194,304");
    }

    #[test]
    fn each_legal_second_character_has_the_same_zuzu_cost() {
        for prefix in ["GAZUZU", "GBZUZU", "GCZUZU", "GDZUZU"] {
            let estimate = validate_prefix(prefix).unwrap();
            assert_eq!(estimate.expected, 4_194_304, "{prefix}");
        }
    }

    #[test]
    fn short_prefixes_have_exact_powers_of_two() {
        assert_eq!(validate_prefix("G").unwrap().expected, 1);
        assert_eq!(validate_prefix("GA").unwrap().expected, 4);
        assert_eq!(validate_prefix("GB").unwrap().expected, 4);
        assert_eq!(validate_prefix("GC").unwrap().expected, 4);
        assert_eq!(validate_prefix("GD").unwrap().expected, 4);
        assert!(validate_prefix("G").unwrap().second_character.is_none());
    }

    #[test]
    fn gzuzu_and_its_relatives_are_rejected() {
        assert_eq!(validate_prefix("GZUZU"), Err(Error::Prefix(ERR_SECOND)));
        assert_eq!(validate_prefix("GZ"), Err(Error::Prefix(ERR_SECOND)));
        assert_eq!(validate_prefix("GE"), Err(Error::Prefix(ERR_SECOND)));
        assert_eq!(validate_prefix("G2"), Err(Error::Prefix(ERR_SECOND)));
        assert_eq!(validate_prefix("G7ZZZ"), Err(Error::Prefix(ERR_SECOND)));
        assert_eq!(validate_prefix("GZuZu"), Err(Error::Prefix(ERR_LOWER)));
        assert_eq!(validate_prefix("ZUZU"), Err(Error::Prefix(ERR_NEEDS_G)));
        assert_eq!(validate_prefix("zuzu"), Err(Error::Prefix(ERR_LOWER)));
        assert_eq!(validate_prefix("G0AAA"), Err(Error::Prefix(ERR_ALPHABET)));
        assert_eq!(
            validate_prefix(&"G".repeat(57)),
            Err(Error::Prefix(ERR_LONG))
        );
    }

    #[test]
    fn fourteen_characters_fit_and_fifteen_do_not() {
        let legal = format!("G{}", "A".repeat(13));
        assert_eq!(legal.len(), 14);
        let estimate = validate_prefix(&legal).unwrap();
        assert_eq!(estimate.pubkey_bits, 62);
        assert_eq!(estimate.expected, 1u64 << 62);
        assert!(estimate.expected >= CONFIRMATION_THRESHOLD);
        assert!(estimate.display_attempts().contains('e'));
        let too_wide = format!("G{}", "A".repeat(14));
        assert_eq!(validate_prefix(&too_wide), Err(Error::Prefix(ERR_RANGE)));
    }

    #[test]
    fn a_real_account_is_too_large_and_a_bad_checksum_is_impossible() {
        let account = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        assert_eq!(validate_prefix(account), Err(Error::Prefix(ERR_RANGE)));
        let mut flipped = account.to_owned();
        flipped.pop();
        flipped.push('G');
        assert_eq!(
            validate_prefix(&flipped),
            Err(Error::Prefix(super::ERR_IMPOSSIBLE))
        );
    }

    #[test]
    fn second_character_follows_the_top_two_public_key_bits() {
        let expected = [(0u8, 'A'), (1, 'B'), (2, 'C'), (3, 'D')];
        for (top, character) in expected {
            let mut public_key = [0u8; 32];
            public_key[0] = top << 6;
            let account = encode_account(&public_key);
            assert_eq!(account.chars().nth(1), Some(character));
            let prefix: String = account.chars().take(2).collect();
            let estimate = validate_prefix(&prefix).unwrap();
            assert!(estimate.matches_public_key(&public_key));
        }
    }

    #[test]
    fn group_digits_inserts_separators() {
        assert_eq!(group_digits("4194304"), "4,194,304");
        assert_eq!(group_digits("4"), "4");
    }
}
