// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer tests. A failure aborts before any search or wallet write.
//!
//! Vectors:
//! - RFC 8032 section 7.1 test 1, raw seed and raw public key
//! - SEP-23 v1.3.0 valid Ed25519 account, and its invalid `G...` strings
//! - `stellar-strkey` documentation, all-zero public key
//! - SEP-0005 test 1, primary account `m/44'/148'/0'`

use crate::error::Error;
use crate::independent::{reference_account, reference_public_key, ring_public_key};
use crate::stellar::{
    account_from_secret_strkey, decode_account, decode_seed, derive_from_seed, encode_account,
    encode_seed, public_key_from_seed, validate_prefix,
};
use crate::verify::confirm_match;

const RFC8032_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC8032_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

const SEP23_PUBLIC: [u8; 32] = [
    0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x05, 0x51,
    0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03, 0xfc, 0x7f, 0xe8, 0x9a,
];
const SEP23_ACCOUNT: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
const ZERO_ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// SEP-0005 test 1, path `m/44'/148'/0'`. This is a published test vector.
const SEP5_SECRET: &str = "SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN";
const SEP5_ACCOUNT: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

const INVALID_ACCOUNTS: [&str; 4] = [
    "GAAAAAAAACGC6",
    "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA",
    "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI",
    "G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I",
];

pub fn run_self_tests() -> Result<(), Error> {
    check_sep23()?;
    check_rfc8032()?;
    check_sep0005()?;
    check_prefix_shortcut()?;
    check_rejected_targets()?;
    Ok(())
}

fn check_sep23() -> Result<(), Error> {
    if encode_account(&SEP23_PUBLIC) != SEP23_ACCOUNT {
        return Err(Error::SelfTest("SEP-23 account encoding mismatch"));
    }
    if decode_account(SEP23_ACCOUNT)? != SEP23_PUBLIC {
        return Err(Error::SelfTest("SEP-23 account decoding mismatch"));
    }
    if reference_account(&SEP23_PUBLIC)? != SEP23_ACCOUNT {
        return Err(Error::SelfTest(
            "stellar-strkey rejected the SEP-23 account",
        ));
    }
    if reference_public_key(SEP23_ACCOUNT)? != SEP23_PUBLIC {
        return Err(Error::SelfTest(
            "stellar-strkey decoded the SEP-23 account differently",
        ));
    }
    if encode_account(&[0u8; 32]) != ZERO_ACCOUNT || reference_account(&[0u8; 32])? != ZERO_ACCOUNT
    {
        return Err(Error::SelfTest("all-zero public key encoding mismatch"));
    }
    let mut flipped: Vec<u8> = SEP23_ACCOUNT.as_bytes().to_vec();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
    let flipped = String::from_utf8(flipped).map_err(|_| Error::SelfTest("checksum fixture"))?;
    if decode_account(&flipped).is_ok() {
        return Err(Error::SelfTest("a damaged SEP-23 checksum was accepted"));
    }
    for text in INVALID_ACCOUNTS {
        if decode_account(text).is_ok() {
            return Err(Error::SelfTest("an invalid SEP-23 account was accepted"));
        }
    }
    Ok(())
}

fn check_rfc8032() -> Result<(), Error> {
    let public_key = public_key_from_seed(&RFC8032_SEED);
    if public_key != RFC8032_PUBLIC {
        return Err(Error::SelfTest("RFC 8032 public key mismatch"));
    }
    if ring_public_key(&RFC8032_SEED)? != RFC8032_PUBLIC {
        return Err(Error::SelfTest("ring disagreed with RFC 8032"));
    }
    let account = encode_account(&RFC8032_PUBLIC);
    if reference_account(&RFC8032_PUBLIC)? != account {
        return Err(Error::SelfTest(
            "StrKey encoders disagreed on the RFC 8032 public key",
        ));
    }
    if !account.starts_with("GD") || account.len() != 56 {
        return Err(Error::SelfTest("RFC 8032 account was not a GD StrKey"));
    }
    let secret = encode_seed(&RFC8032_SEED);
    let parsed = stellar_strkey::ed25519::PrivateKey::from_string(secret.as_str())
        .map_err(|_| Error::SelfTest("stellar-strkey rejected the RFC 8032 seed"))?;
    if parsed.0 != RFC8032_SEED {
        return Err(Error::SelfTest(
            "stellar-strkey decoded a different RFC 8032 seed",
        ));
    }
    confirm_match(&RFC8032_SEED, &account)?;
    Ok(())
}

fn check_sep0005() -> Result<(), Error> {
    let derived = account_from_secret_strkey(SEP5_SECRET)?;
    if derived.account != SEP5_ACCOUNT {
        return Err(Error::SelfTest(
            "SEP-0005 secret did not produce the published account",
        ));
    }
    let seed = decode_seed(SEP5_SECRET)?;
    if encode_seed(seed.as_bytes()).as_str() != SEP5_SECRET {
        return Err(Error::SelfTest("SEP-0005 secret did not re-encode"));
    }
    let parsed = stellar_strkey::ed25519::PrivateKey::from_string(SEP5_SECRET)
        .map_err(|_| Error::SelfTest("stellar-strkey rejected the SEP-0005 secret"))?;
    if parsed.0 != *seed.as_bytes() {
        return Err(Error::SelfTest(
            "stellar-strkey decoded a different SEP-0005 seed",
        ));
    }
    if ring_public_key(seed.as_bytes())? != derived.public_key {
        return Err(Error::SelfTest("ring disagreed on the SEP-0005 public key"));
    }
    if reference_account(&derived.public_key)? != SEP5_ACCOUNT {
        return Err(Error::SelfTest(
            "stellar-strkey disagreed on the SEP-0005 account",
        ));
    }
    confirm_match(seed.as_bytes(), SEP5_ACCOUNT)?;
    Ok(())
}

fn check_prefix_shortcut() -> Result<(), Error> {
    let samples = [[0u8; 32], [0xff; 32], RFC8032_SEED, {
        let mut seed = [0u8; 32];
        seed[0] = 1;
        seed[31] = 2;
        seed
    }];
    for seed in samples {
        let derived = derive_from_seed(&seed)?;
        let second = derived.account.as_bytes()[1];
        if !matches!(second, b'A' | b'B' | b'C' | b'D') {
            return Err(Error::SelfTest(
                "derived account had an impossible second character",
            ));
        }
        for length in [1usize, 2, 6] {
            let prefix = &derived.account[..length];
            let estimate = validate_prefix(prefix)?;
            if !estimate.matches_public_key(&derived.public_key)
                || !derived.account.starts_with(prefix)
            {
                return Err(Error::SelfTest("prefix bit test disagreed with StrKey"));
            }
        }
        for prefix in ["GA", "GB", "GC", "GD"] {
            let estimate = validate_prefix(prefix)?;
            let by_bits = estimate.matches_public_key(&derived.public_key);
            let by_text = derived.account.starts_with(prefix);
            if by_bits != by_text {
                return Err(Error::SelfTest("prefix bit test disagreed with StrKey"));
            }
        }
    }
    Ok(())
}

fn check_rejected_targets() -> Result<(), Error> {
    if validate_prefix("GZUZU").is_ok()
        || validate_prefix("GZuZu").is_ok()
        || validate_prefix("ZUZU").is_ok()
    {
        return Err(Error::SelfTest("an impossible prefix was accepted"));
    }
    let gazuzu = validate_prefix("GAZUZU")?;
    if gazuzu.expected != 4_194_304 || gazuzu.pubkey_bits != 22 || gazuzu.checksum_bits != 0 {
        return Err(Error::SelfTest("GAZUZU difficulty changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_self_tests;

    #[test]
    fn known_answers_pass() {
        run_self_tests().unwrap();
    }
}
