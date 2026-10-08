// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use xlm_vanity::{validate_prefix, Error, CONFIRMATION_THRESHOLD};

#[test]
fn gzuzu_is_rejected_before_any_search_math() {
    let err = validate_prefix("GZUZU").unwrap_err();
    let text = err.to_string();
    assert!(text.contains("second character"));
    assert!(text.contains("GAZUZU"));
    assert!(matches!(err, Error::Prefix(_)));
}

#[test]
fn mixed_case_and_a_missing_g_are_distinct_errors() {
    let mixed = validate_prefix("GZuZu").unwrap_err().to_string();
    assert!(mixed.contains("uppercase"));
    let missing = validate_prefix("ZUZU").unwrap_err().to_string();
    assert!(missing.contains("begin with G"));
    let lower = validate_prefix("zuzu").unwrap_err().to_string();
    assert!(lower.contains("uppercase"));
}

#[test]
fn illegal_characters_and_overlong_prefixes_are_rejected() {
    assert!(validate_prefix("G0AAA").is_err());
    assert!(validate_prefix(&"G".repeat(57)).is_err());
    assert!(validate_prefix("").is_err());
}

#[test]
fn gazuzu_costs_22_public_key_bits() {
    let estimate = validate_prefix("GAZUZU").unwrap();
    assert_eq!(estimate.expected, 4_194_304);
    assert_eq!(estimate.pubkey_bits, 22);
    assert_eq!(estimate.checksum_bits, 0);
    assert_eq!(estimate.median, 2_907_270);
    assert!(!estimate.needs_large_search_confirmation());
    assert!(estimate.expected < CONFIRMATION_THRESHOLD);
}

#[test]
fn fifteen_characters_and_a_full_account_exceed_the_counter() {
    let wide = format!("G{}", "A".repeat(14));
    assert_eq!(wide.len(), 15);
    assert!(matches!(validate_prefix(&wide), Err(Error::Prefix(_))));
    let account = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    assert!(validate_prefix(account).is_err());
    let mut flipped = account.to_owned();
    flipped.pop();
    flipped.push('G');
    assert!(validate_prefix(&flipped).is_err());
}
