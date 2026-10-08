// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use xlm_vanity::independent::{reference_account, reference_public_key, ring_public_key};
use xlm_vanity::{
    account_from_secret_strkey, confirm_match, decode_account, derive_from_seed, encode_account,
    encode_seed, Error,
};

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

/// SEP-0005 test 1, path `m/44'/148'/0'`. Published test vector, not a wallet.
const SEP5_SECRET: &str = "SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN";
const SEP5_ACCOUNT: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

#[test]
fn rfc8032_seed_matches_dalek_and_ring() {
    let derived = derive_from_seed(&RFC8032_SEED).unwrap();
    assert_eq!(derived.public_key, RFC8032_PUBLIC);
    assert_eq!(ring_public_key(&RFC8032_SEED).unwrap(), RFC8032_PUBLIC);
    assert_eq!(derived.account.len(), 56);
    assert!(derived.account.starts_with("GD"));
    assert_eq!(reference_account(&RFC8032_PUBLIC).unwrap(), derived.account);
    confirm_match(&RFC8032_SEED, &derived.account).unwrap();
    let secret = encode_seed(&RFC8032_SEED);
    assert!(secret.as_str().starts_with('S'));
    assert_eq!(secret.as_str().len(), 56);
    assert!(format!("{secret:?}").contains("redacted"));
}

#[test]
fn sep23_account_matches_both_encoders() {
    assert_eq!(encode_account(&SEP23_PUBLIC), SEP23_ACCOUNT);
    assert_eq!(decode_account(SEP23_ACCOUNT).unwrap(), SEP23_PUBLIC);
    assert_eq!(reference_account(&SEP23_PUBLIC).unwrap(), SEP23_ACCOUNT);
    assert_eq!(reference_public_key(SEP23_ACCOUNT).unwrap(), SEP23_PUBLIC);
    let zero = encode_account(&[0u8; 32]);
    assert_eq!(
        zero,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
    );
    assert_eq!(reference_account(&[0u8; 32]).unwrap(), zero);
}

#[test]
fn sep0005_secret_produces_the_published_account() {
    let derived = account_from_secret_strkey(SEP5_SECRET).unwrap();
    assert_eq!(derived.account, SEP5_ACCOUNT);
    assert_eq!(
        reference_account(&derived.public_key).unwrap(),
        SEP5_ACCOUNT
    );
    assert_eq!(ring_public_key(derived_seed()).unwrap(), derived.public_key);
    confirm_match(derived_seed(), SEP5_ACCOUNT).unwrap();
}

fn derived_seed() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static SEED: OnceLock<[u8; 32]> = OnceLock::new();
    SEED.get_or_init(|| {
        let parsed =
            stellar_strkey::ed25519::PrivateKey::from_string(SEP5_SECRET).expect("SEP-0005 secret");
        parsed.0
    })
}

#[test]
fn a_mismatched_account_is_fatal() {
    let derived = derive_from_seed(&RFC8032_SEED).unwrap();
    let err = confirm_match(&RFC8032_SEED, SEP23_ACCOUNT).unwrap_err();
    assert_eq!(err, Error::VerificationFailed);
    assert_eq!(err.to_string(), "FATAL ERROR — DO NOT USE THE WALLET");
    assert_ne!(derived.account, SEP23_ACCOUNT);
}
