//! Offline Stellar Ed25519 vanity account generator.
//!
//! This crate does not use `unsafe`. Ed25519 comes from `ed25519-dalek`.
//! The independent check uses `ring` and the Stellar Development Foundation's
//! `stellar-strkey` crate. The hand-written pieces are SEP-23 StrKey and the
//! wallet wiring.

#![forbid(unsafe_code)]

pub mod error;
mod hexutil;
pub mod independent;
pub mod search;
pub mod secret;
pub mod self_test;
pub mod stellar;
pub mod verify;
pub mod wallet;

pub use error::Error;
pub use search::{counter_would_overflow, search, SearchHit, COUNTER_HEADROOM, MAX_THREADS};
pub use secret::{SecretBytes, SecretString};
pub use self_test::run_self_tests;
pub use stellar::{
    account_from_secret_strkey, decode_account, decode_seed, derive_from_seed, encode_account,
    encode_seed, group_digits, validate_prefix, Derived, PrefixEstimate, CONFIRMATION_THRESHOLD,
    MAX_PREFIX_LEN,
};
pub use verify::confirm_match;
pub use wallet::{
    check_new_passphrase, check_passphrase, open_and_verify, write_encrypted_wallet, KdfParams,
    OpenedWallet, MIN_NEW_PASSPHRASE_CHARS,
};
