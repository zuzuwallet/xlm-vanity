// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stellar Ed25519 StrKey.
//!
//! Account IDs do not contain a network id. The same public key is the account
//! id on the public network and the test network. Funding a network creates
//! the account there. The network passphrase is used for transaction signatures
//! and is not an input to this derivation.

mod crc;
mod keys;
mod prefix;
mod strkey;

pub(crate) use keys::public_key_from_seed;
pub use keys::{account_from_secret_strkey, derive_from_seed, Derived};
pub(crate) use prefix::SEARCH_COUNTER_HEADROOM;
pub use prefix::{
    group_digits, median_attempts, probability_after, validate_prefix, PrefixEstimate,
    CONFIRMATION_THRESHOLD, MAX_PREFIX_LEN,
};
pub use strkey::{decode_account, decode_seed, encode_account, encode_seed};
