// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 account derivation.
//!
//! A Stellar seed is 32 bytes from the operating-system CSPRNG, used directly
//! as an RFC 8032 seed. `ed25519-dalek` hashes and clamps inside
//! `SigningKey::from_bytes`. This is not the 64-byte libsodium secret key, and
//! it is not mixed with the Stellar network passphrase.

use ed25519_dalek::SigningKey;

use crate::error::Error;
use crate::stellar::strkey::{decode_seed, encode_account};

pub struct Derived {
    pub public_key: [u8; 32],
    pub account: String,
}

pub fn derive_from_seed(seed: &[u8; 32]) -> Result<Derived, Error> {
    let public_key = public_key_from_seed(seed);
    let account = encode_account(&public_key);
    Ok(Derived {
        public_key,
        account,
    })
}

pub(crate) fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let signing = SigningKey::from_bytes(seed);
    let public_key = signing.verifying_key().to_bytes();
    // `ed25519-dalek` 2.2 implements `Drop` for `SigningKey` when the
    // `zeroize` feature is on. That drop wipes the 32-byte seed. The type
    // does not implement `Zeroize`, so there is no `zeroize()` method to call.
    drop(signing);
    public_key
}

/// Decode an `S...` seed and derive its account with this crate's encoder.
pub fn account_from_secret_strkey(secret: &str) -> Result<Derived, Error> {
    let seed = decode_seed(secret)?;
    derive_from_seed(seed.as_bytes())
}
