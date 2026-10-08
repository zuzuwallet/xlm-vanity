// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent account derivation.
//!
//! `ring` derives the Ed25519 public key. `stellar-strkey` 0.0.18, the Stellar
//! Development Foundation StrKey crate, encodes it. Neither function is this
//! crate's encoder or `ed25519-dalek`.
//!
//! `ring` keeps the expanded private key inside `Ed25519KeyPair` and does not
//! zeroize it. Wiping the seed passed to `from_seed_unchecked` does not wipe
//! that copy.
//!
//! `stellar-strkey`'s `PrivateKey` can render an `S...` secret only through
//! `Unredacted`. This module never calls that. It encodes public keys only.

use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::error::Error;

pub fn ring_public_key(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
    let keypair =
        Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| Error::VerificationFailed)?;
    let raw = keypair.public_key().as_ref();
    if raw.len() != 32 {
        return Err(Error::VerificationFailed);
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(raw);
    Ok(public_key)
}

pub fn reference_account(public_key: &[u8; 32]) -> Result<String, Error> {
    let encoded = stellar_strkey::ed25519::PublicKey(*public_key).to_string();
    let text = encoded.as_str();
    if text.len() != 56 || !text.starts_with('G') {
        return Err(Error::VerificationFailed);
    }
    Ok(text.to_owned())
}

/// Decode `account` with `stellar-strkey` and return the raw public key.
pub fn reference_public_key(account: &str) -> Result<[u8; 32], Error> {
    let parsed = stellar_strkey::ed25519::PublicKey::from_string(account)
        .map_err(|_| Error::VerificationFailed)?;
    Ok(parsed.0)
}
