//! Checks that agree before a wallet is treated as valid.
//!
//! The independent path starts from the raw seed. `ring` derives the public
//! key and `stellar-strkey` encodes the account. A mismatch is fatal.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::error::Error;
use crate::independent::{reference_account, reference_public_key, ring_public_key};
use crate::stellar::derive_from_seed;

/// Require this crate, `ring`, and `stellar-strkey` to agree.
///
/// `account` is public. The seed is not printed on failure.
pub fn confirm_match(seed: &[u8; 32], account: &str) -> Result<(), Error> {
    let outcome = catch_unwind(AssertUnwindSafe(|| confirm_match_inner(seed, account)));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::VerificationFailed),
    }
}

fn confirm_match_inner(seed: &[u8; 32], account: &str) -> Result<(), Error> {
    let derived = derive_from_seed(seed).map_err(|_| Error::VerificationFailed)?;
    if derived.account != account {
        return Err(Error::VerificationFailed);
    }
    let ring_key = ring_public_key(seed)?;
    if ring_key != derived.public_key {
        return Err(Error::VerificationFailed);
    }
    let encoded = reference_account(&ring_key)?;
    if encoded != account {
        return Err(Error::VerificationFailed);
    }
    let parsed = reference_public_key(account)?;
    if parsed != derived.public_key {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}
