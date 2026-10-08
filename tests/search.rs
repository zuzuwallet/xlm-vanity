// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use xlm_vanity::{counter_would_overflow, search, Error, COUNTER_HEADROOM, MAX_THREADS};

#[test]
fn counter_saturates_before_wrapping() {
    assert!(!counter_would_overflow(0));
    assert!(!counter_would_overflow(u64::MAX - COUNTER_HEADROOM - 1));
    assert!(counter_would_overflow(u64::MAX - COUNTER_HEADROOM));
    assert!(counter_would_overflow(u64::MAX));
    assert_eq!(MAX_THREADS, 256);
}

#[test]
fn preset_cancel_does_no_work() {
    let cancel = Arc::new(AtomicBool::new(true));
    let err = search("G", 4, cancel, |_, _| {}).unwrap_err();
    match err {
        Error::Cancelled { attempts } => assert_eq!(attempts, 0),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn prefix_g_stops_every_worker() {
    let cancel = Arc::new(AtomicBool::new(false));
    let hit = search("G", 4, Arc::clone(&cancel), |_, _| {}).unwrap();
    assert!(hit.account.starts_with('G'));
    assert_eq!(hit.account.len(), 56);
    assert!(hit.attempts > 0);
    assert!(hit.attempts < 10_000);
    assert!(cancel.load(Ordering::Acquire));
    let rendered = format!("{hit:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("seed: ["));
}

#[test]
fn cancel_during_a_wide_prefix_returns_cancelled() {
    // Ten characters constrain 42 public-key bits (2^42). A short wait cannot
    // finish that search. The cancel flag is the reason it returns.
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        flag.store(true, Ordering::Release);
    });
    let err = search("GAAAAAAAAA", 2, cancel, |_, _| {}).unwrap_err();
    match err {
        Error::Cancelled { .. } => {}
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn thread_count_is_checked() {
    let cancel = Arc::new(AtomicBool::new(false));
    assert_eq!(
        search("G", 0, Arc::clone(&cancel), |_, _| {}).unwrap_err(),
        Error::Threads
    );
    assert_eq!(
        search("G", MAX_THREADS + 1, cancel, |_, _| {}).unwrap_err(),
        Error::Threads
    );
}
