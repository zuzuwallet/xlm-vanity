// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::process::Command;

fn bin() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_xlm_vanity") {
        return std::path::PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_xlm-vanity") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("xlm-vanity");
    path
}

#[test]
fn self_test_command_passes() {
    let output = Command::new(bin()).arg("self-test").output().unwrap();
    assert!(
        output.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cryptographic self-tests: PASS"));
    assert!(!stdout.contains("Seed:"));
}

#[test]
fn gzuzu_creates_no_wallet() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("xlm-vanity-cli-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    let output = Command::new(bin())
        .arg("generate")
        .arg("GZUZU")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"));
    assert!(stderr.contains("second character"));
    assert!(!stderr.contains("Seed:"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Public account:"));
    assert!(!stdout.contains("Cryptographic self-tests"));
    assert!(!dir.join("GZUZU-wallet.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
