#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use zeroize::Zeroize;

use xlm_vanity::{derive_from_seed, validate_prefix};

fn bench_derive(c: &mut Criterion) {
    // RFC 8032 section 7.1 test 1. A published test seed, not a wallet this program saves.
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    // GAZUZU does not match this seed (the account starts with GD), so the bit
    // check is the usual miss path.
    let estimate = validate_prefix("GAZUZU").unwrap();
    c.bench_function("derive_from_seed", |b| {
        b.iter(|| {
            let derived = derive_from_seed(black_box(&seed)).unwrap();
            black_box(derived.account);
        });
    });
    c.bench_function("hot_prefix_compare", |b| {
        b.iter(|| {
            let derived = derive_from_seed(black_box(&seed)).unwrap();
            let matched = estimate.matches_public_key(black_box(&derived.public_key))
                && derived.account.starts_with(estimate.as_str());
            black_box(matched);
        });
    });
    c.bench_function("getrandom_and_hot_prefix", |b| {
        b.iter(|| {
            let mut entropy = [0u8; 32];
            getrandom::getrandom(&mut entropy).unwrap();
            let derived = derive_from_seed(black_box(&entropy)).unwrap();
            let matched = estimate.matches_public_key(black_box(&derived.public_key));
            black_box(matched);
            entropy.zeroize();
        });
    });
}

criterion_group!(benches, bench_derive);
criterion_main!(benches);
