# xlm-vanity

An offline, security-focused vanity account generator for **Stellar Ed25519 accounts**.

`xlm-vanity` searches for a Stellar public account beginning with a prefix you choose, for example:

```text
GAZUZU...
```

Each candidate uses a fresh 32-byte seed from the operating-system CSPRNG. A winning seed is independently verified before it is encrypted and saved.

The private `S...` secret is **not printed during generation**.

---

## One important Stellar prefix rule

Every normal Stellar Ed25519 public account begins with:

```text
G
```

but the **second character is not arbitrary**.

For this StrKey type it can only be:

```text
A
B
C
D
```

So this is impossible:

```text
GZUZU
```

while these are valid vanity targets:

```text
GAZUZU
GBZUZU
GCZUZU
GDZUZU
```

The program checks this before running self-tests, starting worker threads, or writing a wallet.

---

# Highlights

- Offline Stellar Ed25519 vanity generation
- Fresh 32-byte OS CSPRNG seed for every candidate
- RFC 8032 Ed25519 derivation
- Native Stellar StrKey `G...` account encoding
- Multi-threaded search
- Fast public-key bit filtering before full StrKey encoding
- Prefix feasibility and difficulty estimation
- Built-in published Stellar/RFC test vectors
- Independent verification using `ring` and SDF's `stellar-strkey`
- Argon2id + ChaCha20-Poly1305 encrypted wallet files
- Best-effort secret-memory zeroization
- Atomic, no-overwrite wallet publication
- Wallet files created with mode `0600`
- Terminal-only `S...` seed export
- No Horizon, Stellar RPC, telemetry, HTTP client, or update checker
- `#![forbid(unsafe_code)]` in this crate

The compiled generator is designed to work with networking disabled.

---

# What it does

For each candidate, the program:

1. Reads exactly **32 bytes** from the operating-system CSPRNG using `getrandom`.
2. Uses those bytes directly as an RFC 8032 Ed25519 seed.
3. Derives the 32-byte Ed25519 public key with `ed25519-dalek`.
4. Tests the public-key bits required by the requested vanity prefix.
5. Builds the full Stellar `G...` StrKey only when the fast bit check matches.
6. Confirms that the full StrKey actually begins with the requested prefix.

A winning candidate is then verified independently before any wallet is written.

The 32-byte seed is encrypted and stored locally.

The private `S...` secret is **not displayed during generation**.

---

# Scope

This project intentionally has a narrow scope.

It supports:

- Stellar Ed25519 accounts
- public `G...` StrKeys
- vanity prefix searching
- encrypted standalone seed storage
- wallet verification
- offline `S...` seed export

It does **not** provide:

- muxed `M...` accounts
- contract `C...` identifiers
- `W...` StrKeys
- pre-authorized transaction signers
- hash signers
- SEP-0005 HD derivation
- mnemonics
- transaction signing
- Horizon access
- Stellar RPC
- online wallet functionality

SEP-0005 is used only as a published test vector.

---

# Network note

A Stellar account ID itself is **not network-specific**.

The same Ed25519 public key produces the same `G...` account ID on the public network and test network.

The network passphrase is not mixed into key derivation.

This project's wallet format records:

```text
network: "public"
```

to represent the intended network of the person using the file.

---

# Building on Fedora

The recommended workflow is:

> **Build and inspect the project while online, then disconnect before generating a real wallet.**

The recorded development environment used:

```text
rustc 1.99.0
cargo 1.99.0
```

Install the required tools:

```bash
sudo dnf install gcc python3

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

rustup component add rustfmt clippy
```

`python3` is required by the PTY integration test.

`ring` also compiles native code, so a working C compiler is required.

Before building, a restrictive umask is recommended:

```bash
umask 077
```

Run the normal checks:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit

cargo deny check advisories bans licenses sources

cargo build --release
```

Read both:

```text
Cargo.toml
Cargo.lock
```

before trusting the resulting binary.

`cargo audit` and `cargo deny` require network access to obtain advisory information.

The `xlm-vanity` binary itself does not.

---

# Recommended offline workflow

After building and reviewing the project, disconnect networking.

For example:

```bash
nmcli networking off
```

or physically disconnect the machine.

Then run:

```bash
./target/release/xlm-vanity self-test
```

Generate an account:

```bash
./target/release/xlm-vanity generate GAZUZU
```

Verify the encrypted wallet:

```bash
./target/release/xlm-vanity verify GAZUZU-wallet.json
```

For wallet storage, create a private directory:

```bash
mkdir -m 700 ~/wallet-output
```

and use:

```bash
umask 077
```

in the shell that runs generation.

Back up the encrypted wallet before funding the account.

For an offline key-generation environment, also consider disabling or avoiding:

- shared clipboard
- shared folders
- VM snapshots containing memory
- unencrypted swap
- hibernation
- crash dumps

The host operating system and hypervisor remain part of your trust boundary.

---

# Commands

### Self-test

```bash
xlm-vanity self-test
```

Runs the built-in cryptographic known-answer checks.

### Generate

```bash
xlm-vanity generate GAZUZU
```

Choose the number of worker threads:

```bash
xlm-vanity generate GAZUZU --threads 16
```

Choose the output file:

```bash
xlm-vanity generate GAZUZU \
  --threads 16 \
  --output GAZUZU-wallet.json
```

### Verify

```bash
xlm-vanity verify GAZUZU-wallet.json
```

Decrypts the wallet, derives the Ed25519 account again, and verifies it independently.

### Export

```bash
xlm-vanity export GAZUZU-wallet.json
```

Displays the private `S...` secret after explicit confirmation.

---

# Generation behavior

`generate` defaults to:

```text
std::thread::available_parallelism()
```

clamped to:

```text
1..=256
```

Values of `0` or greater than `256` are rejected.

The default wallet filename is:

```text
{prefix}-wallet.json
```

For example:

```text
GAZUZU-wallet.json
```

Existing destination files are never overwritten.

There is no overwrite flag.

The parent directory must already exist.

If the directory is writable by group or others, the program warns and continues.

For normal offline use:

```bash
mkdir -m 700 ~/wallet-output
```

is recommended.

---

# Search difficulty

Before searching, the program displays:

- requested prefix
- number of constrained public-key bits
- thread count
- estimated attempts
- median attempt count
- per-candidate probability
- checksum bits constrained

For:

```text
GAZUZU
```

the current estimate is:

```text
Public-key bits constrained: 22
Estimated attempts: 4,194,304
Median attempts: 2,907,270
Probability per candidate: 1 / 4,194,304
```

There is **no guaranteed completion time**.

A random search may finish much earlier—or much later—than the expected attempt count.

If the fair-bit estimate is at least:

```text
1,000,000,000
```

the program requires an additional confirmation:

```text
SEARCH
```

before workers start.

---

# Why `GAZUZU` is a 22-bit search

Stellar StrKeys use RFC 4648 Base32.

The public-account version byte is:

```text
0x30
```

or in binary:

```text
00110000
```

Base32 consumes five bits at a time.

The first five bits are:

```text
00110
```

which always encode as:

```text
G
```

Three version bits remain:

```text
000
```

The second Base32 character therefore contains:

```text
000
+
the first 2 bits of the public key
```

so only four values are possible:

```text
A
B
C
D
```

For:

```text
GAZUZU
```

the constrained public-key bits are:

```text
2 bits for A
+
5 bits for Z
+
5 bits for U
+
5 bits for Z
+
5 bits for U
=
22 bits
```

Therefore:

```text
Probability per candidate = 2^-22
Expected candidates       = 2^22
                          = 4,194,304
```

A class such as:

```text
any valid second character + ZUZU
```

would be a 20-bit condition, but this program searches one exact prefix at a time and does not provide alternation syntax.

---

# Prefix rules

A requested prefix must be a possible Stellar public-account StrKey.

Examples:

| Prefix | Result |
|---|---|
| `GAZUZU` | accepted |
| `GBZUZU` | accepted |
| `GCZUZU` | accepted |
| `GDZUZU` | accepted |
| `GZUZU` | rejected — second character cannot be `Z` |
| `ZUZU` | rejected — public accounts begin with `G` |
| `GZuZu` | rejected — StrKey is uppercase |
| characters outside `A-Z2-7` | rejected |
| longer than 56 characters | rejected |

A full 56-character valid account is also rejected because its expected search does not fit within the implementation's attempt counter.

A full account with an incorrect checksum is rejected as impossible.

---

# Passphrases

There is no:

```text
--password
```

flag.

Passphrases are read directly from the terminal with echo disabled.

When creating a new wallet, the passphrase must contain:

- at least **12 Unicode scalar values**
- no more than **1024 bytes**

The value is not trimmed.

The 12-character minimum is only intended to prevent obvious mistakes.

It is **not** a password-strength guarantee.

For example, twelve spaces technically satisfy the length rule but are not a secure passphrase.

Use a long, unique, randomly generated passphrase for anything you intend to fund.

`verify` and `export` can still open older wallets that use a shorter non-empty passphrase so an existing file is not stranded.

---

# Example generation

```text
Stellar Vanity Generator

Network: Stellar public
Key type: Ed25519
Target: GAZUZU
Second character: A (only A, B, C, or D can occur)
Public-key bits constrained: 22
Threads: 16

Cryptographic self-tests: PASS
Estimated attempts: 4,194,304
Median attempts: 2,907,270
Probability per candidate: 1 / 4,194,304
Checksum bits constrained: 0

Searching...

Attempts: 500,000
Rate: ... candidates/sec
Elapsed: ...

Match found.
Attempts: ...
Elapsed: ...
The public account is printed after the encrypted wallet is saved.

FOUND

Public account:
GAZUZU...

Independent verification: PASS

Encrypted secret saved:
GAZUZU-wallet.json
```

The account is deliberately withheld until wallet persistence succeeds.

If saving fails, the generated seed is discarded and the public account is not shown.

---

# Verifying a wallet

Run:

```bash
xlm-vanity verify GAZUZU-wallet.json
```

The program:

1. validates the wallet format;
2. derives the Argon2id encryption key;
3. authenticates and decrypts the stored seed;
4. derives the Ed25519 public key;
5. derives the Stellar `G...` StrKey;
6. runs the independent verification path;
7. compares the result with the stored account.

A successful verification reports:

```text
Wallet authentication: PASS
Secret validation: PASS
Ed25519 derivation: PASS
StrKey derivation: PASS

Stored:
GAZUZU...

Derived:
GAZUZU...

MATCH: YES
```

The decrypted seed and passphrase are dropped before this public output is printed.

---

# Exporting the private seed

Run:

```bash
xlm-vanity export GAZUZU-wallet.json
```

`export` is the only command that deliberately prints the private secret.

Both stdin and stdout must be attached to a terminal.

Redirected output is refused.

The command displays a warning and requires:

```text
EXPORT
```

before asking for the wallet passphrase.

It then prints one:

```text
Seed: S...
```

line.

> [!CAUTION]
> Anyone with the `S...` secret can control the associated Stellar account.

Never paste the secret into:

- a website
- an AI/chat service
- an issue report
- email
- a shell command
- an online account checker

After securely recording it, clear the terminal scrollback or close the terminal session.

---

# Ctrl-C and cancellation

Cancellation is designed to fail safely.

Ctrl-C sets an atomic flag rather than calling:

```text
process::exit()
```

During a search:

- worker threads observe the flag and stop;
- a candidate racing with cancellation is discarded;
- no wallet is written.

At a passphrase prompt:

- terminal echo is restored;
- the command cancels normally;
- no public account or private seed is printed.

During Argon2:

- the current calculation is allowed to finish internally;
- the cancellation flag is checked before success information is printed.

`export` checks the flag again after the `S...` secret has been encoded and immediately before displaying it.

Once terminal output itself begins, it cannot be taken back.

---

# When the public account is shown

The public `G...` account is withheld until the encrypted wallet has been safely published.

The intended sequence is:

```text
match found
      ↓
passphrase entered
      ↓
wallet encrypted
      ↓
temporary file written
      ↓
file fsynced
      ↓
final destination published
      ↓
parent directory fsynced
      ↓
seed and passphrase dropped
      ↓
FOUND
Public account: G...
```

If wallet persistence fails, the account is not shown.

If another file appears at the destination during generation, the write is refused.

---

# Stellar derivation

Each candidate starts as:

```text
32 bytes from the OS CSPRNG
```

The derivation is:

```text
32-byte RFC 8032 seed
        ↓
Ed25519 public-key derivation
        ↓
32-byte public key
        ↓
StrKey version byte 0x30
        ↓
CRC-16/XMODEM
        ↓
RFC 4648 Base32, no padding
        ↓
56-character G... account
```

## 1. Seed

The candidate is a full 32-byte RFC 8032 seed.

It is **not**:

- a pre-clamped scalar;
- a 64-byte libsodium secret key;
- SHA-512Half of a shorter seed.

`ed25519-dalek::SigningKey::from_bytes` performs the RFC 8032 hash-and-clamp process internally.

## 2. Public key

Ed25519 produces a 32-byte compressed point encoding.

## 3. Account StrKey

The raw account StrKey payload is:

```text
0x30
||
32-byte public key
||
2-byte CRC
```

The CRC uses CRC-16/XMODEM and is appended **low byte first**.

Those 35 bytes are encoded using RFC 4648 Base32 without padding.

The result is always 56 characters and starts with:

```text
G
```

---

# Secret StrKey

The private seed uses StrKey version:

```text
0x90
```

The raw payload is:

```text
0x90
||
32-byte seed
||
2-byte CRC
```

It is then encoded using the same unpadded RFC 4648 Base32.

The result starts with:

```text
S
```

The payload is the original 32-byte RFC 8032 seed.

It is not an expanded libsodium secret key.

---

# Independent verification

A search result is not trusted merely because the primary implementation produced the requested prefix.

The primary path uses:

- `ed25519-dalek`
- this crate's CRC implementation
- this crate's StrKey encoder

The independent verification path uses:

- `ring 0.17.14` for Ed25519 public-key derivation
- SDF's `stellar-strkey 0.0.18` for public StrKey encoding and decoding

A winning seed must satisfy all of these:

1. this crate derives the expected `G...` account;
2. `ring` derives the same 32-byte public key;
3. `stellar-strkey` produces the same account text;
4. decoding that public StrKey returns the same public-key bytes.

Both StrKey implementations are also checked against published SEP-23 vectors.

A mismatch is treated as fatal and no wallet is created.

---

# Known-answer tests

Self-tests run after prefix validation and before any vanity search starts.

A failure stops generation and writes no wallet.

Examples include:

| Check | Vector |
|---|---|
| CRC-16/XMODEM | `"123456789"` → `0x31C3` |
| SEP-23 account | `GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ` |
| all-zero public key | `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF` |
| RFC 8032 test seed | `9d61b19deffd5a60...` |
| RFC 8032 public key | `d75a980182b10ab7...` |
| SEP-0005 seed → account | `SBGWS...` → `GDRXE...` |

The private seeds in these vectors are published test data only.

They are not wallets produced by this program and should never be funded.

---

# Encrypted wallet format

The wallet contains the encrypted **32-byte raw Ed25519 seed**.

It does not store a plaintext `S...` string.

Version 1 uses:

| Property | Value |
|---|---|
| KDF | Argon2id |
| Argon2 version | 19 / `0x13` |
| Memory | 65,536 KiB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 16 random bytes |
| Output key | 32 bytes |
| AEAD | ChaCha20-Poly1305 |
| Nonce | 12 random bytes |
| Plaintext | 32-byte seed |
| Ciphertext | 48 bytes |
| Wallet mode | `0600` |

Authenticated metadata includes:

```text
xlm-vanity-wallet-v1
public account
ed25519
public
```

Changing the stored account, key type, or network field causes authentication to fail.

Production wallets must use the exact expected production Argon2 parameters.

Unexpected KDF settings are rejected before Argon2 is run.

---

# Wallet filesystem safety

Wallet creation uses a temporary file in the destination directory.

The process is:

```text
create temp file with O_CREAT | O_EXCL
        ↓
verify mode 0600
        ↓
write encrypted wallet
        ↓
fsync file
        ↓
hard-link to final destination
        ↓
refuse an existing destination
        ↓
remove temporary name
        ↓
fsync parent directory
```

There is no overwrite mode.

If directory synchronization fails after the link succeeds, the command returns an error and does not print the public account.

The file may still exist and can be checked later with:

```bash
xlm-vanity verify <wallet>
```

Wallet reads:

- open the path once;
- use Linux `O_NOFOLLOW`;
- reject symbolic links;
- read metadata and contents from the same descriptor;
- reject files larger than 1 MiB.

These filesystem protections currently target Fedora/Linux.

---

# Zeroization

Secret data uses the `zeroize` crate where practical.

This includes:

- candidate seed buffers
- decoded private StrKey buffers
- private Base32 working buffers
- Argon2 output
- Argon2 working memory
- AEAD key material
- decrypted wallet plaintext
- exported `S...` strings

`ed25519-dalek` is built with its zeroization feature.

The private StrKey encoder and decoder keep the:

- 35-byte StrKey payload;
- 56-byte encoded text;
- Base32 shift register

inside zeroizing buffers.

The canonical-format check does not allocate a second ordinary `S...` string.

This remains **best-effort memory hygiene**.

It cannot guarantee removal of:

- compiler-created copies
- CPU registers
- allocator copies
- swap
- hibernation
- crash dumps
- VM snapshots
- dependency-internal temporaries
- terminal scrollback after export

`ring` also stores an expanded private key internally and does not provide a way for this crate to zeroize that copy.

---

# Threat model

The project assumes:

- the OS CSPRNG is trustworthy;
- the CPU is trustworthy;
- the operating system is not already compromised;
- the Rust compiler/toolchain is trustworthy;
- dependencies have not been maliciously substituted.

The project tries to defend against mistakes such as:

- incorrect StrKey encoding;
- a private seed that does not match the displayed account;
- a wallet file being world-readable;
- passing a passphrase on the command line;
- silently overwriting an existing wallet;
- printing an account before its encrypted wallet exists;
- damaged or substituted ciphertext;
- continuing the search after a winner has been found.

It does **not** solve:

- malware
- keyloggers
- root access
- physical memory attacks
- side-channel attacks
- weak but sufficiently long passphrases
- compromised dependencies
- bugs inside `ed25519-dalek`, `ring`, `argon2`, or `chacha20poly1305`

---

# Limitations

A few important limitations are intentional:

- The program does not ask Stellar whether an account already exists.
- Funding an account creates it; this tool does not check the network.
- The program does not sign transactions.
- Spending requires a separate, reviewed signing workflow.
- Search estimates are probabilistic.
- Workers draw fresh random seeds rather than deterministically splitting a keyspace.
- A process killed abruptly may not run secret-zeroization destructors.
- Extremely difficult searches are rejected when the expected attempt count exceeds the supported counter.
- Account IDs are not network-specific.
- This is a standalone-key generator rather than an HD wallet.

---

# Benchmarks

The normal search path performs approximately:

```text
getrandom(32 bytes)
+
Ed25519 public-key derivation
+
prefix bit test
```

The full StrKey is built only when the fast prefix test matches.

Run Criterion benchmarks with:

```bash
cargo bench --bench derive
```

Benchmark results can vary significantly with:

- CPU model
- machine load
- power-management settings
- VM configuration
- thermal throttling
- thread count

Do not treat one benchmark run as a guaranteed search rate.

---

# Dependency and security review

Notable direct dependencies include:

| Crate | Role |
|---|---|
| `argon2` | wallet KDF |
| `chacha20poly1305` | authenticated wallet encryption |
| `ed25519-dalek` | primary Ed25519 derivation |
| `ring` | independent Ed25519 implementation |
| `stellar-strkey` | independent public StrKey implementation |
| `getrandom` | operating-system CSPRNG |
| `zeroize` | secret-memory cleanup |
| `rpassword` | terminal passphrase input |
| `clap` | command-line interface |

Security/dependency checks used during development include:

```bash
cargo audit

cargo deny check advisories bans licenses sources
```

The compiled generator does not contain a normal HTTP/RPC client stack.

Generation and verification are designed to work offline.

---

# Development checks

Before creating a release:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit

cargo deny check advisories bans licenses sources

cargo build --release

./target/release/xlm-vanity self-test
```

The integration suite includes PTY tests covering:

- Ctrl-C during `verify`
- Ctrl-C during `export`
- Ctrl-C during `generate`
- terminal-echo restoration
- suppression of private/public output after cancellation
- output-file collisions during generation

Those tests require `python3`.

---

# Repository layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore
LICENSE-APACHE
LICENSE-MIT
NOTICE
README.md

src/
├── lib.rs
├── main.rs
├── error.rs
├── secret.rs
├── hexutil.rs
├── self_test.rs
├── independent.rs
├── verify.rs
├── search.rs
├── wallet.rs
└── stellar/
    ├── crc.rs
    ├── strkey.rs
    ├── keys.rs
    └── prefix.rs

tests/
├── vectors.rs
├── prefix.rs
├── search.rs
├── cli.rs
├── pty_ctrlc.rs
└── pty_ctrlc.py

benches/
└── derive.rs
```

---

# References

The implementation was developed against:

- SEP-23 — Stellar StrKey
- SEP-0005 — published HD derivation test vectors
- RFC 4648 — Base32
- RFC 8032 — Ed25519
- RFC 9106 — Argon2
- RFC 8439 — ChaCha20-Poly1305
- Stellar Core source
- `js-stellar-base`
- SDF's `stellar-strkey`

---

# License

Copyright © 2026 ZuZu Wallet

https://ZuZuWallet.com

Support@ZuZuWallet.com

Licensed under either:

- Apache License, Version 2.0 — `LICENSE-APACHE`
- MIT License — `LICENSE-MIT`

at your option.

`publish = false` is set in `Cargo.toml`.

The GitHub repository is the distribution source; this crate is not published to crates.io.
