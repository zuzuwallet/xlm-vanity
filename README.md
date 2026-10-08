# xlm-vanity

Offline generator for a Stellar Ed25519 account whose StrKey starts with a chosen prefix.

`GZUZU` is not a possible account id. Stellar public account ids use uppercase Base32 and always start with `G`, because the StrKey version byte is `0x30`. The next character is only `A`, `B`, `C`, or `D`. `xlm-vanity generate GZUZU` rejects the prefix before any self-test, search, or wallet write. Reachable prefixes with the same four vanity characters are `GAZUZU`, `GBZUZU`, `GCZUZU`, and `GDZUZU`.

Passing `cargo test` does not make a wallet appropriate for significant funds. This is key-generation software. Review the derivation, the wallet format, and the compiled binary yourself, or have someone else review them, before you send value to an account it produced. A green test run shows that this program matched the vectors and checks named below.

Never paste a generated `S...` secret, the raw 32-byte seed, the encryption passphrase, or the wallet file into a website, an AI or chat system, an issue tracker, a shell command, or an online verification service. The terminal scrollback, shell history, and process list are copies of a secret. Only the public `G...` account may be shared.

The compiled generator does not open network connections. It has no Horizon client, Stellar RPC client, telemetry, update check, or HTTP client. `Cargo.lock` contains no `reqwest`, `hyper`, `tokio`, or `rustls` crate. Generation and verification work with networking disabled.

## What it does

For each candidate the program:

1. Reads exactly 32 bytes from the operating-system CSPRNG (`getrandom`, one call per candidate).
2. Treats those bytes as an RFC 8032 Ed25519 seed. `ed25519-dalek` hashes and clamps inside `SigningKey::from_bytes`.
3. Encodes the 32-byte public key as a Stellar account StrKey (`G...`).
4. Compares that account with the requested prefix. A bit test rejects most candidates before the full StrKey is built. A bit match is accepted only when the full encoding starts with the prefix.

The first match is checked again through `ring` and through the Stellar Development Foundation `stellar-strkey` crate before it is treated as found. The 32-byte seed is then encrypted and written to a new file created with mode `0600`. The `S...` secret is not printed. `export` is the only command that prints an `S...` secret, and it asks you to type `EXPORT` first.

Muxed accounts (`M...`), contract ids (`C...`), pre-auth and hash transaction signers, SEP-0005 HD derivation, mnemonics, transaction signing, and network RPC are out of scope. SEP-0005 is used only as a published test vector.

Account ids are not network-specific. The same public key is the account id on the public network and the test network. This program does not mix the network passphrase into the key. The wallet records `"network": "public"` as the intended network for the person who holds the file.

## Fedora: build online, then disconnect

Install a C compiler and Rust while the machine can reach the network. `ring` compiles C code.

```bash
sudo dnf install gcc python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
```

`python3` is required for the PTY test. The checks recorded in this file used rustc 1.99.0 and cargo 1.99.0. On a machine where `sudo` is unavailable, a user-local GCC works if `CC`, `AR`, `C_INCLUDE_PATH`, and `LIBRARY_PATH` point at that toolchain. A GCC configured with `--prefix=/usr` and then unpacked somewhere else does not search its own `usr/include` unless `C_INCLUDE_PATH` is set. That is an environment workaround, not the normal Fedora install.

From this directory, while still online:

```bash
umask 077
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
cargo deny check advisories bans licenses sources
cargo build --release
```

Read `Cargo.toml` and `Cargo.lock` before you trust the binary. The versions below are the ones resolved for this tree. `cargo audit` and `cargo deny` download advisory data. The `xlm-vanity` binary does not.

Then disconnect and use only the binary you just built:

```bash
nmcli networking off
./target/release/xlm-vanity self-test
./target/release/xlm-vanity generate GAZUZU
./target/release/xlm-vanity verify GAZUZU-wallet.json
```

`nmcli networking off` may require privileges. Unplugging the network is the same step. `GZUZU` will not start a search.

Copy the wallet file to offline storage. The file mode is `0600` from the moment it is created. Keep the passphrase with the same care as the file. Set `umask 077` in the shell that runs `generate`. Put the wallet in a directory you create with `mkdir -m 700`. Only after the encrypted secret is backed up, and after a separate review of how you will sign, consider funding the account. This program does not sign transactions and does not ask the network whether the account exists.

## Commands

```bash
xlm-vanity self-test
xlm-vanity generate GAZUZU
xlm-vanity generate GAZUZU --threads 16
xlm-vanity generate GAZUZU --threads 16 --output GAZUZU-wallet.json
xlm-vanity verify GAZUZU-wallet.json
xlm-vanity export GAZUZU-wallet.json
```

`generate` defaults to `std::thread::available_parallelism`, clamped to 1..=256. `--threads 0` and values above 256 are rejected. The default output path is `{prefix}-wallet.json`. An existing output file is refused. There is no overwrite flag. Pick a different `--output` path. The parent directory must already exist. Both checks happen before the search starts. If that directory is writable by group or others, `generate` prints a warning and continues. Create it with `mkdir -m 700`. Mode `0600` on the wallet does not stop someone who can write the directory from unlinking or replacing the file after the public account is printed.

A prefix whose fair-bit estimate is at least 1,000,000,000 attempts requires you to type `SEARCH` before the interrupt handler is installed. `GAZUZU` is under that line (4,194,304). A prefix of 8 characters is `2^32` and asks for `SEARCH`. A prefix that constrains 64 or more bits is rejected. That includes every full 56-character account id, even when the checksum matches.

`generate`, `verify`, and `export` read the passphrase from the terminal with echo disabled (`rpassword`). There is no `--password` flag. The passphrase is not trimmed. `generate` asks twice, up to three attempts. A new passphrase must contain at least 12 Unicode scalar values and at most 1024 bytes. That minimum only stops accidents: twelve spaces pass it, and they are not a strong passphrase. Use a generated passphrase for anything you might fund. `verify` and `export` still open an existing passphrase that is shorter than 12 characters, so an older wallet can be recovered. Empty passphrases are rejected on every command. The same new-passphrase rule is enforced by `write_encrypted_wallet`, not only by this binary.

During a search the program prints the prefix, the thread count, the estimate, self-test status, attempt totals, a candidates/sec figure, and elapsed time. On a match it prints attempt count and elapsed time, then asks for a passphrase. It prints the public account only after `write_encrypted_wallet` returns success. It does not print the seed.

`verify` is offline. It checks the wallet format, decrypts, derives the Ed25519 public key again, encodes the `G...` account again, and compares that account byte for byte with the stored account. It prints pass lines only after that whole check succeeds.

`export` requires a terminal on both stdin and stdout. Redirecting stdout is refused before any warning or secret is printed. It then prints warnings, waits for the line `EXPORT`, decrypts, and prints one `Seed:` line. Clear the terminal scrollback after you have copied the seed onto offline media.

Ctrl-C during the search sets a flag, the workers stop, and no wallet is written. After a match, Ctrl-C sets the same flag. The program returns normally, drops the seed buffers, and does not write a wallet. It does not call `process::exit`. The public account is printed only after `write_encrypted_wallet` returns success: the ciphertext was hard-linked into place and the parent directory sync succeeded. Cancelling the passphrase, or any error from that write, discards the seed and does not print the account. The message is `Wallet was not saved.` when the passphrase step fails, and `Wallet was not saved successfully.` when the write fails. A file that appears at the output path during the search is not this wallet. The write is refused, including when that file shows up at the passphrase prompt. If the ciphertext was linked and only the directory sync failed, the account is not printed. Run `verify` on that file to read the public account. The error says the file may not survive a power loss.

Passphrase prompts for `generate`, `verify`, and `export` run on the main thread after the handler is installed. `rpassword` reads Ctrl-C itself, restores terminal echo before it returns, and the program then discards the passphrase. `verify` and `export` do not install the handler until after any earlier confirmation line, so Ctrl-C on `SEARCH` or `EXPORT` still stops the process while echo is on. Argon2 is not interrupted mid-calculation. If Ctrl-C arrives during that calculation, or after it returns but before the next line is printed, `verify` does not print a pass line and `export` does not print the seed. A Ctrl-C that arrives after the print has started cannot be taken back. Once an encrypted write has started, that write finishes.

Example for a reachable prefix:

```text
Stellar Vanity Generator

Network: Stellar public
Key type: Ed25519
Target: GAZUZU
Second character: A (only A, B, C, or D can occur)
Public-key bits constrained: 22
Threads: 16

Cryptographic self-tests: PASS
Estimated attempts: 4,194,304 (fair-bit estimate, not a guarantee)
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

Attempts: ...
Elapsed: ...
Rate: ... candidates/sec

Independent verification: PASS

Encrypted secret saved:
GAZUZU-wallet.json
```

`verify` prints:

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

Those four pass lines are printed together after decryption and both derivations succeed. The stored and derived lines are the same public account.

## Derivation

Sources used for the constants in this tree:

- [SEP-23](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md), StrKey, version 1.3.0. Version-byte layout, CRC-16 polynomial `x^16 + x^12 + x^5 + 1`, and the Ed25519 account oracle `GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ`.
- [SEP-0005](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md), test 1, path `m/44'/148'/0'`. Published test vector only. Do not fund it.
- [`stellar-strkey` 0.0.18](https://github.com/stellar/rs-stellar-strkey) `crc` and `ed25519` modules. CRC-16/XMODEM, init 0, polynomial `0x1021`, no reflection, xorout 0, checksum appended little-endian. `"123456789"` checks as `0x31C3`, bytes `c3 31`.
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) Base32 alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`, no padding.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) section 7.1 test 1, the Ed25519 seed and public key.
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) section 4, Argon2id second recommended option.
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), ChaCha20-Poly1305.
- stellar-core `SecretKey::fromSeed` and js-stellar-base `encodeCheck` were read. They were not compiled or executed here. See the last section.

`ed25519-dalek` 2.2.0 (`SigningKey::from_bytes`) and `ring` 0.17.14 (`Ed25519KeyPair::from_seed_unchecked`) implement Ed25519. This crate does not.

Steps for one candidate:

1. The seed is 32 bytes from the OS CSPRNG. Workers do not share a userspace RNG, do not batch those reads, and do not walk a counter.
2. Those 32 bytes are an RFC 8032 seed. They are not a pre-clamped scalar, not a 64-byte libsodium secret key, and not SHA-512Half of a shorter seed. `SigningKey::from_bytes` hashes and clamps them.
3. The public key is the 32-byte Ed25519 point encoding.
4. The account StrKey is version `0x30`, then the 32 public-key bytes, then CRC-16/XMODEM of those 33 bytes, low byte first. `0x30` is SEP-23 `(6 << 3) | ALG_ED25519` with `ALG_ED25519 = 0`.
5. Those 35 bytes are RFC 4648 Base32 with no padding: 56 characters, starting with `G`.

The secret StrKey uses version `0x90`, which is `(18 << 3) | 0`, then the same 32-byte seed, then the same CRC. It also encodes to 56 characters and starts with `S`. The payload is the seed, not the expanded libsodium secret.

### Why the second character is only A–D

Base32 consumes bits from the high end. Version `0x30` is `00110000`.

- The first character is the top 5 bits, `00110`, which is `G`. Every Ed25519 account id starts with `G`.
- Three version bits remain: `000`. The second character is those three bits plus the top two bits of the public key. The four possibilities are `A`, `B`, `C`, and `D`.
- `E` through `Z` and `2` through `7` cannot occur in that position. `Z` would require version bits that this version byte does not have. The checksum is not involved.

`GZuZu` is rejected because lowercase is not a StrKey character. `ZUZU` is rejected because account ids begin with `G`. A character outside `A–Z` and `2–7` is rejected. A prefix longer than 56 characters is rejected.

### Known answers

Self-tests run after prefix validation and before any search. A failure prints `Cryptographic self-tests: FAIL` and writes no wallet. They compare complete strings.

| Check | Vector |
| --- | --- |
| CRC-16/XMODEM | `"123456789"` → `0x31C3`, bytes `c3 31` |
| SEP-23 raw public key | `3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a` |
| SEP-23 account | `GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ` |
| SEP-23 invalid accounts | `GAAAAAAAACGC6`, the SEP-23 string with a trailing `A`, `...UACUSI`, and `G47QYN...P2I` |
| All-zero public key | `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF` |
| RFC 8032 test 1 seed | `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` |
| RFC 8032 test 1 public key | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` |
| SEP-0005 test 1 | `SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN` → `GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6` |

The RFC 8032 account is checked as a 56-character `GD...` string that `stellar-strkey` and this encoder both produce. The full `G...` text is computed at runtime rather than copied into the source as an unchecked literal. The SEP-0005 `S...` string above is a published test vector, not a wallet this program generated.

`stellar-strkey` 0.0.18 also defines a `W` muxed-contract kind that SEP-23 v1.3.0 does not list. This program does not generate `W`, `M`, or `C` StrKeys. The crate README still says the library is early, incomplete, and not recommended for use. It is pinned at `=0.0.18` and used here as an independent encoder of public keys, not as a second Ed25519 implementation. Its `PrivateKey` debug output is redacted. The path that prints an `S...` secret is `Unredacted`. Generate and verify never call that.

### Independent check

`confirm_match` starts from the 32-byte seed and requires all of these to agree:

- This crate's dalek derivation and StrKey encoder produce the stored `G...` account.
- `ring` 0.17.14 `Ed25519KeyPair::from_seed_unchecked` produces the same 32-byte public key. The seed is passed through directly. There is no SHA-512Half and no `0xED` prefix.
- `stellar-strkey` 0.0.18 `ed25519::PublicKey::to_string` produces the same account, and `PublicKey::from_string` returns the same 32 bytes.

Dalek and ring are different Ed25519 implementations. This encoder and `stellar-strkey` are different StrKey implementations. Both encoders are also checked against the SEP-23 oracle, not only against each other. Calling this crate's encoder twice is not the independent check. `stellar-strkey` does not derive Ed25519.

`ring` stores the expanded private key inside `Ed25519KeyPair` and does not zeroize it. Wiping the seed passed to `from_seed_unchecked` does not wipe that copy. `ed25519-dalek` 2.2, with the `zeroize` feature, wipes the 32-byte seed in `SigningKey`'s `Drop`. That type does not implement the `Zeroize` trait, so this crate drops the signing key instead of calling `zeroize()`.

A bug shared by the SEP-23 specification and both encoders would still pass. A bug in the OS CSPRNG would still pass the vectors, because the vectors use fixed seeds.

## Prefix estimate

The estimate counts constrained public-key bits. It assumes those bits are independent and fair. Ed25519 stores the point coordinate little-endian, so a short prefix constrains low bits of that coordinate. This is not a proof that Ed25519 public keys make those bits uniform, and it is not a promise of wall-clock time.

A 56-character account is 280 bits: 8 version bits, 256 public-key bits, and 16 checksum bits. Checksum bits begin at character index 52 (the 53rd character). For a prefix of length `L` from 2 through 52, with a legal version and a legal second character:

- public-key bits = `5 * L - 8`
- expected candidates = `2^(5 * L - 8)`

`G` alone constrains no public-key bits. Expected attempts: 1. `GA`, `GB`, `GC`, and `GD` each constrain the two bits of the second character. Expected attempts: 4.

`GAZUZU` and the other three `*ZUZU` prefixes constrain 22 public-key bits. That is the 2 bits of the second character plus 5 bits for each of `Z`, `U`, `Z`, and `U`.

| Figure | Value |
| --- | --- |
| Probability per candidate | `2^-22` = 1 / 4,194,304 |
| Expected candidates | 4,194,304 |
| Median (50%) | round(4,194,304 × ln(2)) = 2,907,270 |
| After N candidates | `1 - (1 - 2^-22)^N` |

`32^4` = 1,048,576 would be four free Base32 characters. That is not this prefix. `G` is fixed by the version byte, and the second character is two bits, not five. A search for one of `GAZUZU`, `GBZUZU`, `GCZUZU`, or `GDZUZU` is `2^-22`. A class of "any second character, then `ZUZU`" would be `2^-20`. This program has no alternation syntax. Each command searches one prefix.

The median uses `f64::consts::LN_2`. `4_194_304` is `2^22` and is exact in `f64`. The product rounds to 2,907,270.

Length 14 (`G` plus 13 `A`s) is 62 bits and still fits in the `u64` attempt counter. It asks for `SEARCH` because the estimate is above one billion. Length 15 is rejected. A full valid 56-character account is rejected because `2^256` does not fit the counter, not because the checksum failed. A full account whose checksum bits disagree is rejected as impossible. The counter headroom is 1,048,576 attempts. A prefix whose estimate is above `u64::MAX - headroom` is rejected before the search. The in-search overflow check remains a backstop.

That 62-bit prefix is the widest search this program accepts. The counter stops near `2^64`. Under the fair-bit model, `(1 - 2^-62)^(2^64)` is about `e^-4`, roughly 1.8%. A search that reaches the counter returns an error and writes no wallet. Finishing `2^64` Ed25519 derivations is not a practical run, so the counter is left as a `u64`.

## Secret storage

The wallet file holds ciphertext of the 32 raw seed bytes. It does not hold an `S...` string. Ciphertext length is 48 bytes: 32 bytes of seed plus a 16-byte Poly1305 tag. Format version 1 accepts only the production KDF. `open_and_verify` returns a format error before Argon2 runs when the file asks for any other parameters, including the cheap parameters used by unit tests. The binary has no flag that selects a weaker KDF. In-crate tests use a private writer with a small Argon2 setup and still reject parameters outside fixed caps: memory at most 1,048,576 KiB, iterations 1..=100, parallelism 1..=16, and at least 8 KiB per lane.

- KDF: Argon2id, version 19 (`0x13`), memory 65536 KiB, 3 iterations, parallelism 4, 16-byte salt, 32-byte output. This is RFC 9106 section 4, second recommended option.
- AEAD: ChaCha20-Poly1305. The nonce is 12 bytes from the OS CSPRNG.
- Associated data is `xlm-vanity-wallet-v1`, a NUL, the public account, a NUL, `ed25519`, a NUL, and `public`. Changing the stored account, key type, or network name fails authentication.
- After decryption the program derives the account again and runs `confirm_match`. A stored account that does not match the seed is `FATAL ERROR — DO NOT USE THE WALLET`. Nothing is written in that case.

The JSON object uses `deny_unknown_fields` and a trailing newline. Fields:

```text
format_version: 1
network: "public"
key_type: "ed25519"
public_account: "G..."
kdf: "argon2id"
kdf_parameters: { version: 19, memory_kib, iterations, parallelism }
salt: base64, 16 bytes
cipher: "chacha20poly1305"
nonce: base64, 12 bytes
ciphertext: base64, 48 bytes
```

The salt is a top-level field. It is not repeated inside `kdf_parameters`. The public account stays in plaintext. Files larger than 1 MiB are rejected.

The file is created as a temporary name in the same directory with `O_CREAT|O_EXCL` and mode `0600`. If the created mode has any group or other permission bits, the write fails and the temporary file is removed. The temp file is `fsync`ed and then hard-linked onto the destination. The link fails if the destination already exists. The temp name is removed afterward. The parent directory is `fsync`ed. If that sync fails, the wallet file is left in place, the command returns an error, and the account is not printed. Run `verify` on the file to read the public account.

Create that directory with `mkdir -m 700`. A wallet mode of `0600` does not stop another user who can write the parent directory from removing or replacing the file after `generate` has printed the public account. The command warns when the parent is group- or world-writable. It does not refuse the directory, because some shared filesystems use those modes on purpose.

A read opens the path once with the Linux `O_NOFOLLOW` flag (`0x20000`) and takes the size and the bytes from that file descriptor. A symbolic link is rejected. `ELOOP` is errno 40. That flag is Linux-specific. This program targets Fedora. It does not depend on `libc` or `nix` at runtime. `O_NOFOLLOW` is passed through `OpenOptions::custom_flags`.

Decrypting a production wallet uses about 64 MiB of RAM for a few iterations. Plan for that on the machine that runs `verify` or `export`.

### Zeroization

`SecretBytes` and `SecretString` wrap the `zeroize` crate. `Debug` prints `[redacted]`. `ed25519-dalek` is built with its `zeroize` feature, and dropping `SigningKey` wipes the seed it holds. The Argon2 output and the AEAD key are `Zeroizing`. The Argon2 working memory, about 64 MiB for a production wallet, is a `Zeroizing` boxed slice of blocks passed into `hash_password_into_with_memory`. `argon2` is built with its `zeroize` feature. Direct `generic-array` 0.14.7 is pinned with the `zeroize` feature because argon2 0.5.3 calls `GenericArray::zeroize` without enabling that feature itself. There is one `generic-array` 0.14.7 in the lockfile.

`S...` encode and decode keep the 35-byte payload, the 56-byte text, and the Base32 shift register in `Zeroizing` buffers. The canonical check compares those bytes and does not allocate a second `S...` string. The copy that remains is the `SecretString` or `SecretBytes` returned to the caller. `verify` drops the decrypted seed before it prints the public account. `export` drops the passphrase after decryption and the raw seed after `S...` encoding. The `S...` string stays until the `Seed:` line. `generate` drops the passphrase and the raw seed after the wallet is saved, before it prints the public account. Public `G...` encoding does not use those secret buffers.

That is best-effort on a general-purpose Fedora workstation. It does not cover:

- copies the allocator, the compiler, or registers already made
- swap, hibernation, and crash dumps
- the expanded private key stored inside `ring`'s `Ed25519KeyPair`
- the per-lane address and input blocks `argon2` keeps on its own stack during key derivation
- terminal scrollback after `export`
- a process killed with `SIGKILL`, which does not run destructors

The program does not install a process-wide panic hook. Error text does not include a seed, a passphrase, or ciphertext. Disable crash dumps and swap, or encrypt swap, on a machine that will hold a seed in memory. `export` is the operation that deliberately puts the seed on the screen.

## Threat model and limitations

Assumed: the OS CSPRNG, the CPU, and the machine you build and run on are not already hostile. These break the program, and tests do not detect them:

- a compromised Fedora installation, including malware and a keylogger
- a compromised Rust compiler or toolchain
- a malicious Cargo dependency or other supply-chain substitution
- an OS CSPRNG that returns predictable bytes
- memory scraping, swap, and core dumps
- plaintext copies of the seed outside this process
- a weak encryption passphrase, including one that passes the 12-character check
- a stolen backup of the wallet together with the passphrase
- an implementation error in StrKey, the checksum, or the independent check
- a verifier that is not actually independent of the generator

In scope, and what the tests are aimed at: wrong StrKey encoding, a seed that does not match the printed account, a wallet file left world-readable, a passphrase on the command line, a search that continues after the first hit, and a damaged or substituted ciphertext.

Out of scope, and not solved here: malware on the host, someone reading the terminal during `export`, physical access, side channels, and bugs in `ed25519-dalek`, `ring`, `argon2`, or `chacha20poly1305`. Duplicate-version warnings from `cargo deny` are supply-chain noise to read, not a proof those crates are safe.

Further limits:

- The tool never asks the network if the account is already funded or already exists. Funding creates the account. This program does not check.
- There is no signing path. Funding the account still needs a separate, reviewed way to sign.
- Successful tests do not make this software appropriate for storing significant funds.
- Workers stop on the first match. Another worker can have drawn a seed it then discards. That seed is zeroized when the `Zeroizing` buffer drops. A killed process does not run that drop.
- If any worker panics or the RNG fails, a match from another worker is discarded and no wallet is written.
- A hit that races with Ctrl-C is discarded.
- Attempt counters stop with an error before a `u64` would wrap.
- `generate` and `write_encrypted_wallet` reject a new passphrase shorter than 12 Unicode scalar values. Argon2id does not rescue a guessable passphrase.
- Public wallet reads and writes accept only the production Argon2 parameters.

## Assumptions that were not executed

These were read, or checked with a local encoder against published strings. They were not confirmed by running stellar-core or js-stellar-base:

- stellar-core `SecretKey::fromSeed` calls libsodium `crypto_sign_seed_keypair` on 32 bytes. The source was read. It was not built.
- js-stellar-base `encodeCheck` uses version `6 << 3` and `18 << 3` and appends the checksum low byte first. The source was read. It was not executed.
- The fair-bit model is not a proof that Ed25519 public keys are uniform in the constrained bits.
- `ring` does not zeroize its expanded key. `argon2` does not wipe per-lane blocks on its stack.
- `stellar-strkey` 0.0.18's own README says the crate is early and not recommended for use. This tree does not treat 0.0.18 as an audited release. A review of older releases is not a review of this pin.
- No live `GAZUZU` or `GZUZU` search was run, and no generated wallet was funded.

## Benchmarks

Correctness is the constraint. The hot loop was measured after the known-answer tests passed. A search candidate is one `getrandom` of 32 bytes, Ed25519 public-key derivation, and a prefix bit test. The full StrKey is built only when the bit test matches. The benchmark below calls `derive_from_seed`, which also builds the StrKey on every iteration, so it does more work than the usual miss path.

The seed in `derive_from_seed` and `hot_prefix_compare` is RFC 8032 test 1. It is not a wallet. The prefix is `GAZUZU`, which that seed does not match, so the bit check takes the miss path. Entropy buffers in the `getrandom` bench are zeroized.

Two runs on this 16-thread machine disagreed. Criterion's "regressed" line on the second run is that comparison. The source did not change between them.

| Bench | `--quick` | 20 samples, 1 s each |
| --- | --- | --- |
| `derive_from_seed` | 24.64 µs (24.63–24.65) | 34.94 µs (33.67–36.21) |
| `hot_prefix_compare` | 26.14 µs (25.99–26.75) | 88.93 µs (85.48–92.40) |
| `getrandom_and_hot_prefix` | 28.67 µs (28.55–29.13) | 89.07 µs (86.97–91.51) |

At 28.7 µs a single core is on the order of 35,000 candidates per second. At 89 µs it is on the order of 11,000. Do not treat either row as the machine's capacity, and do not turn it into a promised completion time. `GAZUZU` expects 4,194,304 attempts under the fair-bit model. Cores do not have to scale linearly, and the machine can be busy. Repeat the measurement with:

```bash
cargo bench --bench derive
```

## Dependency and security review

Direct dependencies, from the resolved `Cargo.lock`:

| Crate | Version | Role |
| --- | --- | --- |
| argon2 | 0.5.3 | Argon2id, `zeroize` feature on |
| generic-array | 0.14.7 | Enables `GenericArray::zeroize` for argon2 0.5.3 |
| base64 | 0.22.1 | Wallet encoding |
| chacha20poly1305 | 0.10.1 | AEAD |
| clap | 4.6.7 | CLI |
| ctrlc | 3.5.2 | Ctrl-C flag |
| ed25519-dalek | 2.2.0 | Ed25519, with curve25519-dalek 4.1.3 |
| getrandom | 0.2.17 | OS CSPRNG |
| ring | 0.17.14 | Second Ed25519 implementation |
| rpassword | 7.5.4 | Passphrase prompt |
| serde / serde_json | 1.0.229 / 1.0.151 | Wallet JSON |
| stellar-strkey | 0.0.18 | Independent StrKey encoder, Apache-2.0 |
| thiserror | 2.0.21 | Errors |
| zeroize | 1.9.1 | Secret wipe |
| criterion | 0.5.1 | Benchmarks only |

`stellar-strkey` 0.0.18 depends on `data-encoding` 2.11.1 and `heapless` 0.9.3. `blake2` 0.10.6 is pulled in by `argon2`. `sha2` 0.10.9 is pulled in by `ed25519-dalek`. This crate does not call SHA-512Half.

`argon2` 0.5.3's `zeroize` feature calls `GenericArray::zeroize` but does not enable that impl. The direct `generic-array` dependency turns it on for the copy already required by `blake2`. It is not a second hash implementation.

`cargo audit` 0.22.2 loaded 1294 RustSec advisories and scanned 153 crate dependencies. Exit code 0. No vulnerability text was printed.

`cargo deny` 0.20.2 with `deny.toml`: advisories ok, bans ok, licenses ok, sources ok (crates.io only). Exit code 0. It warned:

- `syn` 2.0.119 and 3.0.6
- `windows-sys` 0.52.0 (via `ring`) and 0.61.2
- `CC0-1.0` is on the allow-list and was not encountered. This lockfile has no CC0 crate. The allowance is unused.

The license allow-list is MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-3-Clause, BSD-1-Clause, ISC, Unicode-3.0, CC0-1.0, Unlicense, and Zlib. `stellar-strkey` is Apache-2.0. `ring` is Apache-2.0 AND ISC.

`cargo-geiger` was not installed. This crate's library, binary, integration tests, and benchmark set `#![forbid(unsafe_code)]`. `ring`, `curve25519-dalek`, and other dependencies contain unsafe code inside their own crates.

The `cli` feature of `stellar-strkey` is not enabled. Generation and verify do no DNS, HTTP, Horizon, RPC, telemetry, or update checks.

Recorded local gates, after the source in this tree was in place:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all` (51 tests)

## Layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore          /target and *-wallet.json
LICENSE-APACHE
LICENSE-MIT
README.md
src/lib.rs            crate root, no unsafe
src/main.rs           CLI
src/error.rs
src/secret.rs         zeroizing wrappers
src/hexutil.rs
src/self_test.rs      official vectors, run before a search
src/independent.rs    ring and stellar-strkey
src/verify.rs         dalek + ring + stellar-strkey
src/search.rs         threads, cancellation, one getrandom per candidate
src/wallet.rs         Argon2id, ChaCha20-Poly1305, and wallet tests
src/stellar/crc.rs    CRC-16/XMODEM, little-endian
src/stellar/strkey.rs account and seed StrKey
src/stellar/keys.rs   Ed25519 from a 32-byte seed
src/stellar/prefix.rs prefix rules and the attempt estimate
tests/vectors.rs
tests/prefix.rs
tests/search.rs
tests/cli.rs
tests/pty_ctrlc.rs
tests/pty_ctrlc.py
benches/derive.rs
```

## Tests

`cargo test --all` covers CRC-16/XMODEM and checksum byte order, SEP-23 account encoding and the invalid `G...` strings, version bytes `0x30` and `0x90`, the all-zero account, RFC 8032 test 1 through dalek and ring, SEP-0005 `S...` → `G...`, agreement with `stellar-strkey`, prefix rejection for `GZUZU`, `GZuZu`, `ZUZU`, illegal characters, and overlong strings, the `GAZUZU` estimate, the 15-character range rejection, a full account versus a checksum-flipped full account, encrypted round trip, mode `0600`, wrong passphrase, tampered ciphertext, tampered account, truncated JSON, unknown fields, hostile KDF parameters, non-production KDF rejection, symlink rejection, overwrite refusal, independent verification failure, multithreaded cancellation, and a preset cancel. One test runs `python3` on a PTY: Ctrl-C at the `verify`, `export`, and `generate` passphrase prompts must restore echo, cancel, print no seed, and print no public account before a wallet exists. The same test plants a file at the output path during the `generate` passphrase prompt and checks that the command fails with no `FOUND` line and no `Public account:` line. That test fails if `python3` is not installed. The passphrase in that test is a fixture, not a secret to reuse.

Integration tests find the binary via `CARGO_BIN_EXE` when cargo provides it, and otherwise via `target/debug` or `target/release`. A custom `CARGO_TARGET_DIR` can break that fallback.

## License

Copyright (c) 2026 ZuZu Wallet.

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.

`publish = false` in `Cargo.toml`. This GitHub repository is the release. The crate is not published to crates.io.
