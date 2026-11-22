# Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer, AddressSanitizer) targets for every
parser that sees bytes before authentication, or from inside the desktop container
([architecture §8.1 and §12](../docs/architecture.md)). The crate is its own workspace, excluded from the
product workspace: it needs a nightly compiler and sanitizer flags, and `libfuzzer-sys` must never reach a
product build or its `Cargo.lock`.

The crates under test expose a few entry points behind a `fuzzing` Cargo feature that no product build
enables (`hx-crypto::fuzz`, `hx-transport::fuzz`, `hx-agent::link::fuzz`). Everything else is public API.

## Targets

| Target | Parser | Why it is a target |
|---|---|---|
| `proto_control` | `message::decode::<ControlMessage>` (+ framed), `peek_hello_version` | The first thing a TLS-reachable stranger's bytes are decoded as (`Hello`); round trip |
| `proto_messages` | `InputEvent`, `CursorEvent`, `TransferHeader`, frame length prefix, file/MIME/device-name rules | Post-handshake channel messages; the name rules guard what is written to disk |
| `proto_media` | `MediaHeader::decode`/`decode_frame`, `decode_datagram` | Fixed binary layouts; encode of a decoded value must reproduce the input |
| `transport_hello` | `Hello` check (`check_hello`) | Pre-auth: runs on the first control message of every QUIC and WebSocket connection |
| `transport_ws_first` | tungstenite framing under the server limits, channel byte, `Hello` | Pre-auth WebSocket path, from raw wire bytes |
| `transport_ws_session` | WebSocket framing then the channel router (control, input, cursor, datagrams, video, acks, clipboard/file transfers), as server and as client | Everything a connected peer can send; the server side is reachable by any paired device |
| `crypto_pairing` | pairing/auth envelopes, SPAKE2 elements (both sides), PIN check | Pre-auth pairing messages |
| `crypto_secrets` | `PairingToken::parse`, `PairingCode::parse`, `PairingCredential::parse`, `Pin`, `DeviceId::parse`, `sanitize_label` | Typed or scanned secrets and wire identifiers |
| `crypto_registry` | `PublicKey::from_spki` + registry lookup, registry file decode | The `PendingSession` registry lookup keyed by an attacker-chosen client key |
| `crypto_pin_record` | `PinHash::from_storage_string` | The stored PIN verifier (cost bounds guard Argon2id memory) |
| `ipc_frame` | `Decoder` under every policy (privd, admin, all link lanes, both roles), chunked | The framing under every internal socket |
| `ipc_privd_admin` | privd and admin frame decode + validation, secret frame, command table | gatewayd-admin and privd requests |
| `ipc_link` | session-link frames and messages, media header, transfers, validators | Container-supplied: everything `hx-session` sends |
| `ipc_text` | `sanitize_text` | The only filter between session text and the logs |
| `agent_link_session` | the gateway's `ctl`, `media` and `bulk` lane readers (production loops over socket pairs) | Container-supplied: framing, budgets, decode, Annex B check and transfer rules together |
| `agent_annexb` | `check_frame` (Annex B, NAL headers, SPS exp-Golomb) | Hostile video: runs on every frame from the container |
| `agent_update_manifest` | `Manifest::parse` + `check` | Root daemon input (signed, but parsed first) |
| `agent_update_sig` | minisign signature file and verify | Root daemon input |
| `agent_update_extract` | `extract_tar_gz` into a temporary directory | Root daemon unpacking a downloaded archive; asserts it stays inside its directory |
| `agent_install_stdin` | `install::stdin::read_frames` | Secrets the desktop app pipes to the installer over SSH |
| `agent_verifier_record` | `VerifierRecord::parse` + cost check | PIN/password verifiers handed to the gateway's admin socket |
| `agent_fetcher_url` | `parse_url` | The `Location` of a redirect from the update server |
| `pwcheck_shadow` | `find_hash`, `read_password` | `hx-pwcheck` runs as root on `/etc/shadow` lines and a password from stdin (the `crypt` call is not fuzzed) |

Not fuzzed, on purpose: the recipe TOML of `hx-provision` (maintainer supplied, not a trust boundary); the
fetcher's HTTP response reader (it is tied to a live TLS stream and sits behind rustls, the host allowlist and
the signature check: it needs a small refactor to be generic over `Read` first); `crypt(3)` itself;
third-party decoders (H.264 in the desktop client belongs to 1G: sandboxed, `max_pixels`).

## Running

```sh
rustup toolchain install nightly --profile minimal     # cargo-fuzz needs nightly sanitizers
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run transport_hello corpus/transport_hello seeds/transport_hello -- -max_total_time=300
cargo +nightly fuzz run agent_update_manifest corpus/agent_update_manifest seeds/agent_update_manifest \
    -- -max_total_time=60 -dict=dicts/agent_update_manifest.dict
```

`corpus/` and `artifacts/` are git-ignored. A crash is written to `artifacts/<target>/crash-*`; replay it with
`cargo +nightly fuzz run <target> artifacts/<target>/crash-...` and minimise it with `cargo +nightly fuzz tmin`.
Useful flags: `-max_len=N` (the nightly uses 512 to 16384 per target), `-timeout=20`, `-rss_limit_mb=2048`.

Input layouts that are not "the bytes themselves": `transport_ws_session` (`role byte | raw WebSocket
frames`), `agent_link_session` (`u16 ctl_len | u16 media_len | ctl | media | bulk`), `ipc_link` and
`ipc_privd_admin` (`selector | kind | body`), `ipc_frame` (`policy | chunk size | stream`),
`agent_update_extract` (`mode | bytes`: an odd mode wraps the bytes in gzip so the fuzzer edits tar headers
directly), `agent_update_sig` (`u16 len | signed data | signature text`).

## Seeds and dictionaries

`seeds/<target>/` holds real messages built with the production encoders; regenerate them (deterministic)
with `cargo run --bin gen-seeds` from this directory (stable toolchain). `dicts/<target>.dict` are libFuzzer
dictionaries for the text formats. The nightly passes both.

## Nightly

`.github/workflows/fuzz-nightly.yml` runs every target (15 minutes for the pre-auth and session-link
targets, 5 for the rest), restores the corpus from the Actions cache, uploads `crash-<target>` artifacts and
fails the job on any crash, hang or out-of-memory. The run summary shows one row per target (executions,
exec/s, coverage, corpus size, crashes) and a verdict: **a night counts for Gate 1 only if all 23 targets
reported and none failed**. Run it by hand with "Run workflow" and a small `seconds` for a smoke test.
The toolchain is a dated nightly (`NIGHTLY` in the workflow); move it forward deliberately.

## Adding a target

1. If the parser is not public, add a function to a `fuzz` module behind the crate's `fuzzing` feature (a
   child module of the one that owns the private items, so no visibility is widened) and say so in the commit.
2. `fuzz_targets/<name>.rs` with `#![no_main]` and `fuzz_target!`; assert invariants that are cheap: round
   trips, "accepted means within limits", no side effect outside a temporary directory. Never touch the network
   or the real disk, never read the clock or randomness without fixing them.
3. Add a `[[bin]]` entry to `Cargo.toml`, seeds to `src/bin/gen_seeds.rs` (and re-run it), a dictionary if the
   format is text, and a row to the matrix of `fuzz-nightly.yml` (and the `total` of its verdict job).
4. When a target finds a crash: minimise it, add it as a regression test in the owning crate's normal suite
   (stable Rust), fix the bug in its own commit.
