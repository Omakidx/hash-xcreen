# Spike S5: browser transport and certificates

Status: complete (two criteria UNVERIFIED, see below). Date: 2026-11-20. Code: `spikes/s5-webtransport/` (standalone crate, not in the root workspace).

## Goal

Confirm the web client's foundations: one Rust server serves native QUIC (ALPN `hx/1`) and WebTransport (HTTP/3) on the same UDP port; browsers receive one-frame-per-stream H.264 and decode 1080p60 with WebCodecs; certificates work without a domain; Safari status is recorded.

## Setup

| Item | Version |
|---|---|
| Rust | 1.100.0, edition 2024 |
| `wtransport` | 0.7.2 (features `quinn`, `ring`, default features off) |
| `quinn` | 0.11.12 (single copy in the tree, shared with `wtransport`) |
| `rustls` | 0.23.46 (ring provider, TLS 1.3 only) |
| `rcgen` | 0.14.10 |
| `tokio-tungstenite` / `tokio-rustls` | 0.30.0 / 0.26.6 |
| Chrome | 158.0.8127.36, `--headless=new` |
| Firefox | 160.0.1 (snap), `--headless` |
| Machine | Ubuntu 24.04 VM, 16 cores, no GPU, so every codec ran in software; loopback only |

## What was built

- `src/main.rs`, one binary with `serve`, `native-check`, `ws-check`.
  - One `quinn::Endpoint` on UDP 4433 offering ALPN `[h3, hx/1]`. The accept loop calls `Connecting::handshake_data()` (available before the handshake completes), reads the negotiated ALPN, and dispatches: `h3` goes to `wtransport::endpoint::IncomingSessionFuture::with_quic_connecting` (path must be `/wt`), `hx/1` goes to a plain quinn echo session (stream `ping` returns `pong:ping`, datagram echo).
  - WebTransport session: every client uni stream is read fully and echoed on a fresh server uni stream (one frame per stream, 24-byte header with client and server timestamps); datagrams are echoed.
  - WebSocket over TLS (rustls plus `tokio-tungstenite`) on TCP 4433, same port number as the UDP endpoint.
  - Plain HTTP on `127.0.0.1:8080` serves the test page, `/info` (UDP port and certificate hash) and `/report`, `/log` (browser results are written to the server log). `http://127.0.0.1` is a secure context, so no HTTPS page was needed.
  - Self-signed ECDSA P-256 certificate, valid 13 days, SANs `localhost`, `127.0.0.1`, `::1`, SHA-256 published via `/info`.
- `web/index.html`: connects with `serverCertificateHashes`, tests datagrams, encodes 300 frames (1920x1080, 60 fps, `avc1.64002a`, Annex B, realtime latency mode, 8 Mbit/s target, moving gradient plus text) with `VideoEncoder`, then (a) burst-decodes from memory, (b) streams them paced at 60 fps over per-frame uni streams through the server, decodes in index order, (c) sends them unpaced to measure stream throughput. It POSTs a JSON report.
- `run-browser.sh chrome|firefox`: starts the release server, launches the headless browser, waits for the report.

## Measured results (loopback, software codecs, 300 frames, 1080p60)

Native and fallback checks (debug build, one run each):

- `native-check`: `native hx/1 stream reply: pong:ping`, datagram echo OK, ALPN `hx/1` negotiated. A wrong pinned hash fails with `certificate hash mismatch`.
- `ws-check`: `websocket-over-TLS echo: ping` on TCP 4433.

Chrome 158 (headless, release server). Two full runs, run 2 shown with run 1 in brackets:

| Metric | Result |
|---|---|
| WebTransport connect | 9 ms [24 ms] |
| Datagrams (200 sent, 64 B) | 200 received, 0 % loss; RTT mean 1.9 ms, p99 5.4 ms [mean 2.1, p99 6.3]; max datagram size 1211 B |
| Encode (software, realtime) | 57 fps [67 fps]; 16.6 kB/frame average, 7.96 Mbit/s |
| Burst decode (queue-limited) | 281 fps [277 fps] |
| Paced 60 fps stream run | 300/300 sent, received, decoded; **decoded 60.0 fps**; 0 out-of-order |
| Echo RTT per frame | p50 1.8 ms, p95 4.1, p99 6.4, max 11.4 |
| Server-to-browser one-way (server clock to full receive) | p50 0.9 ms, p99 5.2 ms |
| Per-frame decode time (decode call to output) | mean 4.7 ms, p50 4.2, p95 7.7, p99 18.7, max 27.5 |
| Decoder output gap | p50 16.7 ms, p99 24.9 ms |
| Unpaced echo of 300 frames | 538 frames/s, 71.6 Mbit/s |
| Pixel check | last decoded frame sampled, non-black `[33,40,191]` |

Firefox 160.0.1 (headless):

| Metric | Result |
|---|---|
| WebTransport with `serverCertificateHashes` | connects, 60 ms |
| Datagrams | 198/200 received (1 % loss), RTT mean 4.4 ms |
| Encode (software) | 3.2 fps (94 s for 300 frames; includes software canvas drawing) |
| Burst decode | **37 fps**, pixels decoded correctly |
| Paced 60 fps stream run | only 105/300 frames received and decoded within the window; decode time p50 468 ms with a 13 s stall; **decoded 7 fps** |
| Unpaced echo | 0 frames (run was already behind) |

Interpretation: Firefox's transport path works (streams and datagrams were exchanged, frames decoded correctly). Its 1080p decode in a GPU-less headless VM is far below 60 fps, and the saturated content process also stalled stream reads. We cannot say from this run whether Firefox with hardware decode would reach 60 fps. Treat as a risk, not a conclusion.

## S5 pass criteria

| Criterion | Result | Notes |
|---|---|---|
| WebTransport works in Chromium | **PASS** | Session, per-frame uni streams, datagrams, cert hashes. |
| WebTransport works in Firefox | **PASS** (transport) | Connect, datagrams, streams verified on 160.0.1. Streams stalled under decode overload (see above). |
| Safari status recorded | **PASS (recorded, not tested)** | See research. No Apple device here. |
| IP certificate issues and renews | **UNVERIFIED** | No public IP, so no issuance attempted. Research below says it is supported by the CA and the client library. |
| Browser decode at 1080p60 | **PASS in Chromium** (software decode, 60.0 fps sustained, 4.2 ms median decode); **FAIL in Firefox on this VM** (37 fps burst, no GPU); Safari **UNVERIFIED** | The input was the browser's own `VideoEncoder` output, not the S2 stream; real capture content and bitrates are not covered. |

## Research (sources)

- Safari: WebTransport shipped in Safari 26.4 (March 2026), per secondary coverage; the floor is iOS and macOS 26.4. Not verified against Apple's own notes. Sources: https://9to5mac.com/2026/03/24/apple-details-safari-26-4-with-44-new-features-191-bug-fixes-more/ and MDN (reports Baseline "newly available" since March 2026): https://developer.mozilla.org/en-US/docs/Web/API/WebTransport. Whether Safari supports `serverCertificateHashes` is **not confirmed** (the MDN page fetched did not show the compatibility table). If it does not, Safari needs a CA-trusted certificate or the WebSocket fallback.
- Let's Encrypt IP certificates: generally available since 2026-01-15, IPv4 and IPv6, only via the `shortlived` profile, 160 hours (about 6.7 days) validity. https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability
- Challenges for IPs: `http-01` and `tls-alpn-01` work, `dns-01` cannot. https://letsencrypt.org/docs/challenge-types/ (http-01 needs port 80 reachable on the IP; tls-alpn-01 needs port 443.)
- `instant-acme` 0.8.5: `Identifier::Ip(IpAddr)` exists ("not all ACME servers accept orders with IP address identifiers") and `NewOrder::profile(&str)` exists. https://docs.rs/instant-acme/0.8.5/instant_acme/enum.Identifier.html and https://docs.rs/instant-acme/0.8.5/instant_acme/struct.NewOrder.html. Not exercised against a real CA.
- No code sketch for IP issuance was written; it would be unverified and the API surface above is simple (`NewOrder::new(&[Identifier::Ip(ip)]).profile("shortlived")`, then answer `http-01` or `tls-alpn-01`).

## Decision

1. **Library: `wtransport` 0.7.x**, used on top of our own `quinn` endpoint through its `quinn` feature (`IncomingSessionFuture::with_quic_connecting`). It gave working Chromium and Firefox sessions with little code, exposes the underlying quinn connection, and was never in the way of the native protocol. `h3` + `h3-webtransport` was not tried (spike time spent elsewhere); keep it as the fallback if `wtransport` limits (e.g. stream priorities, its single maintainer) bite.
2. **Port sharing: ALPN dispatch on one `quinn::Endpoint`.** Offer `[h3, hx/1]`, read the ALPN from `handshake_data()`, route `h3` to WebTransport and `hx/1` to native code. Proven working. Both protocols share one UDP port, one certificate and one congestion-control configuration. Native clients should pin the certificate or key themselves (as the spike's pin verifier does).
3. **Safari: do not depend on WebTransport for Safari yet.** It exists from 26.4 but `serverCertificateHashes` support is unconfirmed and untested here. Use the WebSocket-over-TLS fallback (proven feasible on the same port number) when WebTransport is missing or the connection fails, and re-test Safari 26.4+ on real hardware before Phase 3 locks the client.
4. **Certificates without a domain:** use a short-lived IP certificate from Let's Encrypt (`shortlived` profile, `http-01` or `tls-alpn-01`, via `instant-acme` with `Identifier::Ip`), renewed well inside its 160-hour life (for example every 2 days). Because that requires a publicly reachable IP and port 80 or 443, the **fallback is a self-signed ECDSA P-256 certificate rotated every less than 14 days and pinned with `serverCertificateHashes`** (proven in Chromium and Firefox), which also covers LAN and private IP use. The hash is handed to the web client through the paired/authenticated page, so the page itself must come from a trusted origin (or a localhost-style secure context). Issuance and renewal remain to be verified on a machine with a public IP.

## Not verified here, and why

- Let's Encrypt IP issuance and renewal: no public IP; no real issuance allowed by the brief.
- Safari, iOS: no Apple devices.
- Hardware decode: no GPU; Firefox 1080p60 result is a software-only measurement.
- Real network behaviour (loss, jitter, BBR): loopback only. Latency numbers show framework overhead, not network performance.
- Decoding the actual S2 capture stream: input was synthetic, 8 Mbit/s, three keyframes.
- Whether Chrome requires flags: none were needed beyond `--headless=new` (the page is on `http://127.0.0.1`, a secure context; no `--ignore-certificate-errors`, no `--origin-to-force-quic-on`).
- Firefox headless needed a profile directory in the home folder (snap confinement rejects `/tmp`).

## Risks and follow-ups

- Frames arrive on independent streams and can reorder; the page reorders by index before decoding (zero reordering seen on loopback). The real protocol needs a bounded reorder/skip policy.
- Firefox software decode at 1080p is slow; test with hardware decode, and consider a lower resolution/frame rate cap for Firefox.
- `wtransport` pulls its own `rustls` provider choice (`ring` here); `docs/tech-stack.md` says `rustls` only, which is consistent, but check against `cargo-deny` before production adoption.
- Dependencies used (`wtransport`, `rcgen`, `tokio-tungstenite`, `sha2`) are outside tech-stack.md's current table; add `wtransport` (and note the h3 alternative) when Gate 0 updates the docs.
- Re-test serverCertificateHashes in Safari 26.4+ and the 14-day limit renewal flow (page must reload hashes; sessions pinned to an old hash break at rotation unless two hashes are offered during overlap).

## Reproduce

```
cd spikes/s5-webtransport
cargo build --release
./run-browser.sh chrome      # or firefox; prints the JSON report
cargo build && target/debug/s5-webtransport serve &   # then: native-check 4433 <hash>, ws-check 4433 <hash>
```
