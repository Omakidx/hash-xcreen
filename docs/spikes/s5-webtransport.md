# Spike S5: browser transport and certificates

Status: complete. The local run (below) left IP certificates and real-network behaviour UNVERIFIED; the [public-server run](#public-server-run-2026-11-20) settled both (one Chrome IPv6 failure open, Safari still deferred). Date: 2026-11-20. Code: `spikes/s5-webtransport/` (standalone crate, not in the root workspace).

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
| IP certificate issues and renews | **UNVERIFIED** in the local run; **PASS** in the public-server run | See the public-server section. |
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

## Public-server run (2026-11-20)

Follow-up on a real server: Ubuntu 26.04, 4 vCPU, public IPv4 85.190.123.74 and IPv6 2001:880:a:339::26, no domain name. Browsers ran on the spike machine (Ubuntu 24.04 VM, 16 cores, no GPU, headless Chrome 158.0.8127.36 and Firefox 160.0.1) and reached the server over the internet. Round-trip time (ICMP) was 14.9 ms over IPv4 (min 14.3, max 15.5, 0 % loss) and about 18 ms over IPv6. The spike machine was heavily loaded by other jobs during the run (load average 13 to 18 on 16 cores), which affects the software encode and decode numbers below.

### What was built

All in `spikes/s5-webtransport/`:

- `src/acme.rs`, subcommands `acme` and `acme-info`, using `instant-acme` 0.8.5 (features `ring`, `hyper-rustls`, `rcgen`, `time`, `x509-parser`; default features off so `aws-lc-rs` stays out and `ring` remains the single provider). It requests an `Identifier::Ip` order with `NewOrder::profile("shortlived")`, answers `http-01` from a small listener on TCP 80, generates an ECDSA P-256 key and an empty-subject CSR with `rcgen`, finalizes with `finalize_csr`, and writes `key.pem` (mode 0600 from creation) and `fullchain.pem`. `--replaces <old cert>` computes the ARI certificate id (authority key id plus serial) and sets `NewOrder::replaces`; the ARI window is printed through `Account::renewal_info`. The account key is stored per environment (`account.json`, 0600). Multiple IPs are accepted (`--ip a,b`) and `--bind` allows an IPv6 listener.
- `src/main.rs`: `serve --cert --key --bind :: --port 443 --https-port 443 --ws-port 4433` serves the CA certificate on the same three endpoints as before (UDP 443 for QUIC with `h3` and `hx/1`, TCP 443 for the HTTPS test page and `/report`, TCP 4433 for WebSocket over TLS), dual-stack. `native-check` and `ws-check` take `--host H` and a hash argument `ca`, which validates the chain against the Mozilla root set instead of pinning, and now print connect time and 20 datagram round trips. The local mode (self-signed, loopback, pinned hash) is unchanged and was re-checked.
- `web/index.html`: when the server reports `public`, the page connects to `https://<page host>:<port>/wt` with no `serverCertificateHashes`. `run-public.sh` drives a local headless browser at a remote page and fetches the report from the server.

Challenge choice: **`http-01` on TCP 80**. `tls-alpn-01` needs the ACME client to answer a special TLS handshake on TCP 443, which is where the server being renewed already listens, so renewal would need the TLS stack to know about challenges or the server to stop. `http-01` needs only a tiny listener on a separate port and ran next to the live server on 443. The cost is that TCP 80 must be reachable from the internet at issuance time. The provider did not filter it (TCP 80, 443, 4433 and UDP 443 were reachable on the first probe; no host firewall).

### Issuance results

Privilege: `setcap cap_net_bind_service=+ep` on the spike binary (no root process, files owned by the login user). Times are from the client's start to the certificate download (account load, order, validation, finalize, download).

| # | CA | Identifiers | Result | Leaf serial | Issuer | Total time |
|---|---|---|---|---|---|---|
| 1 | staging | IPv4 | FAILED at finalize: `Cannot issue for "rcgen self signed cert": Domain name contains an invalid character`. The validation itself had passed (7 `http-01` requests). Cause: `rcgen::CertificateParams::default()` carries a default common name. Fix: empty subject. | n/a | n/a | n/a |
| 2 | staging | IPv4 | OK | `2c522f4d7bec02259ddb6aa66f4cf71cba0b` | `(STAGING) Artificial Amaranth YE1` | 5.3 s |
| 3 | staging | IPv6 | OK | `2cd0a50e50651464922a0b19f9391f45d919` | `(STAGING) Baloney Bulgur YE2` | 6.5 s |
| P1 | **production** | IPv4 | **OK** | `0578878ce748548bdef4747811c0a026438c` | `C=US, O=Let's Encrypt, CN=YE2` | 5.0 s (order 1.3 s, validation 1.1 s) |
| P2 | **production** | IPv4, renewal (`replaces` = P1) | **OK** | `05d8550940641d01bd35d11fba032c78abf1` | `CN=YE2` | 4.0 s |
| P3 | **production** | IPv4 + IPv6 in one certificate | **OK** | `05a3f0dab62967474609be7dee0d8d1d6618` | `CN=YE1` | 7.4 s (IPv6 validation 4.5 s) |

In total: three production certificates, and three staging orders (two issued, one failed at finalize). One production ACME account was created (no contact address; the terms of service were accepted, as account creation requires) and its key was deleted with the rest.

Certificate details (P1; P2 and P3 are identical in shape):

| Field | Value |
|---|---|
| Subject | empty (no common name); SAN holds only the IP address; EKU `serverAuth` |
| notBefore / notAfter (P1) | 2026-11-20 10:47:59 UTC / 2026-11-27 02:47:58 UTC = 575 999 s = **160.0 h** |
| Backdating | issued about 11:46 UTC, so notBefore is about 1 h in the past; about 159 h of usable life |
| P2 validity | 10:49:33 UTC to 2026-11-27 02:49:32 UTC (160.0 h) |
| P3 validity | 10:51:43 UTC to 2026-11-27 02:51:42 UTC (160.0 h), SAN `85.190.123.74` and `2001:880:a:339::26` |
| Leaf key / signature | ECDSA P-256 (our `rcgen` key) / ecdsa-with-SHA256 |
| Chain as delivered (4 certificates) | leaf, `Let's Encrypt YE2` (or `YE1`), `ISRG Root YE`, `ISRG Root X2` cross-signed by `ISRG Root X1` |
| Revocation pointers | CRL distribution point and AIA `caIssuers`; no OCSP |
| Leaf SHA-256 (P1) | `a9aa6547844f19b0bf918bcc67320333cf1ac4fc89adf63c57e503f57e97297c` |

Validation: Let's Encrypt validates from several network vantage points. The P1 issuance produced 7 `http-01` requests within about 0.5 s, from different cloud regions; the IPv6 validation in P3 produced 6 requests from IPv6 addresses. Both address families validated with a listener on `[::]:80`.

### Renewal

- Renewal is just another order for the same identifier set. P2 passed `replaces` (ARI id derived from P1) and the CA accepted it. P2 was created while the P1 server was running on 443, with no downtime; the server was then restarted with the new files and `openssl s_client` showed the new serial (the spike server does not hot-reload; production must).
- **P2 and the IPv4 part of P3 completed without any new `http-01` request**: the order came back `Ready` at creation because the CA still held a valid authorization for the identifier from P1. So validation was exercised for real at P1 and for IPv6 at P3, and renewals inside the authorization's lifetime skip it. We did not measure how long that authorization stays valid, and a renewal after it lapses (port 80 needed again) was not exercised.
- **ACME Renewal Information is exposed** by the production and staging directories and `instant-acme` reads it (`Account::renewal_info` with a `CertificateIdentifier` built from the authority key id and serial). For P1 it returned a suggested window of 2026-11-23 17:41:48 to 20:52:38 UTC, i.e. 79 to 82 h after notBefore (about 50 % of the life), no explanation URL, `Retry-After` about 25 700 s. That makes "renew at half life, about every 3 days; check ARI every few hours" the CA's own cadence for this profile; the earlier plan of renewing every 2 days is more conservative than needed but fine.

### Real-network results

All with no browser flags, no `serverCertificateHashes`, page and WebTransport both on `https://85.190.123.74/` (certificate P2 or P3, issued by Let's Encrypt). Raw reports are not committed (`out/` is ignored).

Native and WebSocket checks (`ca` mode, validated against the Mozilla roots):

| Check | IPv4 (three runs) | IPv6 |
|---|---|---|
| native `hx/1` QUIC connect | 36, 39 and 35 ms | 44 ms |
| native stream `ping` | `pong:ping` | `pong:ping` |
| native datagram echo x20, RTT min / median / max | 14.3 / 15.1 / 16.9; 14.8 / 16.4 / 30.4; 14.5 / 14.9 / 17.2 ms | 17.7 / 18.0 / 20.8 ms |
| WebSocket over TLS connect, echo RTT | 67 ms, 17 ms; 63 ms, 14 ms; 61 ms, 14 ms | 76 ms, 17 ms |
| IPv6 address against the IPv4-only certificate | n/a | rejected: `certificate not valid for name` (correct) |
| wrong pinned hash | rejected: `certificate hash mismatch` | |

Browsers, IPv4, 300 frames of 1920x1080 at 60 fps (loopback numbers from the earlier run in brackets):

| Metric | Chrome 158, run 1 (heavy local load) | Chrome 158, run 2 | Firefox 160.0.1 |
|---|---|---|---|
| Page loads over HTTPS, no flags | yes | yes | yes |
| WebTransport connect | 61 ms [9] | 57 ms | 207 ms [60] |
| Datagrams received (200 sent) | 200 | 200 | 185 (7.5 % loss) [198] |
| Datagram RTT mean / p50 / p99 | 15.8 / 15.5 / 19.4 ms [1.9 mean] | 15.5 / 15.3 / 18.8 | 22.5 / 21 / 63 [4.4 mean] |
| Max datagram size | 1211 B | 1211 B | 1224 B |
| Encode (software) | 27.6 fps | 55.6 fps | 4.4 fps |
| Burst decode | 109 fps | 213 fps | 69 fps [37] |
| Paced 60 fps stream run: sent / received / decoded | 300 / 300 / 300 | 300 / 300 / 300 | 300 / 300 / 300 [105 of 300] |
| **Decoded fps** (loopback: 60.0 Chrome, 7 Firefox) | 36.3 | 51.4 | **59.4** |
| Out-of-order frames (reordered by the page) | 0 | 0 | 2 |
| Per-frame echo RTT p50 / p95 / p99 / max | 25.1 / 39 / 56 / 82 ms | 18.9 / 25.3 / 36 / 108 | 20 / 30 / 44 / 86 |
| Server-to-browser one way p50 / p99 | 13.5 / 38.8 ms | 8.6 / 16.4 | 8.7 / 28.7 |
| Decode time p50 / p95 / p99 | 17.2 / 43.9 / 55 ms | 5.0 / 9 / 11.9 | 57 / 172 / 227 |
| Decoder output gap p50 / p99 | 26.1 / 59.6 ms | 18.6 / 33.5 | 16 / 33 |
| Unpaced echo of 300 frames | 41 fps, 5.5 Mbit/s | 56 fps, 7.5 Mbit/s | 550 fps, 72 Mbit/s |
| Last frame pixel (non-black) | `[33,40,191]` | same | `[31,48,192]` |

Browsers, IPv6 (`https://[2001:880:a:339::26]/`, certificate P3):

| | Chrome 158 | Firefox 160.0.1 |
|---|---|---|
| Page over HTTPS | loads, certificate accepted | loads |
| WebTransport | **FAILS**: `WebTransportError: Opening handshake failed` | connects in 211 ms |
| Datagrams / RTT | n/a | 199 of 200, RTT mean 20.5 ms, p99 38 |
| Paced stream run | n/a | 300 / 300 decoded at **59.5 fps**, 1 out-of-order; echo RTT p50 20 ms; unpaced 130 Mbit/s |

Chrome's net log for the IPv6 attempt shows the QUIC session closing with `TLS handshake failure (ENCRYPTION_HANDSHAKE) 46: certificate unknown ... CERTIFICATE_VERIFY_FAILED`. The same certificate works in Chrome to the IPv4 literal (run 2 used certificate P3), the Chrome HTTPS page over TCP to the IPv6 literal loads, and native QUIC validates the IPv6 name. So Chrome's QUIC/WebTransport verification path rejects an IPv6 address literal that its TCP path accepts. We did not determine why (no other Chrome versions or flags were tried).

How to read the numbers:

- **Latency is the network, not the framework.** Datagram RTT is 15 to 16 ms against an ICMP RTT of 14.9 ms, so the QUIC and WebTransport layers add about 1 ms. Chrome's connect of 57 to 61 ms is about four round trips (QUIC handshake, HTTP/3 settings, CONNECT); Firefox's 207 ms is about fourteen and was the same over IPv4 and IPv6, so it comes from Firefox's own connect sequence, not path loss.
- **Chrome's 36 and 51 fps and its 5 to 7 Mbit/s unpaced figure are most likely limits of the test page, not of the transport (inferred from the code and the numbers, not isolated by an experiment).** The send loops `await writer.close()` on each frame stream, and in Chrome that resolves only when the server has acknowledged the end of the stream, which costs one round trip (about 15 ms) per frame. At 60 fps with 16.7 ms spacing there is no slack for that wait under CPU load, and the unpaced loop collapses to about one frame per round trip (56 fps, matching 1 / 18 ms). On loopback the round trip was 1.9 ms, so the same page ran at 538 fps. Firefox moved the same 5 MB at 72 to 130 Mbit/s over the same path, so the path is not the limit. Chrome's decode itself was healthy in run 2 (median 5.0 ms, p99 11.9 ms, close to loopback 4.2 ms); run 1 was slowed by local CPU load (decode median 17 ms). This was not re-run with the page fixed because the production certificates were already deleted (see Cleanup) and issuing a fourth would exceed the budget set for this run. **Follow-up:** do not await `close()` in the send loop and re-run.
- **Firefox sustained 59.4 and 59.5 fps** with all 300 frames received and decoded, where the loopback run decoded 7 fps (105 of 300 frames). Decode latency is high (median 40 to 57 ms, p99 up to 227 ms) but pipelined, with decoder output gaps of 16 to 17 ms. We did not isolate why the earlier run stalled; both runs were software-only on the same VM, so treat Firefox 1080p60 as "reached 60 fps twice, failed once", not as stable.
- Firefox datagram loss (7.5 % in the IPv4 run, 0.5 % over IPv6) was not seen from Chrome (0 % in both runs). The page sends 200 datagrams in a burst, so this may be send-queue overflow rather than network loss. Not investigated.
- BBR and loss behaviour on a lossier path were not tested; the path had no packet loss and 15 ms RTT.

### S5 criteria after the public run

| Criterion | Result | Notes |
|---|---|---|
| WebTransport works in Chromium | **PASS** | Real internet, CA certificate, no flags, IPv4. **FAIL for an IPv6 literal** (Chrome 158). |
| WebTransport works in Firefox | **PASS** | IPv4 and IPv6, streams and datagrams, no flags. |
| Safari status recorded | **PASS (recorded, not tested)** | Unchanged; no Mac. A CA-trusted IP certificate removes the dependence on `serverCertificateHashes` for Safari if it supports WebTransport, but that is untested. |
| IP certificate issues and renews | **PASS** | Three real production certificates for the IP, `shortlived`, 160 h, ECDSA P-256, 4 to 7 s each; renewal with ARI `replaces` accepted; ARI exposed. Not exercised: renewal after the cached authorization expires, and `tls-alpn-01`. |
| Browser decode at 1080p60 | **PASS in Chromium** (loopback: 60.0 fps; over the internet the page's own send loop most likely capped it at 36 to 51 fps, decode itself was fast); **PASS in Firefox in this run** (59.4 and 59.5 fps, software, high but pipelined latency; the loopback FAIL was not reproduced); Safari **UNVERIFIED** | Still synthetic content from the browser's own encoder, no GPU. |

### Decision changes

1. **Certificates without a domain: the Let's Encrypt IP certificate path is now verified**, so the `(provisional: not yet issued for real)` mark in `docs/architecture.md` §8.4 can be dropped. The pinned self-signed certificate stays as the fallback for private/LAN servers and for servers whose TCP 80 is blocked. Use `http-01` with a dedicated short-lived listener on TCP 80 separate from the main server, and plan for the port 80 requirement in the setup flow. `instant-acme` works as researched; `finalize_csr` with an empty subject is required (a default `rcgen` common name is rejected).
2. **Renewal cadence:** follow ARI (about half-life, roughly 3 days) with a fallback timer well inside 160 h; the server must hot-reload the certificate for the QUIC endpoint, HTTPS and WebSocket listeners without dropping sessions (the spike restarted).
3. **IPv6-only servers are not covered for Chrome WebTransport** until the Chrome failure is understood. The client must fall back to WebSocket over TLS (which worked over IPv6) when WebTransport fails, which is already the plan.
4. The Safari decision is unchanged.

### Risks

- **Rate limits.** This run used 3 production certificates in a few minutes. Let's Encrypt's published limits for repeated identical certificates (a handful per week for the same identifier set) are low enough that a client retry loop on failure could lock a server out of issuance for days. Not re-checked in this run. Use ARI `replaces`, back off on errors, and keep the previous certificate until the new one is in service.
- **About 6.7 day lifetime.** A missed renewal is an outage within days. The authorization-reuse finding means renewal is cheap while the authorization is cached, but a long outage of port 80 can turn the next renewal into a full validation.
- **Port 80 and provider firewalls.** `http-01` needs TCP 80 reachable from several vantage points. This provider allowed it; many do not. Any network-level block forces the self-signed fallback.
- **Chain size.** Let's Encrypt delivered four certificates (about 4.7 kB), which inflates the first QUIC flight; check whether a shorter chain can be requested.
- **One IP, one account.** Each IP certificate is tied to an ACME account whose key must be stored and backed up with the server secrets (architecture §8.6).
- **Test-page limits** (sequential `close()` waits, burst datagram send) probably understate Chrome throughput and may overstate Firefox datagram loss; fix before using this page for performance claims.
- Spike machine load (13 to 18) perturbed all software encode and decode figures.

### Cleanup evidence

Server: both processes stopped (`pgrep s5` found none), `~/hx-s5/` (binary, ACME account keys, certificate private keys, logs) deleted with `rm -rf`, TCP 80, 443, 4433 closed again (connection refused), no `rustup` or `cargo` was ever installed on the server (the binary was built on the spike machine), and the file capability went away with the binary. No private key material was printed or committed. The ACME accounts still exist at the CA (their keys are gone, so they are unusable). Locally, two headless Firefox processes that this run started could not be killed from the sandbox (snap confinement returned permission denied) and remain running with profile directories under `$HOME/hx-profile.*`; `run-public.sh` now also kills by profile path, which may not work on a snap Firefox.

### Reproduce (public server)

```
cd spikes/s5-webtransport && cargo build --release      # Ubuntu 24.04 binaries run on the 26.04 server
scp target/release/s5-webtransport user@host:hx-s5/s5
ssh user@host 'sudo setcap cap_net_bind_service=+ep ~/hx-s5/s5'
./s5 acme --env staging --ip A.B.C.D --dir ~/hx-s5/acme       # then --env production
./s5 acme --env production --ip A.B.C.D --dir ~/hx-s5/acme --replaces ~/hx-s5/acme/production/fullchain.pem
./s5 serve --cert acme/production/fullchain.pem --key acme/production/key.pem --bind :: --port 443 --https-port 443 --ws-port 4433 --report out/report.json
target/release/s5-webtransport native-check 443 ca --host A.B.C.D ; target/release/s5-webtransport ws-check 4433 ca --host A.B.C.D
./run-public.sh chrome user@host https://A.B.C.D/ frames=300     # or firefox
```
