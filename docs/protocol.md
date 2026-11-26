# Wire protocol (version 1.3)

This document defines protocol 1.0 and its additive revisions 1.1, 1.2 and 1.3 (§4.5, §4.6 and §4.7 list exactly what each adds; everything tagged "1.1" is absent from a 1.0 peer, everything tagged "1.2" from a 1.1 peer, everything tagged "1.3" from a 1.2 peer). The contract between hash-xcreen's session/agent side (the **server**) and its viewers (the **client**: desktop app now, browser and others later). The code in `crates/hx-proto` (messages, media header, versioning) and `crates/hx-transport` (QUIC and WebSocket transports) implements exactly what is written here. If the two disagree, that is a bug in one of them: fix it and update this file in the same branch.

Design background is in [architecture.md](architecture.md) §6–§8. Pairing and authentication (workstream 1B) are specified in §11.

Conventions: "MUST", "SHOULD" and "MAY" are used in the RFC 2119 sense. All multi-byte integers outside protobuf are **little-endian**. Sizes are in bytes. "Server" is the side that streams video (agent or `hx-session`); "client" is the side that views and sends input. The client always opens the connection.

## 1. Connection setup

| Transport | Used when | Address | TLS ALPN | Application entry |
|---|---|---|---|---|
| QUIC (default) | Always tried first | UDP `<port>` | `hx/1` | Streams and datagrams as in §3 |
| WebSocket over TLS (fallback) | UDP is blocked or QUIC fails | TCP `<port>` (same port number) | `http/1.1` | `wss://<host>:<port>/hx/1`, binary messages as in §9 |
| WebTransport over HTTP/3 | Browser client (Phase 3, **not implemented in Phase 1**) | UDP `<port>` | `h3` | Not specified yet |

- TLS is TLS 1.3 only (rustls); a TLS 1.2 handshake is dropped even if the injected configuration allows it. **Session resumption and early data are disabled** on the server (no session cache, no tickets, no 0-RTT) and clients do not resume: every connection runs the full handshake, so the injected certificate verifiers are consulted every time. The server-side QUIC and WebSocket entry points never share TLS session state. Certificates and verification are injected by the caller (§11): the protocol layer never decides who is trusted.
- One QUIC endpoint serves both ALPN values `hx/1` and `h3`. The accept loop dispatches on the negotiated ALPN: `hx/1` goes to the native handler, `h3` to a pluggable handler (absent in Phase 1: the endpoint then offers only `hx/1`). Any other ALPN is refused at the TLS handshake.
- The major version is part of the ALPN and of the WebSocket path (`hx/1`, `/hx/1`). A future major `2` is a new ALPN (`hx/2`), which lets one server support the current and previous major side by side (architecture §7.5). The `Hello` also carries the version and the two MUST agree (§4).
- Congestion control: BBR on QUIC.
- QUIC keep-alive 5 s, idle timeout 30 s. Each side limits what its peer may make it buffer. A **server** starts restricted (§2.1): the client may open 1 bidirectional stream (the control stream; a second one is refused by the transport) and **0 unidirectional streams**, the connection receive window is 256 KiB and the datagram receive buffer 16 KiB. When the application authorizes the connection the limit becomes 64 unidirectional streams (input and transfers) and a 64 MiB connection receive window (the steady-state cap). A **client** allows the server 0 bidirectional streams, 64 unidirectional streams (one per in-flight video frame, plus cursor and transfers), a 64 MiB connection receive window and 8 MiB per stream. The 1024 of earlier drafts is now **64**: a client also reads at most 64 MiB of frame bodies at a time (it takes a byte budget before it reads a frame's body, and holds it until the frame is queued for the application), so a server that opens many streams cannot make it buffer more than that, plus the 16-frame delivery queue.
- The server MAY require QUIC address validation (a Retry) before spending handshake state on an unvalidated source address; `hx-transport` does by default.
- Pre-authentication resource bounds. A connection is *unauthenticated* from transport accept until the application authorizes it (§2.1), is refused, or closes. It passes through up to three stages, each with its own pool so that a flood at an earlier stage cannot starve a later one:
  1. **Handshaking** (transport accept until TLS, and for WebSocket the HTTP upgrade, are complete): at most 256 connections. TLS must finish within **3 s** of transport accept.
  2. **Pending, general**: after TLS, a connection whose client key the application does not know to be paired (`PreAuthClassifier`, below): at most **64**. A valid `Hello` must arrive within **3 s of TLS completing** (`HELLO_TIMEOUT`, §8). If the pool is full the connection is closed with `BUSY` before any `Hello` is read.
  3. **Pending, reserved**: after TLS, a connection whose client key is a known, active (or reinstatable, §11.7) paired device: at most **16**, and at most **2 per key**; a key with two already, or a full reserved pool, falls back to the general pool. These slots are not charged to the per-address counters. Unknown-key floods cannot consume them.
  Per source address the first two stages are limited together: at most 4 per IPv4 address and **16 per IPv4 /24**; for IPv6, 4 per /64 and 16 per /48 (so that one network cannot hold every slot); excess connections are refused at the transport. The application supplies a cheap, in-memory classifier of the client key (`ServerOptions::classifier`, `PreAuthClassifier`); without one every connection is *unknown*. The classifier may also answer *refuse* (a revoked key, or an unknown key while no pairing secret is live, §11.5): such a connection stays in the handshaking pool, its `Hello` is read within the same 3 s, and it is refused at once with the same answers the application would give (`PAIRING_CLOSED` for an `INTENT_PAIR` hello from an unknown key, `UNAUTHORIZED` for everything else, including every hello from a revoked key), without ever taking a pending slot. The application must accept or refuse a pending session within 10 s or the transport refuses it with `BUSY` (a session that is dropped undecided is refused with `BUSY` immediately); writing the `HelloAck` is bounded by the same 10 s (a peer that stops reading is dropped, QUIC close `BUSY`) and releases its slot. A failure while accepting (for example an invalid server reply) closes with `INTERNAL_ERROR`, never code 0. An accepted connection that is not authorized within 30 s is closed with `UNAUTHORIZED`. All of these are configurable server options. Until the hello exchange succeeds, nothing but the control stream (WebSocket: control messages) is processed. **Residual risk, stated:** while a pairing secret is live any key may take a general slot for up to 30 s, so a flood during a pairing window can fill the general pool (paired devices keep the reserved pool); and the handshaking pool can still be filled by many networks that stall in TLS, for 3 s at a time.

## 2. Roles and the session lifecycle

```
client                                          server
  | -- transport + TLS (identity checked by caller) --> |
  | -- control stream: Hello ------------------------>  |
  |                         (version + policy checks)    |
  | <-- HelloAck   or   Refuse + close(code) ----------  |
  | -- [pairing / auth messages, §11] ---------------->  |
  | -- ViewConfig ----------------------------------->  |
  | <-- StreamInfo ------------------------------------ |
  | <== video / cursor / audio / input / clipboard ===>  |
  | -- Goodbye or close(NO_ERROR) -------------------->  |
```

1. The client opens the transport and the **control channel** and sends `Hello` as the first message.
2. The server validates it and answers `HelloAck` (success) or `Refuse` followed by closing the connection with the matching code (§8).
3. After `HelloAck` the connection is **restricted** on the server (§2.1) until the application authorizes the peer; the client may use every channel the negotiated features allow, but the server processes only what §2.1 lists until then.
4. Either side ends the session with `Goodbye` (optional, informational) and a connection close with a code from §8.

### 2.1 Restricted (unauthorized) state

After `HelloAck` the server side of a connection is **restricted** until the server application has authenticated the peer (pinned key, PIN, pairing; §11) and authorizes the connection. While restricted:

- Only control messages are processed, and only `pairing`, `auth`, `goodbye`, `ping` and `pong`. Any other control message is a protocol error.
- Input events and mouse datagrams are dropped without being queued (counted for diagnostics).
- QUIC: the peer cannot open unidirectional streams at all (§1), so transfers and input cannot start. WebSocket: a transfer, audio or video message is a protocol error.
- The server sends nothing but control messages (no video, cursor, audio, transfers).
- The negotiated features (§4.3) are not yet in effect.

**Control-only authorization (1.3, `INTENT_SETUP` only).** A setup connection (§5.10) is authorized with a narrower step than a session: the authorization deadline is satisfied and the pre-authentication slot released, and the control variants that §5.10 lists (`setup`, plus `goodbye`, `ping`, `pong`) are processed, with the `SETUP` feature in effect and nothing else. The QUIC unidirectional-stream credit stays at 0, input and mouse data keep being dropped, the server sends no media, and a transfer, audio or video message on WebSocket remains a protocol error. A setup connection therefore never carries streaming, clipboard or files, whatever it negotiated.

Authorizing makes the negotiated features effective (optionally narrowed by the application, for example clipboard off for one device), raises the QUIC limits of §1 and releases the connection's pre-authentication slot. A client may assume nothing about its own authorization until the server says so in an application-level message (for example the result of the `auth` exchange); a client MUST NOT start input, transfers or other channels before that. The restricted state exists only on the server; a client is never restricted.

## 3. Channels

Every QUIC stream and every datagram begins with a one-byte **channel id**. WebSocket messages carry the same byte first (§9).

| Id | Channel | Direction | QUIC transport | Priority | Messages |
|---|---|---|---|---|---|
| `0x01` | Control | both | One client-opened **bidirectional** stream, opened first | High (50) | `ControlMessage`, length-prefixed (includes the 1.1 `ServerStats`, §5.8, the takeover `Goodbye`, §5.7, the 1.2 `DeviceMgmt`, §5.9, and the 1.3 `SetupMessage`, §5.10) |
| `0x02` | Input (keys, buttons, scroll) | client → server | One long-lived client-opened unidirectional stream | Highest (100) | `InputEvent`, length-prefixed |
| `0x03` | Mouse motion | client → server | **Datagrams**, latest wins | Highest (datagrams are sent ahead of stream data) | `MouseMove` datagram (§7.1) |
| `0x04` | Cursor | server → client | One long-lived server-opened unidirectional stream | High (50) | `CursorEvent`, length-prefixed |
| `0x05` | Video | server → client | **One unidirectional stream per frame** | Normal (0) | Media header + payload (§6) |
| `0x06` | Audio | server → client | **Datagrams** | High | `AudioPacket` datagram (§7.2) |
| `0x07` | Clipboard | both | One unidirectional stream per transfer | Lowest (-100) | `TransferHeader` + raw bytes (§5.4) |
| `0x08` | Files | both | One unidirectional stream per transfer | Lowest (-100) | `TransferHeader` + raw bytes (§5.4) |
| `0x09` | Frame acknowledgement | client → server | **WebSocket only** (QUIC uses stream completion) | n/a | `u32` frame number (§9) |

Priorities are `quinn::SendStream::set_priority` values (higher is sent first). Datagrams are not subject to stream priority but quinn sends them ahead of stream data in the same packet.

Rules:

- The sender writes the channel id as the first byte of a stream or datagram, immediately after opening it.
- The control stream is opened by the client and MUST be the first stream; its first byte is `0x01`. A second control stream is a protocol error (`PROTOCOL_ERROR`).
- The Cursor stream (server) and the Input stream (client) are each opened when first needed. The client's can only succeed after the server has authorized it (§2.1); the server opens nothing during the handshake, so a peer that grants no stream credit cannot stall the handshake. At most one of each per connection; a duplicate is a protocol error.
- A unidirectional stream with an unknown channel id, a channel id that the peer's role must not send (for example the client opening `0x05`), or a channel whose feature was not negotiated (§4.3) is a protocol error.
- An unknown datagram channel id, or a malformed datagram, is **dropped** (datagrams are unreliable by nature; they never close the connection). Implementations count drops for diagnostics.
- Streams carrying length-prefixed messages (control, input, cursor) use the framing in §5.1.

### 3.1 Limits

| Item | Maximum |
|---|---|
| Control message (`ControlMessage` encoded) | 65536 |
| `Hello` strings (`software`, `device_name`) | 128 and 64 bytes |
| Input message | 1024 |
| Cursor message | 327680 (cursor image at most 256 × 256 RGBA) |
| Video payload | 16777216 (16 MiB) |
| Audio payload | 1100 |
| `TransferHeader` encoded | 4096 |
| File name in `TransferHeader` | 255 bytes; also rejected: `/`, `\`, `:`, C0/C1/DEL control characters, bidi controls (U+202A–202E, U+2066–2069, U+200E/F, U+061C), `.` and `..`, a trailing `.` or space, and the Windows device names CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM1–9, LPT1–9 and the superscript forms COM¹²³, LPT¹²³ (with or without extension); also zero-width/invisible characters (U+200B–200D, U+2060, U+FEFF, U+180E) |
| Clipboard transfer total | 67108864 (64 MiB) |
| File transfer total | 4294967296 (4 GiB) ceiling and default, lowered by `max_file_bytes` (§5.6); applies to every version |
| `Goodbye.peer_device_name` / `peer_device_id` (1.1) | 64 bytes (sanitised) / 0 or 16 bytes |
| `ServerStats` rate (1.1) | at most 1 per second sent; a client may drop beyond 4 per second |
| Setup (1.3, §5.10) | `SetupSetPin.pin` at most 16 bytes; `SetupStart.password` at most 1024 bytes on the wire (1 to 511 after validation); strings at their per-field caps (§5.10); `SetupResult.warnings` at most 16 entries; a worst-case `SetupResult` stays below 64 KiB (a test checks it); requests per connection at most 2 per second, burst 8 |
| WebSocket transfer chunk | 65536 |
| Queued, unread incoming transfer data (WebSocket) | 1 MiB per transfer and 4 MiB per connection; a transfer that exceeds either is aborted (`abort`, §9.4). On QUIC the same bound comes from stream and connection flow control (§1) |
| Unread input messages queued (WebSocket) | 4096; a peer that outpaces the application beyond this is closed with `PROTOCOL_ERROR` (QUIC: per-stream flow control instead) |
| Unread cursor events queued | 256. Cursor **positions** are coalesced, latest wins: a burst the application has not read collapses into the newest position (a position never overtakes the shape sent before it); only more than 256 queued shapes is an overflow (`PROTOCOL_ERROR`) |

A receiver that sees a value above its limit treats it as a protocol error (reliable channels) or drops the datagram. Limits are checked **before** allocating.

## 4. Handshake and versioning

### 4.1 Messages

`Hello` (client → server, first control message):

| Field | # | Type | Meaning |
|---|---|---|---|
| `version` | 1 | `Version` | Client protocol `major.minor` (this document: `1.3`; a client that implements only 1.0 sends `1.0`) |
| `capabilities` | 2 | `Capabilities` | What the client can decode and do |
| `intent` | 3 | `Intent` | `INTENT_SESSION` (1) normal session, `INTENT_PAIR` (2) pairing, §11, `INTENT_SETUP` (3, **1.3**) post-pairing setup, §5.10 (sent only to a server known to be at least 1.3). `INTENT_UNSPECIFIED` (0) is invalid |
| `software` | 4 | string | e.g. `hx-desktop 0.1.0`, informational, at most 128 bytes |
| `device_name` | 5 | string | Human label, informational, at most 64 bytes. Never used for authorisation |

`HelloAck` (server → client):

| Field | # | Type | Meaning |
|---|---|---|---|
| `version` | 1 | `Version` | Server protocol version |
| `capabilities` | 2 | `Capabilities` | What the server can encode and do |
| `session_id` | 3 | bytes | 16 random bytes identifying this session in logs |
| `software` | 4 | string | e.g. `hx-session 0.1.0`, at most 128 bytes |

`Refuse` (server → client, sent instead of `HelloAck`, followed by a close):

| Field | # | Type | Meaning |
|---|---|---|---|
| `reason` | 1 | `RefuseReason` (a refusal without a reason is sent as `UNAUTHORIZED`, so the close code is never 0) | `UPDATE_REQUIRED` (1), `UNAUTHORIZED` (2), `BUSY` (3), `PAIRING_CLOSED` (4), `SETUP_CLOSED` (5, **1.3**, `INTENT_SETUP` only); `UNSPECIFIED` (0) is invalid |
| `message` | 2 | string | Human-readable, at most 256 bytes (longer text is cut on a character boundary), safe to show |
| `version` | 3 | `Version` | Server version, so the client can say what to update |

`Version`: `major` (1, uint32), `minor` (2, uint32).

`Capabilities`: `video_codecs` (1, repeated `VideoCodec`, packed), `features` (2, uint64 bitmask, §4.3), `max_file_bytes` (3, uint64, **1.1**: the largest file transfer this side accepts, §5.6; 0 = not stated, otherwise 1 to 4294967296 (4 GiB); a larger value is invalid).

`VideoCodec`: `UNSPECIFIED` 0 (invalid), `H264` 1, `AV1` 2, `H265` 3 (reserved; not produced in v1). The number is also the codec byte in the media header (§6).

### 4.2 Version rules

- The version is `major.minor`; this document defines `1.0`, `1.1`, `1.2` and `1.3`.
- **Different major** (the `Hello` major differs from the ALPN/path major or from the server's): the server answers `Refuse{reason: UPDATE_REQUIRED, version: <server version>}` and closes with `UPDATE_REQUIRED` (§8). The client shows an "update required" message. No other message is processed. The `Hello` of a different major is parsed only as far as `version` (field 1); every other field of it is ignored.
- **Same major, different minor**: accepted. The negotiated minor is `min(client.minor, server.minor)`. Both sides then use only features available at the negotiated minor and present in both capability sets (§4.3). Unknown protobuf fields are ignored (standard protobuf behaviour), so a newer minor can add fields and messages that an older peer skips; a newer minor MUST NOT send a new message type on a channel to a peer whose negotiated minor predates it (a `ControlMessage` whose only variant is unknown to the receiver has no variant set and is malformed, so a new control variant is never safe to send to an older peer).
- Security properties (authentication, authorization, size limits, the restricted state) are never gated by a minor version or a feature bit: every peer enforces them regardless of what was negotiated.
- A change that an older peer cannot safely ignore (removed field, changed meaning, changed byte layout) requires a new major.
- The agent supports the current major and the previous one, by serving both ALPN values. The web client always matches its agent.

### 4.3 Capabilities and features

Capabilities advertised in `HelloAck` are an *offer*: negotiated features take effect only when the server authorizes the connection (§2.1). For an `INTENT_PAIR` hello the server advertises no features and no codecs, so a pairing connection can never carry anything but control messages.

`features` is a bitmask. Both sides compute `negotiated = client.features & server.features & mask(negotiated_minor)` (bits 0 to 2 exist from 1.0, bit 3 from 1.1, bit 4 from 1.2, bits 5 and 6 from 1.3) and `codecs = client.video_codecs ∩ server.video_codecs`, in the server's order of preference. Bits unknown to a side are ignored by that side.

| Bit | Name | Introduced | Enables |
|---|---|---|---|
| 0 | `AUDIO` | 1.0 | Audio channel `0x06` |
| 1 | `CLIPBOARD` | 1.0 | Clipboard channel `0x07` |
| 2 | `FILE_TRANSFER` | 1.0 | Files channel `0x08` |
| 3 | `SERVER_STATS` | 1.1 | `ServerStats` control messages (§5.8), sent only while the client has asked for them (`ViewConfig.stats_enabled`) |
| 4 | `DEVICE_MANAGEMENT` | 1.2 | `DeviceMgmt` control messages (§5.9): list paired devices, revoke one, the server's change notices and (1.3) a request for a pairing code |
| 5 | `SETUP` | 1.3 | `SetupMessage` control messages (§5.10). Offered **only** in the `HelloAck` of an `INTENT_SETUP` connection; a normal session offers `defined_up_to(3)` without it, so a `setup` message on a session is a `PROTOCOL_ERROR` at the application level (the same pattern as `DeviceMgmt`) |
| 6 | `SERVER_MANAGEMENT` | 1.3 | `ServerMgmt` control messages (§5.11): server overview, change PIN and password, restart the desktop, turn Docker off, limits, agent update. Offered on normal sessions only (never on a pairing or setup connection) |

An empty `codecs` intersection is not a handshake error; the server then answers `StreamInfo` only after a `ViewConfig` with a codec that is in the intersection, and rejects other codecs with `Goodbye` (code `PROTOCOL_ERROR`). Video, cursor, input, mouse and control are always available (not feature-gated).

### 4.4 Rules for the first message

- The first message on the control channel MUST be `Hello`; anything else is `PROTOCOL_ERROR`. A second `Hello`, or a `HelloAck`/`Refuse` from a client, is `PROTOCOL_ERROR`.
- No `Hello` within 3 s of TLS completing (TLS itself must complete within 3 s of transport accept): close with `HELLO_TIMEOUT`.
- The server decides acceptance after the version check (e.g. authorisation from the TLS identity, intent, capacity): it answers `HelloAck` or `Refuse` with reason `UNAUTHORIZED`, `BUSY` or `PAIRING_CLOSED`, then closes with the matching code (§8).

### 4.5 What 1.1 adds

Decision: **a minor bump to 1.1, not an unversioned addition to 1.0.** Three of the four additions are skippable by a 1.0 peer (new fields on `Goodbye`, `Capabilities` and `ViewConfig`; a new close code, which a 1.0 peer reads as `INTERNAL_ERROR`, §8), but the fourth, the `ServerStats` control variant, is not: a 1.0 receiver decodes it as a `ControlMessage` with no variant and closes with `PROTOCOL_ERROR`. §4.2 therefore requires it to be gated by the negotiated minor, and the feature bit `SERVER_STATS` makes the client's consent explicit. Nothing in 1.0 changes meaning, so there is no new major and the ALPN stays `hx/1`.

| Addition | Where | Gated by |
|---|---|---|
| `TAKEN_OVER` close code (9) and `Goodbye.peer_device_name` / `peer_device_id` | §5.2, §5.7, §8 | Negotiated minor at least 1; for minor 0 the server uses `BUSY` instead (§5.7) |
| `ServerStats` (`ControlMessage.server_stats` = 11), `ViewConfig.stats_enabled` (9) | §5.2, §5.8 | Negotiated feature `SERVER_STATS` |
| `Capabilities.max_file_bytes` (3) | §4.1, §5.6 | Minor at least 1 for the advertisement; the 4 GiB ceiling itself applies to every peer (§4.2: size limits are never gated) |

### 4.6 What 1.2 adds

Decision: **a minor bump to 1.2, with a new feature bit**, for the client-facing device-management route that 1.1 left open (§5.7, step 4). One addition: the `DeviceMgmt` control variant (`ControlMessage.device_mgmt` = 12, §5.9). It is not skippable by a 1.1 peer (an unknown variant decodes as a `ControlMessage` with no variant set, which closes the connection with `PROTOCOL_ERROR`, §4.2), so it is gated twice: by the negotiated minor (at least 2) and by the feature bit `DEVICE_MANAGEMENT`, which carries the client's consent.

Why 1.2 and not an additive bit inside 1.1: `Features::defined_up_to(1)` is the 1.1 feature mask and §4.5 is what "1.1" means to every implementation already built; a peer that says 1.1 must keep meaning exactly that, so that the negotiated minor alone tells both sides which messages exist. Nothing in 1.0 or 1.1 changes meaning, so there is no new major and the ALPN stays `hx/1`. A 1.1 client still works against a 1.2 server (it never gets the bit), and a 1.2 client against a 1.1 server sees no `DEVICE_MANAGEMENT` in `HelloAck` and offers no device management in its UI.

| Addition | Where | Gated by |
|---|---|---|
| `DeviceMgmt` (`ControlMessage.device_mgmt` = 12): `ListDevices`, `DeviceList`, `RevokeDevice`, `RevokeResult`, `DeviceEvent` | §5.2, §5.9 | Negotiated minor at least 2 **and** feature `DEVICE_MANAGEMENT` |

### 4.7 What 1.3 adds

Decision: **a minor bump to 1.3, with a new feature bit**, for two things the app needs and 1.2 cannot express: finishing a **one-liner** install from the app after pairing (§5.10), and **pairing a new device from an already paired one** (§5.9). Nothing in 1.0 to 1.2 changes meaning, so there is no new major and the ALPN stays `hx/1`. The 1.3 minor is claimed by this change (the image work of 1D changes only the privd schema, not `hx.proto`).

| Addition | Where | Gated by |
|---|---|---|
| `INTENT_SETUP` (`Intent` 3) | §4.1, §5.10 | A client sends it **only** if the `HelloAck.version.minor` it saw on a **successfully confirmed** pairing was at least 3 (the pairing `HelloAck` is trusted only after SPAKE2 confirmation), and checks again that the setup `HelloAck` has minor at least 3 and `SETUP` negotiated |
| `SETUP_CLOSED` (`RefuseReason` 5) and close code 10 (WebSocket 4010) | §4.1, §8 | `INTENT_SETUP` connections only |
| Feature bit 5 `SETUP` | §4.3 | Offered only on `INTENT_SETUP` connections |
| `SetupMessage` (`ControlMessage.setup` = 13) and its messages | §5.2, §5.10 | Negotiated minor at least 3 **and** feature `SETUP`, on `INTENT_SETUP` connections only |
| `AuthStatus` `PIN_REQUIRED` (6) | §11.4 | Sent only on `INTENT_SETUP` connections |
| `DeviceMgmt` bodies `create_pairing_code` (15) and `pairing_code_issued` (16) | §5.9 | Negotiated minor at least 3 **and** feature `DEVICE_MANAGEMENT`, on an authorized `INTENT_SESSION` connection |
| Feature bit 6 `SERVER_MANAGEMENT` and `ServerMgmt` (`ControlMessage.server_mgmt` = 14) | §4.3, §5.11 | Negotiated minor at least 3 **and** feature `SERVER_MANAGEMENT`, on an authorized `INTENT_SESSION` connection of an active device |
| `INTENT_REINSTATE` (`Intent` 4), `AuthStatus` `PASSWORD_REQUIRED` (7) and `WRONG_PASSWORD` (8), and `AuthMessage.password` (`PasswordAttempt`, field 3) | §11.7 | A client sends it **only** to a server whose confirmed version has minor at least 3 (the version it saw on its last successful session or pairing), and only after a session was refused with `REVOKED` |
| Redacting `Debug` for `SetupSetPin`, `SetupStart`, `PairingCodeIssued`, `PasswordAttempt` and `Opaque` (`skip_debug` plus hand-written impls; this also fixes today's `Opaque` PIN leak through `Debug`) | §14 | n/a (implementation rule) |

**Why an old server never sees the new intent.** A same-major `Hello` is fully validated, and an intent other than `SESSION` or `PAIR` is malformed on a 1.2 server, which then closes with `PROTOCOL_ERROR` and never sends a polite `Refuse`. Hence the confirmed-version gate in the table: the client never sends `INTENT_SETUP` to a server that has not shown, inside a confirmed pairing, that it is 1.3 or newer; the app then tells the user to update the server.

## 5. Messages

### 5.1 Framing of reliable message streams

On QUIC control, input and cursor streams, after the channel id byte each message is:

```
+----------------+----------------------------+
| length (u32 LE)| protobuf message (length B)|
+----------------+----------------------------+
```

`length` MUST be between 1 and the channel's maximum (§3.1). The stream is a sequence of such frames; a clean end of stream (FIN) between frames is a normal end of that channel. A truncated frame, a zero or oversized length, or a message that fails to decode or validate is `PROTOCOL_ERROR`.

On WebSocket one WebSocket message carries exactly one protobuf message (§9) with no length prefix.

### 5.2 Control channel: `ControlMessage`

A `oneof` envelope. Exactly one variant MUST be set, else the message is invalid.

| Variant | # | Direction | Meaning |
|---|---|---|---|
| `hello` | 1 | C → S | §4.1 |
| `hello_ack` | 2 | S → C | §4.1 |
| `refuse` | 3 | S → C | §4.1 |
| `view_config` | 4 | C → S | Requested view settings |
| `stream_info` | 5 | S → C | Actual stream format |
| `request_keyframe` | 6 | C → S | Client lost sync, send a fresh full image |
| `ping` | 7 | both | Round-trip probe |
| `pong` | 8 | both | Echo of a `ping` |
| `stats` | 9 | C → S | Client decode statistics |
| `goodbye` | 10 | both | Orderly end, informational |
| `server_stats` | 11 | S → C | **1.1.** Numeric statistics for the stats overlay, §5.8 |
| `device_mgmt` | 12 | both | **1.2.** Device management: list and revoke paired devices, change notices, §5.9; **1.3:** request a pairing code |
| `setup` | 13 | both | **1.3.** Post-pairing setup on an `INTENT_SETUP` connection, §5.10 |
| `server_mgmt` | 14 | both | **1.3.** Server management on an authorized session: overview, change PIN and password, restart, Docker off, limits, agent update, §5.11 |
| `pairing` | 100 | both | **Owned by 1B.** Opaque pairing envelope, §11 |
| `auth` | 101 | both | **Owned by 1B.** Opaque PIN/auth envelope, §11 |

`ViewConfig` (C → S; may be sent any time after `HelloAck`, each one replaces the previous; unset fields keep the previous value):

| Field | # | Type | Meaning |
|---|---|---|---|
| `codec` | 1 | `VideoCodec` | Preferred codec; `UNSPECIFIED` = server's choice. Must be in the negotiated intersection |
| `max_fps` | 2 | uint32 | Frame-rate ceiling; 0 = server default; at most 240 |
| `bandwidth_cap_kbps` | 3 | uint32 | Bitrate ceiling in kbit/s; 0 = Auto |
| `width` | 4 | uint32 | Desired remote width in pixels (client window, physical) |
| `height` | 5 | uint32 | Desired remote height; `width` and `height` are both 0 (keep) or both in 1..=16384 |
| `scale_percent` | 6 | uint32 | HiDPI scale, 100 = 1×; 0 = 100; otherwise 50..=400 |
| `audio_enabled` | 7 | bool | Send audio (requires negotiated `AUDIO`) |
| `clipboard_enabled` | 8 | bool | Allow clipboard (requires negotiated `CLIPBOARD`) |
| `stats_enabled` | 9 | bool | **1.1.** Send `ServerStats` (requires negotiated `SERVER_STATS`); false (the default) means none are sent, so a hidden overlay costs nothing |

`StreamInfo` (S → C; sent after the first `ViewConfig` and whenever format changes, e.g. resize):

| Field | # | Type | Meaning |
|---|---|---|---|
| `codec` | 1 | `VideoCodec` | Codec of frames from `first_frame` on |
| `width` | 2 | uint32 | Frame width in pixels |
| `height` | 3 | uint32 | Frame height in pixels |
| `fps` | 4 | uint32 | Current frame-rate ceiling |
| `first_frame` | 5 | uint32 | Media-header frame number from which this format applies (video streams race the control stream, so the client switches when it reaches this frame) |

Video colour is always BT.709, limited range (also tagged in the bitstream VUI; architecture §6.2).

`RequestKeyframe` (C → S): `last_decoded_frame` (1, uint32). The server answers with a frame flagged `KEY | RESYNC`.

`Ping` / `Pong`: `nonce` (1, uint64); the `Pong` echoes it. Either side may probe; the sender measures RTT locally. A receiver answers a `Ping` immediately and does not surface either message to the application (`hx-transport` handles both).

`ClientStats` (C → S, about once per second): `interval_ms` (1), `decoded_frames` (2), `dropped_frames` (3, stale or undecodable), `decode_p95_us` (4); all uint32, counts are for the interval.

`Goodbye`: `code` (1, uint32, a close code from §8), `message` (2, string, at most 256 bytes), `peer_device_name` (3, string, **1.1**, at most 64 bytes) and `peer_device_id` (4, bytes, **1.1**, empty or exactly 16 bytes). Fields 3 and 4 are set only with code `TAKEN_OVER` (§5.7); a 1.0 peer ignores them.

### 5.3 Input channel: `InputEvent` (client → server)

| Variant | # | Fields | Meaning |
|---|---|---|---|
| `key` | 1 | `scancode` (1, uint32), `pressed` (2, bool) | Physical key as a **USB HID usage** on the Keyboard/Keypad page (`0x07`), value `0x00..=0xE7`; layout-independent. Other values are invalid |
| `button` | 2 | `button` (1, `MouseButton`), `pressed` (2, bool), `x` (3, sint32), `y` (4, sint32) | Button press or release at the given absolute remote pixel position, so a click lands correctly even if a motion datagram was lost |
| `scroll` | 3 | `dx` (1, sint32), `dy` (2, sint32) | Scroll in 1/120 of a wheel notch (positive `dy` = scroll up/away from user, positive `dx` = right) |
| `release_all` | 4 | none | Client lost focus: release every key and button |

`MouseButton`: `UNSPECIFIED` 0 (invalid), `LEFT` 1, `RIGHT` 2, `MIDDLE` 3, `BACK` 4, `FORWARD` 5.

Being on one reliable ordered stream, key and button events arrive in the order they were sent.

### 5.4 Cursor channel: `CursorEvent` (server → client)

| Variant | # | Fields | Meaning |
|---|---|---|---|
| `shape` | 1 | `id` (1, uint64), `width` (2), `height` (3), `hotspot_x` (4), `hotspot_y` (5) (all uint32), `rgba` (6, bytes) | A cursor image, 8-bit straight-alpha RGBA, `rgba.len == width*height*4`, `1 <= width,height <= 256`, hotspot inside the image. `id` is a content hash chosen by the server; the client caches shapes by `id` |
| `position` | 2 | `x` (1, sint32), `y` (2, sint32), `shape_id` (3, uint64), `visible` (4, bool) | Pointer position in remote pixels. `shape_id` MUST refer to a `shape` already sent on this connection (the server resends the shape set after connect; a client ignores a position with an unknown id) |

The client draws the cursor itself, so pointer motion never waits for video.

### 5.5 Clipboard and file transfers

Each transfer is its own unidirectional QUIC stream, opened by whichever side sends it: channel id `0x07` (clipboard) or `0x08` (file), then the `TransferHeader` framed as in §5.1 (limit 4096), then exactly `size` raw bytes, then FIN.

`TransferHeader`: `mime` (1, string, 1 to 255 bytes, printable ASCII only, `type/subtype` of token characters followed by optional `;` parameters; clipboard formats such as `text/plain;charset=utf-8`, `image/png`, `text/uri-list`), `name` (2, string; files only, must be empty for clipboard, see §3.1 for constraints; **a display hint only**: a receiver writes inside a directory of its own choosing, picks its own file name and never treats `name` as a path), `size` (3, uint64, exact byte count of the body).

The receiver enforces `size` (more or fewer bytes than announced is a protocol error for that stream, which is reset with `TRANSFER_ERROR`; the connection continues) and the clipboard limit of §3.1. A receiver MAY abort a transfer at any time with `STOP_SENDING` (`TRANSFER_REJECTED`). Progress is the bytes received so far over `size`. Transfers only occur if the matching feature was negotiated and the user has not disabled it (`clipboard_enabled`).

A small transfer can be fully delivered before the receiver's refusal arrives (the whole body and the end of the stream are already acknowledged when `STOP_SENDING` reaches the sender), so a sender may see a refused transfer complete without error. The refusal is still enforced by the receiver: nothing is stored or made the clipboard. The receiver, not the sender's result, is authoritative.

On WebSocket the same content is carried in messages tagged with a transfer id (§9.4).

### 5.6 Maximum file size (1.1)

Every file transfer is bounded by one limit, in both directions, checked from the header alone (before a single body byte is read).

- **Ceiling.** `MAX_FILE_SIZE` = 4294967296 bytes (4 GiB), also the default. Every implementation enforces it regardless of negotiation (a security property, §4.2): a file `TransferHeader` with `size` above it is refused. Clipboard transfers keep their own 64 MiB limit (§3.1).
- **Configurable lower.** The server operator may lower the limit. The server advertises it in `HelloAck.capabilities.max_file_bytes`; a client MAY advertise its own lower receive limit in `Hello.capabilities.max_file_bytes`. `0` or an absent field means "not stated" (the ceiling). A value above the ceiling is invalid. The **effective limit** is the minimum of the ceiling and every stated value, computed identically by both sides (`hx_proto::version::negotiate` returns it as `Negotiated::max_file_bytes`); with a negotiated minor of 0 it is the ceiling. "No files at all" is expressed by not offering `FILE_TRANSFER`, not by a tiny value.
- **Sender.** A sender MUST NOT open a file transfer whose size exceeds the effective limit, and tells its user why ("file too large, limit N") instead of sending.
- **Receiver.** A receiver that reads a file header with `size` above the effective limit refuses the transfer: QUIC `STOP_SENDING` with `TRANSFER_REJECTED` (`0x101`), WebSocket `abort` (§9.4). The connection continues, nothing is written and no body byte is accepted. A body longer or shorter than the announced `size` remains `TRANSFER_ERROR` (§5.5). A header that is itself invalid is a protocol error as before.
- A zero-byte file is allowed. `size` is the exact body length, so the check is `size <= limit`.
- Gateways: the limit applies on both hops (gateway to client, and gateway to session, where it is the session link's `max_file_bytes`, ipc.md §16); the lower of the two configured values is the one advertised here.

`hx_proto::message::TransferHeader::validate_file(limit)` implements the receiver check.

### 5.7 Takeover notice (1.1)

When a second authenticated client displaces the active one (ipc.md §18), the server tells the displaced client before closing:

1. The server sends `Goodbye{code: TAKEN_OVER, message, peer_device_name, peer_device_id}` on the control channel, finishes the control stream, waits for it to be delivered (at most 1 s), then closes the connection with code `TAKEN_OVER` (QUIC application code 9; WebSocket close code 4009). The close reason is a fixed text (`taken over`) and never carries the name.
2. `peer_device_name` is the **new device's name after sanitisation**: the `device_name` it paired with, with control characters (C0, C1, DEL), bidirectional controls and invisible characters (the sets rejected in file names, §3.1) removed, surrounding whitespace trimmed, and cut to at most 64 bytes on a character boundary. It may be empty. A receiver rejects a `Goodbye` whose name is longer than 64 bytes or still contains one of those characters (the same total-validation rule as every other message; the client then treats the close as a plain `TAKEN_OVER` without a name). `hx_proto::message::sanitize_device_name` is the reference implementation.
3. `peer_device_id` is the new device's 16-byte device id (§11.1), or empty if the server will not say. The name is chosen by the other device and can imitate another ("My phone"), so the client MUST display it as plain text (no markup, no formatting) next to the first 8 hex digits of the id, and never use either for authorization.
4. The displaced client's UI states that another device took over and offers **"Revoke that device"** (a stolen device that gets used is the likely reason to be displaced). The action is the 1.2 `RevokeDevice` request (§5.9) with `peer_device_id` as the device id, sent on a new **authenticated session** of the displaced device: it connects and passes its PIN as usual but does **not** send a `ViewConfig`, so it claims the desktop from nobody (§5.9, "Claiming the desktop"). The displaced connection itself is closed (item 6), so the request cannot ride on it. A client that negotiated no `DEVICE_MANAGEMENT` (a 1.1 server) offers only the notice.
5. To a peer whose negotiated minor is 0 the server cannot use the new code: it sends `Goodbye{code: BUSY, message: "another device took over this desktop"}` and closes with `BUSY`.
6. A client that sees close code `TAKEN_OVER` MUST NOT reconnect automatically (it would displace the other device in turn); reconnecting is a user action.

### 5.8 Server statistics (1.1)

`ServerStats` is one control message (S → C, `ControlMessage.server_stats`, field 11) for the client's stats overlay. It carries **numbers only**: it has no string and no bytes field and none may be added, so nothing a session or the desktop produced can reach a client through it (ipc.md §19.1 rule 3). The server builds it from its own measurements; the gateway builds it from the session's `SessionStats` and its transport numbers.

All fields are `uint32`; counts are for the interval, as for `ClientStats`.

| Field | # | Meaning |
|---|---|---|
| `interval_ms` | 1 | Length of the interval, 1 to 60000 |
| `frames` | 2 | Video frames sent |
| `keyframes` | 3 | Of those, frames flagged `KEY` |
| `dropped_frames` | 4 | Frames cancelled or skipped as stale (§6.2) |
| `bitrate_kbps` | 5 | Measured video bitrate sent, kbit/s |
| `target_bitrate_kbps` | 6 | Encoder target bitrate, kbit/s |
| `fps_ceiling` | 7 | Current frame-rate ceiling, at most 240 |
| `encode_p95_us` | 8 | 95th percentile encode time, microseconds |
| `total_p95_us` | 9 | 95th percentile time from capture to the frame being handed to the transport, microseconds |
| `queue_depth_max` | 10 | Largest number of frames queued for sending in the interval |
| `rtt_us` | 11 | The server's smoothed transport round-trip time in microseconds; 0 if unknown |

Rules: it is sent only after authorization, only if `SERVER_STATS` was negotiated, and only while the client's latest `ViewConfig` has `stats_enabled = true`; **at most once per second** per connection (nominal interval 1000 ms). A client MAY drop messages that arrive faster than 4 per second (counted, never a protocol error) and ignores one it did not ask for. A `ServerStats` from a client, or sent when not negotiated, is a protocol error (`PROTOCOL_ERROR`). Counters the server cannot measure are 0. The values are diagnostic only and never feed any trust decision.

### 5.9 Device management (1.2)

Lets a client list the devices paired with the server, revoke one and (1.3) ask for a pairing code for a new device: the "Revoke that device" action after a takeover (§5.7) and Server details → Security in the app (userflow: "Paired devices: name, last seen; Revoke any device"). It is one control variant, `ControlMessage.device_mgmt` (field 12, `DeviceMgmt`), used in both directions and negotiated by the feature `DEVICE_MANAGEMENT` (§4.3, §4.6).

`DeviceMgmt` = `request_id` (1, uint32) and one body (`oneof`):

| Body | # | Direction | Fields |
|---|---|---|---|
| `list` (`ListDevices`) | 10 | C → S | none |
| `device_list` (`DeviceList`) | 11 | S → C | `devices` (1, repeated `DeviceInfo`, at most 128), `truncated` (2, bool) |
| `revoke` (`RevokeDevice`) | 12 | C → S | `device_id` (1, bytes, exactly 16) |
| `revoke_result` (`RevokeResult`) | 13 | S → C | `status` (1, `RevokeStatus`) |
| `event` (`DeviceEvent`) | 14 | S → C | `kind` (1, `DeviceEventKind`), `device` (2, `DeviceInfo`), `by_device_id` (3, bytes, empty or 16) |
| `create_pairing_code` (`CreatePairingCode`) | 15 | C → S | **1.3.** `expires_in_s` (1, uint32) |
| `pairing_code_issued` (`PairingCodeIssued`) | 16 | S → C | **1.3.** `code` (1, string), `expires_at_unix` (2, uint64), `status` (3, `PairingCodeStatus`), `retry_after_s` (4, uint32) |

`DeviceInfo`: `device_id` (1, 16 bytes), `name` (2, string: the label the device chose at pairing, **already sanitised** by the server as in §5.7, at most 64 bytes; a receiver rejects a longer one or one that still contains a control, bidirectional or invisible character; show it as plain text next to the first 8 hex digits of the id and never use it for authorization), `created_unix` (3), `last_seen_unix` (4, 0 = never), `status` (5, `DeviceStatus`: `ACTIVE` 1 or `REVOKED` 2), `revoke_reason` (6, `DeviceRevokeReason`: `USER` 1 or `TOO_MANY_PIN_FAILURES` 2, set exactly when revoked), `revoked_unix` (7, set only when revoked), `current` (8, true on the entry of the device that asked, in a `DeviceList` only, at most one).

`RevokeStatus`: `OK` 1, `NOT_FOUND` 2, `ALREADY_REVOKED` 3, `LAST_ACTIVE_DEVICE` 4, `RATE_LIMITED` 5, `FAILED` 6 (a server fault). `UNSPECIFIED` (0) is invalid. `DeviceEventKind`: `ADDED` 1, `REVOKED` 2, `REINSTATED` 3. `PairingCodeStatus` (1.3): `OK` 1, `RATE_LIMITED` 2, `INVALID_ARGUMENT` 3, `FAILED` 4 (a server fault); `UNSPECIFIED` (0) is invalid.

**Request ids.** A request and its answer carry the same non-zero `request_id`, chosen by the client; a `DeviceEvent` carries 0 and nothing else may. A client may have several requests outstanding; the server processes the requests of one connection in arrival order and answers each exactly once.

**Authorization.** Device management is available only on a connection that is **authorized** (§2.1: the pinned key checked and the PIN passed) and that negotiated `DEVICE_MANAGEMENT`:

- While the connection is restricted the transport already treats the variant as a protocol error (§2.1 lists the only control messages processed). It is never available on a pairing connection (§11.2), which stays restricted.
- A `DeviceMgmt` from a client that did not negotiate the feature, a body that only the server may send (`device_list`, `revoke_result`, `event`, `pairing_code_issued`), a request with `request_id` 0 or an event with a non-zero one is a protocol error (`PROTOCOL_ERROR`). `hx_proto::pb::DeviceMgmt::direction` tells a receiver which way a body may travel, because the transport cannot see it (one envelope carries both directions).
- Authority comes from the authenticated session alone, never from a field: `device_id` names the **target**, and any authenticated paired device may target any device. That is the intended model (a stolen device is revoked from another device, architecture §8.1) and it rests on the PIN: a thief who holds a device key but not its PIN cannot reach this route.
- The server re-reads the registry for every request and limits the rate: **at most 10 revoke requests per minute per device, counted over all its connections**; further ones are answered `RATE_LIMITED` and change nothing. `list` is bounded by the 128-entry cap.

**Listing.** `ListDevices` returns the registry entries, **revoked ones included** (so that a device that was offline when a revocation happened learns about it on its next list), active devices first, then revoked ones, newest first within each group. At most 128 entries are returned; `truncated` says there were more.

**Revoking.** `RevokeDevice` is a revocation by a user (`revoke_reason` `USER`). Rules:

1. Unknown id: `NOT_FOUND`. Already revoked: `ALREADY_REVOKED`, nothing changes (so a retry after a lost answer is safe).
2. **Self-revoke is allowed** (the "sign out and forget this device" action), **except that the last active device cannot be revoked**: if the revocation would leave the server with no active device, the answer is `LAST_ACTIVE_DEVICE` and nothing changes. The requester is itself an active device, so only a self-revoke can reach that case; revoking *another* device is always allowed. Recovery from "every device is gone" is the operator's (the root CLI), not a protocol path.
3. On `OK` the registry change is persisted first, then every live session of the target is closed with `UNAUTHORIZED` (§11.5; for a self-revoke the `RevokeResult` is sent first and the connection is closed afterwards), and the change is announced (below). **Reinstating is not offered**: lifting a revocation needs the Linux password (§11.3, architecture §8.3), which the operator or the re-pairing flow supplies.
4. **Cooling-off.** A device that holds a stolen key's PIN can revoke the owner's other devices; the owner's counter-revocation must win. If a device is revoked (by another device, the operator or the PIN lockout, but not by itself) **less than 60 seconds** after it revoked other devices, the server **undoes those revocations**: the targets become active again and every live session gets a `DeviceEvent` `REINSTATED` (and the audit log a `DEVICE_REINSTATED`). Only revocations that a device made (reason `USER` **and** cause `DEVICE`, never `OPERATOR`, `SELF` or `LOCKOUT`) are undone, so a target that an operator revoked after the device did stays revoked; a self-revoke (a sign-out) undoes nothing. The window is kept in memory, so a server restart ends it. A client that sees one of its devices revoked by an unfamiliar device therefore has a minute to revoke that device.
5. Every revocation is written to the server's audit log (`RecordEvent` `DEVICE_REVOKED`, ipc.md §6.15) whoever caused it (a device, the operator, or the PIN lockout): the audit log is the record that a compromised gateway cannot edit.

**Change notices.** Whenever the registry changes (a device pairs, is revoked by anyone, or is reinstated by the operator) the server sends a `DeviceEvent` to **every live authorized session that negotiated `DEVICE_MANAGEMENT`**, the actor's own included, with `device` as it is after the change and `by_device_id` set to the device that caused it, or empty if it was the operator, the PIN lockout or the server itself. This is how a revocation is "shown to all paired devices": online devices get the event, offline ones find the revoked entry in their next `DeviceList`. A client shows it as a notice ("Phone revoked by Laptop") and never acts on it beyond display. The server sends at most one event per change and bounds every write to the control channel (5 s): a client that does not read its control channel for that long is disconnected (`BUSY`), because a half-written message cannot be skipped (the next `ListDevices` is authoritative after a reconnect).

**Pairing a new device from the app (1.3).** The Security screen lets an already paired, PIN-logged-in device give a new device a short pairing code, instead of the user running `hx-agent pairing code` on the server. The new bodies are not skippable by a 1.2 peer (an unknown body decodes as a `DeviceMgmt` with no body, which is malformed), so they are gated by the **negotiated minor at least 3** as well as by `DEVICE_MANAGEMENT` (§4.7): a client never sends `create_pairing_code` to a server whose negotiated minor is below 3, and a server never sends `pairing_code_issued` to such a client.

- **Who may ask.** Only a PIN-authenticated `INTENT_SESSION` connection of an **active** device that negotiated `DEVICE_MANAGEMENT`; as for every body of this message, authority comes from the authenticated session alone. Never on a pairing connection or a setup connection (both restricted or control-only, §2.1, §5.10).
- **The code.** `expires_in_s` is 60 to 900; any other value is answered `INVALID_ARGUMENT` and nothing is created. A value above the server's `pairing_ttl_s` is capped silently, so `expires_at_unix` (Unix seconds) is the authoritative expiry. The code is the existing short code of §11.3 (`XXXX-XXXX`, 3 started attempts, single use) created **exactly like** the admin socket's `CreatePairingCode` ([ipc.md](ipc.md) §9); the new device pairs with `INTENT_PAIR`, mode `CODE`, as for an interactive install.
- **Limits.** At most **3 codes per hour per server** (counted over all devices and connections; the fourth is answered `RATE_LIMITED` with `retry_after_s`, and nothing changes) and **one live code at a time**: a new code replaces the previous one, which stops working at once.
- **Audit.** Every issued code is recorded as `RecordEvent DEVICE_PAIRING_CODE_ISSUED` with the requesting device's id ([ipc.md](ipc.md) §6.15); the code itself is never logged or recorded. A device that pairs with it appears as a `DeviceEvent` `ADDED` to every live session, like any new device.
- **What the new device is.** An ordinary device: it needs the PIN to log in and is **never a setup device** (§5.10: only a device paired with the installer's token can open `INTENT_SETUP`).
- **Secrecy.** `PairingCodeIssued` carries a secret: its `Debug` is redacting (`skip_debug`, §14), neither side logs it, and the app shows it only while the dialog is open. The trust model is the one of revoking: a thief needs the device key **and** the PIN, and the audit log and the `ADDED` notice show a device that a thief added.

**Claiming the desktop.** Authenticating claims nothing: the server applies its one-active-client rule and the takeover policy (§5.7, ipc.md §18) when the client sends its first `ViewConfig`, not when the PIN is accepted. A client that connects only to manage devices (the "Revoke that device" path after `TAKEN_OVER`, or a settings screen) therefore never sends `ViewConfig`, displaces nobody and is not displaced. The server closes a session that has sent no `ViewConfig` within 5 minutes of authorization with `NO_ERROR` (configurable).

Limits: a `DeviceList` of 128 worst-case entries stays below the 64 KiB control message limit (§3.1; checked by a test). Field validation and `hx_proto::message::MgmtDirection` are in `crates/hx-proto`.

### 5.10 Post-pairing setup (1.3)

The one-liner path (architecture §5.1) ends the installer at pairing: the password, the PIN and the desktop are chosen **in the app afterwards**. This section is the contract for that. The server side (the coordinator, the job, the privd calls) is [ipc.md](ipc.md) §5.5; the decisions are [ipc.md](ipc.md) §22 (decision 20).

**Why a new connection type.** The pairing connection cannot carry setup: the transport closes any connection that is not authorized within 30 s, pairing alone may use 20 s of that, its `HelloAck` advertises no features, a restricted connection accepts only `pairing`, `auth` and `goodbye`, and the token is single use, so it cannot be resumed. A 45-minute desktop build cannot run on it. Setup messages on a normal PIN session were rejected: they would widen the pre-authentication surface (a new message on a restricted connection), leave a "paired, no PIN" dead end if the 30 s budget is missed, clash with the 5-minute idle close of a session, and mix setup authority into every session. So the pairing connection is unchanged (closed with `NO_ERROR` once pairing is done, §11.2), and the device **reconnects with its pinned key** and `Hello{intent: SETUP, version 1.3, features ⊇ SETUP}`.

**Admission** (decided before `HelloAck` and checked again right before authorizing):

| Condition | Server answer |
|---|---|
| Unknown or revoked key; client minor below 3; `SETUP` not offered; no setup gate installed | `Refuse{UNAUTHORIZED}`, the same uniform text as today |
| A known, active key, unless **all** of these hold: the device is the **bound setup device**, the server's persisted mirror says the setup window is open, and `hx-privd` reports the phase `SETUP_OPEN` | `Refuse{SETUP_CLOSED}`, close code 10. If privd cannot be asked: `Refuse{BUSY}` |
| Admitted, and **no PIN exists** on the server | **KeyOnly**: authorized control-only (§2.1); the server sends `AuthResult{OK}`, then `SetupState`. Only `set_pin` and `goodbye` work; `start`, `cancel` and `finish` are answered `PIN_REQUIRED`. When `set_pin` succeeds on that connection it becomes **SetupAuthorized**: it proved its key and chose the PIN |
| Admitted, and a PIN exists | **NeedsPin**: `AuthResult{PIN_REQUIRED}` (§11.4), then the exchange is exactly §11.4 (an attempt is counted before it is checked, backoff, the 5th failure revokes, the check goes through the server's PIN verifier); on success the connection is SetupAuthorized |

**The bound setup device.** When the installer's token is installed while the setup window is open, the server records the token's public 8-byte id. The device that then pairs with **that token** (not with a code: a code has 40 bits of entropy and belongs to the interactive path) becomes the **setup device**; a previously bound device loses the binding and its live setup connection is closed with `SETUP_CLOSED`. A second device that pairs with any other secret is an ordinary paired device: it cannot log in until a PIN exists, then logs in normally (the PIN is for all devices), and it can **never** open `INTENT_SETUP`. The binding ends when setup finishes, when the window closes or expires, and when the setup device is revoked (which also cancels a running job). To recover from a lost or revoked app device, the user reruns the one-liner, whose token stage always asks for a fresh token.

**Versioning.** See §4.7: a client sends `INTENT_SETUP` only after a confirmed pairing whose `HelloAck.version.minor` was at least 3 (`server_supports_setup`), and re-checks the minor and `SETUP` on the setup `HelloAck`. Otherwise the app says the server must be updated.

#### Wire (`crates/hx-proto/proto/hx.proto`, package `hx.v1`, everything tagged 1.3)

```proto
enum Intent { ...; INTENT_SETUP = 3; }               // 1.3; only to a server known to be >= 1.3
enum RefuseReason { ...; REFUSE_REASON_SETUP_CLOSED = 5; } // 1.3, INTENT_SETUP only
// ControlMessage.oneof message:  SetupMessage setup = 13;  // 1.3, feature SETUP, INTENT_SETUP connections only

message SetupMessage {
  uint32 request_id = 1;           // non-zero on set_pin/start/cancel/finish and the ack answering them; 0 on state/progress/result
  oneof body {
    SetupState    state    = 10;   // S->C push: on authorization and on every job transition
    SetupSetPin   set_pin  = 11;   // C->S
    SetupStart    start    = 12;   // C->S
    SetupCancel   cancel   = 13;   // C->S
    SetupFinish   finish   = 14;   // C->S
    SetupAck      ack      = 15;   // S->C, exactly one per request, same request_id
    SetupProgress progress = 16;   // S->C push
    SetupResult   result   = 17;   // S->C push
  }
}
message SetupSetPin { bytes pin = 1; }                       // 6..=16 ASCII digits. skip_debug, redacted
message SetupStart  { SetupOptions options = 1; bytes password = 2;  // 1..=511 B, UTF-8, no NUL/CR/LF. skip_debug
                      reserved 3 to 9; }                     // Phase 2 sealed secrets (Drive token), sealed only
message SetupCancel {}
message SetupFinish {}

enum SetupDistro { SETUP_DISTRO_UNSPECIFIED=0; SETUP_DISTRO_UBUNTU_24_04=1; SETUP_DISTRO_UBUNTU_26_04=2;
                   SETUP_DISTRO_DEBIAN_12=3; SETUP_DISTRO_DEBIAN_13=4; }   // numbering = privd Distro
enum SetupDesktop { SETUP_DESKTOP_UNSPECIFIED=0 /* = XFCE */; SETUP_DESKTOP_XFCE=1; }
enum SetupPreset  { SETUP_PRESET_UNSPECIFIED=0; SETUP_PRESET_BASIC=1; SETUP_PRESET_DEVELOPER=2; }
enum SetupImageMode { SETUP_IMAGE_MODE_UNSPECIFIED=0 /* = AUTO */; SETUP_IMAGE_MODE_AUTO=1;
                      SETUP_IMAGE_MODE_BUILD=2; SETUP_IMAGE_MODE_PREBUILT=3; }
message SetupOptions {
  SetupDistro distro = 1;            // required
  SetupDesktop desktop = 2;
  SetupPreset preset = 3;            // required
  string username = 4;               // 1..=32, ^[a-z_][a-z0-9_-]{0,31}$; reserved names refused (hx_provision::Username is authority)
  SetupImageMode image_mode = 5;
  SetupLimits limits = 6;            // 0 = server default; host bounds checked by privd (ipc 6.8)
  bool docker = 7;
  bool docker_isolation_acknowledged = 8;   // MUST be true when docker is true
  SetupDesktopSettings settings = 9;
}
message SetupLimits { uint32 cpu = 1; uint64 memory_mib = 2; uint64 disk_gib = 3; }  // static caps: cpu<=1024, memory_mib<=16777216, disk_gib<=65536
message SetupDesktopSettings { string hostname = 1; string timezone = 2; string locale = 3; string keyboard = 4; } // <=63/64/32/40 bytes, printable ASCII; privd validates content (ipc 6.5)

enum SetupJobState { SETUP_JOB_STATE_UNSPECIFIED=0; IDLE=1; RUNNING=2; SUCCEEDED=3; FAILED=4; CANCELLED=5; } // prefixed in the .proto
enum SetupDesktopState { ..._UNSPECIFIED=0; NONE=1; CREATING=2; READY=3; FAILED=4; UNKNOWN=5; }       // from GetDesktop; UNKNOWN if privd unreachable
message SetupHostFacts { uint32 cpu_count = 1; uint64 memory_total_mib = 2; uint64 pool_total_gib = 3;
                         uint64 pool_free_gib = 4; bool docker_supported = 5; string os = 6 /* <=64 */; string arch = 7 /* <=16 */; }
message SetupState {
  SetupJobState job = 1; uint32 job_id = 2; bool pin_set = 3; SetupDesktopState desktop = 4;
  uint64 window_expires_unix = 5; bool finished = 6;
  SetupProgress last_progress = 7;   // when RUNNING
  SetupResult last_result = 8;       // when the job ended (memory only; lost on gatewayd restart)
  SetupHostFacts host = 9;
}
enum SetupAckStatus { ..._UNSPECIFIED=0; OK=1; INVALID_ARGUMENT=2; PIN_REQUIRED=3; PIN_ALREADY_SET=4; BUSY=5;
                      NOT_RUNNING=6; ALREADY_FINISHED=7; WINDOW_TOO_SHORT=8; RATE_LIMITED=9; LOCKED=10;
                      UNAVAILABLE=11; DESKTOP_NOT_READY=12; FAILED=13; }
message SetupAck { SetupAckStatus status = 1; string field = 2 /* <=64, the invalid field, never a value */;
                   string message = 3 /* <=256, sanitized */; uint32 retry_after_ms = 4; uint32 job_id = 5; }
enum SetupStage { ..._UNSPECIFIED=0; PREFLIGHT=1; IMAGE_FETCH=2; IMAGE_IMPORT=3; BUILD=4; LAUNCH=5; POST=6;
                  SESSION=7; DOCKER=8; VERIFIERS=9; FINISH=10; DONE=11; }
message SetupProgress { uint32 job_id = 1; SetupStage stage = 2; uint32 index = 3; uint32 total = 4;
                        string step = 5 /* <=128, sanitized */; uint32 percent = 6 /* 0..=100 or 255 */; bool ok = 7; uint32 elapsed_ms = 8; }
enum SetupPathTaken { ..._UNSPECIFIED=0; PREBUILT=1; BUILD=2; EXISTING=3; }
enum SetupDockerStatus { ..._UNSPECIFIED=0; NOT_REQUESTED=1; ENABLED=2; UNSUPPORTED_INCUS=3; SELF_TEST_FAILED=4; NOT_ENABLED=5; }
message SetupDocker { SetupDockerStatus status = 1; string docker_version = 2; string found = 3; string required = 4;
                      bool isolation_restored = 5; string hint = 6 /* <=256 */; }   // privd output_tail is NOT forwarded
enum SetupErrorCode { ..._UNSPECIFIED=0; INVALID_ARGUMENT=1; DESKTOP_EXISTS=2; INSUFFICIENT_SPACE=3; RATE_LIMITED=4;
                      LOCKED=5; WINDOW_CLOSED=6; TIMED_OUT=7; CANCELLED=8; UNAVAILABLE=9; UNSUPPORTED=10;
                      ISOLATION_NOT_RESTORED=11; INTERNAL=12; }
message SetupError { SetupErrorCode code = 1; SetupStage stage = 2; string message = 3 /* <=256 */; bool retryable = 4; uint32 retry_after_ms = 5; }
message SetupResult { uint32 job_id = 1; SetupJobState status = 2; SetupPathTaken path_taken = 3; string reason = 4;
                      repeated string warnings = 5 /* <=16 x <=256 */; SetupDocker docker = 6; SetupError error = 7;
                      bool finished = 8; uint32 elapsed_ms = 9; }
```

Elided enum names (`...`) are the type's name in upper snake case as a prefix, as `SETUP_JOB_STATE_IDLE`; the `.proto` is authoritative for spelling. Also on the wire: `CloseCode::SetupClosed = 10` (WebSocket 4010, §8) and `AuthStatus::PinRequired = 6` (§11.4), both sent only on `INTENT_SETUP` connections.

**Validation.** `hx-proto` fails with `PROTOCOL_ERROR` on: the hard size caps (password at most 1024 bytes, PIN at most 16, strings at their caps, warnings at most 16); the direction of a body (`SetupMessage::direction()`, modelled on `DeviceMgmt::direction`: `set_pin`, `start`, `cancel` and `finish` only from the client; `state`, `ack`, `progress` and `result` only from the server); and the request-id rules below. **Semantic** checks, answered `SetupAck{INVALID_ARGUMENT, field}` and never as a close, are: the password rules (1 to 511 bytes, valid UTF-8, no NUL, CR or LF: one shared checker, `hx_proto::message::password_problem`, used by the client and the server), the PIN digits (6 to 16 ASCII digits, as §11.4), the username regex (`hx_provision::Username` is the authority), enum values, and Docker requested without `docker_isolation_acknowledged`.

**Request ids.** `set_pin`, `start`, `cancel` and `finish` carry a non-zero `request_id` chosen by the client; the server answers each with exactly one `ack` carrying the same id. `state`, `progress` and `result` carry 0 and nothing else may. A client may keep several requests outstanding; the server handles one connection's requests in order.

**Server state machine, per `INTENT_SETUP` connection:**

```
Pending --(unknown/revoked | minor<3 | no SETUP offered)--> Refuse UNAUTHORIZED
Pending --(gate Closed)--> Refuse SETUP_CLOSED
Pending --(gate KeyOnly)--> HelloAck -> recheck -> authorize control-only -> AuthResult{OK} -> KEY_ONLY
Pending --(gate NeedsPin)--> HelloAck -> AuthResult{PIN_REQUIRED} -> PIN_PENDING
PIN_PENDING --(PIN ok, recheck)--> authorize control-only -> AuthResult{OK} -> SETUP_AUTHORIZED
PIN_PENDING --(wrong x5 / timeout / 5 msgs)--> close UNAUTHORIZED (the 5th wrong PIN revokes: job cancelled, unbound)
KEY_ONLY: set_pin ok -> SETUP_AUTHORIZED; start/cancel/finish -> ack PIN_REQUIRED; others -> PROTOCOL_ERROR
SETUP_AUTHORIZED: set_pin -> ack PIN_ALREADY_SET; start; cancel; finish; goodbye
any: binding moved / window closed with no job to report -> close SETUP_CLOSED; revoked -> close UNAUTHORIZED;
     idle 10 min with no job running -> close NO_ERROR; a new setup connection of the same device -> old closed NO_ERROR "replaced";
     job ended with finished=true -> SetupResult, flush, close NO_ERROR "setup finished"
```

**Job** (one per server, independent of any connection; [ipc.md](ipc.md) §5.5): `IDLE` → `start` → `RUNNING` → `SUCCEEDED` | `FAILED` | `CANCELLED`; from an ended state a new `start` is allowed unless setup is finished; a second `start` while one runs is answered `BUSY`.

**Messages and their rules.**

- **`SetupState`** is pushed on authorization and on every job transition. It reports the job state and id, whether a PIN is set (`pin_set`), the desktop's state as the server sees it, the window's expiry, whether setup is finished, the last progress (while `RUNNING`), the last result (kept in memory only: lost on a server restart) and the host facts the wizard shows.
- **`set_pin`** succeeds at most once, because a PIN can only be set while none exists (`PIN_ALREADY_SET` otherwise). The PIN is for all devices, as in the SSH path.
- **`start`** carries the options and the password. It is refused with `WINDOW_TOO_SHORT` when less than **50 minutes** remain in the setup window (the 45-minute `CreateDesktop` maximum plus a margin; the app then shows `sudo hx-agent setup extend`); an admitted job runs to completion. It is refused with `PIN_REQUIRED` before a PIN exists, `BUSY` while a job runs, `ALREADY_FINISHED` after setup is finished, and `RATE_LIMITED` past 6 `start` requests per hour per server.
- **`cancel`** takes effect only while a privd command is running (the server cancels it, privd destroys the unfinished instance); at any other time it is answered `OK` and the `result` shows what actually happened. After a cancel the window stays open and the app may start again. `cancel` with no job running is `NOT_RUNNING`.
- **`finish`** retries finishing setup if the job's own finish failed transiently; it is idempotent (`OK`, or `ALREADY_FINISHED` when setup is already finished) and is answered `DESKTOP_NOT_READY` when no usable desktop exists. The job itself finishes setup at its end, which closes the window and the setup power that comes with it as early as possible.
- **`progress`** is coalesced, latest wins, at most 4 per second; a stage change is sent at once. `index` and `total` count steps within the stage, and `percent` 255 means unknown. `step` is sanitized again by the server. The server stages map 1:1 to privd's `PREFLIGHT`, `IMAGE_FETCH`, `IMAGE_IMPORT`, `BUILD`, `LAUNCH`, `POST`, `SESSION`, `DOCKER` and `DONE`; `VERIFIERS` and `FINISH` are the server's own.
- **`result`** ends a job: `SUCCEEDED` (with the path taken, `reason`, warnings and the Docker outcome), `FAILED` (with a `SetupError`: code, the stage, a sanitized message, `retryable`, `retry_after_ms`) or `CANCELLED`. With `finished = false` on a success the window had already closed: the warning names `sudo hx-agent setup finish` (Admin `FinishSetup` moves privd to `READY` once a ready desktop exists, [ipc.md](ipc.md) §5.1). The error codes are mapped from privd's in [ipc.md](ipc.md) §5.5. A Docker self-test failure during setup is reported in `SetupDocker`; retrying Docker is possible only afterwards, through the Admin CLI (`hx-agent docker enable`).
- **Secrets.** The password and PIN follow the SSH path's rules (6 to 16 digits; 1 to 511 bytes of UTF-8 without NUL, CR or LF); nothing is cached by the server across a disconnect, a job end or a restart. A client therefore sends the password **only to start a new job**: watching a running job needs none. `SetupSetPin`, `SetupStart` and `Opaque` have a redacting `Debug` (§14); the server copies a secret into zeroizing memory at once and drops the message (the prost-decoded buffers are not wiped, best effort like the PIN of §11.5).
- **Limits.** At most 2 requests per second per connection (burst 8), else close `BUSY`; one live setup connection per server; control writes bounded to 5 s, and a client that does not read is closed `BUSY` while the job continues.

**Client rules.** Pair (record the server key and the confirmed version) → if `server_supports_setup`, reconnect with `INTENT_SETUP` → KeyOnly: `set_pin`; NeedsPin: send the PIN → read `SetupState`:

- `IDLE` or `FAILED`: `start(options, password)`.
- `RUNNING`: watch only; nothing to re-send (this is how a dropped connection resumes).
- `SUCCEEDED` with `finished = false`: `finish`.
- Then wait for the `result` and the close, connect with `INTENT_SESSION` and the PIN, and go on as in §2.

A `SETUP_CLOSED` refusal (or close) at any point means the window is gone: go to the normal PIN login (a server that finished setup refuses `INTENT_SETUP` this way). The app keeps the PIN in zeroizing memory only until the first successful login. `UNAUTHORIZED` after a confirmed pairing means the device lost its binding or was revoked: say so and offer to rerun the one-liner.

**Client library** (`hx_crypto::setup`, so the app and the tests share it):

```rust
pub async fn connect_setup(target:&Target, device:&Arc<IdentityKey>, server_key:&PublicKey, opts:&SetupConnectOptions) -> Result<SetupAuth>;
pub enum SetupAuth { Ready(SetupSession), NeedsPin(AwaitingSetupPin) }
impl AwaitingSetupPin { pub async fn submit_pin(&mut self, pin:&Pin) -> Result<PinReply>; pub fn into_session(self) -> Result<SetupSession>; }
pub struct Password(/* Zeroizing, redacting Debug, validated with hx_proto::message::password_problem */);
impl SetupSession {
  pub fn state(&self) -> &pb::SetupState;
  pub async fn set_pin(&mut self, pin:&Pin) -> Result<pb::SetupAck>;
  pub async fn start(&mut self, opts: pb::SetupOptions, pw:&Password) -> Result<pb::SetupAck>;
  pub async fn cancel(&mut self) -> Result<pb::SetupAck>;
  pub async fn finish(&mut self) -> Result<pb::SetupAck>;
  pub async fn next_event(&mut self) -> Result<SetupEvent>;   // State | Progress | Result | Closed(CloseInfo)
}
pub fn server_supports_setup(v: &pb::Version) -> bool;        // minor >= 3, used with the confirmed pairing HelloAck
// errors: Error::SetupClosed (refuse/close SETUP_CLOSED -> go to normal login), Error::UpdateRequired
```

**Server-side contracts** that this section relies on (code, not wire): `hx_transport::Connection::authorize_control_only(allowed: Features)` (server only; satisfies the deadline, releases the pre-authentication slot, lets the control variants through, keeps the QUIC unidirectional credit at 0, still drops input and mouse and refuses media sends; `Hello` validation accepts `Intent::Setup`; `RefuseReason::SetupClosed` maps to close code 10; `Features::SETUP`, `defined_up_to(3)` and a `Features::without` helper; `PROTOCOL_MINOR = 3`), and in `hx-crypto` a `SetupGate` (`admit(device)` returns `Closed`, `KeyOnly` or `NeedsPin`, bounds its own calls, and without it `INTENT_SETUP` is refused `UNAUTHORIZED`), the additive `Outcome::Paired { …, with: PairedWith::{Token{id}, Code} }` and `Outcome::Setup { connection, device, pin_verified }`. The gate and the registry are checked again immediately before `authorize_control_only`; on a NeedsPin connection the PIN exchange reuses the session's `pin_exchange` unchanged, and the revocation watcher closes the connection.

**Threats this section answers** (the full table is in the 1G design record): a token thief who wins the pairing race gets the desktop setup, which is inherent to bearer tokens; the legitimate app then fails to pair ("wrong or expired, or intercepted", §11.3) and the user reruns the one-liner, and the device is visible in `hx-agent devices` and the audit log. A stolen setup-device key before a PIN exists equals the owner for the few minutes before `set_pin`; afterwards every setup connection needs the PIN, with lockout after 5. A malicious paired client during setup has no field for Admin-only options (the server builds the privd request from typed, validated values: no `image_file`, no pool device, no private networks, `desktop_id` from configuration). A protocol downgrade is impossible inside pinned TLS: `INTENT_SETUP` needs a client minor of at least 3 and `SETUP`, and an old server is never sent the intent.

### 5.11 Server management (1.3)

Lets an app manage the server it is connected to from the "Server details" screens: an overview, changing the PIN and the account password, restarting the desktop, turning Docker off, changing the resource limits and updating the agent. One control variant, `ControlMessage.server_mgmt` (field 14, `ServerMgmt`), used in both directions, negotiated by the feature `SERVER_MANAGEMENT` (bit 6, §4.3, §4.7). The server side is [ipc.md](ipc.md) §5.6; the decision is ipc.md §22 decision 24.

`ServerMgmt` = `request_id` (1, uint32) and one body (`oneof`). Every request is answered by exactly one response with the same non-zero `request_id`; a client may have several outstanding, the server handles one connection's requests in arrival order.

| Body | # | Direction | Fields |
|---|---|---|---|
| `get_overview` | 10 | C → S | none |
| `overview` | 11 | S → C | `ServerOverview` (below) |
| `change_pin` | 12 | C → S | `current` (1, bytes), `new` (2, bytes): 6 to 16 ASCII digits each. **Secret** |
| `change_password` | 13 | C → S | `current` (1, bytes), `new` (2, bytes): 1 to 511 bytes of UTF-8 without NUL, CR or LF (`hx_proto::message::password_problem`). **Secret** |
| `restart_desktop` | 14 | C → S | `force` (1, bool) |
| `set_docker` | 15 | C → S | `enable` (1, bool) |
| `set_limits` | 16 | C → S | `limits` (1, `SetupLimits`: `cpu`, `memory_mib`, `disk_gib`; each non-zero and within the static caps of §5.10) |
| `check_update` | 17 | C → S | none |
| `apply_update` | 18 | C → S | `version` (1, string, at most 32 bytes) |
| `result` | 19 | S → C | `ServerResult` (below): the answer to every request except `get_overview` |

`ServerResult`: `status` (1, `ServerStatus`), `retry_after_s` (2, uint32), `attempts_left` (3, uint32, set with `WRONG_PIN`), `message` (4, string, at most 256 bytes: a fixed or sanitised text, **never** a value that was sent), `restart_required` (5, bool, `set_limits`), `update` (6, `ServerUpdateInfo`, `check_update`), `version` (7, string, `apply_update`: the version being installed). `ServerStatus`: `OK` 1, `INVALID_ARGUMENT` 2 (a semantic check failed; nothing was changed), `WRONG_PIN` 3, `WRONG_PASSWORD` 4, `BACKOFF` 5 (too soon after a wrong secret: not checked, not counted; `retry_after_s`), `LOCKED` 6 (the check is locked: a purpose that privd locked after its failure cap, or the device was revoked by the lockout; only the operator lifts it), `RATE_LIMITED` 7 (`retry_after_s`), `ADMIN_ONLY` 8 (not allowed to the server's gateway after setup, for example turning Docker **on**; the app shows the command in `message`), `UNAVAILABLE` 9 (the privileged daemon cannot be reached now; retry), `DESKTOP_NOT_READY` 10, `FAILED` 11 (a server fault), `UPDATE_REFUSED` 12 (privd refuses the update: not newer, not the fetched release, or a rolled-back release that only an operator may re-apply within 24 hours), `UNSUPPORTED` 13. `UNSPECIFIED` (0) is invalid.

`ServerOverview` (everything is optional data; a field the server cannot know is left unset or `UNKNOWN`, never invented): `agent_version` (1, string ≤ 64), `privd_version` (2, string ≤ 64), `server_time_unix` (3), `agent_uptime_s` (4), `update` (5, `ServerUpdateInfo`, the **cached** result of the last `check_update`, unset if there was none since the agent started; `get_overview` never touches the network), `desktop` (6, `ServerDesktop`), `host` (7, `SetupHostFacts`, §5.10), `host_attention` (8, repeated `ServerAttention`, at most 8), `session_active` (9, bool: some client holds the desktop now). `ServerDesktop`: `state` (1, `ServerDesktopState`: `NONE` 1, `CREATING` 2, `READY` 3, `FAILED` 4, `STOPPED` 5, `RUNNING` 6, `STARTING` 7, `UNKNOWN` 8 when privd could not be asked), `username` (2, ≤ 32), `distro` (3, `SetupDistro`), `preset` (4, `SetupPreset`), `limits` (5, `SetupLimits`), `docker` (6, `ServerDockerState`: `OFF` 1, `ON` 2, `DEGRADED` 3), `needs_attention` (7, repeated `ServerAttention`, at most 8), `created_unix` (8). `ServerAttention` mirrors privd's `NeedsAttention`: `HOST_ACCOUNT_POLICY` 1, `STUCK_OPERATION` 2, `ISOLATION_NOT_RESTORED` 3, `PIN_LOCKED` 4, `PASSWORD_LOCKED` 5, `UPDATE_ROLLED_BACK` 6, `HOST_DOCKER_FORWARDING` 7. `ServerUpdateInfo`: `current` (1, ≤ 32), `available` (2, ≤ 32, empty = none), `channel` (3, `ServerUpdateChannel`: `STABLE` 1, `BETA` 2), `verified` (4), `rolled_back_version` (5, ≤ 32), `rolled_back_reason` (6, ≤ 256), `checked_unix` (7, 0 = never).

**Authorization.** Only on a connection that is **authorized** (§2.1: the pinned key checked and the PIN passed), of an **active** device, that negotiated `SERVER_MANAGEMENT`. A restricted, pairing or setup connection never processes it (the transport already treats the variant as a protocol error there). A body that only the server may send, a request with `request_id` 0, or the variant without the negotiated feature is a protocol error (`PROTOCOL_ERROR`); `hx_proto::pb::ServerMgmt::direction` tells a receiver which way a body may travel. Authority comes from the authenticated session alone; any authenticated paired device may manage the server, as for devices (§5.9), and it rests on the PIN. Hard size caps and the request-id rules are checked by `hx-proto` (a violation is `PROTOCOL_ERROR`); **semantic** checks (PIN digits, password rules, limits non-zero, the version syntax) are answered `INVALID_ARGUMENT`.

**What each request does.**

- **`get_overview`**: the server's version, the cached update status, the desktop (`GetDesktop`: state, limits, Docker, `needs_attention`), the host facts (`GetHostInfo`: CPU, memory, pool, Incus) and the server time. Bounded: if privd does not answer in time the desktop is `UNKNOWN` and the host facts are left unset.
- **`change_pin`**: the **current PIN is checked by the same code as a login** (`Authenticator::check_pin_for`), under the same per-device guard: the attempt is counted before it is checked on the device's own failure counter (the one a PIN login uses); a wait that is running, from a login or from an earlier `change_pin`, answers `BACKOFF` without checking or counting (the backoff is shared); once the counter is past the limit nothing is verified any more; a wrong one answers `WRONG_PIN` with `attempts_left` and the backoff; the 5th consecutive wrong PIN **revokes the device and closes its sessions** (§11.4), and the revocation is **persisted and announced before the answer is built**: the `WRONG_PIN` answer (`attempts_left` 0) is then sent best-effort and may be lost to the close, which the client reads as `UNAUTHORIZED` (device revoked). A right one resets the counter. An unavailable verifier is never a wrong PIN (the attempt is refunded). A concurrent `change_pin` and login of one device therefore cannot undo each other's count. Then the new PIN is enrolled (Argon2id here, privd's `PepperEnrol(PIN)`, at most 5 a day for the gateway after setup: `RATE_LIMITED` past it) and stored **for the PIN the device authenticated with**: if the operator gave this device a PIN of its own (`hx-agent pin set --device`), only that PIN changes and no other device is affected; otherwise the **shared** PIN changes for all devices without their own PIN. The shared PIN is never replaced from a device that uses its own PIN (that would also drop every other device's own PIN). Other devices keep their sessions and use the new PIN at their next login. Audited (`PIN_CHANGED` with the requesting device).
- **`change_password`**: the account password. privd's `SetUserPassword` with `CURRENT_PASSWORD` verifies the current password against the desktop user's shadow hash and charges a failure to privd's global PASSWORD budget (`WRONG_PASSWORD`; `LOCKED` when that budget is spent), then the server refreshes its password verifier. The desktop must be running (`DESKTOP_NOT_READY`). If the verifier cannot be refreshed after privd accepted the change (for example `PepperEnrol`'s daily allowance is used up) the answer is still `OK` but with a non-empty `message` naming `sudo hx-agent desktop password --verifier-only`: the password did change, and only reinstating a locked-out device by password is affected. Audited (`PASSWORD_CHANGED`, then `PASSWORD_VERIFIER_CHANGED` once the verifier is refreshed).
- **`restart_desktop`**: privd's `RestartDesktop`. Open apps in the desktop close; the stream ends and the client reconnects. Audited (`DESKTOP_RESTARTED`).
- **`set_docker`**: `enable = false` is privd's `DisableDocker` (always allowed: it only reduces exposure; the desktop restarts). `enable = true` after setup is **Admin only** (ipc.md §5.1: it lowers container isolation): the server does not call privd and answers `ADMIN_ONLY` with `message` = `sudo hx-agent docker enable`. Audited (`DOCKER_DISABLED`).
- **`set_limits`**: privd's `SetLimits` (bounds are privd's: ipc.md §6.8, an out-of-bounds value is `INVALID_ARGUMENT`); `restart_required` says the CPU count changed on a running desktop. Audited (`LIMITS_CHANGED`).
- **`check_update`**: privd's `CheckUpdate` (the sandboxed fetcher, verified manifest); the answer is also cached for `get_overview`. At most 6 an hour (privd's own limit).
- **`apply_update`**: privd's `ApplyUpdate` for `version`, which must equal the release privd fetched and verified; `OK` means privd accepted it and is restarting the agent. **The session ends when the gateway restarts**: the client reconnects and reads the new version from `get_overview`. privd's rules apply unchanged: no downgrade, at most 2 started a day, and a release that was rolled back cannot be re-applied by the gateway for 24 hours (`UPDATE_REFUSED`). Audited (`UPDATE_APPLIED`).

**Limits.** Every request is rate limited per device over all its connections (overview 30 a minute, other requests 10 a minute, `RATE_LIMITED` with `retry_after_s`), on top of the privd limits quoted above. Control writes are bounded to 5 s as in §5.9. A request that is waiting on privd is not cancelled by the client dropping the connection (the effect of a mutation that was admitted is applied and audited).

**Secrecy.** `ServerChangePin` and `ServerChangePassword` have a redacting `Debug` (`skip_debug`, §14); the server copies each secret into zeroizing memory at once and drops the message, never logs a secret and never puts one in a `ServerResult.message` or an error; the client wipes its copies after sending (`hx_crypto::server_admin`).

**Client library** (`hx_crypto::server_admin::ServerAdmin`, over an authorized session connection, like `DeviceAdmin`):

```rust
impl ServerAdmin {
  pub fn new(connection: Connection) -> Result<Self>;             // needs SERVER_MANAGEMENT negotiated
  pub async fn overview(&mut self) -> Result<pb::ServerOverview>;
  pub async fn change_pin(&mut self, current: &Pin, new: &Pin) -> Result<ServerReply>;
  pub async fn change_password(&mut self, current: &Password, new: &Password) -> Result<ServerReply>;
  pub async fn restart_desktop(&mut self, force: bool) -> Result<ServerReply>;
  pub async fn set_docker(&mut self, enable: bool) -> Result<ServerReply>;
  pub async fn set_limits(&mut self, limits: pb::SetupLimits) -> Result<ServerReply>;
  pub async fn check_update(&mut self) -> Result<ServerReply>;
  pub async fn apply_update(&mut self, version: &str) -> Result<ServerReply>;
}
```

`ServerReply` is the decoded `ServerResult` (its `status` is never turned into an `Err`: only transport and protocol failures are errors).

## 6. Media (video) channel

One unidirectional stream per encoded frame:

```
+------+----------------------------+----------------------+
| 0x05 | media header (20 bytes)    | payload (payload_len)|
+------+----------------------------+----------------------+
```

Media header (all little-endian):

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 1 | `version` | u8 | Header layout version, MUST be `1` |
| 1 | 1 | `codec` | u8 | `VideoCodec` number: 1 H.264, 2 AV1, 3 H.265. 0 or unknown is invalid |
| 2 | 2 | `flags` | u16 | Bit 0 `KEY` (frame decodes without earlier frames), bit 1 `RESYNC` (the fresh image sent after stale frames were cancelled; implies a decoder restart). Other bits MUST be 0, a receiver rejects them |
| 4 | 4 | `frame_number` | u32 | Increases by 1 per frame produced, wraps modulo 2^32, compared with serial-number arithmetic (RFC 1982); a gap means frames were cancelled or skipped |
| 8 | 8 | `capture_timestamp_us` | u64 | Capture time in microseconds on the server's monotonic clock (arbitrary epoch; only differences are meaningful) |
| 16 | 4 | `payload_len` | u32 | Length of the encoded payload that follows; at most 16 MiB |

Total header size `MEDIA_HEADER_LEN = 20`. The payload is one encoded frame in the codec's Annex B (H.264/H.265) or low-overhead OBU (AV1) form with in-band parameter sets on key frames.

Receiver validation (all before allocating the payload): stream's first byte is `0x05`; the 20 header bytes arrive; `version == 1`; `codec` known; no reserved flag bits; `payload_len <= 16 MiB`; the stream then delivers exactly `payload_len` bytes followed by FIN. An invalid header, or a stream that ends with fewer or more bytes than `payload_len`, is a `PROTOCOL_ERROR` for the connection. A stream **reset** by the sender (normally with `STALE_FRAME`, §6.2) is a dropped frame: it is counted and the connection continues.

### 6.1 Ordering and the reorder window

Streams are independent, so frames can complete in a different order than they were sent. The client keeps a reorder window (default 32 frames, held for at most 250 ms: frame streams are reliable, so a frame that is late is late by a loss recovery of one to three round trips, and releasing past it costs a key frame; both numbers are client policy, not wire format) with these rules:

1. Track `last_released`, the frame number last handed to the decoder.
2. A frame whose number is **not newer** than `last_released` (equal or older in serial order) is dropped as stale and counted.
3. A frame equal to `last_released + 1` is released at once, followed by any held frames that are now contiguous.
4. Another newer frame is held until its predecessors arrive, until more than the window capacity is held, or until the hold time expires (the timer restarts whenever a frame is released); then the lowest held frame is released (the missing numbers become stale and are dropped if they arrive later).
5. A frame flagged `KEY` or `RESYNC` is released at once and discards held frames older than it.
6. Before anything has been released, only a key frame is released at once; any other frame is held as in rule 4. A stream starts with a `KEY | RESYNC` frame, which is large and travels on its own stream, so a P frame sent after it can complete first. Releasing that P frame would make the key frame stale (rule 2), and the decoder, which cannot use a P frame without it, would wait for a `request_keyframe` round trip and a second key frame. If the hold time expires or the window overflows first, the lowest held frame is released as in rule 4, and the gap is handled as below.

`hx_proto::ReorderWindow` implements these rules as a pure state machine; `hx_transport::Connection::recv_video_frame` applies them.

A gap that remains (a cancelled frame, a frame later than the hold) leaves the decoder without a frame: the client drops frames until a key frame arrives and sends `request_keyframe`. A request, or its answer, can be lost or late, and the server sends nothing while its display is still, so the client **repeats the request** (about every 500 ms) until the key frame arrives; the server coalesces repeats. A key frame is a complete picture but not always a good one: its quality is whatever the server's rate control could afford, and the server keeps sending refinement frames of the unchanged screen until the picture is back at the normal quality (architecture §6.2). The client needs nothing special for this; they are ordinary P frames.

### 6.2 Congestion control hooks

- **Acknowledgement.** On QUIC a frame stream's **completion** is the per-frame ack: the sender finishes the stream and learns when the peer has received all of it (quinn's `SendStream::stopped` resolving with no error code). `hx-transport` surfaces each completion as a `FrameAck` (frame number, bytes, time from first write to ack, outcome `Delivered`, `Cancelled` or `ConnectionLost`) to the sender's congestion controller (workstream 1F owns the policy). On WebSocket the receiver sends channel `0x09` with the frame number once the frame is fully received, which plays the same role.
- **Cancellation.** The sender may cancel a frame that is queued too long by resetting its stream with application error code `STALE_FRAME` (`0x57A1E`) and then send a fresh full image flagged `KEY | RESYNC` (architecture §7.4). The receiver treats a `STALE_FRAME` reset as a normal drop. On WebSocket a frame can only be cancelled before its message has been handed to the socket.
- The sender never drops an already-encoded frame mid-chain except by this mechanism.

## 7. Datagram channels

A datagram is `channel id (1 byte)` followed by the body below. The whole datagram MUST fit in one QUIC datagram (`Connection::max_datagram_size`); a sender whose payload does not fit does not send it.

### 7.1 Mouse motion (`0x03`, client → server)

```
 0      1      2        6        10       14
+------+------+--------+--------+--------+
| 0x03 | flags|  seq   |   x    |   y    |
|  u8  |  u8  | u32 LE | i32 LE | i32 LE |
+------+------+--------+--------+--------+
```

Total 14 bytes. `flags` bit 0 `RELATIVE`: `x`,`y` are deltas in remote pixels; otherwise absolute remote pixel coordinates. Other bits MUST be 0 (datagram dropped otherwise). `seq` increases by 1 per datagram per client, wrapping, serial-number arithmetic.

Latest wins: the server discards a datagram whose `seq` is not newer than the newest `seq` seen (reordered or duplicated). An **absolute** datagram replaces any pending, not yet consumed, absolute position. A **relative** datagram is added to the pending relative delta (so a consumer that is slower than the sender loses no motion that arrived). The consumer drains the coalesced value. `hx_proto::MouseCoalescer` implements this.

### 7.2 Audio (`0x06`, server → client)

```
 0      1        5           9
+------+--------+-----------+----------------------+
| 0x06 |  seq   | timestamp |  Opus packet         |
|  u8  | u32 LE |  u32 LE   |  (1..=1100 bytes)    |
+------+--------+-----------+----------------------+
```

`seq` increases per packet (wrapping; gaps are loss and the decoder uses in-band FEC / packet-loss concealment). `timestamp` is the Opus sample clock at 48 kHz of the first sample (wrapping). The packet is one Opus frame (10 ms, 48 kHz, stereo in v1). The payload length is the datagram length minus 9 and MUST be 1..=1100. Late or duplicate packets are dropped by the receiver's jitter buffer.

## 8. Close and reset codes

Connection close (QUIC `CONNECTION_CLOSE` application error code; WebSocket close code is `4000 + code`):

| Code | Name | Sent when |
|---|---|---|
| 0 | `NO_ERROR` | Normal end of session |
| 1 | `PROTOCOL_ERROR` | Malformed, oversized, unexpected or forbidden message or channel |
| 2 | `UPDATE_REQUIRED` | Different major version |
| 3 | `HELLO_TIMEOUT` | No valid `Hello` in time |
| 4 | `UNAUTHORIZED` | Peer not allowed (identity, intent, PIN) |
| 5 | `BUSY` | Server cannot take another session |
| 6 | `PAIRING_CLOSED` | `INTENT_PAIR` while no pairing token is valid |
| 7 | `SHUTDOWN` | Server is stopping |
| 8 | `INTERNAL_ERROR` | Server fault |
| 9 | `TAKEN_OVER` | **1.1.** Another device took over this desktop (§5.7). Sent only to a peer whose negotiated minor is at least 1; a 1.0 peer would read it as `INTERNAL_ERROR` |
| 10 | `SETUP_CLOSED` | **1.3.** An `INTENT_SETUP` connection that is not (or no longer) admitted: the device is not the bound setup device, the setup window is closed, or the binding moved (§5.10). Sent only on `INTENT_SETUP` connections, so only to a 1.3 peer |

Unknown codes received are treated as `INTERNAL_ERROR` (so a 1.0 peer reads `TAKEN_OVER` that way). The reason string of a close is for logs only (at most 128 bytes, never secrets).

Stream reset / stop codes (application error codes on a single stream; the connection continues):

| Code | Name | Meaning |
|---|---|---|
| `0x57A1E` | `STALE_FRAME` | Sender cancelled a video frame (§6.2) |
| `0x100` | `TRANSFER_ERROR` | Transfer body did not match its header |
| `0x101` | `TRANSFER_REJECTED` | Receiver refused a transfer (policy; a file header above the effective limit, §5.6) |

## 9. WebSocket fallback

Same port number over TCP. TLS 1.3 with ALPN `http/1.1`, then an HTTP/1.1 WebSocket upgrade at path `/hx/1`; any other path is answered `404`. All messages are **binary**; text messages are a protocol error. The maximum WebSocket message size depends on the direction: **client to server `64 KiB + 64`** (the largest legitimate message is a control message or a transfer chunk), **server to client `16 MiB + 64`** (a video frame). A larger message is a protocol error, detected from the frame header before the payload is buffered (WebSocket close `PROTOCOL_ERROR`). The sender of unacknowledged video keeps only per-frame metadata, for at most 256 frames in flight.

Every message is `channel id (1 byte)` followed by the body. Channels `0x01`–`0x09` of §3 keep their meaning; there are no streams or datagrams, everything is multiplexed on the one ordered connection (head-of-line blocking is inherent and accepted for a fallback).

| Channel | Body |
|---|---|
| `0x01` Control, `0x02` Input, `0x04` Cursor | One protobuf message, no length prefix (limits of §3.1 apply) |
| `0x03` Mouse motion | Datagram body of §7.1 after the channel byte (13 bytes after the id) |
| `0x05` Video | Media header (20 bytes) + payload, exactly as §6 minus the stream |
| `0x06` Audio | Datagram body of §7.2 after the channel byte |
| `0x07` Clipboard, `0x08` Files | Transfer chunk message, §9.4 |
| `0x09` Frame ack | `frame_number` (u32 LE), 4 bytes |

Keep-alive: each side sends a WebSocket `Ping` every 5 s; a connection with no inbound traffic for 30 s is dropped (close reason `idle timeout`, code `INTERNAL_ERROR` locally).

### 9.1 Handshake over WebSocket

Identical to §2 using control messages; the first WebSocket message after the upgrade MUST be a control `Hello`. Close is a WebSocket close frame with code `4000 + code` (§8).

### 9.2 Acks and cancellation

The receiver sends channel `0x09` for each fully received video message (valid or not). The sender resolves the frame's `FrameAck` on receipt. Unknown or duplicate acks are ignored.

### 9.3 Priorities

There are none on the wire. The sender SHOULD interleave: control, input, mouse and cursor messages are written before queued video; transfers are chunked (at most 64 KiB) so they do not starve other traffic.

### 9.4 Transfers

```
+------+-------------+------+------------------+
| 0x07 | id (u32 LE) | type |      body        |
| 0x08 |             | u8   |                  |
+------+-------------+------+------------------+
```

`id` identifies the transfer; the client allocates odd ids and the server even ids. `type` is `1` header (body: `TransferHeader` protobuf), `2` data (body: at most 65536 raw bytes), `3` end (empty body), `4` abort (empty body; `STOP_SENDING`/reset equivalent). A transfer is `header`, zero or more `data`, `end`. Chunks of different transfers may interleave; the receiver enforces `size` as in §5.5.

## 10. Error handling summary

| Situation | Receiver action |
|---|---|
| Malformed or oversized frame on control, input or cursor | Close, `PROTOCOL_ERROR` |
| Unknown channel id on a stream | Close, `PROTOCOL_ERROR` |
| Duplicate control, input or cursor stream | Close, `PROTOCOL_ERROR` |
| Channel sent by the wrong role or without its feature | Close, `PROTOCOL_ERROR` |
| Control message other than `pairing`, `auth`, `goodbye`, `ping`, `pong` while restricted; transfer, audio or video message while restricted (WebSocket) | Close, `PROTOCOL_ERROR` |
| Input queue overflow (WebSocket) or cursor shape queue overflow | Close, `PROTOCOL_ERROR` |
| Input or mouse data while restricted | Drop, count, continue |
| Not authorized within the authorization deadline | Close, `UNAUTHORIZED` |
| Pending session not decided within the decision window | `Refuse(BUSY)`, close `BUSY` |
| Invalid media header | Close, `PROTOCOL_ERROR` |
| Video stream reset with `STALE_FRAME` | Drop the frame, continue |
| Video frame not newer than `last_released` | Drop the frame, count it, continue |
| Malformed or unknown datagram | Drop it, count it, continue |
| Transfer body length mismatch | Reset that stream, continue |
| File header with `size` above the effective limit (§5.6) | `STOP_SENDING` `TRANSFER_REJECTED` (WebSocket: `abort`), continue |
| `ServerStats` from a client, or without `SERVER_STATS` negotiated | Close, `PROTOCOL_ERROR` |
| `Goodbye` with an over-long or unsanitised `peer_device_name`, or a `peer_device_id` of other than 0 or 16 bytes | Malformed (as any invalid message) |
| `DeviceMgmt` without negotiated `DEVICE_MANAGEMENT`, a server-only body from a client, or a request id that breaks §5.9 | Close, `PROTOCOL_ERROR` |
| `DeviceMgmt` while restricted | Close, `PROTOCOL_ERROR` (transport, §2.1) |
| `DeviceMgmt` `create_pairing_code` or `pairing_code_issued` with a negotiated minor below 3, or `pairing_code_issued` from a client | Close, `PROTOCOL_ERROR` |
| `create_pairing_code` with `expires_in_s` outside 60 to 900 | `PairingCodeIssued{INVALID_ARGUMENT}`, nothing created |
| More than 3 pairing codes in an hour | `PairingCodeIssued{RATE_LIMITED, retry_after_s}`, nothing changes |
| `INTENT_SETUP` from an unknown or revoked key, from a client below 1.3 or without `SETUP` offered | `Refuse(UNAUTHORIZED)`, close `UNAUTHORIZED` (uniform text) |
| `INTENT_SETUP` from a device that is not the bound setup device, with the window closed or privd not in `SETUP_OPEN` | `Refuse(SETUP_CLOSED)`, close `SETUP_CLOSED` (the app goes to the normal PIN login) |
| `INTENT_SETUP` while privd cannot be asked | `Refuse(BUSY)`, close `BUSY` |
| `SetupMessage` on a connection that is not `INTENT_SETUP`, without `SETUP` negotiated, a server-only body from a client, or a request id that breaks §5.10 | Close, `PROTOCOL_ERROR` |
| `SetupMessage` that fails `hx-proto`'s hard caps (password above 1024 bytes, PIN above 16, a string above its cap, more than 16 warnings) | Close, `PROTOCOL_ERROR` |
| A setup request with an invalid value (password rule, PIN digits, username, enum, Docker without the acknowledgement) | `SetupAck{INVALID_ARGUMENT, field}`, continue |
| `start`, `cancel` or `finish` on a KeyOnly connection | `SetupAck{PIN_REQUIRED}`, continue |
| `start` with less than 50 minutes of setup window left | `SetupAck{WINDOW_TOO_SHORT}`; the app shows `sudo hx-agent setup extend` |
| Close `TAKEN_OVER` | End the session, show the notice (§5.7), do not reconnect automatically |
| Control message sent by the wrong role (`ViewConfig`, `RequestKeyframe`, `ClientStats` from the server; `StreamInfo` and `ServerStats` from the client) | Close, `PROTOCOL_ERROR` |
| `Hello`, `HelloAck` or `Refuse` after the handshake | Close, `PROTOCOL_ERROR` |
| Different major in `Hello` | `Refuse(UPDATE_REQUIRED)`, close `UPDATE_REQUIRED` |
| No `Hello` in 3 s after TLS | Close `HELLO_TIMEOUT` |

Unknown protobuf fields are always ignored. A decoded message whose required semantic constraints (§5) fail is treated as malformed.

## 11. Pairing and authentication (workstream 1B, `crates/hx-crypto`)

### 11.1 Identity and TLS: raw public keys

Every party has an **Ed25519 key pair**: the server (agent) one identity key, each client device one device key. TLS authenticates with **raw public keys (RFC 7250)**, not certificates, and there is no certificate authority:

- The "certificate" in the TLS `Certificate` message is the key's `SubjectPublicKeyInfo` DER (44 bytes: the fixed Ed25519 prefix `302a300506032b6570032100` followed by the 32-byte key). The only signature scheme is `ED25519`.
- TLS 1.3 only (the `rustls` configs built by `hx-crypto::tls` list only `TLS13`; `tls12` stays banned in `deny.toml`). Session resumption is off on both sides (also enforced by `hx-transport`).
- **Client authentication is mandatory.** The server's verifier accepts **any** well-formed Ed25519 client key whose handshake signature verifies (a signature check proves possession of the key); it does not decide who may connect, because a not-yet-paired device must be able to reach the pairing step. The decision is the application's, made from `PendingSession::peer_certificates()` (§11.5).
- The client's verifier has two modes. **Session**: the SPKI must equal the pinned server key byte for byte and the signature must verify; anything else fails the handshake. **Pairing** (no server key known yet): any well-formed Ed25519 key with a valid signature is accepted *provisionally*; the key is then bound into the SPAKE2 confirmation (§11.3), and a pairing that does not complete that confirmation MUST be discarded. The pairing client never stores or uses a server key before the confirmation succeeded.
- All verifiers fail closed: a real X.509 certificate, wrong length or prefix, a key that does not decode or has small order, a signature scheme other than `ED25519`, an invalid signature, or TLS 1.2 ends the handshake.

Why raw public keys rather than self-signed X.509 certificates: the pinned identity is exactly the 32-byte key, with no certificate parsing (a large attack surface on the pre-authentication path), no generated certificate with validity dates or names to keep in sync, and no `ServerName` handling. `rustls` 0.23 supports RPK for both server and client authentication with the `ring` provider, and `quinn` and the WebSocket `tokio-rustls` path both take an ordinary `rustls` config, so one code path serves QUIC and WebSocket. The browser transport (Phase 3) uses a different mechanism (architecture §8.4) and is not affected. The cost: a peer that only speaks X.509 (for example a generic TLS tool) cannot connect, which is intended.

Key identifiers: the **fingerprint** of a key is the SHA-256 of its 32 raw bytes, shown as lowercase hex; the **device id** is the first 16 bytes of the fingerprint. A secret key is stored as its 32-byte Ed25519 seed (where is up to 1C on the server and 1G on the client), never logged, and wiped from memory on drop on a best-effort basis (see §11.5).

### 11.2 Handshake placement and state machine

`Hello.intent` declares the purpose. After the version check the server application receives a `PendingSession` and looks at the **current** registry, never at anything cached from a previous connection.

| Intent | Peer key | Server answer |
|---|---|---|
| `PAIR` | revoked | `Refuse{UNAUTHORIZED}` |
| `PAIR` | any, no token or code valid | `Refuse{PAIRING_CLOSED}`, close `PAIRING_CLOSED` |
| `PAIR` | any, a token or code valid | `HelloAck` (no features, no codecs), pairing exchange (§11.3) |
| `SESSION` | unknown or revoked | `Refuse{UNAUTHORIZED}` (the message does not say which) |
| `SESSION` | paired, no PIN configured on the server | `Refuse{UNAUTHORIZED}` |
| `SESSION` | paired | `HelloAck`, PIN exchange (§11.4), then `authorize()` |
| `SETUP` (1.3) | unknown or revoked; client minor below 3; `SETUP` not offered | `Refuse{UNAUTHORIZED}` (the same uniform text) |
| `SETUP` | known and active, but not the bound setup device, the window closed, or privd not in `SETUP_OPEN` | `Refuse{SETUP_CLOSED}` (close code 10); `Refuse{BUSY}` if privd cannot be asked |
| `SETUP` | the bound setup device, window open, **no PIN configured** | `HelloAck` (feature `SETUP` only), control-only authorization, `AuthResult{OK}`, `SetupState`; only `set_pin` works until a PIN exists (§5.10) |
| `SETUP` | the bound setup device, window open, a PIN configured | `HelloAck`, `AuthResult{PIN_REQUIRED}`, then the PIN exchange of §11.4, then control-only authorization |

On the **pairing connection** only `ControlMessage.pairing` (field 100) is processed. When the exchange succeeds the server **always** closes the connection with `NO_ERROR` (the gateway after about 2 s); it never carries setup, a password or a PIN. The device reconnects using its pinned key: with `INTENT_SESSION` and the PIN, or, in the one-liner path, with `INTENT_SETUP` (§5.10). A failed or timed-out exchange ends with `PairFailure` (when it can be sent) and a close with `UNAUTHORIZED`. The whole exchange is bounded (default 20 s).

On a **session connection** only `ControlMessage.auth` (field 101) and `goodbye`/`ping`/`pong` are processed until authorization. A **setup connection** (§5.10) is processed the same way until it is authorized control-only; on a KeyOnly connection it is authorized straight away (§2.1), because the PIN does not exist yet. The server calls `Connection::authorize()` **before** sending the `AuthResult` that reports success (§13), so a client that sees success can use every channel at once.

### 11.3 Pairing exchange (field 100)

`Opaque.data` (at most 4096 bytes) carries a protobuf `PairingMessage { oneof body { start = 1; server_hello = 2; client_confirm = 3; server_confirm = 4; failure = 5 } }`. The schema is `crates/hx-crypto/src/wire.rs` (prost-derived; the field numbers below are final, additions are additive).

| Message | Fields |
|---|---|
| `PairStart` (C→S) | `mode` 1 (`TOKEN` = 1, `CODE` = 2), `token_id` 2 (bytes, 8, `TOKEN` only), `spake` 3 (bytes, the SPAKE2 message, 33), `device_name` 4 (string, at most 64 bytes) |
| `PairServerHello` (S→C) | `spake` 1 (bytes, 33), `server_name` 2 (string, at most 64 bytes) |
| `PairClientConfirm` (C→S) | `mac` 1 (bytes, 32) |
| `PairServerConfirm` (S→C) | `mac` 1 (bytes, 32) |
| `PairFailure` (S→C) | `reason` 1 (`FAILED` = 1, `BUSY` = 2, `PROTOCOL` = 3) |

Flow: `PairStart` → `PairServerHello` → `PairClientConfirm` → `PairServerConfirm`. Any other message, a repeat, a wrong size or an unparsable message ends the exchange with `PairFailure{PROTOCOL}`.

**Secrets.** Two kinds, both used as the SPAKE2 password (Ed25519 group, identities `"hx-pair-client"` and `"hx-pair-server"`, the client is side A):

- **Token** (from the one-liner and the app): an 8-byte random id plus a 32-byte random secret, written `hxt1-` plus lowercase RFC 4648 base32 without padding. The id is a public lookup label; the SPAKE2 password is `"hx-pair-token" || secret`. Valid 15 minutes by default (configurable); 5 started attempts. A token need not be generated by the server: the installer creates one and the server installs it (`PairingWindow::install_token`), with exactly the rules above (single use, 5 attempts, same eviction). A caller may give a token or a code a shorter life (`install_token`, `issue_token_with_ttl`, `issue_code_with_ttl`); a longer one is capped at the configured value, and a zero life is refused.
- **Code** (interactive install): 8 symbols from the 32-symbol Crockford alphabet (`0-9 A-Z` without `I L O U`), written `XXXX-XXXX`; parsing ignores case and separators and maps `O`→`0`, `I` and `L`→`1`. 40 bits of entropy. The SPAKE2 password is `"hx-pair-code" || the 8 normalised symbols`. Valid 15 minutes by default; **3 started attempts**, then invalidated. A code has no id: the server uses its active code.

The server keeps secrets in memory only (SPAKE2 needs the plaintext, so hashing at rest would not help) and never persists them. Token expiry uses the monotonic clock, which on Linux does not advance while the machine is suspended: after a suspend a token can outlive its 15 wall-clock minutes by the length of the suspend. Pairing windows are short-lived and opened by an operator, so this is accepted.

**Attempt budget.** Every `PairStart` that names an existing, unexpired secret consumes one attempt *when it arrives*, not when it fails, so parallel connections cannot multiply the guesses; when the budget is spent the secret is deleted as soon as its last running attempt has ended. A secret is single use: success removes it, and two concurrent attempts that both prove knowledge race for one atomic removal, the loser fails. A guessing attacker therefore gets at most 3 guesses against a code (success probability about 3·2⁻⁴⁰) and none against a token. The accepted cost: an attacker who can reach the port can burn a code's budget with junk attempts (a denial of service the user fixes by issuing a new code; a token's id is sent in clear in `PairStart`, so an on-path attacker who sees it can burn that token the same way, which is again only a denial of service: without the secret he cannot pair). If the id is unknown, or the secret expired or its budget is spent, the server does not say so: it uses a random password and fails at the confirmation like any wrong secret.

**Transcript binding.** The names go into the transcript **exactly as they were sent** (`device_name` as the client sent it, `server_name` as the server sent it); only what is stored or shown is sanitised, so a name that the sanitiser would change still pairs. `cs` and `ss` are the 44-byte SPKIs of the keys each side saw in the TLS handshake (the server: the client's key; the client: the server's key, taken from the connection), `lp(x)` is a 4-byte big-endian length followed by `x`:

```
T   = SHA-256( "hx-pair-v1" || lp(cs) || lp(ss) || lp(mode byte) || lp(token_id) ||
               lp(client spake msg) || lp(server spake msg) || lp(device_name) || lp(server_name) )
K   = the 32-byte SPAKE2 output
client_mac = HMAC-SHA-256(K, "hx-pair-v1 client" || T)
server_mac = HMAC-SHA-256(K, "hx-pair-v1 server" || T)
```

The server verifies `client_mac` (constant time) and only then consumes the secret, registers the device and sends `server_mac`; the client verifies `server_mac` (constant time) and only then pins the server key. A man in the middle who terminates TLS with his own key on one or both legs makes the two ends hold different `cs` or `ss`, hence different `T`, and without the secret he cannot make `K` agree with a transcript of his choice, so a confirmation fails: the client sees `PairFailure` or a bad `server_mac`. The client must treat that as a possible attack and not only as a typo (a wrong code and an interception cannot be told apart, so the UI says "wrong or expired code, or the connection is being intercepted"). A passive observer or a relay without the secret learns nothing usable (SPAKE2).

On success the server stores `{id, name = device_name (sanitised), public key = cs}` and the client stores `{server key = ss, server_name}`. Pairing an already paired, non-revoked key updates its name and keeps its PIN failure count. Pairing a **revoked** key is refused (`UNAUTHORIZED`): re-pairing a revoked device needs the Linux password (architecture §8.3), which the server application verifies before it calls the registry's `reinstate`.

### 11.4 PIN exchange (field 101)

The PIN is a 6 to 16 digit secret chosen by the user at setup. The server stores only an **Argon2id** hash: m = 64 MiB, t = 3, p = 1, 16-byte random salt, 32-byte output, as the string `hx-pin1$m=65536,t=3,p=1$<salt hex>$<hash hex>`. Parameters read back from storage are bounded (m ≤ 1 GiB, t ≤ 16, p ≤ 16) so a corrupted file cannot force an arbitrary cost. The hash comparison is constant time. Verification runs on a blocking thread, one at a time per device.

`AuthMessage { oneof body { pin = 1; result = 2 } }`:

| Message | Fields |
|---|---|
| `PinAttempt` (C→S) | `pin` 1 (bytes, 6 to 16 ASCII digits) |
| `AuthResult` (S→C) | `status` 1 (`OK` = 1, `WRONG_PIN` = 2, `BACKOFF` = 3, `REVOKED` = 4, `NOT_AVAILABLE` = 5, sent if the server has no PIN verifier when the attempt arrives, `PIN_REQUIRED` = 6, **1.3**, sent by the server **only** on an `INTENT_SETUP` connection, unsolicited, to ask the client for its PIN: §5.10), `attempts_left` 2, `retry_after_ms` 3 |

The channel is TLS 1.3 with both keys pinned, so the PIN travels in clear inside it. Rules, enforced on the server only:

1. **An attempt is counted before it is checked.** The failure counter is incremented and persisted, then the hash is computed, then a correct PIN resets the counter to 0 and a wrong one leaves it counted (the 5th consecutive failure revokes the device: `status = REVOKED`, close `UNAUTHORIZED`). The count, the hash and the outcome run as one unit that keeps the per-device lock and finishes even if the connection or the deadline ends the exchange, so an attempt that is cut off still counts. An attempt is not started when less than a hash's time remains before the exchange deadline.
2. After the n-th consecutive failure the device must wait `min(2^(n-1), 30)` seconds. An attempt that arrives earlier gets `BACKOFF` with `retry_after_ms` and is neither verified nor counted. The wait is held in memory (a restart clears the wait, not the counter).
3. A connection is allowed at most 5 attempt messages (including those answered `BACKOFF`), then it is closed with `UNAUTHORIZED`; the transport's authorization deadline bounds the whole exchange.
4. A malformed PIN (wrong length or a non-digit) is answered `WRONG_PIN` without a hash computation and counts as a failure.
   **4a. (shared failure budget)** When the verifier's wrong answers are charged to a budget shared by every device (the gateway's: privd caps PIN failures globally at 10 an hour, [ipc.md](ipc.md) §5.3), attempts 1 to 4 are always sent to the verifier. The attempt that reaches the revocation limit (the 5th) is sent too, **unless** sending it could bring the shared budget to its cap (`PinVerifier::allow_last_attempt` is false: the failures charged in the last hour plus one would reach the cap); then it is judged `Wrong` locally and revokes, like an attempt past the limit. In the normal case (an owner who made four typos) the 5th attempt is checked and a correct PIN logs in. Under attack, two stolen keys without the PIN charge at most 9 of the 10 and cannot lock every device out. A local verifier (`Authenticator::set_pin`) has no shared budget and checks every attempt. `attempts_left` is unchanged.
5. The registry check is repeated immediately before `authorize()`; a revocation that happened while the exchange ran ends the connection.

**Where the check runs.** By default the Argon2id comparison is local (`Authenticator::set_pin`). A deployment whose verifier ends in a step only another process can compute (the gateway: `HMAC(pepper, Argon2id(pin))` is computed by `hx-privd`, [ipc.md](ipc.md) §5.3 and §6.15) installs a `PinVerifier` with `Authenticator::set_pin_verifier`. The rules 1 to 5 stay with the authenticator; the verifier only returns a verdict, and the PIN's format (rule 4) is checked before it is asked:

| Verdict | Effect |
|---|---|
| `Right` | As a correct PIN today: the counter is reset, `last_seen` is stamped, the connection is authorized. |
| `Wrong` | As a wrong PIN today: the attempt stays counted, the backoff starts, the 5th consecutive one revokes. |
| `Unavailable` (the check could not be made: privd down, timeout) | The attempt is **refunded** (`refund_pin_attempt`, one saturating decrement), never revokes and is never a failure. The client gets `BACKOFF` with `unavailable_retry` (default 2 s), and the device is held for that long server-side. If the refund itself cannot be written the attempt stays counted (safe side). |
| `Locked { retry_after }` (the verifier refuses to check PINs at all, e.g. privd's global cap) | Refunded like `Unavailable`; the client gets `NOT_AVAILABLE` with the wait in `retry_after_ms` and the connection ends. The device is held for `retry_after` (default 60 s when absent or zero, capped at 24 h), set under the per-device guard like the other waits: an attempt that arrives earlier gets `BACKOFF` and is neither verified nor counted. |

The attempt is still counted before the verifier is asked, and the per-device guard is held, and the backoff set, across the whole verifier round trip, in the same detached unit as today, so a slow verifier delays other attempts on that device instead of letting them run in parallel, and a cut-off attempt is still counted (a cut-off `Unavailable` is still refunded when the verifier answers). A verifier that never returns would hold its device's guard, so it must bound its own calls. `status = NOT_AVAILABLE` is also sent when the verifier has no PIN for the device (`PinVerifier::has_pin`).

### 11.7 Reinstate after a PIN lockout (1.3)

The fifth wrong PIN revokes a device (§11.4). The owner gets back in from that same device with the **account password** (architecture §8.3: "re-pairing needs the password"), without SSH and without another device. Decision 23 in [ipc.md](ipc.md) §22 records it; the app screen is "Pair again" (userflow §5).

- **Who may.** Only a device whose registry record says it was revoked **by the PIN lockout** (`revoked_by = LOCKOUT`; the registry records the cause of every revocation: `LOCKOUT`, `DEVICE` (revoked from another device), `OPERATOR` (CLI or admin socket) or `SELF`). A device revoked by its owner, another device or the operator can never reinstate itself, so a stolen device whose owner revoked it stays out even if the thief knows the password. A device revoked more than **30 days** ago cannot reinstate itself either.
- **Connection.** `Hello{intent: INTENT_REINSTATE, version >= 1.3}` over TLS with the device's own (revoked) key pinned as usual. Every other key, and a revoked key that does not qualify, gets the same uniform `Refuse{UNAUTHORIZED}` as an unknown key (§11.2), so the intent reveals nothing to a key that does not qualify. A qualifying key gets `HelloAck` (no features), then `AuthResult{PASSWORD_REQUIRED}`.
- **Exchange.** `AuthMessage.password` = `PasswordAttempt { password = 1 }` (bytes, 1 to 511, UTF-8 without NUL, CR or LF; `skip_debug` with a redacting `Debug`), at most **3 attempt messages per connection** and the transport's authorization deadline. The server verifies it with privd `PepperVerify(PASSWORD)` against the password verifier, so privd's global PASSWORD budget applies (5 per hour, 20 per day, then locked until Admin `ResetLockout`, [ipc.md](ipc.md) §5.3), plus a per-device limit of 3 attempts per hour. A wrong password is answered `AuthResult{WRONG_PASSWORD}` (`AuthStatus` 8, 1.3) and counts against both budgets; an attempt over a limit gets `BACKOFF` with `retry_after_ms` and is not verified; when the verifier cannot answer (privd down, or the PASSWORD purpose locked) the answer is `NOT_AVAILABLE`, and the attempt is refunded as for PINs (§11.4). No password verifier on the server (never set, or made stale by `passwd` and not refreshed with `hx-agent desktop password --verifier-only`) answers `NOT_AVAILABLE`.
- **Success.** The registry reinstates the device (state `active`, PIN failure counter reset, `revoked_by` cleared; a `DeviceEvent REINSTATED` is announced, §5.9; `RecordEvent DEVICE_REINSTATED` is audited with the cause `PASSWORD`), the server answers `AuthResult{OK}` and closes the connection with `NO_ERROR`. The audit record and the `DeviceEvent` follow **the commit, not the connection**: `Authenticator::subscribe_reinstatements` fires from the same blocking unit that writes the registry, so a deadline that drops the exchange after the write cannot leave a reinstatement unaudited (`Outcome::Reinstated` is only returned if the exchange finishes in time). Whichever way a device was reinstated (password, operator or cooling-off), its **next** lockout is audited and announced again (the gateway derives "already recorded" from the registry, not from the events it saw). The device then connects normally with `INTENT_SESSION` and **its existing PIN**; reinstating does not authorize a session and does not change the PIN.
- **Version.** A 1.2 server never sees the intent (the client gates on the confirmed version, as for `INTENT_SETUP`, §4.7); against an older server the app tells the user to ask the administrator (`hx-agent devices reinstate`).

### 11.5 Application obligations (summary of §13)

On **every** `PendingSession` the application looks the peer key up in the current registry. The key comes from the connection's single raw-public-key "certificate"; more than one entry, or one that is not a 44-byte Ed25519 SPKI, is refused. `Hello.software` and `Hello.device_name` are stripped of control characters and truncated before they are logged, shown or stored. Revoking a device closes its live sessions (`UNAUTHORIZED`) and announces the revocation on a channel for other components (for example `hx-session` supervision). Secrets (tokens, codes, PINs, keys, `K`) are never written to logs, command lines or `Debug` output; their types print `[redacted]`. Wiping them from memory is **best effort**: the types hold them in zeroizing buffers, but `spake2`'s internal state, the protobuf and `Bytes` buffers, and the transport's buffers are not wiped, and a process dump of a running agent can contain secrets (hence the agent runs unprivileged with core dumps off, architecture §8.5).

**Pre-authentication classification.** `Authenticator::pre_auth_classifier()` implements the transport's `PreAuthClassifier` (§1) from the same registry, **in memory, with no I/O**, right after TLS and before the `Hello`: a known key that is not revoked, or that was revoked by the PIN lockout less than `reinstate_max_age` ago (§11.7), is *paired* (reserved pool, keyed by its device id); a revoked key is *refuse* (answers: `UNAUTHORIZED` whatever the intent); an unknown key is *unknown* (general pool) while a pairing token or code is live (`PairingWindow::is_open`), and *refuse* otherwise (answers: `PAIRING_CLOSED` to an `INTENT_PAIR` hello, `UNAUTHORIZED` to every other intent, exactly as the authenticator itself answers). The classification only moves a connection between pools and shortens its wait; **every `PendingSession` is still decided by the full checks above**, so a stale classification (a key revoked or a window closed meanwhile) can cost a slot for a moment but never grants access. The refusals above are the existing uniform ones (§11.6): the classifier adds no new answer and no new timing channel for anyone who does not hold a paired key.

**Revocation reaches live sessions through the authenticator only.** `Authenticator::revoke`, `remove` and (for completeness) `reinstate` are the mutating paths; they persist and announce as one unit that finishes even if the caller is cancelled. `Authenticator::registry()` is a read-only view. A live session also re-reads the registry every few seconds and closes itself if its device is revoked or gone, as a backstop. `FileRegistry` is single-writer: it takes an exclusive `flock` on `<file>.lock` and fails if another instance holds it, so no tool may open the file next to the agent; the CLI revokes and reinstates through the agent's IPC.

### 11.6 Notes for the agent (1C)

- Never call `authorize()` on an `Outcome::Paired` connection: it is a pairing connection with no features. An `Outcome::Setup` connection is authorized with `authorize_control_only` only, never `authorize()` (§5.10). `Outcome::Paired` carries `with: PairedWith::{Token{id}, Code}`, which is how the application binds the setup device (only a `Token` whose id the installer registered while the window was open binds).
- Post-pairing password and PIN setup does **not** run on the pairing connection (the transport's 30 s authorization deadline, of which the pairing exchange may use 20 s, cannot hold a 45-minute build, and the single-use token cannot be resumed). It runs on an `INTENT_SETUP` connection (§5.10, [ipc.md](ipc.md) §5.5), allowed only to the bound setup device while the setup window is open, for first-time setup. Setting a password or PIN later, or after a lockout, is not a protocol path (the operator's CLI, or re-pairing with the Linux password).
- CLI revoke, remove and reinstate go through the agent. `reinstate` only after the Linux password was verified by `hx-privd`'s peppered verifier (`PepperVerify`, a failure-capped yes/no check, with `PepperEnrol` for setting it up; see [ipc.md](ipc.md) §6.15).
- An operator's lockout reset (zero the failure counter of a device that is not revoked) is `Authenticator::reset_lockout` (`DeviceRegistry::reset_pin_failures` underneath, which does not stamp `last_seen`); it waits for a running PIN check of that device and also drops the in-memory wait.
- `Authenticator::is_backing_off(&DeviceId)` (and `backoff_remaining`, the wait left) tell whether a device's PIN is held back right now: a wrong-PIN backoff, an `Unavailable` hold or a `Locked` wait. It is an in-memory lookup, for the admin device list.
- A PIN-lockout revocation (the 5th wrong PIN) is made by the authenticator itself, so the application cannot wrap it in its own lock. `Authenticator::set_revocation_guard(Arc<dyn RevocationGuard>)` installs a hook: right before a lockout revocation is persisted the authenticator awaits `RevocationGuard::enter(device)` and holds the returned permit until the revocation is persisted and announced. The gateway implements it with the mutex under which it enforces "never zero active devices". The hook serializes only: the lockout always revokes, even the last device (a guesser must not get unlimited tries), and a hook slower than `revocation_guard_timeout` (5 s) is bypassed. It is entered under the device's PIN guard, so the gateway must take its revocation lock last and never wait for a PIN check or `reset_lockout` while holding it.
- Clients must sanitise `Refuse.message` (and any server text) before showing it; the server's refusal text for unknown, revoked and no-PIN cases is deliberately one fixed string (`not authorized`, with `UNAUTHORIZED`), so a refusal never tells which case applies.
- The identity seed is root-only (`systemd-creds`), the registry directory must not be writable by group or others, and the registry file is 0600 and owned by the agent user.

## 12. Client behaviour on security failures

A TLS or certificate verification failure while connecting (QUIC TLS alert, rejected server key or certificate) is reported to the application as a distinct error and is **final**: a client that tries QUIC first and falls back to WebSocket does so only when QUIC could not be established (no answer in time, UDP blocked), never after a failed security check, and never after a `Refuse`. The same rule applies to any future fallback.

## 13. Known follow-ups (not specified here)

- Phase 3 (WebTransport): the `h3` path currently holds its pre-authentication slot for the whole lifetime of the handler it dispatches to, not only until authorization. The Phase 3 handler must release or re-account the slot once the browser session is authorized, or long-lived WebTransport sessions would exhaust the pre-authentication limits.
- Application-layer policy owned by 1B/1C: re-check pinned/revoked keys on every `PendingSession`, close live sessions on revocation, sanitize `Hello.software` and `Hello.device_name` before display or logging, clamp input coordinates in the injector, and treat transfer file names as hints.
- `hx-transport` does not yet enforce the 1.1 rules for `ServerStats` (rejecting it from a client or when `SERVER_STATS` was not negotiated, §5.8) nor apply `Negotiated::max_file_bytes` to incoming file headers (§5.6); the gateway/transport round must add both, and until then the application layer does.
- Resolved in 1.2: the client-facing "Revoke that device" route is `DeviceMgmt` (§5.9).
- Resolved in 1.3: password, PIN and desktop setup from the app in the one-liner path is `INTENT_SETUP` (§5.10; the open item was the pairing connection that "keeps the restricted connection open … for the password and PIN setup", §11.2, and the 30 s budget of §11.6). Pairing a new device from the app is `DeviceMgmt` `create_pairing_code` (§5.9).
- Fuzz targets for 1H: `MediaHeader::decode`, `decode_datagram`, `message::decode::<ControlMessage | InputEvent | CursorEvent | TransferHeader>`, `message::decode_framed`, `version::peek_hello_version`, `file_name_problem`, and the WebSocket message router.

## 14. Schema location

The protobuf schema is `crates/hx-proto/proto/hx.proto` (package `hx.v1`); field numbers there are the numbers in this document. The messages inside the `pairing` and `auth` envelopes (§11) are defined by `crates/hx-crypto/src/wire.rs`. Field numbers are never reused. Adding fields or messages is a minor-version change (§4.2); the 1.1 additions are listed in §4.5, the 1.2 additions in §4.6 and the 1.3 additions in §4.7. The 1.3 messages (`SetupMessage` and its parts, `DeviceMgmt` bodies 15 and 16, `Intent` 3, `RefuseReason` 5) are in `hx.proto` itself. **Secret-bearing types** (`SetupSetPin`, `SetupStart`, `PairingCodeIssued`, and the existing `Opaque`, whose generated `Debug` prints its bytes, so the auth PIN leaked through it) are built with `prost_build::Config::skip_debug` and have hand-written redacting `Debug` impls in `hx-proto`; the redaction must also hold through every envelope that can contain one (`DeviceMgmt`, `SetupMessage`, `ControlMessage`), so a derived `Debug` on an envelope never prints a nested secret.
