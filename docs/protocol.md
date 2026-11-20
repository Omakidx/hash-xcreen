# Wire protocol (version 1.0)

The contract between hash-xcreen's session/agent side (the **server**) and its viewers (the **client**: desktop app now, browser and others later). The code in `crates/hx-proto` (messages, media header, versioning) and `crates/hx-transport` (QUIC and WebSocket transports) implements exactly what is written here. If the two disagree, that is a bug in one of them: fix it and update this file in the same branch.

Design background is in [architecture.md](architecture.md) §6–§8. Pairing cryptography is **not** specified here (workstream 1B); §11 says where it plugs in.

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
- QUIC keep-alive 5 s, idle timeout 30 s. Each side limits what its peer may make it buffer. A **server** starts restricted (§2.1): the client may open 1 bidirectional stream (the control stream; a second one is refused by the transport) and **0 unidirectional streams**, the connection receive window is 256 KiB and the datagram receive buffer 16 KiB. When the application authorizes the connection the limit becomes 64 unidirectional streams (input and transfers) and a 64 MiB connection receive window (the steady-state cap). A **client** allows the server 0 bidirectional streams, 1024 unidirectional streams (one per in-flight video frame), a 64 MiB connection receive window and 8 MiB per stream.
- The server MAY require QUIC address validation (a Retry) before spending handshake state on an unvalidated source address; `hx-transport` does by default.
- Pre-authentication resource bounds. A connection is *unauthenticated* from transport accept until the application authorizes it (§2.1), is refused, or closes. At most 64 connections may be unauthenticated at once and at most 4 per source address (IPv6: per /64, and at most 16 per /48 so that one network cannot hold every slot); excess connections are refused at the transport. TLS plus the HTTP upgrade must finish within 5 s and a valid `Hello` within 10 s of transport accept (`HELLO_TIMEOUT`, §8). The application must accept or refuse a pending session within 10 s or the transport refuses it with `BUSY` (a session that is dropped undecided is refused with `BUSY` immediately); writing the `HelloAck` is bounded by the same 10 s (a peer that stops reading is dropped, QUIC close `BUSY`) and releases its slot. A failure while accepting (for example an invalid server reply) closes with `INTERNAL_ERROR`, never code 0. An accepted connection that is not authorized within 30 s is closed with `UNAUTHORIZED`. All of these are configurable server options. Until the hello exchange succeeds, nothing but the control stream (WebSocket: control messages) is processed.

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

Authorizing makes the negotiated features effective (optionally narrowed by the application, for example clipboard off for one device), raises the QUIC limits of §1 and releases the connection's pre-authentication slot. A client may assume nothing about its own authorization until the server says so in an application-level message (for example the result of the `auth` exchange); a client MUST NOT start input, transfers or other channels before that. The restricted state exists only on the server; a client is never restricted.

## 3. Channels

Every QUIC stream and every datagram begins with a one-byte **channel id**. WebSocket messages carry the same byte first (§9).

| Id | Channel | Direction | QUIC transport | Priority | Messages |
|---|---|---|---|---|---|
| `0x01` | Control | both | One client-opened **bidirectional** stream, opened first | High (50) | `ControlMessage`, length-prefixed |
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
| `version` | 1 | `Version` | Client protocol `major.minor` (this document: `1.0`) |
| `capabilities` | 2 | `Capabilities` | What the client can decode and do |
| `intent` | 3 | `Intent` | `INTENT_SESSION` (1) normal session, `INTENT_PAIR` (2) pairing, §11. `INTENT_UNSPECIFIED` (0) is invalid |
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
| `reason` | 1 | `RefuseReason` (a refusal without a reason is sent as `UNAUTHORIZED`, so the close code is never 0) | `UPDATE_REQUIRED` (1), `UNAUTHORIZED` (2), `BUSY` (3), `PAIRING_CLOSED` (4); `UNSPECIFIED` (0) is invalid |
| `message` | 2 | string | Human-readable, at most 256 bytes (longer text is cut on a character boundary), safe to show |
| `version` | 3 | `Version` | Server version, so the client can say what to update |

`Version`: `major` (1, uint32), `minor` (2, uint32).

`Capabilities`: `video_codecs` (1, repeated `VideoCodec`, packed), `features` (2, uint64 bitmask, §4.3).

`VideoCodec`: `UNSPECIFIED` 0 (invalid), `H264` 1, `AV1` 2, `H265` 3 (reserved; not produced in v1). The number is also the codec byte in the media header (§6).

### 4.2 Version rules

- The version is `major.minor`; this document defines `1.0`.
- **Different major** (the `Hello` major differs from the ALPN/path major or from the server's): the server answers `Refuse{reason: UPDATE_REQUIRED, version: <server version>}` and closes with `UPDATE_REQUIRED` (§8). The client shows an "update required" message. No other message is processed. The `Hello` of a different major is parsed only as far as `version` (field 1); every other field of it is ignored.
- **Same major, different minor**: accepted. The negotiated minor is `min(client.minor, server.minor)`. Both sides then use only features available at the negotiated minor and present in both capability sets (§4.3). Unknown protobuf fields are ignored (standard protobuf behaviour), so a newer minor can add fields and messages that an older peer skips; a newer minor MUST NOT send a new message type on a channel to a peer whose negotiated minor predates it.
- Security properties (authentication, authorization, size limits, the restricted state) are never gated by a minor version or a feature bit: every peer enforces them regardless of what was negotiated.
- A change that an older peer cannot safely ignore (removed field, changed meaning, changed byte layout) requires a new major.
- The agent supports the current major and the previous one, by serving both ALPN values. The web client always matches its agent.

### 4.3 Capabilities and features

Capabilities advertised in `HelloAck` are an *offer*: negotiated features take effect only when the server authorizes the connection (§2.1). For an `INTENT_PAIR` hello the server advertises no features and no codecs, so a pairing connection can never carry anything but control messages.

`features` is a bitmask. Both sides compute `negotiated = client.features & server.features & mask(negotiated_minor)` and `codecs = client.video_codecs ∩ server.video_codecs`, in the server's order of preference. Bits unknown to a side are ignored by that side.

| Bit | Name | Introduced | Enables |
|---|---|---|---|
| 0 | `AUDIO` | 1.0 | Audio channel `0x06` |
| 1 | `CLIPBOARD` | 1.0 | Clipboard channel `0x07` |
| 2 | `FILE_TRANSFER` | 1.0 | Files channel `0x08` |

An empty `codecs` intersection is not a handshake error; the server then answers `StreamInfo` only after a `ViewConfig` with a codec that is in the intersection, and rejects other codecs with `Goodbye` (code `PROTOCOL_ERROR`). Video, cursor, input, mouse and control are always available (not feature-gated).

### 4.4 Rules for the first message

- The first message on the control channel MUST be `Hello`; anything else is `PROTOCOL_ERROR`. A second `Hello`, or a `HelloAck`/`Refuse` from a client, is `PROTOCOL_ERROR`.
- No `Hello` within 10 s of transport accept: close with `HELLO_TIMEOUT`.
- The server decides acceptance after the version check (e.g. authorisation from the TLS identity, intent, capacity): it answers `HelloAck` or `Refuse` with reason `UNAUTHORIZED`, `BUSY` or `PAIRING_CLOSED`, then closes with the matching code (§8).

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

`Goodbye`: `code` (1, uint32, a close code from §8), `message` (2, string, at most 256 bytes).

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

On WebSocket the same content is carried in messages tagged with a transfer id (§9.4).

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

Streams are independent, so frames can complete in a different order than they were sent. The client keeps a small reorder window (default 4 frames, held for at most 10 ms) with these rules:

1. Track `last_released`, the frame number last handed to the decoder.
2. A frame whose number is **not newer** than `last_released` (equal or older in serial order) is dropped as stale and counted.
3. A frame equal to `last_released + 1` is released at once, followed by any held frames that are now contiguous.
4. Another newer frame is held until its predecessors arrive, until more than the window capacity is held, or until the hold time expires (the timer restarts whenever a frame is released); then the lowest held frame is released (the missing numbers become stale and are dropped if they arrive later).
5. A frame flagged `KEY` or `RESYNC` is released at once and discards held frames older than it.
6. The very first frame is released immediately.

`hx_proto::ReorderWindow` implements these rules as a pure state machine; `hx_transport::Connection::recv_video_frame` applies them.

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

Unknown codes received are treated as `INTERNAL_ERROR`. The reason string of a close is for logs only (at most 128 bytes, never secrets).

Stream reset / stop codes (application error codes on a single stream; the connection continues):

| Code | Name | Meaning |
|---|---|---|
| `0x57A1E` | `STALE_FRAME` | Sender cancelled a video frame (§6.2) |
| `0x100` | `TRANSFER_ERROR` | Transfer body did not match its header |
| `0x101` | `TRANSFER_REJECTED` | Receiver refused a transfer (policy, size) |

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
| Control message sent by the wrong role (`ViewConfig`, `RequestKeyframe`, `ClientStats` from the server; `StreamInfo` from the client) | Close, `PROTOCOL_ERROR` |
| `Hello`, `HelloAck` or `Refuse` after the handshake | Close, `PROTOCOL_ERROR` |
| Different major in `Hello` | `Refuse(UPDATE_REQUIRED)`, close `UPDATE_REQUIRED` |
| No `Hello` in 10 s | Close `HELLO_TIMEOUT` |

Unknown protobuf fields are always ignored. A decoded message whose required semantic constraints (§5) fail is treated as malformed.

## 11. Pairing and authentication (owned by workstream 1B)

This document only reserves the places where pairing slots into the protocol; the cryptography (SPAKE2, token and PIN semantics, key pinning) is specified by 1B.

- **TLS layer.** Authentication of an already paired device is **mutual TLS 1.3 with pinned keys**; the verifiers are injected into `hx-transport` as ordinary rustls configs. A device that is not paired yet has no pinned key, so the server's client-certificate verifier (supplied by 1B) accepts an unknown client key **only while a pairing token is valid**; the connection is then restricted to pairing.
- **Handshake placement.** `Hello.intent` declares the purpose. With `INTENT_PAIR` the server (after the version check and after consulting its policy through `hx-transport`'s pending-session hook, which exposes the peer's certificates and the `Hello`) answers `HelloAck` and the only messages processed afterwards are `ControlMessage.pairing` (field 100) until pairing finishes, then the connection is closed with `NO_ERROR`; the device then reconnects with `INTENT_SESSION` using its now pinned key. If pairing is not open the server answers `Refuse{PAIRING_CLOSED}` and closes with `PAIRING_CLOSED`. With `INTENT_SESSION` the server rejects an unknown or revoked key with `Refuse{UNAUTHORIZED}`; the PIN step (architecture §8.3) uses `ControlMessage.auth` (field 101) between `HelloAck` and the first `ViewConfig`, and until it succeeds the server accepts nothing else but `auth` and `goodbye`.
- **Envelope.** Both `pairing` and `auth` carry `Opaque { bytes data = 1; }` (at most 4096 bytes). 1B defines what the bytes contain (its own protobuf messages inside the envelope) and the state machine. The transport only delivers them; it does not interpret them.
- **Application hook.** `hx-transport` hands the server application a `PendingSession` after the version check; the application calls `accept` (returning a restricted `Connection`) or `refuse`, and later `Connection::authorize` once the peer is authenticated (§2.1). The application MUST re-check the peer's key against its **current** pinned and revoked set on **every** `PendingSession` (TLS session resumption is disabled by the transport, but revocation can happen at any time), MUST close live sessions of a device when it is revoked, and MUST treat `Hello.software` and `Hello.device_name` as untrusted text (sanitize before showing or logging).

## 12. Client behaviour on security failures

A TLS or certificate verification failure while connecting (QUIC TLS alert, rejected server key or certificate) is reported to the application as a distinct error and is **final**: a client that tries QUIC first and falls back to WebSocket does so only when QUIC could not be established (no answer in time, UDP blocked), never after a failed security check, and never after a `Refuse`. The same rule applies to any future fallback.

## 13. Known follow-ups (not specified here)

- Phase 3 (WebTransport): the `h3` path currently holds its pre-authentication slot for the whole lifetime of the handler it dispatches to, not only until authorization. The Phase 3 handler must release or re-account the slot once the browser session is authorized, or long-lived WebTransport sessions would exhaust the pre-authentication limits.
- Application-layer policy owned by 1B/1C: re-check pinned/revoked keys on every `PendingSession`, close live sessions on revocation, sanitize `Hello.software` and `Hello.device_name` before display or logging, clamp input coordinates in the injector, and treat transfer file names as hints.
- Fuzz targets for 1H: `MediaHeader::decode`, `decode_datagram`, `message::decode::<ControlMessage | InputEvent | CursorEvent | TransferHeader>`, `message::decode_framed`, `version::peek_hello_version`, `file_name_problem`, and the WebSocket message router.

## 14. Schema location

The protobuf schema is `crates/hx-proto/proto/hx.proto` (package `hx.v1`); field numbers there are the numbers in this document. Field numbers are never reused. Adding fields or messages is a minor-version change (§4.2).
