# Spike S2: streaming loop

Status: complete. Branch `spike/s2-streaming-loop`. Code, scripts and raw results: `spikes/s2-streaming-loop/` (throwaway; nothing under `crates/` or `apps/` was touched).

## 1. Goal

Prove the latency and CPU budget of the streaming path end to end (execution-phase.md, S2; architecture.md sections 6, 7 and 10):

XFCE on headless Xorg in an unprivileged Incus container -> XDamage/XShm capture (`x11rb`) -> RGB to YUV (`yuvutils-rs`) -> x264 through libavcodec (`ffmpeg-next`) -> `quinn` QUIC, one unidirectional stream per frame -> headless client that decodes with libavcodec in software.

Pass criteria (4 vCPU, no GPU): added latency <= 40 ms p95 on LAN; <= 1.5 cores while typing or scrolling; about 0 CPU and bandwidth when idle. The spike decides encoder settings, threading model, and frame-per-stream versus alternatives.

## 2. Setup

| Item | Value |
|---|---|
| Host | Ubuntu 24.04 VM, kernel 6.8.0-151, 16 vCPU AMD EPYC 9645, 62 GB, no GPU, Incus 6.0.0. The host was **shared**: other agents compiled and ran their own spikes throughout (details in section 7). |
| Container | `images:ubuntu/24.04` (`s2-desktop`), unprivileged, `limits.cpu=12-15` (4 cores), `limits.memory=8GiB`. XFCE 4.18, `xserver-xorg-video-dummy` 0.4.0 at 1920x1080, mousepad 0.6.1, mpv 0.37, xdotool 3.20160805. Xorg runs as root inside the container, the XFCE session and `s2-server` run as the normal user `desk`. |
| Client | `s2-client` on the host, `taskset -c 0-3` (disjoint from the container cores 12-15). |
| FFmpeg / x264 | libavcodec 60.31 (FFmpeg 6.1.1), libx264 0.164.3108, same packages on host (build) and container (runtime), same glibc. |
| Crates | `x11rb` 0.13.2, `yuvutils-rs` 0.8.3, `ffmpeg-next` 7.1.0 (`ffmpeg-sys-next` 7.1.3, builds against FFmpeg 6.1), `quinn` 0.11.12 (`quinn-proto` 0.11.19, BBR), `rustls` 0.23.46 (ring), `tokio` 1.54.1, `crossbeam-channel` 0.5.17, `rcgen` 0.14.10. Rust 1.100.0, edition 2024. |
| Network | Container on `incusbr0` (veth + bridge). Profiles use `tc netem` on the container `eth0` egress, which is the server-to-client (video) direction: |

| Profile | netem on container egress |
|---|---|
| `lan` | none |
| `rtt50` | `delay 50ms rate 50mbit limit 1000` |
| `rtt150-loss` | `delay 150ms rate 10mbit loss 1% limit 1000` |
| `mobile` | `delay 40ms 30ms distribution normal loss 0.5% rate 20mbit limit 1000` |

The client-to-server direction (acks, input) is not shaped, so RTT equals the configured delay and loss applies to data packets only.

Reproduce: `spikes/s2-streaming-loop/scripts/setup-container.sh`, `cargo build --release`, `scripts/deploy.sh` (pushes `s2-server` and `scenario.sh`), `incus exec s2-desktop -- start-desktop.sh`, then `scripts/run.py` for one run, `scripts/matrix.py`, `scripts/repeat.sh`, `scripts/constrained.sh`, `scripts/final.sh` for the sets used here, and `scripts/analyze.py`, `compare.py`, `cc_table.py`, `timeline.py` for the tables. Every incus command goes through `sg incus-admin -c`.

## 3. Architecture as built

```
Xorg(dummy) --DamageNotify--> [capture thread] --job--> [convert thread] --YUV frame--> [encode thread] --OutFrame--> [tokio: 2 workers]
              XShm GetImage     slot pool (3 x 8 MB)     yuvutils BGRA->I420   pool of 3 AVFrames    x264 (libx264)       one uni stream per frame
              XFixes cursor     crossbeam bounded        full frame, BT.709     reused after encode    payload Vec pool     congestion controller
                                                                                                                              |
client: tokio accept_uni -> per-stream read task -> [decode thread: in-order reassembly, resync, libavcodec H.264 (slice threads)] -> CSV
```

- **Threads**: capture, convert, encode and a 2 Hz stats thread are plain OS threads joined by bounded `crossbeam-channel` array queues; BGRA slots, YUV frames and payload buffers are pooled, so there is no per-frame allocation on the hot path. tokio (2 workers) only does networking. Back-pressure is natural: when the BGRA slot pool is empty the capture thread stops capturing and damage keeps coalescing.
- **Capture**: `XDamage` with `ReportLevel::NON_EMPTY`; on the first event after a capture the damage time is recorded, then `damage_subtract` + full-screen `shm_get_image` into a pooled SysV segment. The pacer enforces a minimum interval between captures (set by the congestion controller). With no damage the thread blocks in `poll(2)`; the only periodic work is a 30 Hz `QueryPointer` for the cursor. Cursor shape (`XFixes`) and position travel on their own long-lived unidirectional stream, so pointer movement never waits for video.
- **Convert**: whole frame BGRA to I420 (BT.709 limited) with `yuvutils-rs` straight into the planes of a pooled `AVFrame`.
- **Encode**: libx264 via libavcodec, `preset=ultrafast`, `tune=zerolatency`, `crf=23` with VBV `maxrate` = current ladder rate and `bufsize` = one frame (`rate / fps`), `bframes=0`, `rc-lookahead=0`, `sync-lookahead=0`, `intra-refresh` (configurable), `keyint=120`, `forced-idr=1`, `repeat-headers=1`, Annex B, `threads=N` with `sliced-threads` (configurable). A forced IDR is produced on connect, on bitrate-ladder changes (encoder reopen) and after a stale-frame cancel.
- **Wire format**: kind byte, then a fixed little-endian 60-byte header (codec, flags, frame number, length, six CLOCK_MONOTONIC timestamps: damage, capture done, convert done, encode start, encode end, send) and the payload. The timestamps are spike instrumentation; the production header needs only the capture timestamp. Flags: key, resync. Control and input channels were not built.
- **Transport**: quinn, TLS 1.3, ALPN `hx/1`, BBR, self-signed certificate (the client skips verification: spike only). Each frame gets its own `open_uni()` stream, written and finished at once; a per-frame task waits for `stopped()` (all data acknowledged) to learn the ack delay, or resets the stream when cancelled.
- **Congestion handling (sender side only, no client feedback)**: every 4 ms while frames are in flight (100 ms when idle) the controller computes queueing lag = max(median ack delay of the last second's acked frames minus base RTT, time since anything was acked minus base RTT). Base RTT is the 20th percentile of smoothed RTT over 10 s. Lag > 40 ms: one step down a bitrate ladder (500 kbit/s ... 20 Mbit/s; the fps cap follows, `kbps/100` clamped to 10-60) and the failed level is blocked for 2 s, doubling to 8 s. Lag > 100 ms: two steps down, reset every in-flight frame stream, drain the encoder-to-network queue, force an IDR flagged `resync`. Lag <= 15 ms for 700 ms: one step up. Already-encoded frames are never dropped mid-chain except by the cancel, which is always followed by an IDR; the client discards everything older than a `resync` key frame and otherwise waits in order.
- **Client**: `quinn` client with 1024 concurrent uni streams, per-stream read tasks stamp `t_recv` when the whole frame has arrived, a decode thread reorders by frame number, decodes with libavcodec H.264 (`LOW_DELAY`, slice threading 4), stamps decode start/end, and writes a per-frame CSV plus a JSON summary. No colour conversion or presentation.
- **Clocks**: the container shares the host kernel and no time namespace is in use, so `CLOCK_MONOTONIC` is the same clock in the server and the client; this was checked by reading it from the host and from inside the container in turn. Timestamps are therefore directly comparable.

Clock sync across real machines (not built): NTP-style exchange on the control stream. The client sends `t1`, the server answers with its receive time `t2` and send time `t3`, the client stamps `t4`. Offset = ((t2 - t1) + (t3 - t4)) / 2, delay = (t4 - t1) - (t3 - t2). Keep the lowest-delay sample of the last N exchanges, repeat every few seconds, fit a slope to track drift, and apply the offset only to display-side latency accounting (server capture timestamp to client present time). Latency decisions at the sender use only sender-local clocks (ack delay), as in this spike.

## 4. Measurement method

- Scenarios are scripted with xdotool inside the container (`scripts/scenario.sh`): `idle` (30 s), `typing` (mousepad, about 12 characters/s), `scroll` (mouse wheel, about 40 notches/s over a 4000-line document), `video` (mpv full-screen, software `--vo=x11`, a synthetic 1080p30 `testsrc2` clip, deliberately busy), `drag` (Alt+drag of the mousepad window in circles at about 100 moves/s).
- Each run: fresh server and client, 3 s warm-up (excluded), 20 s measured window (30 s idle). Per-frame stage timings come from the client CSV. Total added latency = decode end minus the damage event time (for coalesced damage this is the oldest unsent damage, which is conservative); it excludes presentation.
- Stage meaning: `cap` = damage to capture done (includes the pacing wait, up to one frame interval, plus slot wait and the XShm copy), `conv` = convert queue plus conversion, `enc` = x264 time only, `net` = send start to whole frame received (includes send queue in quinn), `dec` = decode only.
- Server CPU is `CLOCK_PROCESS_CPUTIME_ID` of `s2-server` (all threads) sampled twice a second and interpolated over the client's window; container CPU is the container cgroup's `cpu.stat` (Xorg, XFCE, the application, xdotool, the server); client CPU is the client process.
- `/proc/loadavg` and per-core busy percentages of cores 12-15, cores 0-3 and the whole host (from `/proc/stat` over the window) are recorded in each run's `meta.json`.

## 5. Results

All numbers are from runs performed in this spike (`results/*/`; raw per-frame CSVs are git-ignored, summaries, meta and server stats are committed; `results/summary.md` has every run).

### 5.1 LAN, final binary (headline)

Run back to back at the end with the final server (`final_lan_*`). Host load was low at that point (loadavg 1.9 to 4.9; cores 12-15 busy 26 to 49 %, which includes the container's own load). p50 / p95 / p99 in ms.

| Scenario, config | fps | Mbit/s | cap | conv | enc | net | dec | **total** | KB/frame | server cores | container cores | client cores |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| typing, base | 42 | 0.46 | 6.3/16.4/19.1 | 1.4/2.4/3.4 | 4.2/7.3/9.8 | 0.7/1.7/3.2 | 1.0/2.0/2.9 | **14.8/24.6/27.6** | 1.3 | 0.48 | 0.90 | 0.11 |
| typing, fps120 | 50 | 0.46 | 1.1/2.7/3.9 | 1.6/2.8/3.3 | 4.7/8.5/11.1 | 0.7/1.9/3.6 | 1.1/2.2/3.6 | **10.2/16.2/18.9** | 1.1 | 0.59 | 1.07 | 0.14 |
| scroll, base | 37 | 1.63 | 4.5/15.2/19.3 | 2.0/4.4/6.7 | 7.4/15.2/21.8 | 1.0/3.8/6.1 | 1.5/4.3/6.1 | **18.8/34.6/42.3** | 5.3 | 0.58 | 1.77 | 0.14 |
| scroll, fps120 | 37 | 1.03 | 1.7/7.1/12.0 | 2.2/4.7/7.0 | 7.7/16.1/23.9 | 1.1/4.2/8.1 | 1.6/4.4/7.7 | **16.9/32.0/43.6** | 3.4 | 0.60 | 1.84 | 0.15 |
| drag, base | 49 | 6.82 | 8.3/17.1/18.7 | 1.7/2.9/4.7 | 6.4/10.9/13.2 | 1.0/2.5/3.7 | 1.7/3.3/4.5 | **20.2/30.2/33.6** | 16.9 | 0.80 | 1.41 | 0.21 |
| drag, fps120 | 50 | 5.16 | 1.4/4.0/5.6 | 2.0/3.7/5.8 | 7.1/13.1/17.7 | 1.1/3.3/4.9 | 1.9/4.3/5.9 | **14.4/26.0/34.5** | 12.4 | 0.91 | 1.60 | 0.24 |
| video, base | 44 | 9.21 | 4.1/16.5/20.0 | 1.7/4.4/7.5 | 6.4/16.6/21.2 | 1.2/4.9/8.9 | 1.9/4.6/7.8 | **17.9/40.5/56.0** | 25.5 | 0.71 | 1.84 | 0.22 |
| video, fps120 | 44 | 5.11 | 1.4/4.8/6.6 | 2.1/4.4/6.8 | 7.8/14.9/18.3 | 1.3/4.6/6.6 | 2.0/4.5/6.4 | **16.6/28.6/33.8** | 13.9 | 0.74 | 1.94 | 0.22 |
| idle (30 s) | 0 | 0.00 | | | | | | 0 frames | | **0.01** | 0.02 | 0.01 |

`base` = 60 fps pacing cap, `fps120` = the same pipeline with the pacing cap raised to 120 so that damage is not held back to a 16.7 ms grid (`--fps 120`). The `cap` p95 of about 16 ms in `base` is almost entirely that pacing wait; the measured pipeline time without it is `cap` in the `fps120` rows (capture itself about 1 to 2 ms at p50).

Stage budget check (p50, fps120 rows): capture 1.1-1.7 ms (budget <= 2), convert 1.6-2.2 (1-2), encode 4.7-7.8 (4-8), send/net 0.7-1.3 (< 1 on LAN, includes quinn queueing), software decode 1.1-2.0 (hardware 2-4 in the budget; software is no slower here for 1080p with small damage).

### 5.2 LAN, encoder configuration comparison

Averages over all LAN runs of each scenario and configuration (`results/config-comparison.md`; `scripts/compare.py`). **These runs happened under varying host load (cores 12-15 busy 35 to 68 %) and are noisy**; one run per cell for typing and video, three for scroll and drag (`base`, `t1`, `noir`, `fps120`). Treat differences below about 5 ms as noise.

| Scenario | Config | Runs | Total p50 | Total p95 | Total p99 | Encode p50 / p95 | Mbit/s | Server cores | Host busy 12-15 % |
|---|---|---|---|---|---|---|---|---|---|
| scroll | base (4 sliced threads, intra refresh, 60 fps) | 3 | 28.2 | 48.5 | 61.0 | 11.1 / 22.8 | 1.93 | 0.71 | 58 |
| scroll | t1 (1 thread, no slices) | 3 | 29.3 | 52.7 | 75.7 | 12.4 / 22.7 | 2.44 | 0.63 | 56 |
| scroll | noir (intra refresh off) | 3 | 22.1 | 43.1 | 54.3 | 9.1 / 19.5 | 1.47 | 0.62 | 50 |
| scroll | fps120 | 3 | 20.4 | 35.6 | 45.2 | 9.2 / 18.7 | 1.08 | 0.65 | 53 |
| scroll | superfast | 1 | 20.2 | 38.9 | 50.9 | 9.6 / 20.7 | 1.17 | 0.74 | 47 |
| scroll | t2 (2 sliced threads) | 1 | 38.3 | 61.1 | 79.2 | 13.1 / 25.1 | 3.10 | 0.76 | 68 |
| drag | base | 3 | 27.6 | 45.6 | 60.7 | 9.7 / 19.2 | 6.36 | 0.95 | 49 |
| drag | t1 | 3 | 29.4 | 42.2 | 48.9 | 12.0 / 18.1 | 5.61 | 0.78 | 44 |
| drag | noir | 3 | 23.6 | 37.9 | 51.1 | 8.7 / 17.0 | 5.23 | 0.90 | 44 |
| drag | fps120 | 2 | 23.5 | 41.3 | 59.4 | 11.1 / 20.4 | 4.12 | 0.97 | 50 |
| typing | base / t1 / t2 / noir / superfast / fps120 | 1 each | 19.3 / 28.6 / 24.5 / 18.3 / 17.9 / 11.2 | 35.3 / 43.7 / 39.3 / 32.7 / 29.9 / 21.9 | | enc p50 6.2 / 10.7 / 9.0 / 5.9 / 6.4 / 5.1 | 0.44 / 0.36 / 0.42 / 0.29 / 0.27 / 0.43 | 0.60-0.69 | 35-50 |
| video | base / t1 / t2 / noir | 1 each | 14.1 / 23.1 / 23.7 / 11.7 | 34.4 / 38.4 / 35.3 / 19.1 | | enc p50 5.6 / 11.0 / 8.2 / 4.4 | 9.6 / 9.5 / 10.0 / 9.7 | 0.57-0.69 | 38-46 |

What the data supports:

- **Pacing is the biggest latency lever.** Letting damage through without a 16.7 ms grid (`fps120`) cut total p95 by roughly 10 to 13 ms (scroll 48.5 to 35.6, typing 35.3 to 21.9, final-run drag 30.2 to 26.0, video 40.5 to 28.6) at the same CPU, and it also lowered bitrate (smaller, more frequent frames).
- **Sliced threads (4) versus one thread**: x264 encode p50 is about 1.5 to 2x lower with 4 slices (typing 6.2 vs 10.7 ms, video 5.6 vs 11.0) for about the same total server CPU (0.6-0.7 cores either way), so it buys latency, not efficiency. Two threads sat between them but was measured only once, under the heaviest host load, so it is inconclusive.
- **Intra refresh on versus off**: no latency difference above the noise on LAN. Off was 15 to 25 % lower in bitrate in typing and scroll (typing 0.29 vs 0.44 Mbit/s, scroll 1.47 vs 1.93). The benefit of intra refresh (no keyframe bursts on loss or late join) is not exercised by these runs except in the cancel path, where an IDR is forced anyway.
- `superfast` was not distinguishable from `ultrafast` in latency or CPU in the two runs made.
- **x264 does meet the budget.** There is no case in which x264 ultrafast could not meet the encode budget: p50 encode time is 4-8 ms and p95 9-17 ms on a half-loaded shared host, and tails above 100 ms appeared only in the noisiest runs (for example `t2` drag p99 144 ms with cores 12-15 62 % busy).

### 5.3 Constrained profiles (default config, final controller)

`rtt*`, `mobile`, `recovery_*` runs, final server. Congestion control on unless the row says `nocc` (`--cc 0`: the controller never reduces rate or cancels). Table from `scripts/cc_table.py`; cancel and restart counts are within the 20 s measured window (the initial convergence at connect happens in the 3 s warm-up and is not counted).

| Run | fps | Mbit/s | Lowest target (kbit/s) | Cancel events | Streams cancelled | Encoder reopens | Total p50 / p95 (ms) |
|---|---|---|---|---|---|---|---|
| rtt50 typing | 41.7 | 0.43 | 10000 | 1 | 2 | 3 | 68 / 78 |
| rtt50 scroll | 42.0 | 1.60 | 10000 | 2 | 2 | 6 | 65 / 77 |
| rtt50 drag | 50.4 | 6.77 | 10000 | 1 | 2 | 3 | 71 / 81 |
| rtt50 video | 43.9 | 9.68 | 20000 | 0 | 0 | 0 | 67 / 89 |
| rtt50 video, nocc | 45.7 | 9.94 | 20000 | 0 | 0 | 0 | 71 / 83 |
| rtt150-loss scroll | 13.2 | 0.38 | 500 | 1 | 4 | 7 | 229 / 293 |
| rtt150-loss drag | 32.7 | 3.30 | 500 | 1 | 8 | 17 | 188 / 328 |
| rtt150-loss video | 29.4 | 3.52 | 500 | 0 | 0 | 12 | 191 / 339 |
| rtt150-loss video, nocc | 42.1 | 9.15 | 20000 | 0 | 0 | 0 | 1443 / 1781 |
| mobile scroll | 14.9 | 0.34 | 500 | 0 | 0 | 8 | 111 / 186 |
| mobile drag | 12.1 | 0.57 | 500 | 0 | 0 | 5 | 150 / 193 |
| mobile video | 10.8 | 0.43 | 500 | 0 | 0 | 7 | 139 / 193 |
| mobile video, nocc | 42.0 | 9.14 | 20000 | 0 | 0 | 0 | 1991 / 3801 |

(50 ms RTT / 50 Mbit/s is not congested for 10 Mbit/s of content, so the cancel events there are brief start-up and burst events; end-to-end p95 is 77-89 ms = 50 ms of netem delay plus the 25-40 ms pipeline.)

Verified congestion behaviour:

1. **Frame rate and bitrate drop at the source.** Under `rtt150-loss` the controller steps the encoder down to 500 kbit/s / 10 fps and then probes up; the video scenario settles around 3.5 Mbit/s at about 29 fps against 9.2 Mbit/s at 42 fps unconstrained. Without control (`nocc`) the same content on the same link queues in netem and quinn for 1.4 s median / 1.8 s p95 (`rtt150-loss`), and 2.0 s median / 3.8 s p95 on `mobile` (an earlier run on the first controller version even reached 17 s); with control it stays at 190-340 ms (RTT 155 ms plus 35-180 ms).
2. **Stale-frame cancellation.** The `rtt150-loss` drag and scroll windows contain cancel events (4 to 8 frame streams reset each); `s2-client` counts `streams_reset` and `resync_jumps`, and in every case the decoder resynced on the following `resync` IDR (max reorder stall 160-190 ms, only frames older than the IDR discarded). Cancelled streams cost no further bandwidth and no head-of-line blocking, which is the property that makes frame-per-stream attractive here.
3. **Recovery** (video, netem removed 15 s into a 40 s window):
   - `rtt150-loss`: target 500 kbit/s at t = -1 to 5 s, ramps 1000 kbit/s at 6.8 s, 3000 at 9.3 s, 10000 at 11.8 s, 15000 at 14.3 s, 20000 at 19 s (4 s after the impairment was removed); fps cap back to 60 by 11.8 s. After the clear the network stage dropped to about 1 ms at p50 (the window p95 of 172 ms covers the impaired first 15 s; see `results/recovery_rtt150-loss_video/` and `scripts/timeline.py`).
   - `rtt50`: stays at 20 Mbit/s throughout (no congestion at that rate).
   - Convergence from a cold start at the maximum rate on the 150 ms / 10 Mbit/s link takes about 10 to 15 s.

Controller weaknesses found and fixed during the spike (kept as evidence in `results/v1-controller/` and `results/v2-controller/`): the first version used a raw minimum RTT and an unexpiring ack-delay median, which made lossy and jittery links look permanently congested (cancel storms of about 7 per second at the floor rate) and, with a 30 s probe back-off, never recovered after the impairment ended (rate stuck at 1 Mbit/s for 25 s). Using a windowed percentile base RTT, a 1 s expiring median, a stall term and a shorter back-off fixed the storm and the recovery.

### 5.4 Idle

Final server: 30 s idle window, 0 frames received, 0 bytes of video, server 0.01 cores, container 0.02 cores, client 0.01 cores. An earlier version had a fixed 4 ms controller tick that cost 0.09 cores while idle (`results/v1-controller/lan_idle_base_tick4ms`); the tick now backs off to 100 ms when nothing is in flight. During `idle` runs the XFCE panel clock redraw produced one frame per minute in some runs (a few hundred bytes).

### 5.5 Host baseline

With the container desktop idle and no spike processes running, over 30 s: cores 12-15 busy 21.8 %, cores 0-3 31.8 %, whole host 25.4 %, loadavg 10.26 (`results/host-baseline.txt`). Other agents' work was never absent.

## 6. Verdicts against the S2 pass criteria

| Criterion | Verdict | Evidence and reasons |
|---|---|---|
| Added latency <= 40 ms p95 on LAN | **PASS (thin margin, conditional)** | Final runs, damage event to decode end: typing 24.6 ms (16.2 with `fps120`), scroll 34.6 (32.0), drag 30.2 (26.0), video 40.5 (28.6). Condition: measured with the host about 25-50 % busy on the container cores and loadavg 2-5. Under heavier concurrent load the same configuration gave p95 37-61 ms for scroll and drag and 34-76 ms for video (earlier runs, `results/summary.md`), so the budget is only met with some CPU headroom. It excludes presentation (0-8 ms in the budget), so the design budget is at risk for video unless pacing is relaxed. |
| <= 1.5 cores while typing or scrolling | **PASS** | `s2-server` (capture, convert, encode, network): typing 0.48-0.59, scroll 0.58-0.60 cores in the final runs (0.6-0.7 and 0.6-0.8 in earlier loaded runs). The whole container, including Xorg, XFCE, mousepad and xdotool, used 0.9-1.1 (typing) and 1.8 (scroll) cores. The server is full-frame capture and conversion every frame, so there is headroom from damage-rectangle processing. |
| About 0 CPU and bandwidth idle | **PASS** | 0.01 cores, zero frames and zero bytes in 30 s (after the controller tick fix, section 5.4). |
| Congestion handling works (spike goal, not a numeric criterion) | **PASS with caveats** | Rate drops at the source, stale frame streams are cancelled and the decoder resyncs, recovery within about 4 s of the link clearing (section 5.3). Caveat: the `mobile` jittery profile is over-conservative (see risks). |
| Pixel correctness of the decoded image | **UNVERIFIED** | The client decodes every frame without error and reports frame sizes, but decoded pictures were never compared or dumped. Colour handling (BT.709 limited) is therefore untested. |

## 7. What differs from a real VPS and a real network

- **Shared, noisy host.** Cores 12-15 were shared with other agents' builds and VMs (host loadavg 2 to 45 during the spike; wait-for-quiet logic and `meta.json` per run record it). Latency tails and encode time are inflated in the noisier runs; a dedicated 4 vCPU VPS may do better on tails, or worse if its vCPUs are slower or steal-prone than this EPYC.
- **Network.** The veth/bridge adds well under 1 ms; netem shapes only the video direction, loses only data packets, and uses a simple drop-tail queue of 1000 packets. Real paths have asymmetric and bursty loss, ack-path jitter and ISP shaping.
- **Clocks.** One monotonic clock; no clock sync error, no NTP drift.
- **Client.** Headless software decode with no presentation, no GPU texture upload, no display vsync (the budget allows 0-8 ms to present). The real desktop client uses VAAPI/GPU decode (spike S1).
- **Content.** xdotool input at fixed rates; `video` is a synthetic `testsrc2` clip played with mpv's software output, busier than typical video; text and window drag are real XFCE and mousepad. xfwm4 composited on the dummy driver may damage differently from a real GPU session.
- **Scope.** Input-to-photon latency (input injection, round trip) was not measured: only damage to decode. No audio, clipboard, files, resize, multi-client, or TLS verification.
- **Controller state.** Single connection, spike-quality thresholds, tuned on three profiles.

## 8. Decision

**Encoder settings (hx-codec defaults)**

- x264 through libavcodec, `preset=ultrafast`, `tune=zerolatency`, no B-frames, no lookahead, `repeat-headers`, Annex B, `forced-idr`, `crf=23` plus a one-frame VBV (`vbv-bufsize = maxrate / fps`), `maxrate` from the congestion ladder with a 20 Mbit/s default ceiling (capped by the per-device bandwidth setting), `intra-refresh=1`, `keyint=120`.
- **Slice threads = the number of encode cores (4 here)**: x264 encode p50 is 1.5-2x lower than single-thread for the same CPU. A single-thread, no-slice configuration is the low-CPU fallback; its latency cost is about 5 ms at p50.
- **Keep intra refresh** on, as the architecture assumes, with the explicit finding that it showed no LAN latency benefit and cost 15-25 % bitrate in typing and scroll runs; revisit with a lossy-link measurement (section 9). Forced IDR stays for connect and resync.
- `ultrafast` stays; `superfast` showed no measurable gain.

**Pacing**: do not hold damage to a fixed 60 fps grid. Capture immediately when the pipeline is free and let back-pressure (slot pool) and the congestion controller set the rate; the 60 fps (later 120) figure is a ceiling, not a clock. The measured saving is 5-13 ms at p95.

**Threading model**: dedicated capture, convert and encode OS threads linked by bounded lock-free queues with pooled buffers, tokio only for networking. Validated: hot-path stage times fit the budget and the process stays at 0.5-0.9 cores. The next optimisation is damage-rectangle capture and conversion; it is not needed to pass.

**Frame-per-stream**: adopt it. It gave no head-of-line blocking between frames, trivial stale-frame cancellation by resetting streams (verified), and a free per-frame ack signal (`stopped()`) that drives the congestion controller without client feedback. The costs seen: a receiver-side in-order reassembly and resync path is mandatory (about 100 lines in the spike client), stream credit must be generous (client allowed 1024 concurrent uni streams), and cancelled P-frames force an IDR. Alternatives (a single long-lived stream with sequence resync, datagrams with application fragmentation) were **not** measured, so this is a decision to proceed with the architecture's choice, not a measured win over those alternatives.

**Congestion controller (hx-session / hx-transport)**: keep the sender-side design (ack-delay queueing estimate, bitrate ladder with failed-level back-off, cancel plus IDR). Required fixes before production: jitter-aware thresholds, faster convergence, and a cold start below the ladder top on unknown links.

## 9. Risks and follow-ups

1. **Latency margin is thin.** LAN p95 met 40 ms only with CPU headroom (section 6). Re-measure on a quiet 4 vCPU VPS; adopt relaxed pacing; add damage-rect capture and conversion; consider multi-slice only on boxes with spare cores.
2. **Jittery links** (`mobile`: 40 ms plus 30 ms jitter, 0.5 % loss, 20 Mbit/s) sat at 0.3-0.6 Mbit/s and 11-15 fps with p95 about 190 ms for a link that could carry the content. The 40 ms lag threshold is of the order of the jitter. The controller needs a jitter-adaptive threshold (for example based on the spread of ack delays) or a bandwidth probe based on BBR's delivery rate.
3. **Slow convergence**: about 10-15 s to ramp on a 150 ms link, plus an initial cancel burst when starting at the ladder top; `rtt150-loss` scroll finished the window at 13 fps because the ramp had not completed. Start at a conservative rate and use quinn's `cwnd`/RTT as a ceiling.
4. **Encoder reopen on every ladder step** forces an IDR (12-17 reopens in the lossy windows). One-frame VBV keeps it small but it is not free; prefer runtime reconfiguration of VBV (not verified to work through libavcodec 6.1) or a few pre-opened encoders.
5. **Sharp-text refinement** is not implemented: a screen that stops changing while the VBV was binding stays at the quality of its last frame. A refinement frame after a short quiet period is needed (architecture section 6.2).
6. **Pixel fidelity unverified** (colour matrix and range, resolution changes); verify with a decoded-frame dump before hx-codec is built.
7. **Cursor**: shape and position channel works (position latency measured under 2 ms on LAN) but position is polled at 30 Hz; the real implementation should use XInput2 raw motion or XFixes cursor events instead of polling.
8. **Server runs Xorg as root in the container** for this spike; the product should follow the architecture's privilege-separation section.
9. **Container limits on the host**: the host's `fs.inotify.max_user_instances` limit (128) was exhausted by concurrent Incus containers during the spike, which blocked another spike's desktop; the coordinator raised it. Worth a line in the installer's preflight checks.
10. **Harness is single-run**: `run.py` uses fixed ports, one container and one netem qdisc; run one measurement at a time.
