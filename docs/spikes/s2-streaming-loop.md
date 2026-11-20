# Spike S2: streaming loop

Status: complete; quiet-VPS follow-up in section 10 (branch `spike/s2-vps-remeasure`). Branch `spike/s2-streaming-loop`. Code, scripts and raw results: `spikes/s2-streaming-loop/` (throwaway; nothing under `crates/` or `apps/` was touched).

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

**Update 2026-11-20:** the margin and the UNVERIFIED pixel item above were re-measured on a quiet 4 vCPU VPS; see section 10 (all criteria PASS with margin; pixel fidelity measured, two findings).

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

## 10. VPS re-measure (2026-11-20)

Follow-up on the open items of section 9 (quiet-host re-measure, decoded-pixel fidelity) plus a real-internet run. Branch `spike/s2-vps-remeasure`. Everything here was measured on a dedicated, otherwise idle 4 vCPU VPS; sections 1 to 9 above are the earlier local results and stay as they were. Raw summaries, meta, server stats and fidelity CSVs: `results/vps/<run>/`; generated tables `results/vps/summary-A.md`, `summary-B.md`, `summary-variants.md`; crops `results/vps/crops/`; the harness is `scripts/run_vps.py`, `vps-matrix.sh`, `wan-matrix.sh`, `analyze_vps.py`, `fidelity_report.py` (commands in 10.9). Per-frame CSVs and frame dumps are git-ignored.

### 10.1 Headline

- **Every S2 criterion passes with a wide margin on a quiet 4 vCPU VPS.** With the recommended relaxed pacing (`fps120`) added latency (damage to decode end, LAN) is **10.7 to 16.5 ms p95** (was 16 to 32 ms locally on the shared host) and with the 60 fps pacing cap of the first spike 21 to 27 ms p95 (was 25 to 40 ms). The video scenario, the thin spot (40.5 ms p95), is 26.7 ms (60 fps cap) or 16.5 ms (relaxed pacing).
- **Over a real internet path** (client on this machine, about 14.4 ms RTT) total latency is **20 to 25 ms p95** (typing 24.8, p99 33), of which the network is the expected one-way delay of about 8 ms.
- **Pixels**: colour handling is correct (BT.709 limited round-trips white and black, no bias beyond 1 level), text is legible and PSNR is 47 dB while typing. Two real findings: the stream must carry VUI colour tags (without them a client cannot know the matrix and range), and frames that follow a large change (scroll direction reversal, window drag) are heavily blocky for one frame (worst frames 15 to 24 dB PSNR).

### 10.2 Setup

| Item | Value |
|---|---|
| VPS | Ubuntu 26.04.1, kernel 7.0.0-43, 4 vCPU AMD EPYC-Rome (older and slower per core than the 9645 used locally), 7.9 GB, Incus 6.0.5, btrfs pool, existing bridge `hxbr0` (NAT). Python 3.14. |
| Idle baseline (30 s, before anything was created) | whole host busy 0.04 %, steal 0.01 %, per core 0.03 to 0.10 %, loadavg 0.14 / 0.26 / 0.56 (`results/vps/host-baseline.txt`). During runs steal stayed at 0.1 to 1.3 %, the host was otherwise empty (Docker had no running container). |
| Containers | `s2-desktop` (`images:ubuntu/24.04`, XFCE 4.18 on Xorg dummy 1920x1080, same setup scripts as locally, 5 GiB) runs `s2-server`; `s2-client` (same image, only the FFmpeg 6.1 runtime libraries, 1 GiB) runs `s2-client`. The decoder is in its own container because the VPS host is Ubuntu 26.04, whose FFmpeg is not the 6.1 the binaries link (not checked in detail, and installing packages on the host was out of scope); both share the host kernel, so `CLOCK_MONOTONIC` is one clock and LAN timestamps are directly comparable (offset verified, 10.7). Traffic crosses the veth pair and `hxbr0`. |
| Binaries | Same code as section 3 plus instrumentation (clock probes, frame dumps, `--vui`, `--vbv-frames`): built locally on Ubuntu 24.04 with Rust 1.100.0 and the same FFmpeg 6.1.1 / x264 0.164, copied to the VPS. |
| Scenarios and method | Unchanged (section 4): 3 s warm-up, 20 s window (30 s idle), `scenario.sh`, one fresh server and client per run, **3 repeats per scenario and configuration**, percentiles pooled over the three repeats (per-repeat p95 listed too). |
| CPU sharing | **A1 (primary)**: both containers unpinned, so the desktop (Xorg, XFCE, the application, xdotool), `s2-server` with its four x264 slice threads, the decoder and Incus all compete for the same 4 vCPU. This is pessimistic for the server (in production the client is elsewhere) and honest about "4 vCPU total". **A2**: `s2-desktop` pinned to cores 1-3 and `s2-client` to core 0 (3+1 split). The two agree within noise (10.7 vs 11.2 ms typing p95, 13.9 vs 16.5 scroll, 11.7 vs 13.9 drag, 16.5 vs 17.5 video), so the result does not depend on how the client is placed. |
| Network | Config A: veth and `hxbr0`, no netem. Config B: 14.0 to 15.0 ms RTT (`ping` min/avg 14.0/14.4 ms) between this machine and the VPS, server reached through an Incus UDP proxy device on a high port (added for the run, removed afterwards). |
| Encoder | Section 8 final configuration (ultrafast, zerolatency, crf 23, 4 sliced threads, intra refresh, one-frame VBV, 20 Mbit/s ceiling). `base` = 60 fps pacing cap, `fps120` = relaxed pacing (the section 8 recommendation). |

### 10.3 Configuration A, LAN, quiet VPS (A1: shared cores)

p50 / p95 / p99 in ms, pooled over 3 runs of 20 s each. "server cores" = `s2-server` process CPU, "container cores" = the whole desktop container (Xorg, XFCE, app, xdotool, server), "client cores" = the decoder process.

| Scenario, config | fps | Mbit/s | cap | conv | enc | net | dec | **total** | per-run total p95 | KB/frame | server cores | container cores | client cores |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| typing, base | 44.4 | 0.47 | 7.3/17.1/18.2 | 1.0/1.5/1.9 | 3.5/5.4/6.8 | 0.4/0.8/1.7 | 0.8/1.5/2.2 | **13.7/23.4/25.8** | 23.8, 24.2, 22.7 | 1.2 | 0.45 | 0.79 | 0.11 |
| typing, fps120 | 50.0 | 0.46 | 1.2/3.0/4.5 | 1.1/1.5/2.0 | 3.4/5.3/7.2 | 0.4/0.8/1.5 | 0.8/1.5/2.2 | **7.3/10.7/14.3** | 11.5, 10.8, 7.8 | 1.1 | 0.49 | 0.84 | 0.12 |
| scroll, base | 43.4 | 1.90 | 4.4/12.5/16.5 | 1.1/1.7/2.5 | 4.3/8.1/10.3 | 0.5/1.3/2.3 | 0.9/2.0/2.9 | **11.9/21.2/25.1** | 21.7, 21.4, 19.8 | 5.3 | 0.49 | 1.29 | 0.11 |
| scroll, fps120 | 43.6 | 1.23 | 1.2/3.9/7.0 | 1.1/1.7/2.5 | 4.1/7.7/10.3 | 0.4/1.2/2.5 | 0.9/1.8/2.5 | **8.4/13.9/17.7** | 14.7, 14.4, 11.8 | 3.4 | 0.48 | 1.27 | 0.11 |
| drag, base | 51.1 | 6.72 | 8.8/17.0/17.6 | 1.0/1.5/1.9 | 4.7/7.0/8.4 | 0.5/1.0/1.6 | 1.1/2.0/2.6 | **16.5/25.4/27.4** | 25.7, 25.3, 24.2 | 16.0 | 0.69 | 1.08 | 0.17 |
| drag, fps120 | 57.9 | 5.02 | 1.1/2.3/3.0 | 1.1/1.7/2.1 | 4.6/6.7/8.8 | 0.5/0.7/1.1 | 1.0/1.7/2.3 | **8.7/11.7/15.5** | 12.6, 11.7, 10.4 | 10.5 | 0.75 | 1.15 | 0.18 |
| video, base | 47.5 | 10.24 | 6.1/16.8/18.5 | 1.0/1.9/3.3 | 4.6/8.2/10.6 | 0.6/1.8/3.3 | 1.4/2.8/4.1 | **15.7/26.7/30.7** | 28.4, 18.6, 26.0 | 26.2 | 0.54 | 1.62 | 0.16 |
| video, fps120 | 56.1 | 6.38 | 1.3/3.3/4.7 | 1.2/2.0/3.3 | 5.3/9.3/11.2 | 0.5/2.3/3.7 | 1.3/2.9/4.3 | **10.7/16.5/19.3** | 17.1, 16.4, 15.4 | 13.8 | 0.64 | 1.78 | 0.17 |
| idle (30 s), base | 0 | 0.00 | | | | | | 0 frames in all 3 runs | | 0 | **0.02** | 0.02 | 0.01 |

A2 (desktop on cores 1-3, client on core 0), `fps120`: typing **7.9/11.2/14.7** (server 0.45 cores), scroll **9.6/16.5/20.6** (0.45), drag **10.1/13.9/18.8** (0.72), video **11.1/17.5/21.7** (0.57); idle 0.02 cores (one tiny 0.4 KB frame, the panel clock, in some 30 s windows). Full tables: `results/vps/summary-A.md`. Host loadavg at the middle of the runs 0.9 to 3.3 (our own load), steal at most 1.3 %.

What changed against the shared local host: encode p50 is 3.4 to 5.3 ms (was 4.7 to 7.8), p95 5.3 to 9.3 (was 7.3 to 16.6), and the tails collapsed (video total p99 19 ms against 34 to 56). The CPU the container uses (0.8 to 1.8 cores) is the same as locally, so the VPS vCPUs are not slower for this workload than the 16 vCPU host.

### 10.4 Configuration B, real internet

Client on this machine (Ubuntu 24.04, 16 vCPU, shared, loadavg 2.5 to 8.0 and 15 to 32 % busy during the runs), server in `s2-desktop` on the VPS, QUIC over the public internet (14.4 ms RTT), `fps120`, 3 repeats. Total = server damage time to client decode end, with the client clock mapped onto the server clock (10.5).

| Scenario | fps | Mbit/s | enc | net (send to fully received) | dec | **total p50/p95/p99** | per-run total p95 | server cores | client cores |
|---|---|---|---|---|---|---|---|---|---|
| typing | 48.6 | 0.46 | 3.6/5.5/7.4 | 8.1/11.6/15.1 | 1.3/4.9/8.8 | **16.3/24.8/33.1** | 20.8, 18.6, 29.9 | 0.47 | 0.21 |
| scroll | 45.8 | 1.35 | 3.9/7.2/9.3 | 7.8/9.7/11.4 | 1.0/3.2/4.9 | **15.9/21.6/25.5** | 21.8, 22.6, 19.6 | 0.47 | 0.17 |
| drag | 58.4 | 5.30 | 4.5/6.4/8.0 | 7.9/9.5/10.9 | 1.4/3.2/4.6 | **16.7/20.4/23.6** | 20.7, 20.6, 20.1 | 0.75 | 0.27 |
| video | 52.9 | 5.94 | 5.1/9.6/12.8 | 8.0/9.4/10.7 | 1.3/2.5/3.9 | **17.8/23.8/30.5** | 24.9, 20.7, 23.9 | 0.64 | 0.21 |
| idle (30 s) | 0 | 0.00 | | | | 1 to 2 tiny frames (0.6 KB) per window | | 0.01 | 0.03 |

**Network share.** The `net` stage is 7.8 to 8.1 ms at p50 (about 50 % of the 16 to 18 ms total) against RTT/2 = 7.2 ms; the remainder over the floor is serialisation of the frame plus pacing, about 0.6 to 0.9 ms at p50, and p95 is 9.4 to 11.6 ms (typing's wider tail comes from the busy local client machine, whose decode p95 was 4.9 ms against 1.5 on the VPS). Non-network work (capture, convert, encode, decode) adds about 8 to 10 ms at p50. Relative to LAN the p95 total rises by 7 to 14 ms, which is the one-way path plus the busier client. On a 14 ms-RTT path the criterion of 40 ms p95 added latency is still met by a factor of 1.6 including the whole network.

### 10.5 Clock offset method (config B) and its error bound

Only the offset from the server's monotonic clock to the client's is needed for stages that span machines (`net`, `total`). Method (`s2-client` and `s2-server`, QUIC datagrams on the data connection, no extra socket):

1. The client sends a datagram with its monotonic time `t1` every 50 ms for the whole run (about 460 samples per run, 660 for idle). The server stamps its receive time `t2` and, just before replying, `t3`; the client stamps `t4` on arrival.
2. Per sample, `theta = ((t2 - t1) + (t3 - t4)) / 2` (server minus client) and `delay = (t4 - t1) - (t3 - t2)`.
3. `analyze_vps.py` keeps the 10 % lowest-delay samples of the run and fits a straight line `theta(t)` (so slow drift is tracked), then maps every client timestamp with `t_server = t_client + theta(t)`.

Error bound: **worst case +/- min(delay) / 2 = +/- 7.0 to 7.3 ms** (the offset is exact only if the two legs are equal; any path asymmetry puts half of it into the offset). Typical error is much smaller and not knowable without an external reference; the run-to-run scatter of the fitted offset is 0.04 to 0.08 ms and the drift 0 to 8 ppm (the fitted offset moved by at most 0.2 ms between runs minutes apart). Practical consequences: (a) the constant floor of `net` (about RTT/2) and therefore of `total` is uncertain by up to +/- 7 ms, so the 20 to 25 ms totals are best read as "within about +/- 7 ms"; (b) everything that depends on differences of the same stage, notably the jitter of `net` (p95 minus p50: 1.4 to 3.5 ms) and all server-side stages, is independent of the offset. Also note that `net` minimum equals RTT/2 by construction, so it is not an independent check of the offset.

**Validation of the method.** On the LAN runs the true offset is 0 (shared clock). The same estimator, on the 42 LAN runs of sets A1 and A2, returned +0.03 to +0.10 ms with a worst-case bound of 0.07 to 0.13 ms and a scatter of 0.01 to 0.04 ms (`results/vps/summary-A.md`, second table), i.e. well inside its own bound. Probe minimum delay over the internet (14.0 to 14.3 ms) matches `ping` (14.0 min).

NTP/chrony against a common reference would cut the unknown asymmetry only if both ends had a good reference; a one-way delay measurement with an error below the RTT/2 bound would need a GPS/PTP source and is not worth it for the product (the product needs only the capture timestamp and RTT).

**Netem on the internet path was tried and discarded.** With the Incus userspace proxy device the server's replies reach the proxy over loopback inside the container, so `tc netem` on the container's `eth0` shaped nothing (the runs were unconstrained, which was noticed from bitrate and latency, and the runs were deleted). Shaping the VPS's uplink would have meant changing host networking shared with Docker, which was out of bounds. `rtt150-loss` and `mobile` therefore remain covered only by the local runs of section 5.3 (not re-measured on the VPS).

### 10.6 Verdicts per S2 criterion, quiet VPS

| Criterion | Verdict | Evidence |
|---|---|---|
| Added latency <= 40 ms p95 on LAN | **PASS** (margin 1.4x to 3.5x) | Config A, 3 repeats each, worst repeat: typing 11.5 (base 24.2), scroll 14.7 (21.7), drag 12.6 (25.7), video 17.1 (28.4); p99 at most 31 ms in any scenario and configuration. The margin is now real: it does not depend on a lightly loaded shared host. Presentation (0 to 8 ms in the budget) is still excluded, so video with presentation is about 25 ms p95 with relaxed pacing. |
| <= 1.5 cores typing or scrolling | **PASS** | `s2-server` 0.45 to 0.49 cores (typing, scroll), 0.64 to 0.75 (video, drag); whole container including Xorg, XFCE, the app and xdotool 0.8 (typing) and 1.3 (scroll), at most 1.8 (video). Both CPU sharing setups agree. |
| About 0 CPU and bandwidth idle | **PASS** | 0.01 to 0.02 cores for the server and for the container, 0 Mbit/s, 0 frames in 30 s in the 3 A1 runs and a single 0.4 to 0.6 KB frame (the XFCE panel clock) in some A2 and B windows. |
| Added latency over a real internet path (not a numeric criterion) | **PASS (reported)** | 20 to 25 ms p95, 16 to 18 ms p50 total at 14.4 ms RTT, network share about 8 ms; offset uncertainty +/- 7 ms (10.5). |
| Congestion handling | **UNVERIFIED on the VPS** | The netem profiles could not be applied here (10.5). Section 6's verdict stands on the local runs. |
| Pixel correctness of the decoded image | **PASS with two findings** | 10.7. |

### 10.7 Pixel fidelity

Method: `s2-server --dump` copies every 40th captured BGRA frame (frame number = encoder frame number) to disk, `s2-client --dump` writes every 40th decoded I420 picture, matched by frame number (25 to 33 pairs per run; first run of each scenario). `s2-fidelity` converts the decoded picture to RGB (BT.709 limited range, bilinear chroma upsampling) and computes against the source RGB: PSNR over RGB, PSNR and SSIM (7x7 window, population statistics) of BT.709 luma, plane PSNR of Y/U/V against the source converted to I420 (isolates codec loss from colour conversion), mean colour bias, the decoded value of pure-white source pixels, and PSNR when the same decoded planes are interpreted as BT.601 or as full range. The frames pair up correctly (47 dB, not noise). Rows are the VUI-tagged `fps120` runs; `results/vps/FID_*/fidelity.csv` has every frame and `results/vps/crops/` the side-by-side crops (source | decoded | difference x8, 4x zoom of 128x72 pixels).

| Scenario | Pairs | PSNR RGB mean / min (dB) | PSNR luma (dB) | SSIM luma mean / min | PSNR Y / U / V plane (dB) | mean bias R,G,B (levels) | PSNR if read as BT.601 / full range |
|---|---|---|---|---|---|---|---|
| typing | 26 | **47.1** / 46.9 | 55.0 | **0.9995** / 0.9993 | 57.1 / 59.4 / 59.7 | +0.41, +0.05, +0.41 | 45.5 / 23.8 |
| scroll | 25 | 43.7 / **19.6** | 51.7 | 0.983 / **0.798** | 56.0 / 59.4 / 59.5 | +0.83, +0.05, +1.03 | 41.9 / 25.8 |
| window drag | 33 | 36.6 / **24.1** | 37.3 | 0.988 / 0.929 | 37.6 / 51.1 / 51.7 | +0.28, -0.48, +0.22 | 36.3 / 23.9 |
| video (testsrc2) | 27 | 33.6 / 32.9 | 40.3 | 0.987 / 0.985 | 41.7 / 42.8 / 41.5 | -0.08, +0.11, +0.05 | **23.1** / 24.3 |

Findings:

1. **Colour range and matrix are correct end to end.** Decoded pure-white pixels come back as 255/255/255 within 0.1 level while typing (253.3 to 254.0 in the busier scenarios, the codec's noise), and the mean colour bias is at most about 1 level. Reading the same decoded planes with the wrong assumptions would cost a lot: a BT.601 reading costs 10 dB on the colourful video content (23.1 against 33.6; gray text hides it, 45.5 against 47.1) and a full-range reading 10 to 25 dB. The conversion in the server (`yuvutils-rs`, BT.709, limited) is what the decoder assumes.
2. **The stream must be tagged.** Without VUI parameters the decoder reports range, matrix, primaries and transfer as unspecified (`FID_*_fps120_r1`); a client then has to guess (FFmpeg and most GPU paths guess BT.709 for HD, a hardware path or a different decoder can guess BT.601 or full range, with the 10 to 25 dB penalty above). With `colorprim/transfer/colormatrix=bt709` and `fullrange=off` (`--vui 1`) libavcodec reports range MPEG (limited), matrix BT.709, primaries BT.709, transfer BT.709 (`FID_*_fps120-vui_r1`) and PSNR is unchanged. **Decision: hx-codec must always write the VUI colour description (and the product protocol should carry it too).** Note: x264's parameter key is `fullrange=off`; `range=tv` (the CLI spelling) is rejected by `x264-params`.
3. **Static or slowly changing content is excellent**: typing 47 dB RGB, 55 dB luma, SSIM 0.9995; the crop `crops/FID_typing_fps120-vui_r1.png` shows crisp, fully legible menu and editor text, the 8x amplified difference is invisible. The losses are the codec's (Y plane 57 dB) and 4:2:0 chroma on coloured edges (chroma plane 59 dB, colour fringes on small coloured glyphs would show only in the difference image). 4:2:0 is the dominant error for RGB; there is no colour shift.
4. **Transient frames after large changes are poor.** Mean quality in scroll (43.7 dB) and drag (36.6 dB) is dominated by good frames, but the frames that carry a big change are heavily compressed: the scroll direction reversal frames score **19.6 dB / SSIM 0.80** and the worst drag frame 24.1 dB (`crops/FID_scroll_fps120-vui_r1-worst.png`: blocky and not legible for that picture, which the next frames repair). The frame size shows the cause: those frames are 16 to 17 KB against a 1.3 KB median, right at the one-frame VBV budget (20 Mbit/s / 120 fps = 20.8 KB). Video has no such outliers but a lower plateau (33.6 dB, SSIM 0.987) because `testsrc2` is high-entropy and the VBV is tight; its crop is soft but there is no text.
5. **A 4-frame VBV (`--vbv-frames 4`) does not fix the worst frame** in the one run made: the scroll reversal frame grew to 53 KB and still scored 14.8 dB (single run, different sampled frames; mean PSNR 39.3 vs 43.7 dB is not comparable). It does lift the plateau where the VBV bound (video 34.5 vs 33.6 dB, drag 40.5 vs 36.6 dB). So the VBV is part of the explanation but not all of it. This is an open item (10.10).

### 10.8 Encoder trade-offs re-tested on the quiet machine (A1 sharing, relaxed pacing, 3 repeats each)

Totals are pooled p50 / p95 / p99; Mbit/s and server cores are means. Baseline is the `fps120` rows of 10.3. Full table: `results/vps/summary-variants.md`.

| Scenario | fps120 (4 sliced threads, intra refresh) | no intra refresh | 1 thread, no slices | 2 sliced threads | VBV 4 frames |
|---|---|---|---|---|---|
| typing | 7.3/10.7/14.3, 0.46 Mbit/s, 0.49 cores, enc p50 3.4 | 7.8/10.5/13.6, **0.35**, 0.49, 3.8 | 11.1/14.6/17.7, 0.43, 0.43, 6.4 | 8.2/10.4/13.4, 0.45, 0.45, 4.3 | not run |
| scroll | 8.4/13.9/17.7, 1.23, 0.48, 4.1 | 7.7/12.4/14.8, 1.34, 0.46, 3.8 | 12.5/20.5/24.5, 1.63, 0.44, 7.4 | 9.6/15.5/19.2, 1.41, 0.46, 5.2 | 7.8/12.5/16.6, **2.94**, 0.46, 3.9 |
| drag | 8.7/11.7/15.5, 5.02, 0.75, 4.6 | 8.7/11.5/15.2, 4.62, 0.75, 4.6 | 13.6/18.6/21.6, 4.52, 0.61, 8.2 | 10.6/14.2/17.1, 4.52, 0.69, 6.1 | 8.0/10.5/12.4, 5.88, 0.68, 4.1 |
| video | 10.7/16.5/19.3, 6.38, 0.64, 5.3 | 9.3/15.0/17.7, 5.79, 0.55, 4.6 | 14.1/20.0/23.6, 5.96, 0.52, 8.1 | 10.9/16.3/19.4, 5.32, 0.51, 5.8 | 8.4/13.4/15.9, 7.97, 0.46, 4.1 |

- **Slice threads: keep 4 sliced threads.** One thread without slices costs +4 to +7 ms p95 everywhere (typing +3.9, scroll +6.6, drag +6.9, video +3.5) for 0.04 to 0.14 fewer cores; two threads cost up to +2.5 ms p95 (scroll +1.6, drag +2.5, typing and video within noise) and save nothing visible. On a 4 vCPU box the latency is worth the CPU. The single-thread, no-slice mode stays the fallback for smaller boxes (encode p50 3 to 4 ms slower).
- **Intra refresh: no latency effect** (all differences within +/- 1.5 ms p95, inside the noise of 3 repeats). Bitrate with it off: typing -24 % (0.35 vs 0.46 Mbit/s, tiny in absolute terms), drag -8 %, video -9 %, scroll +9 % (the earlier +15 to 25 % claim for scroll is not reproduced). **Decision unchanged: keep intra refresh on**; it costs at most about 10 % bitrate outside typing. Its benefit (no keyframe bursts after loss or late join) still needs a lossy-link run.
- **VBV of 4 frames costs no latency** (p95 equal or 1 to 3 ms lower: scroll 12.5 vs 13.9, drag 10.5 vs 11.7, video 13.4 vs 16.5, server CPU equal or lower) but raises the bitrate by 17 % (drag), 25 % (video) and 139 % (scroll, 1.23 to 2.94 Mbit/s), because large-change frames are no longer squeezed. Given 10.7 this is the cheap knob to improve transient quality; the absolute rates (3 to 8 Mbit/s) are far inside any broadband link. **Decision: make the VBV size a tunable and default hx-codec to 2 to 4 frames of the current rate instead of 1 (provisional)**, then re-measure the worst-frame quality with a dedicated test. The congestion controller still sees queueing the same way because it uses ack delay, not the encoder's VBV.

### 10.9 Reproduce

On the VPS (Incus and `hxbr0` as the S3 spike left them): `scripts/vps-setup.sh` (creates `s2-desktop` and `s2-client`), `scripts/vps-deploy.sh`, `incus exec s2-desktop -- start-desktop.sh`, then `scripts/vps-matrix.sh FID A1 A2 X V` (about 1.5 hours, resumable; sets are documented in the script). Config B: `scripts/vps-ctl.sh proxy-add 47433` on the VPS, then `scripts/wan-matrix.sh <host>` from the client machine (ssh key access; needs the local `target/release/s2-client`), then `proxy-del`. Tables: `scripts/analyze_vps.py <substring>`; fidelity: copy the `FID_*` results back and run `scripts/fidelity_report.py <work-dir>` (needs Pillow and `target/release/s2-fidelity`). Checks in the crate: `cargo build --release`, `cargo clippy --release -- -D warnings`, `cargo test --release`.

On the VPS (kernel 7.0, Incus 6.0.5, AppArmor) processes started by one `incus exec` session cannot be signalled from another, from the container's own root or from systemd inside it (`kill` gives "Permission denied"; the host denies ptrace/signal across the stacked profile). The harness therefore kills the spike's processes from the host (`scripts/vps-kill.sh`, restricted to the `s2-*` containers' cgroups and a short list of process names). This is a deployment note for the product's session management: do not depend on `pkill` from an exec session to stop a streaming server in a container.

### 10.10 Decisions changed, risks and what remains open

Decision changes:

1. **Relaxed pacing is confirmed as required, not optional**: it moves video from 26.7 to 16.5 ms p95 and drag from 25.4 to 11.7 ms at the same CPU. The 60 fps grid of the first spike passes too (21 to 27 ms), so pacing is now a quality knob, not the thing keeping S2 passing.
2. **Always tag the H.264 stream with the BT.709 limited-range VUI** (new, 10.7).
3. **VBV: from a fixed one-frame buffer to a tunable, provisional default of 2 to 4 frames** (10.8), pending the worst-frame test.
4. Unchanged: x264 ultrafast/zerolatency, 4 sliced threads, intra refresh on, frame-per-stream, threading model, sender-side congestion controller.
5. The criteria-level wording of section 6 ("PASS, thin margin, conditional") becomes **PASS**; the "UNVERIFIED" pixel item becomes **PASS with the two findings above**.

Risks and open items:

1. **Transient blur after large changes** (scroll reversal, window drag start): one to a few frames at 15 to 24 dB. Not solved by a 4-frame VBV alone. Needs (a) a per-frame QP/size investigation, (b) a refinement frame after a short quiet period (already risk 5 of section 9), and a check whether it is visible at the real 60 fps presentation, since each such frame lasts under 20 ms. Section 9 risk 6 is closed for colour, open for this.
2. **Not re-measured on the VPS**: the netem profiles (`rtt150-loss`, `mobile`) and with them the jitter-adaptive-threshold item (not implemented, as instructed). The `mobile` finding (risk 2 of section 9) stands unmeasured on the VPS, and the lossy-link value of intra refresh is still unquantified.
3. **Real-internet numbers come from one path** (14.4 ms RTT, a residential or office client machine to this VPS) and one client machine that was itself loaded; the clock offset is uncertain by +/- 7 ms (10.5). A longer path, packet loss and a Wi-Fi last hop are untested. Only the 8 ms one-way share is path-specific; the other 8 to 10 ms is processing.
4. **Presentation, input path and GPU decode are still out of scope**: totals exclude presentation (0 to 8 ms) and the input round trip; software decode on the client was 1 to 5 ms.
5. **Content realism**: scripted xdotool input, a synthetic video clip, a software X server (dummy driver). The mean fidelity numbers for video are specific to `testsrc2`.
6. **Host-side deployment note** (10.9): AppArmor on kernel 7.0 blocks cross-session signals in Incus containers; the installer and the session manager must manage the streaming process through the container's init (systemd) or the exec session that started it.
7. **Scale**: one desktop, one client; 4 vCPU with the client on the same host (A1) and a pinned 3+1 split (A2) agree, but nothing was measured with two simultaneous streams.
