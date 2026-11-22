# Testing: end to end under netem, and the performance suite

How the streaming path is tested end to end under real network impairment, how it is benchmarked, what the thresholds are and why, and how a maintainer registers the machine that runs the performance suite. The layers of the whole test strategy are in [architecture.md](architecture.md) section 12; the targets are in section 10.

## 1. Where each kind of test lives

| What | Where | How to run |
|---|---|---|
| Unit and property tests | each crate | `cargo nextest run --workspace` |
| Relay, gateway and session on one X server | `apps/hx-agent/tests/relay_e2e.rs` | runs with the workspace (needs Xvfb) |
| The whole stack on a real Incus desktop | `apps/hx-agent/tests/e2e_real_incus.rs` | `HX_E2E_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-agent --run-ignored only --test e2e_real_incus --no-capture'` |
| The installer on VMs and in a nested Incus | `.github/workflows/installer-vm.yml`, `apps/hx-agent/tests/install_nested_incus.rs` | see `docs/spikes/1e-installer-nested-incus.md` |
| **Streaming end to end under netem profiles** | `apps/hx-agent/tests/e2e_netem.rs`, `perf_common/` | section 2 |
| **Performance suite** | `crates/*/benches`, `apps/hx-session/benches`, the `perf_macro_lan` test, `perf/` | section 3 |

## 2. End to end under netem

### 2.1 What it does

For each network profile the test builds a network, applies the profile, **measures that the profile is real**, and then runs the complete client flow against the real server binaries:

```text
controller (the test, host namespaces)
  unshare -rn -> orchestrator (server namespace 10.77.0.1)
                   Xvfb + "desk" (an X client that paints marks for each input event)
                   hx-session   (the real binary; its link socket is passed as fd 3, as systemd does)
                   hx-gatewayd  (the real binary, seccomp enforce, listening on the veth address)
                   a fake privd (pepper and desktop state)
                   |  veth hxs0 <==== netem on both ends ====> hxc0
                   nsenter -n -> client (client namespace 10.77.0.2)
                                 pair -> PIN login -> view -> type -> scroll -> idle
                                 -> F12 (picture check) -> disconnect -> reconnect
```

* **Install.** The stack is assembled the way the installer leaves it: the gateway runs from a `gatewayd.toml` with an identity credential file, a state directory and a privd socket, and the session gets its socket by activation. The installer itself is tested by the installer suites of section 1; creating a real Incus desktop by `e2e_real_incus`. This test does not start Incus, so it can run unprivileged on any CI runner.
* **Pair and connect.** A pairing code from the gateway's admin socket, `hx_crypto::pair_device`, a PIN verifier set through the admin socket, `connect_with_pin`, a `ViewConfig` (H.264, 60 fps), the first IDR.
* **Type and scroll.** 60 key presses at 12 Hz and 80 wheel notches at 20 Hz are sent over the protocol, injected by `hx-session` through XTEST, and reacted to by the desk. The desk paints a black cursor block for each key and a bar code of the notch counter for each scroll step.
* **Disconnect and reconnect.** The client closes with `NoError`, then logs in again and must decode a fresh stream.

### 2.2 The netem method, and why it is not the S2 one

S2 found that `tc netem` on the container interface shaped nothing, because the Incus proxy device re-sends the traffic over loopback inside the container. Here the impaired link is a **veth pair between two network namespaces of one user namespace**:

* `unshare -rn` gives root inside a user namespace that owns its network namespace, so `ip`, `tc` and `nsenter` work with no host privilege and no change to the host's network, firewall or sysctls (the namespaces vanish with their last process). The server namespace creates the client namespace with `unshare -n` (same user namespace), moves one end of a veth into it and puts `tc qdisc ... netem` on **both** ends, each direction getting half of the delay and jitter and the full loss percentage.
* The client process runs inside the client namespace, so its packets must cross the veth and both qdiscs: there is no loopback shortcut.

**Evidence that the impairment applied** is measured by every run before the flow starts (`perf_common/net.rs`, `Net::control`) and is a failure condition:

1. an unimpaired baseline `ping` on the same veth (about 0.07 to 0.12 ms, no loss);
2. with the profile applied: ping RTT min/avg/max/mdev against the profile's RTT, ping loss (a loss profile must lose pings, and `tc -s qdisc` must show `dropped N`), jitter (mdev), and for rate-limited profiles the UDP throughput that crosses a one-second flood;
3. the transport's own RTT, measured by the connection after login (`Connection::ping`), is recorded in the result.

Measured on this development host:

| Profile | RTT configured | Ping min/avg/max/mdev (ms) | Ping loss | netem drops | UDP flood through |
|---|---|---|---|---|---|
| unimpaired veth | none | 0.07 avg | 0 % | 0 | n/a |
| lan | 1 ms | 1.08 / 1.23 / 3.45 / 0.32 | 0 % | 0 | n/a |
| broadband | 20 ms, 50 Mbit | 20.11 / 20.26 / 21.30 / 0.24 | 0 % | 869 025 (flood) | 38.0 Mbit/s |
| lossy | 40 ms, 1.5 % each way | 40.07 / 40.34 / 42.57 / 0.41 | 2.5 % (390 of 400) | 4 | n/a |
| mobile | 80 ms, +-10 ms jitter, 10 Mbit | 62.79 / 80.14 / 98.14 / 8.11 | 0 % | 1 043 854 (flood) | 8.0 Mbit/s |

(The UDP figure is delivered bytes over the 1.5 s flood plus a 0.5 s drain, so it reads about 76 to 80 % of the configured rate by construction; the check accepts 40 % to 130 %.)

### 2.3 Profiles

| Profile | RTT | Jitter | Loss | Rate | Meaning |
|---|---|---|---|---|---|
| `lan` | 1 ms | 0 | 0 | unlimited | the Gate 1 conditions |
| `broadband` | 20 ms | 0 | 0 | 50 Mbit/s | a good home or office link |
| `lossy` | 40 ms | 0 | 1.5 % per direction | unlimited | a congested or wireless link |
| `mobile` | 80 ms | +-10 ms per direction (reorders) | 0 | 10 Mbit/s, a 150-packet queue | a phone on LTE |

The rate profiles use a 150-packet queue (about 180 ms at 10 Mbit/s), not netem's 1000-packet default, so the bufferbloat is that of a router and not of a test rig.

### 2.4 What it measures

Per phase (typing, scrolling, idle): frames, key frames, video bytes, bytes through the client's interface (all protocol overhead), the longest gap between two frames, decode failures, and the CPU of `hx-session` and `hx-gatewayd` read from `/proc/<pid>/stat` over exactly the phase window (the client prints phase markers that the orchestrator timestamps). **Added latency per input event** is *mark and detect*, the S2 method moved to the input: the client records `t0` before sending event `i`; the desk paints a mark that identifies `i`; the client decodes every frame with FFmpeg and records the time of the first decoded picture that shows mark `i`. That includes the whole path (the network both ways, injection, the application's repaint, damage, capture, conversion, x264, the relay, the transport and the decode), so it is larger than S2's damage-to-decode figure by the input half of the trip. Presentation is excluded, as in S2.

**Decoded correctness.** After the idle phase the client sends F12; the desk writes its window as black and white pixels; the client compares the last decoded picture with it (the share of pixels on the wrong side of the midpoint between the two decoded luma levels, which does not depend on the decoder's colour range). A 720p picture measures 0.000 %, a 1080p one about 0.45 % (the 2 px strokes are coded at crf 23); a picture one scrolled line behind measures about 1.5 % and a corrupt one 2 % and more; the bound is 1 %.

### 2.5 Thresholds

Defined in `perf_common/result.rs` (`limits_for`, `evaluate`) and unit-tested there.

| Check | lan | broadband | lossy | mobile | Why |
|---|---|---|---|---|---|
| input-to-picture latency p95 | **40 ms** (Gate 1); 160 ms on a loaded host or without `HX_PERF_STRICT=1` (x4 again for a debug build) | RTT + 120 ms | 4 x RTT + 600 ms | 4 x RTT + 600 ms | Gate 1 is a LAN number. The others are bounds that separate "slow" from "stalled": the network, the pipeline, and one or two retransmission rounds |
| every input event shows up on screen | all | all | all | all | a lost event or a stuck picture |
| cores (session + gateway) while typing or scrolling | **1.5** (Gate 1), doubled for a debug build | same | same | same | the CPU budget does not depend on the network |
| idle cores | **0.05** (about 0), doubled for a debug build | same | same | same | Gate 1: idle is about 0 |
| idle bytes per second through the interface | **2 048** | same | same | same | Gate 1: idle is about 0 bandwidth (keep-alives only; measured 55 to 95 B/s) |
| longest gap between frames while active | 1 s | 2.5 s | 2.5 s | 2.5 s | "no stall" |
| first decoded frame after `ViewConfig` | 15 s | 20 s | 20 s | 20 s | start-up sanity |
| picture matches the desktop | < 1 % wrong | same | same | same | decoded correctness, also after loss |
| clean disconnect, decodable frame after reconnect | yes | yes | yes | yes | the end of the flow |
| the netem control | passes | passes | passes | passes | the impairment is real |

The strict latency number is applied only when the run asks for it (`HX_PERF_STRICT=1`, which the performance runner sets) **and** the host is quiet. A development host with a load average above half its CPUs marks the run `noisy`; the number is then reported and held to 4 x. Numbers from such a host are an upper bound, never a baseline.

### 2.6 Running it

Needs `unshare`, `nsenter`, `ip`, `tc` (iproute2), `ping` (iputils), Xvfb, the FFmpeg and x264 libraries used by the workspace, and unprivileged user namespaces. On Ubuntu 24.04 an AppArmor sysctl restricts them (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`; the CI workflow does this on its throwaway VM). Nothing runs as root and nothing touches the host's network.

```sh
# the impairment alone (about 1 minute), then the whole flow (about 45 s per profile)
export HX_E2E_NETEM=1 HX_REQUIRE_XVFB=1
cargo nextest run -p hx-agent --run-ignored only --test e2e_netem --no-capture \
    -E 'test(netem_control_proves_the_impairment_applies)'
cargo nextest run --release -p hx-agent --run-ignored only --test e2e_netem --no-capture \
    -E 'test(netem_e2e_over_all_profiles)'
```

Useful variables: `HX_NETEM_PROFILES=lan,lossy` (a subset), `HX_NETEM_OUT=<dir>` (one JSON per profile), `HX_PERF_RES=1920x1080` (default 1280x720), `HX_NETEM_LOGS=1` and `HX_NETEM_GW_LOG=debug` (the gateway and session logs after the run), `HX_PERF_KEYS`, `HX_PERF_SCROLL_TICKS`, `HX_PERF_IDLE_S`. The pure parts (thresholds, parsers, mark geometry) are ordinary unit tests and run with the workspace.

In CI, `.github/workflows/e2e-netem.yml` runs both tests on every change to the streaming path on a hosted runner (a release build on a shared machine: the functional thresholds, not the strict ones). A debug build (the default of the commands above without `--release`) is for a quick functional check: its CPU limits are doubled and its latency bounds are four times as wide.

### 2.7 Results

One run per profile, release build, 1280x720, on the shared development host (load average 12 to 17 on 16 CPUs while it ran, so **noisy**: an upper bound for the latency, not a baseline). Latency is input to decoded picture, p95; cores are `hx-session` + `hx-gatewayd`.

| Profile | typing p95 | scroll p95 | typing / scroll cores | idle cores, bytes/s | pair, login, first frame | picture |
|---|---|---|---|---|---|---|
| lan | 18.1 ms | 15.5 ms | 0.11 / 0.20 | 0.019, 64 | 111, 52, 40 ms | 0.000 % wrong |
| broadband | 32.9 ms | 30.8 ms | 0.12 / 0.17 | 0.019, 93 | 317, 123, 61 ms | 0.000 % |
| mobile | 107.1 ms | 114.0 ms | 0.13 / 0.23 | 0.018, 55 | 914, 399, 141 ms | 0.000 % |
| lossy | 52 to 110 ms | 74 ms to 1.1 s | 0.11 / 0.2 | 0.02, 65 to 230 | 508, 246, 109 ms | 0.000 % (was failing in most runs, see 2.8) |

The LAN profile meets the Gate 1 numbers even on this loaded host (p95 under 40 ms, 0.20 cores, idle 0.02 cores and 64 bytes a second). At 1080p (the macro run, 5 runs, load average 29) the median p95 is 63 ms typing and 92 ms scrolling: the host, not the code, is the limit there, which is why such numbers are never used as a baseline.

### 2.8 The lossy defect (found by this suite, fixed)

With 1.5 % loss in each direction at 40 ms RTT the flow used to end with a corrupt picture in most runs (4 of 5, then 3 of 5 failed the picture check), and sometimes marks never appeared. The test client was right (it follows protocol section 6) and the server's statistics were clean (0 dropped frames): two independent causes, found by logging every frame at each layer.

1. **A starved key frame was never refined (the grey picture).** The ffmpeg program decoding `stream.h264` gave the same grey picture, and every key frame carried an IDR slice, so the bytes were what the encoder made: the key frame itself decodes to flat grey. An IDR requested while the VBV buffer is empty (a scroll of dense text, the ladder at 2 Mbit/s) was 2 to 4 KB at QP 55 to 64 (the S2 "known quality gap", here at its worst), and the display then stopped changing, so no further frame was captured and the client kept that picture. Decoding each IDR of the dump alone shows it; the lossy flow makes several IDRs per run, the LAN flow only the first one (a blank screen). A codec test pins the mechanism (a starved IDR is far from the screen, and repeating the unchanged picture refines it) and a pipeline test the cure.
2. **A late frame was skipped instead of waited for (the loop that fed it).** Frame streams are reliable, but the reorder window held a late frame for 10 ms: any retransmission (one to three round trips, 40 to 150 ms here) made the window release past it, the late frame arrived to be dropped as stale, the decoder skipped a frame, the client asked for a key frame, and the key frame (the biggest frame) was itself overtaken by the small frames behind it: more gaps, more key frames (the encoder log showed IDRs ten frames apart). Typical run before: 2 to 3 gaps in each phase. After: none.

Fixes: `hx-session::refine` (refinement frames of the unchanged screen after a frame the rate control starved, QP from `hx-codec`), the reorder window default of 32 frames and 250 ms (protocol 6.1), and a client that repeats `request_keyframe` while it waits for a key frame (a request or its answer can be lost; the test client asked once). Not a protocol change: the wire format and the window rules are unchanged, only the client's default sizes and its duty to repeat.

Evidence, lossy profile, release build, loaded host (load 15 to 50 on 16 CPUs), picture check strict:

| | before | after |
|---|---|---|
| runs passing | 3 of 6 on the unmodified branch (4 of 5 failing in the earlier report), 2 of 6 with a first refinement version | 12 of 12 (6 and 5 lossy-only runs and the lossy leg of the all-profile run) |
| frame gaps per run | 2 to 5 | 0 in every run of the last 11 |
| picture | 2 to 62 % wrong | 0.000 % wrong |

Ablation (refinement fixed, reorder hold put back to 10 ms): 4 of 5 passed and one showed 51 % wrong, with 1 to 3 gaps per phase, so both fixes are kept. Regression tests that fail without them: `hx-codec` `tests/encode.rs` `a_starved_key_frame_is_refined_by_repeating_the_unchanged_picture`; `hx-session` `tests/pipeline.rs` `a_starved_key_frame_is_followed_by_refinement_frames_of_the_static_screen` (0 refinement frames before) and `src/refine.rs` unit tests; `hx-transport` `tests/channels.rs` `video_late_frame_is_waited_for` (both transports; the late frame was dropped before). Reproduce a failure, if one ever returns:

```sh
HX_NETEM_LOGS=1 HX_NETEM_OUT=/tmp/hx-netem HX_E2E_NETEM=1 HX_REQUIRE_XVFB=1 HX_NETEM_PROFILES=lossy \
  cargo nextest run --release -p hx-agent --run-ignored only --test e2e_netem --no-capture \
  -E 'test(netem_e2e_over_all_profiles)'
# on a mismatch: /tmp/hx-netem/mismatch-decoded.pgm and mismatch-desk.pgm (what was decoded and what the
# desk drew) and stream.h264 (the bytes handed to the decoder; decode each IDR alone to see its quality)
```

Build `hx-session` as well as the test (`cargo build --release -p hx-session --bins`): the end-to-end test starts the binary next to the gateway and `cargo nextest run -p hx-agent` does not rebuild it. `e2e-netem.yml` runs lossy as its own step, and it fails the job.

### 2.9 What it does not cover

Incus and a real XFCE desktop (see `e2e_real_incus`); the installer (see the installer suites); window drag and video scenarios of S2 (the macro run can be extended with them); audio, clipboard and files (see `relay_e2e`); kernel segmentation offload of a real NIC (a veth passes large segments through netem, which splits them only for loss).

The macro run and the thresholds treat a development host as noisy; do not tune thresholds to its numbers.

## 3. Performance suite

### 3.1 Parts

1. **Microbenchmarks** (`criterion`, default features off): `hx-proto` (media header encode and decode, control framing of an input event and of a ping, mouse datagram encode, decode and coalescing), `hx-ipc` (the link frame path the relay forwards through: read and parse a video frame of 512 B, 16 KiB and 256 KiB, encode its prefix, the frame feedback message), `hx-codec` (BGRX to YUV conversion at 1080p, the x264 P-frame encode of a typing and of a scrolling change, the buffer pool) and `hx-session` (`capture_to_encode`: a rectangle painted on Xvfb until the pipeline delivers the encoded frame; skipped without Xvfb).
2. **The macro run**: the LAN flow of section 2, `HX_PERF_RUNS` times (default 5) at 1920x1080, release build, aggregated into one JSON file (`target/tmp/perf-macro.json`). Latency and CPU metrics are the median over the runs of each run's p95 or cores, with the worst run kept next to them.
3. **The regression check**: `perf/check.py` compares the macro file and the criterion results with the committed `perf/baseline.json`.

```sh
perf/run.sh                          # everything, Gate 1 gates (timing gates are warnings on a noisy host)
perf/run.sh --mode regression --strict   # what the runner does: also against the recorded baseline
perf/run.sh --update --reference     # record a new baseline (on the runner only)
perf/run.sh --micro-only             # or --macro-only
python3 -I perf/test_check.py        # the checker's own tests
```

### 3.2 Baseline and thresholds

`perf/baseline.json` holds, per metric, two kinds of limit:

* **Gates**: absolute, always checked. The macro gates are the Gate 1 numbers: added latency p95 40 ms (typing and scrolling), 1.5 cores while typing or scrolling, idle 0.05 cores and 2 048 bytes/s, picture mismatch under 1 %, first frame under 5 s. The micro budgets (`max_ns`) are about 20 times what a quiet machine measures: they catch an algorithmic regression, not noise.
* **Regression limits**: `baseline` plus `regress_pct` (and an absolute `slack` so that tiny numbers do not trip on noise): 25 % on latency, 30 % on CPU and on the microbenchmarks. They are checked only with `--mode regression` and only when the file says `"reference": true`, i.e. it was recorded on the dedicated runner. The file in the repository was recorded on a loaded development host and is `"reference": false`: its numbers document what the suite produced, and are not used for relative checks. **The first run on the runner records the reference** (`perf/run.sh --update --reference`, then commit the file).

A noisy host or a debug build cannot prove a timing gate, so such results report the timing gates as warnings unless `--strict`; the runner always passes `--strict`.

The committed baseline was recorded on the shared development host (16 CPUs, load average 29, release build, 1080p, 5 runs; `recorded.noisy: true`, `reference: false`): median p95 latency typing 63.4 ms and scrolling 92.2 ms (worst run 98.8 and 107.7 ms), typing 0.24 cores, scrolling 0.43 cores (worst 0.57), idle 0.023 cores and 199 bytes/s, first frame 177 ms, picture mismatch at most 0.47 %. The latency figures are far above the Gate 1 gate **because of the host's load**, which is why timing gates are warnings there; the CPU and idle figures are well inside the gates even so. The microbenchmark numbers (media header encode 19 ns and decode 4 ns, a 16 KiB link frame read and parsed in 0.8 us, a 1080p BGRX to I420 conversion 9 ms, an x264 P-frame encode of a 1080p change 23 ms, damage to encoded frame on Xvfb at 720p 15 ms) were taken with short criterion settings on the same host.

The rationale for each number:

* Latency 40 ms and the CPU numbers are Gate 1 of [execution-phase.md](execution-phase.md); they come from the S2 budget (architecture section 10).
* 25 % and 30 % are wider than the run-to-run spread S2 saw on a quiet VPS (3 repeats within about 10 to 20 %) and narrower than any change worth a review.
* The median of 5 runs is used because the tail of one run is a property of the host's scheduler; the worst run is recorded for inspection.

## 4. The performance runner

The performance workflow (`.github/workflows/perf.yml`) targets `runs-on: [self-hosted, hx-perf]`, on `workflow_dispatch` and a nightly schedule. **It is inactive until a runner with the label `hx-perf` is registered and the repository variable `HX_PERF_RUNNER` is set to `true`**: the job carries `if: vars.HX_PERF_RUNNER == 'true'`, so a schedule produces a skipped job instead of one that waits for a runner that does not exist. Until then run `perf/run.sh` on demand.

### 4.1 Machine requirements

* **Dedicated and quiet**: nothing else runs on it (no Docker workloads, no other runner, no builds); the workflow's first step refuses to run while the 1-minute load average is above 0.5 (waiting up to 15 minutes). A VM on a shared host is acceptable only if its CPU is not oversubscribed (steal time near 0).
* **Hardware like the target**: 4 vCPU, 8 GB RAM, 20 GB free disk, no GPU (Gate 1 is stated for a 4 vCPU server without a GPU). A fixed CPU frequency policy (`performance` governor or a VM without frequency scaling).
* **OS**: Ubuntu 24.04 (the supported host). Packages: `build-essential clang libclang-dev pkg-config libavcodec-dev libavformat-dev libavutil-dev libswresample-dev libswscale-dev libx264-dev xvfb iproute2 iputils-ping util-linux python3 git curl`.
* **Unprivileged user namespaces** for the runner's user: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, persisted in `/etc/sysctl.d/`. The suite itself never uses root, never touches the host's network or firewall, and creates only namespaces that vanish with its processes.
* A non-root user (for example `hxperf`) that owns the runner and a persistent `target/` directory (the build cache is the runner's work directory, so repeated runs are fast), with Rust installed through rustup (the workflow runs `rustup toolchain install` for the pinned toolchain) and outbound HTTPS to crates.io, GitHub and the Ubuntu mirrors.

### 4.2 Registering a machine (for example the VPS)

1. Make the machine meet section 4.1; stop other services on it.
2. In the repository: **Settings, Actions, Runners, New self-hosted runner**, Linux x64. Follow the commands shown there as the unprivileged user, and when running `./config.sh` pass the label and a dedicated group: `./config.sh --url https://github.com/Omakidx/hash-xcreen --token <the token shown> --labels hx-perf --name hx-perf-1 --work /home/hxperf/_work`. (The registration token is single-use; never put it in a file in the repository.)
3. Install it as a service so that it survives reboots: `sudo ./svc.sh install hxperf && sudo ./svc.sh start`.
4. Restrict what runs on it: **Settings, Actions, General, Fork pull request workflows**: require approval, and keep the runner out of any runner group that public forks can use. The performance workflow only runs from `workflow_dispatch` and the schedule on the default branch, never from pull requests.
5. Set the repository variable: **Settings, Secrets and variables, Actions, Variables**: `HX_PERF_RUNNER` = `true`.
6. Record the reference. On the runner, in a checkout of `main`, as the runner's user and with the machine quiet (`sh perf/quiet.sh`): `perf/run.sh --update --reference`. Review the diff of `perf/baseline.json` (it must say `reference: true`, `noisy: false`, `release_build: true`, and the macro numbers must be inside the Gate 1 gates), commit it on a `chore/` branch and merge it. From then on the nightly run checks regressions against it; re-record after a deliberate performance change or a change of hardware.
7. To deactivate: set `HX_PERF_RUNNER` to anything else, or remove the runner.
