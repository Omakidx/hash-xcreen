# Spike S4: backup round trip

Status: done against a LOCAL repository (sections 1 to 9) and, on 2026-11-20, against REAL Google Drive with scope `drive.file` (section 10). Sections 6 to 8 are the original local-run text, kept as written; where section 10 settles or changes one of their "UNVERIFIED" items, the section 10 verdict wins.
Code: `spikes/s4-backup-roundtrip/` (standalone crate, not in the root workspace).

## 1. Goal

Prove that a full desktop container can be snapshotted, backed up with `rustic_core` (deduplicated, zstd, encrypted), backed up again incrementally after a simulated day of use, resumed after an interruption, and restored into a fresh container that boots with everything intact (Claude Code and Codex data, live SQLite databases). Decide: OpenDAL vs rclone backend, exclude defaults, compression level.

## 2. Setup

| Item | Value |
|---|---|
| Crates | `rustic_core 0.14.0` (feature `clap` only to reach a private enum), `rustic_backend 0.8.0` (feature `opendal`), `opendal 0.59.5`, `proptest 1` |
| Toolchain / host | Rust 1.100.0, Ubuntu 24.04 VM, 16 cores, Incus 6.0.0, btrfs pool. Other agents kept `loadavg` at 12 to 44 during every timing below, so wall times are pessimistic and noisy |
| Source desktop | `s4-desktop`, Ubuntu 24.04, xfce4 + dummy Xorg, user `alice` (uid 1001), 1068 packages, XFCE session running during every snapshot. After the seed the backed-up tree is 2.24 GB in 70,571 files |
| Seed data | `seed-desktop.sh`: Claude Code (`~/.claude/projects/*/*.jsonl`, settings, `.claude.json`, `.credentials.json`), Codex (`sessions`, `auth.json`), Electron app dir with `Local Storage`, `IndexedDB`, `Session Storage` and `Cache`, `Code Cache`, `GPUCache`, `DawnCache`; a `chromium` profile with SQLite DBs and caches; `~/.cache` junk; `special/` with ACL, xattr, hard link, symlinks, fifo, setuid root file, sticky dir, 50 MB sparse file, file capability on `/usr/local/bin/s4-ping`; a SQLite WAL database written ~1000 rows/s by a live process during every snapshot. All credentials are dummy values |

### Snapshot access without host sudo, and why

The brief proposed copying the snapshot to a temporary container. I used a closer match to production: the Incus daemon (reachable through the `incus-admin` group, no sudo) bind-mounts the real btrfs snapshot read-only into a helper container `s4-worker`:

```
incus snapshot create s4-desktop s4-bk-<ts>
incus config device add s4-worker src disk readonly=true shift=true \
   source=/var/lib/incus/storage-pools/default/containers-snapshots/s4-desktop/s4-bk-<ts> path=/src
# worker runs: s4 backup --source /src/rootfs   (root of the worker's user namespace)
incus config device remove s4-worker src; incus snapshot delete s4-desktop s4-bk-<ts>
```

`shift=true` produces an idmapped mount, so the worker sees the same in-container uids/gids (alice is 1001, files owned by root:daemon stay 0:1) and, being root in the same id range, can read every file, xattr and ACL. The repository is a host directory mounted into the worker (`shift=true`, writable). Restore is the mirror image: `incus init --empty s4-restored`, mount `.../containers/s4-restored` into the worker as `/target`, restore into `/target/rootfs`, recreate the excluded mount points, start. No file is copied through a second filesystem, and no step needed host root.

Production difference: `hx-privd` (root) performs the snapshot and the read-only mount itself and starts the sandboxed worker (bubblewrap or similar) with the mount and a repository credential only. In the spike the worker container is the sandbox, and the repository is a local directory rather than Drive. Everything the worker did (read the tree, preserve ownership) is the same operation hx-privd would grant it.

`s4ctl.sh` is the host driver, `treesum.py` and `compare.py` do the tree verification, `interrupt-test.sh`, `torn-pack.sh`, `corrupt-pack.sh`, `restore-resume-test.sh` are the failure experiments.

## 3. Results

### 3.1 Full backup and compression level (one snapshot, four repositories)

2,235,316,470 bytes processed, 70,571 files, 53 excluded paths. Seed data is about half incompressible random bytes (caches, blobs) and half text, so real desktops should compress somewhat better than this.

| zstd level | wall | CPU (user+sys) | repository size | ratio |
|---|---|---|---|---|
| 0 (none) | 31 s | 65 s | 2,186.6 MB | 0.98 |
| 1 | 51 s | 111 s | 950.6 MB | 0.43 |
| 3 | 46 s | 117 s | 905.9 MB | 0.41 |
| 9 | 73 s | 200 s | 869.7 MB | 0.39 |

Level 3 to 9 saves 4% for about 70% more CPU. An earlier level 3 run on the same data gave 881 MB in 30 s at lower load. Snapshot creation took 0.26 to 0.44 s.

### 3.2 Simulated day (second backup)

New packages (htop, ncdu, gimp-data), 40 new files, appended chat histories, a new Claude session, SQLite churn, browser profile churn, cache rotation (about 170 MB of it in excluded paths). 4,414 new files, 430 changed, 70,131 unmodified.

| zstd level | bytes added to repository | wall |
|---|---|---|
| 0 | 208.3 MB | 16.6 s |
| 1 | 100.1 MB | 13.4 s |
| 3 | 97.7 MB | 17.4 s |
| 9 | 96.7 MB | 17.7 s |

Repository growth on disk matched within 1 MB. The typical increment is about 100 MB, a fifth of the 500 MB criterion. About 30 MB of it is a rotated browser-profile cache that the protected list forces into the backup (see 5).

### 3.3 Interruption and resume

A 3 GB new random data set was added, the backup was SIGKILLed in the worker, then retried from identical copies of the post-kill repository. Packs reach the repository as they fill, but the index is only written every 5 minutes or 50,000 blobs, so a killed run leaves unindexed orphan packs.

| Run | Stored before kill | Retry without `repair index` (A) | Retry with `repair index` first (B) |
|---|---|---|---|
| 1 (kill at 25 s, about 97% done) | 3,102 MB orphans | re-uploaded 3,196 MB (100%) | uploaded 138 MB |
| 2 (kill at 9 s, about 70% done) | 2,215 MB orphans | re-uploaded 3,165 MB (100%) | uploaded 992 MB (the missing part; about 40 MB wasted) |

So a naive rerun re-uploads everything and leaves the orphans as permanent garbage, because prune ignores packs not in the index. Running `repair index` (list packs, read headers of unknown ones, 0.2 s) before the backup makes the retry upload only what was missing. That is what `s4 backup` does by default.

Other findings:
- rustic_core 0.14 has no lock files (no `Lock` file type). "Stale repository locks" do not exist; hx-backup needs its own single-writer guard (flock or a state file) to enforce "never overlapping".
- The local backend writes packs in place (`create`, `set_len`, copy). A kill mid-write can leave a pack-named file with a zeroed tail. Simulated (`torn-pack.sh`): `repair index` logs a warning and skips it, `check` passes with a warning, and prune never removes it. It is harmless garbage but permanent on a local repo. Drive uploads are one request per object, so a torn object cannot appear there (UNVERIFIED).
- Leftover snapshot and device are cleaned by the shell `trap` here; in hx-privd this is the tagged-snapshot cleanup at start-up already in architecture 9.6.

### 3.4 Restore and verification

Restore of the day-2 snapshot (level 3) into `s4-restored`: 57,762 files, 2.39 GB, 27.8 s wall, 24 s CPU. Mount points `/proc /sys /dev /run /tmp /var/tmp` recreated afterwards (excluded, so absent from the repository). Container booted in 6 s.

| Check | Result |
|---|---|
| Tree comparison (`treesum.py`: path, type, mode, uid, gid, size, mtime ns, nlink, SHA-256, symlink target, all xattrs including POSIX ACL and `security.capability`) source snapshot vs restored | 81,065 entries, 0 missing, 0 different, 0 unexpected extra; the only extras are the six recreated mount points. 9 hard-link groups equal. RESULT: PASS |
| Ownership, permissions, special files | alice 1001, setuid `root:daemon` 4750, sticky 1777, fifo, ACL (`group:daemon:r--`), `user.s4.tag`, `cap_net_raw=ep` all identical |
| AI data | 11 Claude session files (10 seeded + 1 new), 3 Codex rollouts, settings, `.claude.json`, `.credentials.json` and `auth.json` (mode 600) identical by hash |
| Excluded caches | `.cache` (recreated empty by the session), Electron `Cache`, `Code Cache`, `GPUCache`, `DawnCache`, `/var/cache/apt` absent |
| SQLite (snapshot taken while the writer was running) | `PRAGMA integrity_check` = `ok`, 258,120 rows, WAL recovered. Four browser-profile DBs also `ok` |
| Boot | `systemctl is-system-running` = `running`, no failed units, XFCE session, `xfwm4`, `xfce4-panel` and Xorg (dummy, 1920x1080) up, lightdm started its own Xorg |
| Packages | `dpkg --audit` clean, 1068 packages, the day's `htop` and `ncdu` present; `apt-get update && apt-get install cowsay` works (apt recreates its excluded dirs) |

Observations that the restore flow must handle: the restored container keeps the source's hostname and `/etc/machine-id` (fine when it replaces the old desktop, a conflict if both run); the sparse 50 MB file restored fully allocated by default and as 512 KiB with `--sparse` (ByContent), so restore should always use it (matters for Docker and VM disk images).

Interrupted restore (architecture 9.8 step 2): killed after 10 s with 48,126 of about 57,700 files on disk; the rerun trusting size and mtime restored only the missing 9,636 files (140 MB of 2.39 GB); a `--verify` rerun then found nothing to do. Rerun prints noisy "creating special file failed" warnings for symlinks that already exist (harmless).

### 3.5 Retention, prune and verification

| Operation | Result |
|---|---|
| 12h policy (keep-last 14, weekly 4, monthly 6) on 400 synthetic snapshots (200 days) | 21 kept, 379 forgotten in 81 ms, prune plan 308 ms, prune 1.5 s |
| 24h policy (keep-last 2, daily 7, weekly 4, monthly 6) on 200 snapshots | 14 kept, 186 forgotten, prune 1.2 s |
| Guard: never delete the two newest snapshots | enforced in `retention`; first version without `keep-last 2` on the 24h policy tripped the guard when four snapshots fell on one day, hence `keep_last(2)` is part of the 24h policy |
| `check` (metadata) | 1.3 to 1.5 s |
| `check --read-data all` | 4.0 s (4.2 GB), 8.0 s (7.4 GB); local, page-cache warm |
| `check --read-data 5%` | 1.9 s |
| Corrupted pack (21 bytes flipped) | metadata `check` passes, `--read-data` fails: the monthly 5% sample is what finds bit rot |

The synthetic creation of snapshots took 0.8 s each, dominated by per-snapshot setup, irrelevant for production.

## 4. S4 criteria

| Criterion | Verdict | Reason |
|---|---|---|
| Restored desktop boots with everything intact | PASS (local repository) | 3.4. Dummy Claude/Codex logins and histories byte-identical, SQLite ok, XFCE/Xorg start. Real vendor CLIs were not installed (non-goal); only their data layout is simulated |
| Typical daily increment < 500 MB | PASS (synthetic) | About 98 MB at level 3. Depends on the synthetic day; real chat and project churn must be re-measured (see 7) |
| Interrupted upload resumes without re-uploading | PASS with a required step, FAIL without it | Only with `repair index` before the retry (3.3). Plain rerun re-uploads everything. Same result on real Drive (10.5) |
| Google Drive end to end | PASS with `drive.file` (section 10) | Full, incremental, killed-and-resumed, restore and verification all ran on real Drive. Two design changes follow: permanent deletes and a Drive-aware restore plan (10.6, 10.8) |

## 5. Exclude and protected-path design

Implemented in `src/rules.rs`. Excludes are exact absolute path patterns (`*` is one segment, e.g. `/home/*/.config/*/Code Cache`). At backup time they are resolved against the mounted snapshot into concrete paths, any path that is inside, equal to or an ancestor of a protected pattern is dropped, and the rest become literal ignore globs for rustic. Protected paths therefore cannot be excluded whatever the user-editable list says. Tests: unit tests plus a proptest (200 random trees and random exclude lists, default list on or off): no resolved exclude prunes a protected path or the credential files.

Findings for the design doc:
- Architecture 9.2 conflicts with itself: trash (`~/.local/share/Trash`) is excluded, but `~/.local/share/` is protected and protection wins, so Trash is kept. Same for Chromium-style caches inside a browser profile (`Default/Cache`, `Code Cache`, `GPUCache`, `Service Worker/CacheStorage`): protecting the whole profile backs them up (about 90 MB of seed cache and 30 MB of the daily increment). Recommendation: protect `~/.config/<browser>/Default/{Local Storage,IndexedDB,Session Storage,Cookies,Login Data,History,Preferences,Extensions,...}` rather than the whole profile, or make the protected list win only over user excludes and let the built-in cache list win inside browser profiles.
- `/var/log/*` globs and `/var/lib/apt/lists/*` were added to the default list; `/var/log/app/big.log` (a subdirectory) was correctly kept, as "exact paths only" intends.
- rustic's override glob engine cannot express "protected wins" (a whitelist glob would make every other file ignored), which is why resolution to concrete paths is done outside rustic.

## 6. Google Drive evaluation (before the Drive run: all UNVERIFIED, from code and docs; settled in section 10)

- Compiles and fits: `rustic_backend 0.8` with feature `opendal` enables OpenDAL's `gdrive` service. `s4 --repo opendal:gdrive --opt root=... drivecheck` builds a `RepositoryBackends` and a `Repository` with no network I/O, so the trait fit is proven at compile and construct level. The release binary is 43 MB because all OpenDAL services are linked; production should depend on `opendal`/`rustic_backend` selectively (the crate offers no per-service feature through rustic_backend, so a thin custom `ReadBackend`/`WriteBackend` over `opendal-service-gdrive` is an option).
- Auth: options `client_id`, `client_secret`, `refresh_token` (OpenDAL refreshes the access token itself, 120 s early, by POSTing to `oauth2.googleapis.com/token`), or a bare `access_token` that expires. OpenDAL does not run the OAuth flow; the PKCE desktop flow stays in hx. Its docs name scope `drive`. Whether `drive.file` suffices is UNVERIFIED: OpenDAL resolves paths by listing by name under a parent, which should work for folders the app created itself, but it must be tested.
- Uploads: `GdriveWriter` is a one-shot write: one `uploadType=multipart` request per object (`uploadType=media` for overwrite). There are no resumable sessions, so the resume granularity is one pack: a failed pack upload restarts from byte 0. With rustic's default pack sizes (tens of MB) that is acceptable, and content addressing plus `repair index` handles the rest; Google recommends resumable uploads above 5 MB, so large packs on flaky links are a risk. Setting `treepack`/pack size smaller is possible through repository config.
- Layout: rustic uses `data/<2 hex>/<id>`, so 256 subfolders plus `index`, `snapshots`, `keys`. Drive allows duplicate names; OpenDAL picks the newest match, which is a risk if two writers overlap. Path lookups cost list API calls (OpenDAL caches ids).
- Retries and rate limits: rustic wraps the operator in OpenDAL's `RetryLayer` (5 retries default, jitter, option `retry=N`), plus options `connections=N` (concurrency limit) and `throttle=bandwidth,burst`. In the gdrive service only 5xx, 405 and the exact message "User rate limit exceeded." are marked retryable. HTTP 429 and 403 `rateLimitExceeded`/`dailyLimitExceeded` are not, so the "pause until tomorrow at the 750 GB limit" and generic backoff behaviour in 9.6 need a wrapper around the backend (or an upstream fix).
- Fallback: rustic's `rclone` backend (spawns `rclone serve restic`) has mature Drive handling (resumable uploads, 429 backoff, token refresh from rclone config) but adds an external binary and a config file with the token.

## 7. DECISION

1. Backend: start with `rustic_backend` + OpenDAL `gdrive` behind a thin hx-owned wrapper that adds 429/403-rate-limit classification, exponential backoff with jitter, the daily-limit pause and `connections`/`throttle`. Keep rclone as the documented fallback; switch if the first real-Drive test (7 below) shows `drive.file` not working or large packs failing without resumable uploads. This decision was provisional until re-tested with real Drive; it was re-tested and is confirmed with changes (10.7).
2. Compression: zstd level 3 (rustic's default). Level 1 is no cheaper in practice, level 9 costs about 70% more CPU for 4%. Set at repository init; changing it later only affects new packs.
3. Exclude defaults: the list in `rules.rs` (virtual and scratch dirs, `/var/cache/apt`, apt lists, logs, `~/.cache`, Trash, npm and cargo caches, Electron `Cache`/`Code Cache`/`GPUCache`/`DawnCache`/`GrShaderCache`/`ShaderCache`, VS Code `CachedData`, Docker BuildKit), with protected paths resolved as in section 5, and the Trash and browser-profile-cache conflicts resolved as recommended there.
4. Mandatory operational rules: run `repair index` before every backup; always restore with sparse handling and numeric ids; recreate excluded mount points and fix hostname and machine-id after restore; own single-writer lock; weekly metadata `check`, monthly `check --read-data 5%`; retention as in 3.5 including `keep-last 2`.

## 8. Risks and follow-ups

- Re-test with real Drive (all UNVERIFIED): scope `drive.file` listing and creation, multipart upload of 32 MB+ packs on a slow uplink, behaviour on 429 and 403 limits, `repair index` after a killed upload, `check --read-data` download cost, per-run API call count, token revocation error mapping.
- Real Claude Code and Codex installs: confirm paths (`~/.claude`, `~/.codex`, and any state outside them such as `~/.config/claude` or keyring use) and that a restored login really works; a keyring-based credential store would not be in the files.
- Measure a real day of use; the 98 MB figure is synthetic. Browser profile caches are the largest unknown.
- Orphan garbage: packs from killed runs that `repair index` cannot read are never pruned; add an explicit cleanup (delete unindexed, unreadable packs older than N hours) or accept the garbage.
- Timing was taken under load 12 to 44 on a shared VM; relative ordering of levels is reliable, absolute times are not.
- Not covered: Docker data modes, restore onto a different server, XFCE session restore of open apps, encryption key handling (the spike uses a fixed password file; production follows 8.6), upload bandwidth capping against a real uplink, `drive.file` quota behaviour.
- Binary size (43 MB) and `rustic_core` API instability (0.x, private types such as `SparseRestore` not exported) argue for pinning versions.

## 9. Reproduce

```
cd spikes/s4-backup-roundtrip
cargo build --release && cargo clippy -- -D warnings && cargo test
# containers: s4-desktop (seed-desktop.sh install|seed|day|bulk), s4-worker (binary, treesum.py, repos mount)
./s4ctl.sh init L3 3
S4_SUM=full1 ./s4ctl.sh backup L3 --tag full
./s4ctl.sh restore L3 s4-restored <snapshot-id>      # then recreate mount points, ./verify-boot.sh s4-restored
```

## 10. Google Drive run (2026-11-20)

Scope `drive.file` only, a real Google account, one folder `hash-xcreen-spike-s4`. All numbers below were measured on real Drive. No credential value appears anywhere in this report, the repository, or the logs kept: the token file is read in-process, never printed, never copied into a container.

### 10.1 Verdicts for the items left UNVERIFIED in section 6

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 1 | `drive.file` suffices for OpenDAL's `gdrive` service | **PASS** | The stock path (`rustic_backend 0.8` + OpenDAL 0.59.5 `gdrive`, unchanged) ran `init` (root folder, 5 type folders, 256 `data/xx` folders, config, key), `backup`, `snapshots`, `ls`, `restore --sparse` (tree identical to the source with `diff -r`), `check` and `check --read-data all` without a single API error (timings: init 26 s, a 1.2 MB backup 20 s, restore 6.6 s, `check` 10 s). The same calls ran later through the hx wrapper (below). OpenDAL resolves paths by listing by name under a parent id, which `drive.file` allows for folders and files the same OAuth client created. OpenDAL's docs name scope `drive`; that is not needed |
| 2 | One multipart upload per pack, no resumable sessions | **PASS for packs up to about 60 MB; UNVERIFIED above and on slow links** | `GdriveWriter` sends one `uploadType=multipart` request per object (code read, and visible in the call counts: one `upload.create` per pack). 17 packs of about 35 MB (bulk data) and 35 packs averaging 29 MB (full backup) uploaded without a failure at 8 to 25 MB/s. A 60 MB multipart upload with a separate probe ran at 24.7 MB/s. A SIGKILL during an upload leaves no partial object on Drive: after the first kill the file list held only whole packs (12 packs of about 35 MB, no zero-length or short file), `repair index` read all 12 orphan headers, and a final `check --read-data all` passed. Not tested: packs of 128 MB or more, uplinks slower than a few MB/s (the wrapper assumes a minimum of 256 KiB/s: request timeout 60 s plus 4 s per MiB) |
| 3 | 429 and 403 rate limits need an hx wrapper | **CONFIRMED by code and by test; no real limit was ever hit** | OpenDAL marks only 5xx, 405 and the exact message "User rate limit exceeded." as retryable; `rustic_backend`'s OpenDAL glue additionally logs and drops listing errors. The wrapper (10.4) is covered by 14 unit tests plus fault-injected runs on real Drive. Real rate-limit replies were not seen in several thousand API calls (including 261 folder creations at 4 in parallel and a probe of 320 folder creations at 22 requests/s with 16 threads: all 200). A harder probe (48 threads) was declined by the session's permission system as a stress test of the real account, so the true 403/429 body formats are still UNVERIFIED; the injected bodies follow Google's documented format |
| 4 | `repair index` after a kill mid-upload on Drive | **PASS** | 10.5. After the kill, `repair index` found the 12 unindexed orphan packs, read their headers with ranged reads, and the retry uploaded only the missing data. Without it the retry re-uploaded everything it had produced |
| 5 | Download cost of `check --read-data` subsets | **PASS, measured** | 10.7: 5% of a 3.24 GB repository is 155 to 161 MB, 69 API calls, about 15 s; metadata-only `check` is 6.7 MB, 41 calls, 12 s |

New findings, not in section 6:

- **A delete on Drive is a move to the trash and does not free quota.** OpenDAL's gdrive deleter calls `files.update {trashed: true}`. After `forget` + `prune`, live bytes fell from 3,901 MB to 1,107 MB while 2,797 MB (89 files) sat in the trash and the account's `storageQuota.usage` did not drop (14,314.1 MB before, 14,317.0 MB after). Permanent deletion (`DELETE files/{id}`) works under `drive.file` for the app's own files (392 objects, all 204). `files.emptyTrash` was deliberately not used: it would delete the user's other trashed files. Architecture 9.6 "Drive full: prune oldest backups" therefore does not work as written until the backend deletes permanently (10.8).
- **A recursive delete of the top folder is refused** (`DELETE` of `hash-xcreen-spike-s4` returned 403 `appNotAuthorizedToChild` while it had children, even though every child was created by this app). Deleting leaves first, in folder order, worked. Any "disconnect and delete my backups" feature must delete children first (or only trash the folder, untested).
- **`prune` defaults keep removed packs for 23 hours** (rustic's marked-for-deletion period); `forget --prune` without `--instant` removed the snapshot and index but left the pack bytes on Drive. Space freeing is therefore delayed by a day even before the trash problem.
- **Call counts are dominated by path resolution.** Every object access lists a folder first (OpenDAL's `path_index` caches ids per process). A fresh `init` costs 534 calls (261 folder creates, 270 lists, 2 uploads), a full backup 230 calls for 35 uploads, an incremental 55 calls for 6 uploads, `repair index` on a clean repository about 3.5 s. Latency per call is 0.2 to 0.7 s, so many small operations are slow even though bytes are fast.
- **Restore time varied by 19x for the same snapshot** (10.6). Treat the tail of a restore from Drive as latency-bound and unpredictable until re-measured.

### 10.2 Method

| Item | Value |
|---|---|
| Binary | `s4` built from `spikes/s4-backup-roundtrip` (Rust 1.100.0). Stock path: `rustic_backend` with feature `opendal` (all OpenDAL services linked). hx path: own `HxDrive` backend over OpenDAL with only `services-gdrive` (+ `rest` client for the worker) |
| Credentials | `~/.config/hash-xcreen-spike/drive-token.json`, read in the host process only (`--drive-token-file`); output is piped through a masking filter in the helper scripts |
| Credential-free worker | The `s4-worker` container never held Google credentials. `s4 serve` runs on the host, speaks the restic REST protocol on the Incus bridge address with a random throw-away basic-auth password, and forwards to Drive through `HxDrive`. The worker backs up and restores with rustic's built-in `rest:` backend. This is the shape hx-privd gives the production worker (a repository handle, not a token) |
| Desktop, snapshot, restore | As in section 2: `s4-desktop` seeded with `seed-desktop.sh` (XFCE running), read-only idmapped snapshot mount into `s4-worker`, restore into `incus init --empty s4-restored`. The seed is regenerated per run, so sizes differ slightly from the local run (2.44 GB here, 2.24 GB there) |
| Drive accounting | Bytes and calls from `Stats` in the transport (per request category, status, bytes up and down, retries); Drive-side bytes from `drivectl.py usage` (files.list sizes and `about.storageQuota`) |
| Machine bandwidth to Google | `drivectl.py bw`: 20 MB probe: 11.6 and 9.1 MB/s up, 20.8 and 20.2 MB/s down; 60 MB probe: 24.7 MB/s up, 35.3 MB/s down (single stream). Multi-stream `check --read-data all` read 1,110 MB in 21 s (53 MB/s). The backup runs below were CPU-bound (the host was shared, load 3 to 6), not link-bound |
| Scaling to a home link | Times scale with bytes over the real uplink: at 20 Mbit/s up (2.5 MB/s) the 1.0 GB full backup is about 7 min of transfer, the 98 MB daily increment about 40 s, the 1.7 GB resumed upload about 11 min; at 100 Mbit/s down (12.5 MB/s) a 1.1 GB restore download is about 1.5 min |
| Binary size | 43,618,344 B (stock, all OpenDAL services) to 19,873,632 B (hx path: gdrive only, rest client), 54% smaller. `rustic_backend` has no per-service flag, so the saving comes from not enabling its `opendal` feature and depending on `opendal` directly |

### 10.3 Full backup and simulated day on Drive (zstd level 3)

| Run | Processed | New / changed / unmodified files | Added to repository (packed) | Uploaded (HTTP bytes) | Drive bytes after | Wall | API calls |
|---|---|---|---|---|---|---|---|
| Full | 2,439.6 MB, 70,575 files, 53 excluded paths | 70,575 / 0 / 0 | 1,003.9 MB (ratio 0.41) | 1,009.0 MB in 35 uploads | 1,008.9 MB in 37 files | 125.0 s for `backup` (153 s including snapshot, manifest, tree sums); repair index 3.5 s; CPU 57 s user + 19 s sys | 230 (185 list, 35 upload, 7 get.meta, 3 get.media) |
| Simulated day | 2,596.7 MB, 74,979 files | 4,414 / 433 / 70,132 | 97.5 MB | 98.0 MB in 6 uploads | 1,106.9 MB | 28.4 s (51.5 s including sums); repair index 3.5 s | 55 |

Local run for comparison: 906 MB full in 46 s, 97.7 MB day in 17.4 s. The full repository is 11% larger here only because the reseeded desktop differs; the increment (97.5 MB against 97.7 MB) matches. The 500 MB criterion has a 5x margin.

### 10.4 The retry and rate-limit wrapper

Code: `src/drive.rs` (backend, transport, classifier, retrier, tests), `src/serve.rs` (REST bridge).

What it wraps. OpenDAL's operator is built without its `RetryLayer`; every retry decision is made by hx's `Retrier`, around each whole operation (a listing is retried from the start, a pack write re-sends the multipart body). `HxDrive` implements rustic's `ReadBackend`/`WriteBackend`, so `rustic_core` sees an ordinary backend. Differences from `rustic_backend`'s OpenDAL glue: listing errors propagate (the stock glue logs and drops them, which would hand `repair index` and prune a silently truncated listing), `create` runs 4 folder creations at a time, and every HTTP request is bounded by a timeout.

Classification (`classify`, from the OpenDAL error: HTTP status in the `response` context, Drive's `message` text; Drive's `reason` field is not carried by OpenDAL's error, so the message is matched case-insensitively, and the reason names too in case a future OpenDAL adds them):

| Reply | Class | Behaviour |
|---|---|---|
| 429; 403 with "rate limit" / `rateLimitExceeded` / `userRateLimitExceeded`; OpenDAL `RateLimited` | rate-limited | Retry with exponential backoff and jitter; a `Retry-After` header raises the delay to at least that value (capped at 1 h) |
| 5xx, 408, 405 (Drive abuse detection), network errors flagged temporary | transient | Same backoff |
| 403 "daily limit" / `dailyLimitExceeded` | daily limit | Set a gate shared by all threads, sleep `daily_pause` (default 1 h), probe again; give up after `max_daily_pauses` (default 26, about a day) with the original error |
| 403 storage quota exceeded | fatal (quota) | No retry; hx-backup should show "Drive full" |
| 401, other 403 (for example `appNotAuthorizedToFile`), 404 and everything else | fatal | No retry, error returned unchanged |

Backoff: delay for retry n = min(64 s, 1 s x 2^(n-1)), "equal jitter" (uniform between half and full delay, so concurrent uploaders spread out and the delay never collapses), at most 8 retries (worst case about 3 min per operation) before the error is returned and the backup run fails and is rescheduled.

Transport (`Transport<T>`, wraps OpenDAL's reqwest transport): counts calls by category (`list`, `get.media`, `upload.create`, ...), bytes up and down, and status codes; records every real non-2xx reply (status, Drive reason, message; never headers or tokens); applies a request timeout (60 s plus 4 s per MiB sent); and injects faults from a script (`S4_FAULTS='upload.create:429:rateLimitExceeded:3,list:403:dailyLimitExceeded:1:50'`, format `category:status:reason:times[:skip[:retry_after]]`). Injected replies carry Google's documented JSON error body and travel through OpenDAL's real error parser, so tests cover the real classification path, not a mock of it.

Tests (`cargo test`, 18 passing including the 4 existing rule tests): 429 retried with the exact 1, 2, 4 s schedule; 403 `rateLimitExceeded` and `userRateLimitExceeded` retried; `Retry-After: 30` wins over a 1 s backoff; backoff caps at 64 s and gives up after 8 retries (9 requests); 503 retried; jitter bounds; daily limit pauses once, resumes and succeeds; daily limit gives up after `max_daily_pauses`; a daily-limit pause started by one caller delays a second caller (two threads, real sleeps); storage quota, `appNotAuthorizedToFile` and 401 are fatal with exactly one request and no sleep; an exhausted listing is an error, not an empty list; classification table over 13 reply shapes; fault-spec parsing; credentials never appear in `Debug` output.

Fault-injected runs on real Drive (the injected replies replace real ones for the chosen categories, everything else is real traffic):

| Run | Injected | Result |
|---|---|---|
| Backup of a small tree | 9 faults: 3x 403 `userRateLimitExceeded` and 2x 429 on listings, 2x 429 and 1x 403 `dailyLimitExceeded` (pause 2 s) on uploads, 1x 503 on a metadata read | Completed in 45.5 s with 9 retries (7 rate-limited, 1 daily, 1 transient; 19.9 s of backoff sleeps); restore tree identical; `check --read-data all` ok |
| Restore of a 6 MB subtree of the real repository | 8 faults: 3x 429 and 2x 403 `userRateLimitExceeded` on reads (one of them the key read), 2x 503 on listings, 1x 403 `dailyLimitExceeded` on a metadata read | Completed with 8 retries; restored files identical to an unfaulted restore (`diff -r`) |

Real replies observed: none of 429, 403 rate-limit or 5xx in any run (`real_api_errors` empty in every `Stats` snapshot). The only real error body seen was 403 `appNotAuthorizedToChild` (recursive folder delete, from the helper script, not the backend).

Not covered by the wrapper (to build in Phase 2): permanent delete (10.8), refresh-token revocation (OpenDAL surfaces the token endpoint failure as an error; mapping it to "Action needed: reconnect Google Drive" was not tested because that needs revoking the token), a download of a damaged object.

### 10.5 Interrupted upload and resume on Drive

The kill is a SIGKILL of the bridge process (cuts the in-flight Drive upload mid-request at TCP level, as a crash or a lost link would) together with the worker's backup process.

| Run | New data | Killed after | On Drive at kill | Retry | Uploaded by the retry | Result |
|---|---|---|---|---|---|---|
| 1, retry **with** `repair index` (the default) | 2,000 files of 1 MiB random (2,097 MB) | 55 s (about 20% done) | 421.3 MB in 12 orphan packs, none of them partial | `repair index` 34.8 s (reads the 12 headers; 3.5 s when there are no orphans), then backup | 1,707.1 MB; the run reports 1,723 MB added against 2,097 MB of new files, so at least 374 MB came from the orphans | Stored total 2,128.4 MB = 421.3 + 1,707.1. Nothing the kill had stored was uploaded again. Wall 237 s |
| 2, retry **without** `repair index` | 300 MiB rewritten plus the growth of the live SQLite file (487.4 MB packed in total) | 30 s | 178.3 MB in 5 orphan packs | plain backup (`--no-repair-index`) | 487.5 MB, equal to 100% of the run's own added data | Stored total 665.8 MB for 487 MB of content: 178 MB (37%) of orphan garbage. Wall 71.5 s |

Same result as locally: only `repair index` turns the orphans into reusable data; the in-flight object at the time of the kill is lost whole (no torn object on Drive, unlike the local backend's in-place writes). The retry wrapper does not change this (a killed process does not retry). Whether prune removes unindexed orphan packs is unclear: the later prune trashed 2,797.2 MB against a plan of 2,615.5 MB, a difference close to the 178 MB of garbage, which would contradict the local finding that prune ignores them; not verified separately.

### 10.6 Restore and verification from Drive

Restore of the day snapshot (`643a7d3c`) into a new `s4-restored` container, through the bridge, `--sparse`.

| Check | Result |
|---|---|
| Restore | 57,766 files, 2,592.0 MB. Wall **366.6 s** the first time (CPU 7.3 s user + 9.6 s sys; 1,062.9 MB downloaded in 51 ranged reads, 121 calls; the first 913 MB arrived in 3 min, the tail trickled at about 0.4 to 1 MB/s). The same snapshot restored a second time into the worker's own filesystem took **19.0 s** (1,063 MB, the network ran at tens of MB/s); a 679 MB subtree restored in 10.1 s both through the bridge and directly with the hx backend. The 19x spread is unexplained: no retry, no real error and no slow request (over 5 s) was logged, and the host was shared. It is not the Drive backend's throughput (10.1 s direct restore, `check --read-data all` 53 MB/s). Re-measure on a quiet host before quoting a restore time |
| Tree comparison (`treesum.py` against `compare.py`: path, type, mode, uid, gid, size, mtime ns, nlink, SHA-256, symlink target, all xattrs including POSIX ACL and `security.capability`) | 81,070 entries: identical 81,070, missing 0, different 0, unexpected extra 0; 9 hard-link groups equal. **PASS** |
| AI data and credentials | The 11 Claude session files, 3 Codex rollouts, settings, `.claude.json`, `.credentials.json` and `auth.json` (mode 600) are part of the tree comparison and byte-identical |
| Excluded caches | Electron `Cache`, `Code Cache`, `GPUCache`, `DawnCache` and `/var/cache/apt/archives` absent; `~/.cache` was recreated by the new session with fresh content only |
| Boot | `systemctl is-system-running` = `running` after 3 s, 0 failed units; lightdm's Xorg and the dummy Xorg (1920x1080) up, `xfce4-session`, `xfwm4`, `xfce4-panel` running |
| SQLite | `PRAGMA integrity_check` = `ok` for the live database (707,700 rows, WAL recovered) and the four browser-profile databases (4,500, 4,500, 3,000, 3,000 rows) |
| Packages | `dpkg --audit` clean, 1,068 packages, `htop` and `ncdu` present, `apt-get update` and `apt-get install cowsay` work (apt recreates its excluded directories) |
| Sparse file | 52,428,800 B apparent, 512 KiB on disk with `--sparse` |

### 10.7 Metadata check, read-data subsets, prune

Repository at the time of the check numbers: 3.24 GB (full, day, resumed bulk data).

| Operation | Wall | API calls | Downloaded |
|---|---|---|---|
| `check` (metadata, cold cache) | 12.3 s | 41 | 6.7 MB |
| `check --read-data 5%` (two runs) | 15.4 s, 14.9 s | 69 | 155.3 MB, 161.2 MB (5% of 3.24 GB is 162 MB) |
| `check --read-data all` (1.11 GB repository after the prune below) | 21.0 s | 172 | 1,110.4 MB |
| `forget` 2 snapshots + `prune --instant` | 252 s | 89 trash moves (one `PATCH` each) plus listing and stat calls | about 0.2 MB besides the deletes |

Monthly 5% verification costs 5% of the repository in download, plus about 15 s of API time, which is negligible against Drive's download limits; on a home link the bytes dominate (a 50 GB repository: 2.5 GB, about 3.5 min at 100 Mbit/s).

Prune and trash, measured with `drivectl.py usage`:

| | Live bytes | Trashed bytes | `storageQuota.usage` |
|---|---|---|---|
| Before prune | 3,901.1 MB (129 files) | 0 | 14,314.1 MB |
| After prune | 1,106.9 MB (42 files) | 2,797.2 MB (89 files) | 14,317.0 MB |

### 10.8 Decisions

1. **Backend: OpenDAL `gdrive`, confirmed, behind the hx wrapper (`HxDrive`).** `drive.file` works, so the "switch to rclone if `drive.file` fails" trigger did not fire. Large-pack uploads did not fail either, so rclone's resumable uploads are not needed on this evidence; they remain the documented fallback if packs of 128 MB or more, or slow uplinks, fail in the field (Phase 2 test: 128 MB pack over a 1 MB/s throttle). Phase 2 should depend on `opendal` directly with only `services-gdrive` (binary 54% smaller than the stock rustic path) instead of `rustic_backend`'s `opendal` feature.
2. **The wrapper is required, not optional**, for three reasons: 429/403 classification and the daily-limit pause (10.4), propagation of listing errors, and timeouts on every call. The design in 10.4 is the starting point for `hx-backup`'s Drive backend.
3. **Add permanent deletion to the backend.** `remove` must end in `DELETE files/{id}` (or trash followed by deletion of the trashed copy), otherwise "Drive full: prune oldest backups" frees nothing. The call needs the file id (OpenDAL caches it internally but does not expose it): either a small hx-owned Drive client for `files.list` by name and `files.delete` (it can share the OAuth token handling), or a periodic job that lists the app's trashed files (`q=trashed=true`, visible under `drive.file`) and deletes them. Never use `files.emptyTrash`. Until then prune only reclaims the quota when the trash is emptied separately.
4. **Keep `repair index` before every backup** (confirmed on Drive), plus the single-writer guard (still no repository locks).
5. **Restore planning:** treat restore time as latency-bound and variable (10.6); the restore flow should show progress by bytes and not promise a duration, and the Phase 2 restore test should run at least twice on a quiet host.
6. **Compression, exclude defaults, schedules, retention:** unchanged from section 7 (zstd level 3; increment about 98 MB).
7. **The OAuth client identity matters.** With `drive.file` an app only sees files it created. The repository stays visible across installs only for the same OAuth client id (observed: separate processes and access tokens of the one client all saw the same files). "Restore onto a new server" therefore needs the same OAuth client as the backup; shipping one fixed client for all installs satisfies it, per-user client ids would not. Not tested with a second client.

### 10.9 Risks and follow-ups

- Real rate-limit replies are still unseen; the matched message strings ("Rate Limit Exceeded", "User Rate Limit Exceeded", "Daily Limit Exceeded") come from Google's documentation. The wrapper logs and records every non-2xx reply, so the first real occurrences in the nightly Drive test will confirm or correct the classifier. The 750 GB per day upload limit was not approached (the spike uploaded about 4 GB in total; peak live data on Drive 3.9 GB) and its error shape is unknown; if it arrives as `userRateLimitExceeded` it will be retried 8 times (about 3 min) and then fail the run, which is the safe outcome.
- Trash accounting (10.1) affects the "Drive full" logic and free-space estimates: free space should come from `about.storageQuota` (which includes trash) rather than from the sum of live pack sizes.
- Restore time variance (10.6) is open.
- Packs of 128 MB or more, slow uplinks and token revocation were not tested.
- The REST bridge (`s4 serve`) exists only to keep the token out of the worker container; in production hx-privd owns that boundary. It buffers whole packs in memory (fine for 30 to 100 MB packs).
- `init` cost: 261 folder creations took 58 s with 4 in parallel (the stock path used more threads: 26 s). Raising the wrapper to 8 workers is safe given the retry logic; creating the 256 `data/xx` folders lazily would remove the cost entirely (Drive folders are only needed when a pack is written to them).
- Prune's treatment of unindexed orphan packs needs a direct test (10.5).
- Dependencies added to the spike crate only: `opendal`, `opendal-http-transport-reqwest`, `tokio`, `futures`, `http`, `bytes`, `hex`, `tiny_http`, `base64`, `log`, `serde`. Before Phase 2 uses them, `docs/tech-stack.md` needs the OpenDAL (gdrive only) entry.
- Proposed edits for the other docs (not made here): `architecture.md` 9.6 failure table (429 and 403 rows now have a tested design; add the permanent-delete requirement and the trash behaviour), 9.7/Drive-full logic (quota includes trash), section 5.4 (one fixed OAuth client), risk table line "OpenDAL's Google Drive backend, `drive.file` scope, rate limits" to "confirmed with `drive.file`; rate-limit bodies still unseen"; `execution-phase.md` 0.4 "S4 Drive run" to done with the open items above.

### 10.10 Cleanup (done)

The bridge was stopped, every object the spike created on Drive was deleted (392 objects including the 89 trashed files and the folder itself; `files.list` for the app returned 0 objects, live or trashed; account usage back to its pre-run value), the three Incus containers (`s4-desktop`, `s4-worker`, `s4-restored`) and the rustic caches were removed.

### 10.11 Reproduce the Drive run

```
cd spikes/s4-backup-roundtrip
cargo build --release && cargo clippy --all-targets -- -D warnings && cargo test   # 18 tests, no network
# host: token at ~/.config/hash-xcreen-spike/drive-token.json (client_id, client_secret, refresh_token); never printed
./drive-bridge.sh start &                                   # REST bridge over the hx Drive backend (incusbr0 address)
export S4_REPO_URL=$(./drive-bridge.sh url)                 # throw-away bridge password, not a Google credential
./s4ctl.sh init drive 3
S4_SUM=full1 ./s4ctl.sh backup drive --tag full            # then seed-desktop.sh day, S4_SUM=day ./s4ctl.sh backup drive --tag day
./kill-bridge-test.sh 55 --tag bulk                         # kill mid-upload; restart the bridge; ./s4ctl.sh backup drive again
./s4ctl.sh restore drive s4-restored <snapshot-id>          # then mount points, ./verify-boot.sh s4-restored, compare.py
./drive-bridge.sh stats                                     # API calls, bytes, retries, real error replies
python3 -I drivectl.py usage | purge | bw 20                # quota and live/trashed bytes; permanent cleanup; bandwidth probe
python3 -I ratelimit-probe.py 16 320                        # tries to provoke a real 429/403 (did not)
S4_FAULTS='upload.create:429:rateLimitExceeded:3,list:403:dailyLimitExceeded:1:50' ./drive-bridge.sh start   # fault injection
```
