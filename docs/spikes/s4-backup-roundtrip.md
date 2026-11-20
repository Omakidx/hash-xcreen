# Spike S4: backup round trip

Status: done against a LOCAL repository. Google Drive items are UNVERIFIED (no OAuth client yet, no Drive calls were made).
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
| Interrupted upload resumes without re-uploading | PASS with a required step, FAIL without it | Only with `repair index` before the retry (3.3). Plain rerun re-uploads everything. Not tested against Drive, so UNVERIFIED for Drive |
| Google Drive end to end | UNVERIFIED | No credentials |

## 5. Exclude and protected-path design

Implemented in `src/rules.rs`. Excludes are exact absolute path patterns (`*` is one segment, e.g. `/home/*/.config/*/Code Cache`). At backup time they are resolved against the mounted snapshot into concrete paths, any path that is inside, equal to or an ancestor of a protected pattern is dropped, and the rest become literal ignore globs for rustic. Protected paths therefore cannot be excluded whatever the user-editable list says. Tests: unit tests plus a proptest (200 random trees and random exclude lists, default list on or off): no resolved exclude prunes a protected path or the credential files.

Findings for the design doc:
- Architecture 9.2 conflicts with itself: trash (`~/.local/share/Trash`) is excluded, but `~/.local/share/` is protected and protection wins, so Trash is kept. Same for Chromium-style caches inside a browser profile (`Default/Cache`, `Code Cache`, `GPUCache`, `Service Worker/CacheStorage`): protecting the whole profile backs them up (about 90 MB of seed cache and 30 MB of the daily increment). Recommendation: protect `~/.config/<browser>/Default/{Local Storage,IndexedDB,Session Storage,Cookies,Login Data,History,Preferences,Extensions,...}` rather than the whole profile, or make the protected list win only over user excludes and let the built-in cache list win inside browser profiles.
- `/var/log/*` globs and `/var/lib/apt/lists/*` were added to the default list; `/var/log/app/big.log` (a subdirectory) was correctly kept, as "exact paths only" intends.
- rustic's override glob engine cannot express "protected wins" (a whitelist glob would make every other file ignored), which is why resolution to concrete paths is done outside rustic.

## 6. Google Drive evaluation (all UNVERIFIED, from code and docs)

- Compiles and fits: `rustic_backend 0.8` with feature `opendal` enables OpenDAL's `gdrive` service. `s4 --repo opendal:gdrive --opt root=... drivecheck` builds a `RepositoryBackends` and a `Repository` with no network I/O, so the trait fit is proven at compile and construct level. The release binary is 43 MB because all OpenDAL services are linked; production should depend on `opendal`/`rustic_backend` selectively (the crate offers no per-service feature through rustic_backend, so a thin custom `ReadBackend`/`WriteBackend` over `opendal-service-gdrive` is an option).
- Auth: options `client_id`, `client_secret`, `refresh_token` (OpenDAL refreshes the access token itself, 120 s early, by POSTing to `oauth2.googleapis.com/token`), or a bare `access_token` that expires. OpenDAL does not run the OAuth flow; the PKCE desktop flow stays in hx. Its docs name scope `drive`. Whether `drive.file` suffices is UNVERIFIED: OpenDAL resolves paths by listing by name under a parent, which should work for folders the app created itself, but it must be tested.
- Uploads: `GdriveWriter` is a one-shot write: one `uploadType=multipart` request per object (`uploadType=media` for overwrite). There are no resumable sessions, so the resume granularity is one pack: a failed pack upload restarts from byte 0. With rustic's default pack sizes (tens of MB) that is acceptable, and content addressing plus `repair index` handles the rest; Google recommends resumable uploads above 5 MB, so large packs on flaky links are a risk. Setting `treepack`/pack size smaller is possible through repository config.
- Layout: rustic uses `data/<2 hex>/<id>`, so 256 subfolders plus `index`, `snapshots`, `keys`. Drive allows duplicate names; OpenDAL picks the newest match, which is a risk if two writers overlap. Path lookups cost list API calls (OpenDAL caches ids).
- Retries and rate limits: rustic wraps the operator in OpenDAL's `RetryLayer` (5 retries default, jitter, option `retry=N`), plus options `connections=N` (concurrency limit) and `throttle=bandwidth,burst`. In the gdrive service only 5xx, 405 and the exact message "User rate limit exceeded." are marked retryable. HTTP 429 and 403 `rateLimitExceeded`/`dailyLimitExceeded` are not, so the "pause until tomorrow at the 750 GB limit" and generic backoff behaviour in 9.6 need a wrapper around the backend (or an upstream fix).
- Fallback: rustic's `rclone` backend (spawns `rclone serve restic`) has mature Drive handling (resumable uploads, 429 backoff, token refresh from rclone config) but adds an external binary and a config file with the token.

## 7. DECISION

1. Backend: start with `rustic_backend` + OpenDAL `gdrive` behind a thin hx-owned wrapper that adds 429/403-rate-limit classification, exponential backoff with jitter, the daily-limit pause and `connections`/`throttle`. Keep rclone as the documented fallback; switch if the first real-Drive test (7 below) shows `drive.file` not working or large packs failing without resumable uploads. This decision is provisional until re-tested with real Drive.
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
