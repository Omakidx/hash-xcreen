# hx-backup

Full-desktop backups with `rustic_core` (architecture section 9). This is the first,
**transport-agnostic slice of workstream 2A**: the rules, the manifest and the engine. It knows
nothing about Google Drive, Incus, HTTP or `hx-privd`; it is handed a rustic backend and a path.

## Module map

| Module | What it does |
|---|---|
| `rules` | Exclude patterns, the protected list, named caches and Docker modes, resolved against a real mounted tree into concrete paths and rustic ignore globs. |
| `manifest` | The versioned, strictly parsed backup manifest stored with each snapshot. |
| `engine` | `Engine`: open-or-init a repository, backup, restore (with resume), forget, prune, check, snapshot listing; progress sink and cancellation token; the zeroizing `RepoKey`. |

## Features

`default = []`: the default build is `rules` and `manifest` only, with no rustic dependency, which
is what `hx-privd` uses. The `engine` feature brings `rustic_core` and is enabled only by the backup
worker (ipc.md §36). The crate's own tests always build with `engine` (a self dev-dependency).

Dependencies are pinned in the workspace `Cargo.toml`; `rustic_core` is pinned **exactly**
(`=0.14.0`, no default features, no `clap`) because its API changes between minors.

## Rules (`rules`)

* **Excludes** are exact cache locations: absolute path patterns where a segment may use `*`, `?`
  and `[...]` and never matches across `/` (so `*` is one segment; `**`, `.` and `..` are
  rejected). `default_excludes()` is the editable default list (`/proc /sys /dev /run /tmp
  /var/tmp`, apt caches, logs, `~/.cache`, package-manager caches, Electron `Cache`,
  `Code Cache`, `GPUCache`, `DawnCache`, ...). A caller passes the full list it wants to
  `RuleSet::new`; nothing is added behind its back.
* **Protected paths** (`protected_patterns()`, not editable): `~/.claude`, `~/.claude.json`,
  `~/.codex`, `~/.gemini`, `~/.cursor`, `~/.config/*/{Local Storage,IndexedDB,Session Storage}`,
  `~/.config/Code/User`, all of `~/.local/share`, and whole browser profiles (Chromium family,
  Firefox, snap variants). Homes are `/home/*` and `/root`.
* **Protected wins.** A candidate exclude that equals, contains, or lies inside a protected path
  that exists in the tree is rejected (and listed in `ResolvedRules::rejected()`). Excluding a
  home that contains nothing protected is allowed.
* **...except named caches.** Always applied, not user-editable: `~/.local/share/Trash`, and
  inside browser profiles any directory named `Cache*`, `Code Cache`, `GPUCache`, `DawnCache`,
  `GraphiteDawnCache`, `GrShaderCache`, `ShaderCache`, `cache2` or `Service Worker/ScriptCache`
  (found at any depth up to 8 levels, never inside `Local Storage`, `IndexedDB`,
  `Session Storage`, `Extensions`, `Local Extension Settings`). A named cache is still refused if
  it would contain another protected path. (S4: protecting whole profiles and `~/.local/share`
  pulled Trash and about 30 MB of browser cache per day into backups.)
* **Docker** (`DockerMode`): `Complete` excludes only `/var/lib/docker/buildkit`; `Light` keeps
  `volumes/` and each container's `config.v2.json` and `hostconfig.json` and excludes the rest of
  `/var/lib/docker` (images are pulled again; Compose files sit in the users' homes and are
  backed up there).
* **Resolution is safe.** It walks the mounted tree without ever following a symlink (a link can
  be excluded as a node, nothing behind it is read) and within an entry budget
  (`DEFAULT_ENTRY_BUDGET`, 5 million). Running out of budget or hitting an unreadable directory
  does not fail the backup: that discovery step is skipped (its paths stay in the backup) and
  counted in `ResolvedRules::discovery_skipped()`. If the protected paths themselves cannot be
  discovered, nothing is excluded at all, so the protected guarantees hold.
* **Output.** `resolve()` returns `ResolvedRules`: the sorted, de-duplicated list of concrete
  excluded paths (nothing inside another entry), the concrete protected paths, and the rejected
  candidates. `rustic_globs(prefix)` turns them into literal, escaped `!`-prefixed override globs
  for `BackupOptions::excludes.globs` (rustic's globs cannot express "protected wins, except
  named caches"); `report()` / `Display` is the human-readable list for logs. Excluded paths that
  are not valid UTF-8 cannot be written as globs and stay in the backup (reported, never silent).
* `MOUNT_POINTS` lists what a restore recreates (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`,
  `/var/tmp`) and their modes.

Tested with unit tests and a `proptest` property: over random trees and random exclude lists, no
protected path (or an ancestor needed to reach it) is ever excluded, and named caches inside
protected trees always are, judged by an independent oracle.

## Manifest (`manifest`)

JSON, compact, at most 64 KiB, stored as the **snapshot description** (inside the encrypted
snapshot; readable from a listing without fetching data; not a file in the restored tree).

```json
{"format_version":1,"created_at":"2026-11-26T03:00:00Z","agent_version":"0.1.0",
 "distro":{"id":"ubuntu","version_id":"24.04","pretty_name":"Ubuntu 24.04 LTS"},
 "desktop":"xfce4","preset":"dev","docker_mode":"light",
 "container_config":{"limits.cpu":"4","security.idmap.isolated":"true"},
 "source_sizes":{"files":70575,"directories":9000,"bytes":2439600000,"excluded_paths":53}}
```

* `rustic_snapshot_id` is **absent inside the repository**: a snapshot cannot contain its own id.
  `Engine::read_manifest` and `Engine::snapshots` fill it in when reading back.
* `source_sizes` is measured by the engine before the backup (apparent sizes, hard links once);
  the exact figures of the run are in `BackupOutcome::summary`.
* `container_config` is an **explicit allow-list** (`config_entry_allowed`): `limits.cpu`,
  `limits.memory`, `limits.processes` (a positive integer, never `unlimited`), `root.size`,
  `boot.autostart`, `security.nesting`, `security.syscalls.intercept.mknod` and
  `security.syscalls.intercept.setxattr` (`true`/`false`), each with a strict value grammar.
  `restorable_container_config` drops everything else and counts it (never fatal);
  `Manifest::new` applies it, and parsing drops anything else and counts it
  (`Manifest::from_slice_counting`), so an older backup stays restorable if the list narrows.
  **A restore must still re-validate the manifest's configuration against its own policy and
  never trust it:** the manifest is writable by anyone holding a repository key.
* `docker_mode` comes from the backup rules (`rules.docker_mode()`, one source of truth);
  `BackupRequest::docker_enabled` says whether Docker is in use at all.
* `Distro::from_os_release` cleans values from the (untrusted) guest instead of failing: control
  characters are removed, values are cut on a character boundary, and an unusable `PRETTY_NAME` is
  dropped.
* **Versioning rule.** `format_version` is read first. Each version has a strict parser
  (`deny_unknown_fields`). A new agent must always read older manifests (restore onto a newer
  agent, architecture 9.8 item 5): any field change bumps `CURRENT_FORMAT_VERSION`, the old
  struct stays with a conversion into the current type, and old structs are never removed. An
  older agent reading a newer manifest returns `ManifestError::NewerFormat` (update the agent).
  Version 0 and non-numeric versions are invalid; oversized input is refused before parsing.

## Engine (`engine`)

```text
Engine::open(&RepositoryBackends, &RepoKey, &EngineOptions, Arc<dyn ProgressSink>)
engine.backup(&BackupRequest, &CancelToken)    -> BackupOutcome
engine.restore(&RestoreRequest, &CancelToken)  -> RestoreOutcome
engine.forget(&ForgetRequest, &CancelToken)    -> ForgetOutcome   // explicit keep rules
engine.prune(&CancelToken)                     -> PruneOutcome    // always --instant
engine.check(ReadData::{None|Percent|All}, &CancelToken) -> CheckReport
engine.snapshots() / engine.read_manifest(&SnapshotSelector)
```

* **Backend-agnostic.** One `Arc<dyn WriteBackend>` through `open_with_backend` (or any
  `RepositoryBackends` through `open`). No local cache is ever used (`no_cache`), so the worker
  creates no directories.
* **Opening.** The default is `OpenMode::OpenExisting`; a repository is created only when the
  caller asks for `OpenOrInit`, so a wrong location never becomes a silently new repository.
* **Repository settings at init.** zstd level 3, `datapack_size_limit` 64 MiB and
  `treepack_size_limit` 16 MiB (rustic's own limit is `u32::MAX`). These are **soft** limits:
  rustic saves a pack once its size reaches the limit, so a pack can overshoot by about one blob,
  and a single tree blob (a directory with a huge number of entries) is not bounded at all. They
  keep packs near 64 MiB; they do not guarantee that every object fits the 96 MiB cap of the link
  to the privileged side. The link must refuse an oversize object with a clear `TOO_LARGE` error
  (follow-up for the link).
* **Keys.** The repository is opened with a password credential (never a raw master key), so
  stock rustic/restic open it with the same passphrase. `add_key` adds a second key (the recovery
  key) and returns its `KeyId`; `remove_key` removes one by id (never the key in use).
* **Repository writes during a backup** are limited to new `PACK`, `INDEX` and `SNAPSHOT` files
  and removal of `INDEX` files; nothing is replaced and no `PACK`/`SNAPSHOT`/`KEY`/`CONFIG` is
  removed. An integration test records every backend call across a backup, an incremental backup
  and a backup after an interrupted run (index and snapshots lost, `repair index` runs) and
  asserts this. Forget removes `SNAPSHOT` files and prune removes/rewrites packs and indexes;
  those are separate operations.
* **Key.** `RepoKey` zeroizes on drop, is not `Clone`, and prints `RepoKey(<redacted>)`. The
  `String` copy the engine builds for rustic is wiped as soon as the repository is open or
  initialised; rustic keeps its own copy inside the open repository, which this crate cannot
  wipe. A wrong key is `EngineError::WrongKey` and never triggers an
  init.
* **Backup** = `repair index` first (architecture 9.4 step 0: an interrupted run's packs are
  reused, not uploaded again), resolve rules, measure the source, build the manifest, back up
  with the resolved excludes, zstd level 3 for new repositories. The source is stored as `/`.
  The snapshot records the fixed command `hx-backup`, not the worker's argv.
  **Partial runs.** rustic skips unreadable files and still writes the snapshot; the count is
  `BackupSummary::error_count`. A non-zero count (or `unreadable_entries` in the manifest's
  `source_sizes`) means a partial backup: `BackupOutcome::is_partial()`. Callers must not report
  such a run as a clean success. The pre-backup scan never fails a backup: unreadable directories
  and entries (EACCES, a path chain longer than `PATH_MAX`) are skipped and counted.
  Snapshots of the same `host` are chained as parents, so keep `host` stable for a desktop. The
  caller holds the single-writer lock (rustic has none).
* **Restore** restores modes, xattrs, symlinks and hard links; with `Ownership::Numeric` (the
  default) it restores the numeric uid/gid from the snapshot, and requires `CAP_CHOWN` in the
  effective set (checked up front: `EngineError::MissingCapability`), because rustic itself only
  logs a failed chown, chmod or utime. After the data transfer the engine compares owner (numeric
  mode only) and permission bits of **every** restored entry with the snapshot and fails with
  `EngineError::RestoreVerification` on any mismatch. `Ownership::Skip` works unprivileged and
  leaves files owned by the restoring user. Timestamps and xattrs are not re-verified.  sparse files stay sparse (`sparse: true`); then it recreates the mount
  points backups skip, without following symlinks in the target. Resume: with the default
  `Resume::VerifyContent`, files already in place and matching the snapshot are skipped, damaged
  or partial ones are rewritten. Restoring onto a new server still needs a new hostname and
  `/etc/machine-id`, applied by the caller afterwards.
* **Forget/prune.** Explicit keep counts; the newest `protect_latest` (default 2) snapshots are
  never removed. Prune deletes immediately so space is freed now, not after rustic's 23 hours.
* **Check.** Metadata check, or a read-data check of a percentage or all packs. A percentage
  reads at least p% of the data rounded up to whole packs and never less than one pack (rustic's
  own subset logic would read nothing when p% is smaller than a pack and report "ok"); 100 means
  everything. `CheckReport::bytes_read` says how much pack data was read (rustic does not say how
  many packs). A subset check is a random sample: it may miss a damaged pack that `All` finds. Problems come back as `CheckReport { ok: false, findings }`, not as
  an `Err`.
* **Progress and cancellation.** `ProgressSink::event` gets `{phase, unit, title, done, total,
  finished}`; rustic's events are throttled to about ten per second. `CancelToken` is checked
  between steps and inside the source scan. A running rustic backup or restore call cannot be
  interrupted from inside; killing the worker is safe because backups resume through `repair
  index` and restores resume by skipping verified files.
* **Errors** are typed (`EngineError`); no panic on bad input. After a failed index load the
  engine is `Closed` and must be reopened (rustic consumes the repository handle for that call).

## Tests

`cargo nextest run -p hx-backup`: rules unit tests and the property test, manifest tests, and
engine integration tests against rustic's local backend in a temp directory (offline, no root).
The test that checks restoring arbitrary numeric owner ids needs root and is `#[ignore]`d; run
it with `sudo -E cargo nextest run -p hx-backup --run-ignored only`. 

## Deliberately not here yet

* The Google Drive backend (S4's `HxDrive` over OpenDAL), the REST bridge and any HTTP.
* The sandboxed backup worker binary, and the repository handle it receives from `hx-privd`
  (the worker never holds the Google credential).
* Mounting the Incus snapshot (idmapped, read-only) and writing restores through Incus.
* Scheduling, the retention policy engine (the 12h/24h defaults of 9.7), Drive quota checks,
  alerts, the weekly/monthly verification schedule.
* Post-restore identity (new hostname, new `/etc/machine-id`) and the single-writer lock.

Known gaps, for later branches:

* `get_all_snapshots` parses every snapshot file before the manifest size cap applies, so a key
  holder can make it allocate a lot; the privileged helper's 1 GiB limit bounds it.
* Flatpak browser profiles (`~/.var/app/*`) and Electron `Partitions/*/Cache` or
  `Service Worker/CacheStorage` outside browser profiles are not recognised as caches.
* Rootless Docker/Podman data under `~/.local/share` cannot be excluded (it is protected).
* `ignore_ctime` is off, so a ctime change alone re-reads a file.
* The restore verification does not compare timestamps or xattrs.
