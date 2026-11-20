//! Spike S4 backup tool: a thin, single-purpose wrapper around `rustic_core`.
//!
//! Runs inside a worker container that has the snapshot mounted read-only. Subcommands:
//! init, backup, restore, snapshots, check, repair-index, synth, retention, drivecheck.

mod drive;
mod rules;
mod serve;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use rustic_backend::BackendOptions;
use rustic_core::{
    BackupOptions, CheckOptions, ConfigOptions, Credentials, KeepOptions, KeyOptions,
    LocalDestination, LsOptions, PathList, PruneOptions, ReadSubsetOption, Repository,
    RepositoryOptions, RestoreOptions, SnapshotOptions, repofile::SnapshotFile,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(about = "S4 spike backup tool (rustic_core)")]
struct Cli {
    /// Repository location (local path, or an OpenDAL url such as `opendal:gdrive`)
    #[arg(long, global = true, default_value = "/repo")]
    repo: String,
    /// File holding the repository password (the recovery key in production)
    #[arg(long, global = true, default_value = "/etc/s4-password")]
    password_file: PathBuf,
    /// Extra backend option key=value (repeatable), for example `root=/hash-xcreen`
    #[arg(long = "opt", global = true)]
    opts: Vec<String>,
    /// JSON file with `client_id`, `client_secret`, `refresh_token` for the gdrive service. Read in-process
    /// at start-up and never printed or logged.
    #[arg(long, global = true)]
    drive_token_file: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Init {
        /// zstd level (rustic maps 0 = no compression)
        #[arg(long, default_value_t = 3)]
        compression: i32,
    },
    Backup {
        /// Mounted (read-only) snapshot root
        #[arg(long, default_value = "/src")]
        source: PathBuf,
        #[arg(long)]
        tag: Option<String>,
        /// Print what would be excluded and stop
        #[arg(long)]
        dry_run: bool,
        /// Skip adding orphan packs from an interrupted run to the index before starting
        #[arg(long)]
        no_repair_index: bool,
        /// Extra exclude pattern (absolute, rootfs-relative, `*` is one segment); repeatable
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Do not use the built-in default exclude list
        #[arg(long)]
        no_default_excludes: bool,
        /// File whose content becomes the snapshot description (the manifest JSON)
        #[arg(long)]
        description_file: Option<PathBuf>,
        /// Synthetic snapshot time (RFC 3339) for retention tests
        #[arg(long)]
        time: Option<String>,
    },
    Restore {
        #[arg(long, default_value = "latest")]
        snapshot: String,
        #[arg(long, default_value = "/target")]
        dest: String,
        /// Remove files in dest that are not in the snapshot
        #[arg(long)]
        delete: bool,
        /// Re-create holes for zero blocks (sparse files)
        #[arg(long)]
        sparse: bool,
        /// Verify the content of files already present in dest instead of trusting size+mtime
        #[arg(long)]
        verify: bool,
    },
    Snapshots,
    /// List all paths in a snapshot (one per line)
    Ls {
        #[arg(long, default_value = "latest")]
        snapshot: String,
    },
    Check {
        /// Read and verify a subset of pack data, for example `5%` or `all`
        #[arg(long)]
        read_data: Option<String>,
    },
    RepairIndex,
    /// Forget snapshots by (short) id and optionally prune; used to observe what deletes do on Drive
    Forget {
        ids: Vec<String>,
        #[arg(long)]
        prune: bool,
        /// Delete pruned packs immediately instead of marking them for 23 h (rustic default)
        #[arg(long)]
        instant: bool,
    },
    /// Create N small synthetic snapshots with backdated times, for retention tests
    Synth {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        count: u32,
        #[arg(long)]
        interval_hours: i64,
    },
    /// Apply the architecture 9.7 retention policy
    Retention {
        /// 12h or 24h
        #[arg(long)]
        every: String,
        #[arg(long)]
        apply: bool,
    },
    /// Construct the backend only (no I/O): proves the backend fits rustic_core's traits
    Drivecheck,
    /// Serve the repository backend over the restic REST protocol (bridge for the credential-free worker)
    Serve {
        #[arg(long, default_value = "10.36.142.1:8765")]
        listen: String,
        /// File whose first line is the bridge password (basic auth, user `s4`)
        #[arg(long)]
        bridge_password_file: PathBuf,
        #[arg(long, default_value_t = 6)]
        threads: usize,
    },
    /// Print the effective excludes for a tree
    Excludes {
        #[arg(long, default_value = "/src")]
        source: PathBuf,
    },
}

fn e<E: std::fmt::Display>(x: E) -> anyhow::Error {
    anyhow!("{x}")
}

fn creds(p: &Path) -> Result<Credentials> {
    let pw = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
    Ok(Credentials::Password(pw.trim().to_string()))
}

fn hx_stats() -> &'static std::sync::Arc<drive::Stats> {
    static S: std::sync::OnceLock<std::sync::Arc<drive::Stats>> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Arc::new(drive::Stats::default()))
}

fn hx_backend(cli: &Cli, root: &str) -> Result<std::sync::Arc<dyn rustic_core::WriteBackend>> {
    let tf = cli
        .drive_token_file
        .as_ref()
        .ok_or_else(|| anyhow!("hxdrive: needs --drive-token-file"))?;
    let creds = drive::DriveCreds::from_file(tf)?;
    let faults = match std::env::var("S4_FAULTS") {
        Ok(spec) => drive::Faults::parse(&spec)?,
        Err(_) => drive::Faults::default(),
    };
    let mut policy = drive::RetryPolicy::default();
    if let Ok(v) = std::env::var("S4_DAILY_PAUSE_MS") {
        policy.daily_pause = std::time::Duration::from_millis(v.parse()?);
    }
    if let Ok(v) = std::env::var("S4_MAX_DAILY_PAUSES") {
        policy.max_daily_pauses = v.parse()?;
    }
    let be = drive::HxDrive::new(
        &creds,
        root,
        policy,
        std::sync::Arc::new(faults),
        hx_stats().clone(),
    )?;
    Ok(std::sync::Arc::new(be))
}

fn backend(cli: &Cli) -> Result<rustic_core::RepositoryBackends> {
    if let Some(root) = cli.repo.strip_prefix("hxdrive:") {
        return Ok(rustic_core::RepositoryBackends::new(
            hx_backend(cli, root)?,
            None,
        ));
    }
    let mut b = BackendOptions::default().repository(&cli.repo);
    for kv in &cli.opts {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--opt needs k=v"))?;
        b.options.insert(k.to_string(), v.to_string());
    }
    if let Some(tf) = &cli.drive_token_file {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tf).context("read token file")?)?;
        for k in ["client_id", "client_secret", "refresh_token"] {
            let val = v[k]
                .as_str()
                .ok_or_else(|| anyhow!("token file lacks {k}"))?;
            b.options.insert(k.to_string(), val.to_string());
        }
    }
    b.to_backends().map_err(|e| anyhow!("{e}"))
}

fn repo_opts() -> RepositoryOptions {
    RepositoryOptions::default()
        .cache_dir(std::env::var("S4_CACHE_DIR").unwrap_or_else(|_| "/var/cache/s4-rustic".into()))
}

fn cpu_secs() -> (f64, f64) {
    // utime, stime from /proc/self/stat (fields 14 and 15), 100 ticks per second
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = rest.split_whitespace().collect();
    let g = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0) / 100.0;
    (g(11), g(12))
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let cli = Cli::parse();
    let t0 = Instant::now();
    let be = backend(&cli)?;
    let ropts = repo_opts();
    let c = creds(&cli.password_file)?;

    match &cli.cmd {
        Cmd::Init { compression } => {
            let cfg = ConfigOptions::default().set_compression(*compression);
            let _ = Repository::new(&ropts, &be)
                .map_err(e)?
                .init(&c, &KeyOptions::default(), &cfg)
                .map_err(e)?;
            println!("{{\"init\":true,\"compression\":{compression}}}");
        }
        Cmd::Serve {
            listen,
            bridge_password_file,
            threads,
        } => {
            let pw = std::fs::read_to_string(bridge_password_file)?;
            let root = cli
                .repo
                .strip_prefix("hxdrive:")
                .ok_or_else(|| anyhow!("serve needs --repo hxdrive:<root>"))?;
            let be = hx_backend(&cli, root)?;
            let st = hx_stats().clone();
            serve::serve(
                listen,
                "s4",
                pw.trim(),
                be,
                std::sync::Arc::new(move || st.snapshot()),
                *threads,
            )?;
        }
        Cmd::Drivecheck => {
            // `be` was built above from `--repo opendal:gdrive --opt ...`; building does no network I/O.
            let _repo = Repository::new(&ropts, &be).map_err(e)?;
            println!("{{\"backend_constructed\":true,\"repo\":{:?}}}", cli.repo);
        }
        Cmd::Excludes { source } => {
            let prot = rules::Protected::default_set();
            let r = rules::resolve_excludes(source, &rules::default_excludes(), &prot)?;
            for p in r {
                println!("{}", p.display());
            }
        }
        Cmd::Backup {
            source,
            tag,
            dry_run,
            no_repair_index,
            excludes,
            no_default_excludes,
            time,
            description_file,
        } => {
            let prot = rules::Protected::default_set();
            let mut pats = if *no_default_excludes {
                vec![]
            } else {
                rules::default_excludes()
            };
            pats.extend(excludes.iter().cloned());
            let resolved = rules::resolve_excludes(source, &pats, &prot)?;
            let prefix = source.to_string_lossy().into_owned();
            let globs = rules::to_rustic_globs(&prefix, &resolved);
            if *dry_run {
                for g in &globs {
                    println!("{g}");
                }
                return Ok(());
            }
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?;
            let mut repair_ms = 0u128;
            if !*no_repair_index {
                let t = Instant::now();
                // Resume support: packs uploaded by an interrupted run are not in the index yet.
                repo.repair_index(&rustic_core::RepairIndexOptions::default(), false)
                    .map_err(e)?;
                repair_ms = t.elapsed().as_millis();
            }
            let repo = repo.to_indexed_ids().map_err(e)?;
            let mut bo = BackupOptions::default().as_path(PathBuf::from("/"));
            bo.excludes.globs = globs;
            bo.parent_opts.ignore_inode = true; // snapshot mounts differ per run
            let src = PathList::from_string(&prefix)
                .map_err(e)?
                .sanitize()
                .map_err(e)?;
            let mut so = SnapshotOptions::default().host("hx-desktop".to_string());
            if let Some(t) = tag {
                so = so.add_tags(t).map_err(e)?;
            }
            if let Some(d) = description_file {
                so = so.description_from(d.clone());
            }
            if let Some(t) = time {
                so = so.time(t.parse::<jiff::Zoned>().map_err(|x| anyhow!("{x}"))?);
            }
            let snap = so.to_snapshot().map_err(e)?;
            let la0 = loadavg();
            let snap = repo.backup(&bo, &src, snap).map_err(e)?;
            let s = snap.summary.as_ref().ok_or_else(|| anyhow!("no summary"))?;
            let (u, sy) = cpu_secs();
            println!(
                "{}",
                serde_json::json!({
                    "snapshot": snap.id.to_string(),
                    "files_new": s.files_new, "files_changed": s.files_changed,
                    "files_unmodified": s.files_unmodified,
                    "files_total": s.total_files_processed,
                    "bytes_processed": s.total_bytes_processed,
                    "data_added": s.data_added, "data_added_packed": s.data_added_packed,
                    "data_added_files_packed": s.data_added_files_packed,
                    "data_added_trees_packed": s.data_added_trees_packed,
                    "excluded_paths": resolved.len(),
                    "repair_index_ms": repair_ms,
                    "wall_s": t0.elapsed().as_secs_f64(),
                    "cpu_user_s": u, "cpu_sys_s": sy,
                    "loadavg_start": la0, "loadavg_end": loadavg(),
                })
            );
        }
        Cmd::Restore {
            snapshot,
            dest,
            delete,
            sparse,
            verify,
        } => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?
                .to_indexed()
                .map_err(e)?;
            let node = repo
                .node_from_snapshot_path(snapshot, |_| true)
                .map_err(e)?;
            let ls = repo.ls(&node, &LsOptions::default()).map_err(e)?;
            let d = if dest.ends_with('/') {
                dest.clone()
            } else {
                format!("{dest}/")
            };
            let ld = LocalDestination::new(&d, true, !node.is_dir()).map_err(e)?;
            let mut ro = RestoreOptions::default();
            ro.numeric_id = true; // the target has no passwd database of its own yet
            ro.delete = *delete;
            ro.verify_existing = *verify;
            if *sparse {
                // `SparseRestore` is not re-exported by rustic_core 0.14; parse it through its clap derive.
                ro = RestoreOptions::try_parse_from([
                    "restore",
                    "--numeric-id",
                    "--sparse",
                    "by-content",
                ])?;
                ro.delete = *delete;
                ro.verify_existing = *verify;
            }
            let info = repo
                .prepare_restore(&ro, ls.clone(), &ld, false)
                .map_err(e)?;
            let (u0, s0) = cpu_secs();
            println!(
                "{}",
                serde_json::json!({"to_restore_files": info.stats.files.restore,
                    "unchanged": info.stats.files.unchanged, "matched_size": info.matched_size,
                    "restore_size": info.restore_size})
            );
            repo.restore(info, &ro, ls, &ld).map_err(e)?;
            let (u, s) = cpu_secs();
            println!(
                "{}",
                serde_json::json!({"restored": true, "wall_s": t0.elapsed().as_secs_f64(),
                    "cpu_user_s": u - u0, "cpu_sys_s": s - s0, "loadavg": loadavg()})
            );
        }
        Cmd::Ls { snapshot } => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?
                .to_indexed()
                .map_err(e)?;
            let node = repo
                .node_from_snapshot_path(snapshot, |_| true)
                .map_err(e)?;
            for item in repo.ls(&node, &LsOptions::default()).map_err(e)? {
                let (path, _node) = item.map_err(e)?;
                println!("{}", path.display());
            }
        }
        Cmd::Snapshots => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?;
            let mut snaps = repo.get_all_snapshots().map_err(e)?;
            snaps.sort_by(|a, b| a.time.cmp(&b.time));
            for s in snaps {
                let sum = s.summary.as_ref();
                println!(
                    "{} {} files={} added_packed={}",
                    s.id,
                    s.time,
                    sum.map(|x| x.total_files_processed).unwrap_or(0),
                    sum.map(|x| x.data_added_packed).unwrap_or(0)
                );
            }
        }
        Cmd::Check { read_data } => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?;
            let mut o = CheckOptions::default();
            if let Some(r) = read_data {
                o = o
                    .read_data(true)
                    .read_data_subset(r.parse::<ReadSubsetOption>().map_err(e)?);
            }
            let res = repo.check(o).map_err(e)?;
            res.is_ok().map_err(e)?;
            println!(
                "{}",
                serde_json::json!({"check_ok": true, "read_data": read_data,
                    "wall_s": t0.elapsed().as_secs_f64(), "loadavg": loadavg()})
            );
        }
        Cmd::Forget {
            ids,
            prune,
            instant,
        } => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?;
            let snaps = repo.get_all_snapshots().map_err(e)?;
            let drop: Vec<_> = snaps
                .iter()
                .filter(|s| ids.iter().any(|i| s.id.to_string().starts_with(i.as_str())))
                .map(|s| s.id)
                .collect();
            anyhow::ensure!(
                drop.len() == ids.len(),
                "every id must match exactly one snapshot"
            );
            repo.delete_snapshots(&drop).map_err(e)?;
            let mut removed = serde_json::Value::Null;
            if *prune {
                let mut po = PruneOptions::default();
                po.instant_delete = *instant;
                let plan = repo.prune_plan(&po).map_err(e)?;
                let st = plan.stats.size_sum();
                removed = serde_json::json!({"plan_remove": st.remove, "plan_repack": st.repack, "plan_unused": st.unused});
                repo.prune(&po, plan).map_err(e)?;
            }
            println!(
                "{}",
                serde_json::json!({"forgot": drop.len(), "prune": removed, "wall_s": t0.elapsed().as_secs_f64()})
            );
        }
        Cmd::RepairIndex => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?;
            repo.repair_index(&rustic_core::RepairIndexOptions::default(), false)
                .map_err(e)?;
            println!(
                "{{\"repair_index\":true,\"wall_s\":{}}}",
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::Synth {
            source,
            count,
            interval_hours,
        } => {
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?
                .to_indexed_ids()
                .map_err(e)?;
            let now = jiff::Zoned::now();
            let src = PathList::from_string(&source.to_string_lossy())
                .map_err(e)?
                .sanitize()
                .map_err(e)?;
            for i in 0..*count {
                let age = (*count - 1 - i) as i64 * interval_hours;
                let t = now
                    .checked_sub(jiff::Span::new().hours(age))
                    .map_err(|x| anyhow!("{x}"))?;
                std::fs::write(source.join("counter"), format!("{i}\n"))?;
                let so = SnapshotOptions::default()
                    .host("hx-desktop".to_string())
                    .time(t);
                let snap = so.to_snapshot().map_err(e)?;
                let mut bo = BackupOptions::default().as_path(PathBuf::from("/synth"));
                bo.parent_opts.ignore_inode = true;
                repo.backup(&bo, &src, snap).map_err(e)?;
            }
            println!(
                "{{\"synth\":{count},\"wall_s\":{}}}",
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::Retention { every, apply } => {
            let keep = match every.as_str() {
                "12h" => KeepOptions::default()
                    .keep_last(14)
                    .keep_weekly(4)
                    .keep_monthly(6),
                "24h" => KeepOptions::default()
                    .keep_last(2)
                    .keep_daily(7)
                    .keep_weekly(4)
                    .keep_monthly(6),
                _ => return Err(anyhow!("every must be 12h or 24h")),
            };
            let repo = Repository::new(&ropts, &be)
                .map_err(e)?
                .open(&c)
                .map_err(e)?;
            let snaps: Vec<SnapshotFile> = repo.get_all_snapshots().map_err(e)?;
            let total = snaps.len();
            let latest_two: Vec<_> = {
                let mut s = snaps.clone();
                s.sort_by(|a, b| b.time.cmp(&a.time));
                s.iter().take(2).map(|x| x.id).collect()
            };
            let now = jiff::Zoned::now();
            let res = keep.apply(snaps, &now).map_err(e)?;
            let kept = res.iter().filter(|f| f.keep).count();
            let drop_ids: Vec<_> = res
                .iter()
                .filter(|f| !f.keep)
                .map(|f| f.snapshot.id)
                .collect();
            // Invariant from architecture 9.7: never delete the two most recent snapshots.
            anyhow::ensure!(
                !drop_ids.iter().any(|d| latest_two.contains(d)),
                "retention would delete one of the two latest snapshots"
            );
            println!(
                "{}",
                serde_json::json!({"policy": every, "total": total, "kept": kept,
                    "dropped": drop_ids.len(), "applied": apply})
            );
            if *apply {
                let t = Instant::now();
                repo.delete_snapshots(&drop_ids).map_err(e)?;
                let del_ms = t.elapsed().as_millis();
                let t = Instant::now();
                let po = PruneOptions::default();
                let plan = repo.prune_plan(&po).map_err(e)?;
                let plan_ms = t.elapsed().as_millis();
                let stats = plan.stats.size_sum();
                let t = Instant::now();
                repo.prune(&po, plan).map_err(e)?;
                println!(
                    "{}",
                    serde_json::json!({"forget_ms": del_ms, "prune_plan_ms": plan_ms,
                        "prune_ms": t.elapsed().as_millis(),
                        "plan_unused": stats.unused, "plan_remove": stats.remove, "plan_repack": stats.repack})
                );
            }
        }
    }
    if cli.repo.starts_with("hxdrive:") {
        println!(
            "{}",
            serde_json::json!({ "drive_stats": hx_stats().snapshot() })
        );
    }
    Ok(())
}
