//! The job specs privd sends (ipc.md section 28) and the `Job` message built from them.
//!
//! The caller of the runner states a [`JobSpec`] in privd's own terms; every field of the wire
//! message that is not the caller's to choose (the manifest input, the snapshot's name, the
//! `forget` list of a prune) is filled in here from privd's own knowledge. The built `Job` is
//! validated with the codec's rules before anything is sent ([`build_job`]), and the worker
//! validates it again (ipc.md section 26, step 3).

use bytes::Bytes;
use hx_backup::manifest::{CURRENT_FORMAT_VERSION, restorable_container_config};
use hx_ipc::repo::{self, Endpoint, pb};
use zeroize::Zeroizing;

use super::completed::{CompletedRecord, Retention, forget_prune_spec};
use super::host::{DesktopFacts, HostKind};

/// What the caller asks a job to do.
#[derive(Debug, Clone)]
pub enum JobSpec {
    /// Create the repository (`create` on `OpenRepo`; the worker refuses an existing one).
    Init,
    /// Back the desktop up.
    Backup(BackupParams),
    /// List the snapshots of the repository.
    Snapshots,
    /// Read the manifest of one snapshot.
    RestorePlan {
        /// The snapshot.
        snapshot_id: [u8; 32],
    },
    /// Restore a snapshot into a new target instance.
    Restore {
        /// The snapshot.
        snapshot_id: [u8; 32],
        /// Resume an interrupted restore (the worker verifies what is already there).
        verify_existing: bool,
        /// Keep the target, success or not, for the restore flow (2C) to resume or promote.
        resumable: bool,
    },
    /// Forget and prune. The `forget` list is built from privd's record of completed backups
    /// (never from a listing of the repository) with these rules.
    ForgetPrune {
        /// The retention rules.
        retention: Retention,
    },
    /// Check the repository.
    Check {
        /// 0 (metadata only) to 100.
        read_data_percent: u32,
    },
    /// Add or remove repository keys.
    Keys {
        /// Add the key of slot 1.
        add: bool,
        /// Key ids to remove (at most 4).
        remove_key_ids: Vec<[u8; 32]>,
    },
}

/// The caller's part of a `BACKUP` spec.
#[derive(Debug, Clone)]
pub struct BackupParams {
    /// The user's excludes (`hx_backup::rules` syntax).
    pub excludes: Vec<String>,
    /// The Docker backup mode.
    pub docker_mode: pb::DockerMode,
    /// Whether Docker is enabled on the desktop.
    pub docker_enabled: bool,
    /// The schedule kind, a tag (`manual`, `scheduled`).
    pub schedule: String,
}

impl Default for BackupParams {
    fn default() -> Self {
        Self {
            excludes: Vec::new(),
            docker_mode: pb::DockerMode::Complete,
            docker_enabled: false,
            schedule: "manual".into(),
        }
    }
}

impl JobSpec {
    /// The wire kind.
    pub fn kind(&self) -> pb::JobKind {
        match self {
            Self::Init => pb::JobKind::Init,
            Self::Backup(_) => pb::JobKind::Backup,
            Self::Snapshots => pb::JobKind::Snapshots,
            Self::RestorePlan { .. } => pb::JobKind::RestorePlan,
            Self::Restore { .. } => pb::JobKind::Restore,
            Self::ForgetPrune { .. } => pb::JobKind::ForgetPrune,
            Self::Check { .. } => pb::JobKind::Check,
            Self::Keys { .. } => pb::JobKind::Keys,
        }
    }

    /// What the helper mounts.
    pub fn host_kind(&self) -> HostKind {
        match self {
            Self::Backup(_) => HostKind::Backup,
            Self::Restore { .. } => HostKind::Restore,
            _ => HostKind::RepositoryOnly,
        }
    }

    /// Whether the job writes to the repository (a back-off refuses it, ipc.md section 31).
    pub fn writes(&self) -> bool {
        writes(self.kind())
    }

    /// Whether the job needs a second secret (`NEW_KEY_PASSWORD`, slot 1).
    pub fn needs_new_key(&self) -> bool {
        matches!(self, Self::Init | Self::Keys { add: true, .. })
    }
}

/// Whether a job of `kind` writes to the repository.
pub fn writes(kind: pb::JobKind) -> bool {
    matches!(
        kind,
        pb::JobKind::Init | pb::JobKind::Backup | pb::JobKind::ForgetPrune | pb::JobKind::Keys
    )
}

/// Why a spec cannot become a `Job`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    /// The codec refused the built `Job` (the rule's name, never content).
    #[error("the job is not valid: {0}")]
    Invalid(String),
    /// A `BACKUP` needs facts about the desktop.
    #[error("the desktop's facts are missing")]
    NoFacts,
}

/// Parses a recipe id (`ubuntu-24.04-xfce-basic`) into the manifest's distro, desktop and preset.
fn recipe_parts(recipe: &str) -> (String, String, String, String, String) {
    let mut it = recipe.splitn(4, '-');
    let (id, ver, desktop, preset) = (
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
    );
    let or_unknown = |s: &str| {
        if s.is_empty() || s.len() > 100 || s.chars().any(char::is_control) {
            "unknown".to_string()
        } else {
            s.to_string()
        }
    };
    let pretty = match id {
        "ubuntu" => format!("Ubuntu {ver}"),
        "debian" => format!("Debian {ver}"),
        _ => or_unknown(id),
    };
    (
        or_unknown(id),
        or_unknown(ver),
        or_unknown(desktop),
        or_unknown(preset),
        pretty,
    )
}

/// The manifest input of a `BACKUP` (ipc.md section 28): the desktop's distro, desktop, preset,
/// the container configuration without `volatile.*` and what the manifest does not allow, the
/// agent version and the backup format version.
pub fn manifest_input(facts: &DesktopFacts, agent_version: &str) -> pb::ManifestInput {
    let (id, version_id, desktop, preset, pretty) = recipe_parts(&facts.recipe);
    let cfg = restorable_container_config(
        facts
            .config
            .iter()
            .filter(|(k, _)| !k.starts_with("volatile.")),
    );
    pb::ManifestInput {
        agent_version: agent_version.chars().take(64).collect(),
        distro: Some(pb::Distro {
            id,
            version_id,
            pretty_name: pretty,
        }),
        desktop,
        preset,
        container_config: cfg
            .config
            .into_iter()
            .map(|(key, value)| pb::ConfigEntry { key, value })
            .collect(),
        format_version: CURRENT_FORMAT_VERSION,
    }
}

/// What [`build_job`] needs besides the spec.
pub struct BuildCtx<'a> {
    /// The 16 random bytes of the job.
    pub job_id: [u8; 16],
    /// The desktop's facts (a `BACKUP`).
    pub facts: Option<&'a DesktopFacts>,
    /// The snapshot's name (a `BACKUP`).
    pub snapshot: Option<&'a str>,
    /// privd's record of completed backups (a `FORGET_PRUNE`).
    pub completed: &'a CompletedRecord,
    /// The agent's version, for the manifest.
    pub agent_version: &'a str,
    /// Length of the secret of slot 0.
    pub slot0_len: usize,
    /// Length of the secret of slot 1, when there is one.
    pub slot1_len: Option<usize>,
}

/// Builds the `Job` message of `spec` and validates it as the worker will.
pub fn build_job(spec: &JobSpec, ctx: &BuildCtx<'_>) -> Result<pb::Job, SpecError> {
    use pb::job::Spec;
    let job_spec = match spec {
        JobSpec::Init => Spec::Init(pb::InitSpec {
            compression: repo::INIT_COMPRESSION,
            datapack_size_limit: repo::INIT_DATAPACK_SIZE_LIMIT,
            treepack_size_limit: repo::INIT_TREEPACK_SIZE_LIMIT,
        }),
        JobSpec::Backup(p) => {
            let facts = ctx.facts.ok_or(SpecError::NoFacts)?;
            let mut tags = Vec::new();
            if let Some(s) = ctx.snapshot {
                tags.push(s.to_string());
            }
            tags.push(p.schedule.clone());
            Spec::Backup(pb::BackupSpec {
                manifest: Some(manifest_input(facts, ctx.agent_version)),
                excludes: p.excludes.clone(),
                docker_mode: p.docker_mode as i32,
                tags,
                docker_enabled: p.docker_enabled,
            })
        }
        JobSpec::Snapshots => Spec::Snapshots(pb::SnapshotsSpec {}),
        JobSpec::RestorePlan { snapshot_id } => Spec::RestorePlan(pb::RestorePlanSpec {
            snapshot_id: Bytes::copy_from_slice(snapshot_id),
        }),
        JobSpec::Restore {
            snapshot_id,
            verify_existing,
            ..
        } => Spec::Restore(pb::RestoreSpec {
            snapshot_id: Bytes::copy_from_slice(snapshot_id),
            verify_existing: *verify_existing,
        }),
        JobSpec::ForgetPrune { retention } => {
            Spec::ForgetPrune(forget_prune_spec(ctx.completed, retention))
        }
        JobSpec::Check { read_data_percent } => Spec::Check(pb::CheckSpec {
            read_data_percent: *read_data_percent,
        }),
        JobSpec::Keys {
            add,
            remove_key_ids,
        } => Spec::Keys(pb::KeysSpec {
            add: *add,
            remove_key_ids: remove_key_ids
                .iter()
                .map(|k| Bytes::copy_from_slice(k))
                .collect(),
        }),
    };
    let mut slots = vec![pb::SecretSlot {
        slot: 0,
        kind: pb::SecretKind::RepoPassword as i32,
        length: u32::try_from(ctx.slot0_len).unwrap_or(u32::MAX),
    }];
    if spec.needs_new_key() {
        slots.push(pb::SecretSlot {
            slot: 1,
            kind: pb::SecretKind::NewKeyPassword as i32,
            length: u32::try_from(ctx.slot1_len.unwrap_or(0)).unwrap_or(u32::MAX),
        });
    }
    let job = pb::Job {
        job_id: Bytes::copy_from_slice(&ctx.job_id),
        kind: spec.kind() as i32,
        secret_slots: slots,
        spec: Some(job_spec),
    };
    let frame = pb::RepoFrame {
        frame: Some(pb::repo_frame::Frame::Job(job.clone())),
    };
    repo::validate_frame(&frame, Endpoint::Worker)
        .map_err(|e| SpecError::Invalid(e.to_string()))?;
    Ok(job)
}

/// The secrets of a job, in slot order. Both buffers are wiped on drop.
pub struct JobSecrets {
    /// Slot 0: the password that opens the repository.
    pub slot0: Zeroizing<Vec<u8>>,
    /// Slot 1: the password of a key being added.
    pub slot1: Option<Zeroizing<Vec<u8>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> DesktopFacts {
        DesktopFacts {
            recipe: "ubuntu-24.04-xfce-basic".into(),
            config: [
                ("limits.cpu", "2"),
                ("limits.memory", "4GiB"),
                ("volatile.idmap.next", "[]"),
                ("security.privileged", "true"),
                ("user.hx.username", "alice"),
                ("root.size", "40GiB"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        }
    }

    #[test]
    fn the_manifest_input_keeps_only_allowed_config_and_never_volatile_keys() {
        let m = manifest_input(&facts(), "0.1.0");
        let keys: Vec<_> = m.container_config.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["limits.cpu", "limits.memory", "root.size"]);
        let d = m.distro.unwrap();
        assert_eq!((d.id.as_str(), d.version_id.as_str()), ("ubuntu", "24.04"));
        assert_eq!(d.pretty_name, "Ubuntu 24.04");
        assert_eq!((m.desktop.as_str(), m.preset.as_str()), ("xfce", "basic"));
        assert_eq!(m.format_version, CURRENT_FORMAT_VERSION);
    }

    #[test]
    fn an_odd_recipe_becomes_unknown_text_not_an_invalid_job() {
        let f = DesktopFacts {
            recipe: "x\u{1b}y".into(),
            config: Default::default(),
        };
        let m = manifest_input(&f, "1");
        assert_eq!(m.distro.unwrap().id, "unknown");
    }

    fn ctx<'a>(
        f: Option<&'a DesktopFacts>,
        rec: &'a CompletedRecord,
        s1: Option<usize>,
    ) -> BuildCtx<'a> {
        BuildCtx {
            job_id: [9; 16],
            facts: f,
            snapshot: Some("hx-backup-20261127T030000Z-ab12"),
            completed: rec,
            agent_version: "0.1.0",
            slot0_len: 43,
            slot1_len: s1,
        }
    }

    #[test]
    fn every_kind_builds_a_job_the_worker_will_accept() {
        let rec = CompletedRecord::default();
        let f = facts();
        let specs = [
            (JobSpec::Init, Some(30)),
            (JobSpec::Backup(BackupParams::default()), None),
            (JobSpec::Snapshots, None),
            (
                JobSpec::RestorePlan {
                    snapshot_id: [1; 32],
                },
                None,
            ),
            (
                JobSpec::Restore {
                    snapshot_id: [1; 32],
                    verify_existing: true,
                    resumable: true,
                },
                None,
            ),
            (
                JobSpec::ForgetPrune {
                    retention: Retention::EVERY_24H,
                },
                None,
            ),
            (
                JobSpec::Check {
                    read_data_percent: 5,
                },
                None,
            ),
            (
                JobSpec::Keys {
                    add: true,
                    remove_key_ids: vec![[2; 32]],
                },
                Some(30),
            ),
            (
                JobSpec::Keys {
                    add: false,
                    remove_key_ids: vec![],
                },
                None,
            ),
        ];
        for (spec, s1) in specs {
            let job = build_job(&spec, &ctx(Some(&f), &rec, s1)).unwrap_or_else(|e| {
                panic!("{:?}: {e}", spec.kind());
            });
            assert_eq!(job.kind, spec.kind() as i32);
            assert_eq!(
                job.secret_slots.len(),
                if spec.needs_new_key() { 2 } else { 1 }
            );
        }
    }

    #[test]
    fn a_job_the_codec_refuses_is_an_error_before_anything_is_created() {
        let rec = CompletedRecord::default();
        let f = facts();
        // A key of 5 bytes is outside 16 to 1024.
        let mut c = ctx(Some(&f), &rec, None);
        c.slot0_len = 5;
        assert!(matches!(
            build_job(&JobSpec::Snapshots, &c),
            Err(SpecError::Invalid(_))
        ));
        // Too many excludes.
        let p = BackupParams {
            excludes: vec!["x".into(); 300],
            ..BackupParams::default()
        };
        assert!(matches!(
            build_job(&JobSpec::Backup(p), &ctx(Some(&f), &rec, None)),
            Err(SpecError::Invalid(_))
        ));
        assert_eq!(
            build_job(
                &JobSpec::Backup(BackupParams::default()),
                &ctx(None, &rec, None)
            )
            .unwrap_err(),
            SpecError::NoFacts
        );
    }

    #[test]
    fn only_the_four_writing_kinds_write() {
        assert!(JobSpec::Init.writes());
        assert!(JobSpec::Backup(BackupParams::default()).writes());
        assert!(
            JobSpec::ForgetPrune {
                retention: Retention::EVERY_12H
            }
            .writes()
        );
        assert!(
            JobSpec::Keys {
                add: false,
                remove_key_ids: vec![]
            }
            .writes()
        );
        assert!(!JobSpec::Snapshots.writes());
        assert!(
            !JobSpec::Check {
                read_data_percent: 0
            }
            .writes()
        );
        assert!(
            !JobSpec::RestorePlan {
                snapshot_id: [1; 32]
            }
            .writes()
        );
    }
}
