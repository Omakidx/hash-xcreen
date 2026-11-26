#![cfg(feature = "engine")]
//! Q-S1 of `docs/ipc.md` section 36: can a compromised `BACKUP` worker, using only what the
//! section 30 policy allows it, make a later legitimate `FORGET_PRUNE` delete pack data that
//! live snapshots need?
//!
//! The attacker holds the repository password (a `BACKUP` worker gets it in slot 0), so it can
//! create validly encrypted `INDEX` and `SNAPSHOT` files and `PACK` files; privd's hash check only
//! proves that an id is the SHA-256 of the body. Through the policy it can list and read
//! everything, write new `PACK`, `INDEX` and `SNAPSHOT` files (never overwrite: ids are content
//! hashes) and remove any `INDEX`. It cannot remove `PACK`, `SNAPSHOT`, `KEY` or `CONFIG` files.
//!
//! Every attacker action goes through [`Policed`], a backend that applies the real
//! `hx_ipc::repo::check_op` for a `BACKUP` job and privd's SHA-256 write check, so each attack is
//! provably within policy (the tests assert nothing was denied). The legitimate `FORGET_PRUNE` runs
//! through a [`Policed`] backend for a `FORGET_PRUNE` job whose spec holds the forgotten snapshot ids,
//! so the mitigation is provably within policy as well.
//!
//! Each scenario is run twice on the real `rustic_core` 0.14.0: with `rustic_core`'s own prune
//! (`instant_delete`), which is what the engine did before the fix, and with `Engine::prune`,
//! which now removes unreadable index files, rebuilds the index from the pack headers, refuses when
//! a pack file is in no index, and reads every copy of a blob that is stored in two packs and checks
//! that it decrypts to its id. Findings are in `docs/ipc.md` section 36.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes256ctr_poly1305aes::{
    Aes256CtrPoly1305Aes,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use bytes::Bytes;
use hx_backup::engine::{
    BackupRequest, CancelToken, Engine, EngineError, EngineOptions, ForgetRequest, KeepRules,
    NullSink, OpenMode, Ownership, ReadData, RepoKey, RepositoryBackends, RestoreRequest,
    SnapshotId, SnapshotSelector,
};
use hx_backup::manifest::{Distro, ManifestInput};
use hx_backup::rules::{DockerMode, RuleSet};
use hx_ipc::repo::{Verdict, check_op, pb};
use jiff::Timestamp;
use rustic_backend::BackendOptions;
use rustic_core::repofile::{IndexFile, SnapshotFile};
use rustic_core::{
    BytesList, Credentials, ErrorKind, FileType, Id, PruneOptions, ReadBackend, RepairIndexOptions,
    Repository, RepositoryOptions, RusticError, RusticResult, WriteBackend,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KEY: &str = "q-s1 correct horse battery staple 77aa";
const BLOB_LEN: usize = 1 << 20;

// ---------------------------------------------------------------------------------------------
// The policy-enforcing backend
// ---------------------------------------------------------------------------------------------

/// Which job the backend plays (section 30).
#[derive(Clone)]
enum Job {
    Backup,
    /// `BACKUP` under a tightened policy (mitigation iii of Q-S1): no `INDEX` removal at all.
    BackupNoIndexRemoval,
    /// `FORGET_PRUNE` with the snapshot ids privd chose.
    ForgetPrune(Vec<SnapshotId>),
}

#[derive(Default)]
struct Log {
    denied: Vec<String>,
    removed_packs: Vec<String>,
    removed_indexes: usize,
    pack_reads: u64,
    pack_read_bytes: u64,
}

/// A backend that refuses what section 30 forbids for its job and, like privd, commits a write only
/// when SHA-256 of the body equals the id (except `CONFIG`).
struct Policed {
    inner: Arc<dyn WriteBackend>,
    job: Job,
    log: Arc<Mutex<Log>>,
}

fn object(t: FileType) -> pb::ObjectType {
    match t {
        FileType::Config => pb::ObjectType::Config,
        FileType::Key => pb::ObjectType::Key,
        FileType::Snapshot => pb::ObjectType::Snapshot,
        FileType::Index => pb::ObjectType::Index,
        FileType::Pack => pb::ObjectType::Pack,
    }
}

fn id_bytes(id: &Id) -> Bytes {
    let hex = id.to_hex();
    let s = hex.as_str();
    Bytes::from(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>(),
    )
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn id_of(data: &[u8]) -> Id {
    hex_of(&Sha256::digest(data)).parse().unwrap()
}

impl Policed {
    fn new(inner: Arc<dyn WriteBackend>, job: Job) -> (Arc<Self>, Arc<Mutex<Log>>) {
        let log = Arc::new(Mutex::new(Log::default()));
        let me = Arc::new(Self {
            inner,
            job,
            log: Arc::clone(&log),
        });
        (me, log)
    }

    fn gate(&self, op: pb::repo_request::Op, what: String) -> RusticResult<()> {
        use pb::repo_request::Op;
        let (kind, spec) = match &self.job {
            Job::Backup | Job::BackupNoIndexRemoval => (pb::JobKind::Backup, None),
            Job::ForgetPrune(ids) => (
                pb::JobKind::ForgetPrune,
                Some(pb::job::Spec::ForgetPrune(pb::ForgetPruneSpec {
                    forget: ids
                        .iter()
                        .map(|i| {
                            Bytes::from(
                                (0..64)
                                    .step_by(2)
                                    .map(|k| u8::from_str_radix(&i.as_str()[k..k + 2], 16).unwrap())
                                    .collect::<Vec<u8>>(),
                            )
                        })
                        .collect(),
                    instant: true,
                })),
            ),
        };
        let tightened = matches!(self.job, Job::BackupNoIndexRemoval)
            && matches!(&op, Op::Remove(r) if r.object_type == pb::ObjectType::Index as i32);
        let verdict = if tightened {
            Verdict::Deny
        } else {
            check_op(kind, spec.as_ref(), &op)
        };
        match verdict {
            Verdict::Allow => Ok(()),
            v => {
                self.log
                    .lock()
                    .unwrap()
                    .denied
                    .push(format!("{what}: {v:?}"));
                Err(RusticError::new(
                    ErrorKind::Backend,
                    "operation denied by the section 30 policy",
                ))
            }
        }
    }
}

impl ReadBackend for Policed {
    fn location(&self) -> String {
        self.inner.location()
    }
    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        self.inner.warmup_path(tpe, id)
    }
    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        self.gate(
            pb::repo_request::Op::List(pb::List {
                object_type: object(tpe) as i32,
            }),
            format!("list {tpe:?}"),
        )?;
        self.inner.list_with_size(tpe)
    }
    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        self.gate(
            pb::repo_request::Op::ReadFull(pb::ReadFull {
                object_type: object(tpe) as i32,
                id: id_bytes(id),
            }),
            format!("read {tpe:?}"),
        )?;
        let r = self.inner.read_full(tpe, id)?;
        if tpe == FileType::Pack {
            let mut l = self.log.lock().unwrap();
            l.pack_reads += 1;
            l.pack_read_bytes += r.len() as u64;
        }
        Ok(r)
    }
    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<Bytes> {
        self.gate(
            pb::repo_request::Op::ReadPartial(pb::ReadPartial {
                object_type: object(tpe) as i32,
                id: id_bytes(id),
                offset,
                length,
            }),
            format!("read partial {tpe:?}"),
        )?;
        let r = self
            .inner
            .read_partial(tpe, id, cacheable, offset, length)?;
        if tpe == FileType::Pack {
            let mut l = self.log.lock().unwrap();
            l.pack_reads += 1;
            l.pack_read_bytes += r.len() as u64;
        }
        Ok(r)
    }
}

impl WriteBackend for Policed {
    fn create(&self) -> RusticResult<()> {
        self.gate(
            pb::repo_request::Op::Create(pb::Create {}),
            "create".to_owned(),
        )?;
        self.inner.create()
    }
    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        self.gate(
            pb::repo_request::Op::Write(pb::Write {
                object_type: object(tpe) as i32,
                id: id_bytes(id),
                size: u32::try_from(content.size()).unwrap(),
            }),
            format!("write {tpe:?}"),
        )?;
        if tpe != FileType::Config {
            let mut h = Sha256::new();
            for b in content.slice() {
                h.update(b);
            }
            if hex_of(&h.finalize()) != id.to_hex().as_str() {
                self.log
                    .lock()
                    .unwrap()
                    .denied
                    .push(format!("write {tpe:?}: INTEGRITY"));
                return Err(RusticError::new(ErrorKind::Backend, "INTEGRITY"));
            }
        }
        self.inner.write_bytes(tpe, id, cacheable, content)
    }
    fn remove(&self, tpe: FileType, id: &Id, cacheable: bool) -> RusticResult<()> {
        self.gate(
            pb::repo_request::Op::Remove(pb::Remove {
                object_type: object(tpe) as i32,
                id: id_bytes(id),
            }),
            format!("remove {tpe:?}"),
        )?;
        if tpe == FileType::Pack {
            self.log
                .lock()
                .unwrap()
                .removed_packs
                .push(id.to_hex().as_str().to_owned());
        }
        if tpe == FileType::Index {
            self.log.lock().unwrap().removed_indexes += 1;
        }
        self.inner.remove(tpe, id, cacheable)
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture: a repository with four snapshots, the oldest pack shared with the newer ones
// ---------------------------------------------------------------------------------------------

fn manifest_input() -> ManifestInput {
    ManifestInput {
        agent_version: "0.1.0-test".into(),
        distro: Distro {
            id: "ubuntu".into(),
            version_id: "24.04".into(),
            pretty_name: None,
        },
        desktop: "xfce4".into(),
        preset: "dev".into(),
        container_config: Default::default(),
    }
}

fn request(source: &Path, time: &str) -> BackupRequest {
    BackupRequest {
        source: source.to_owned(),
        rules: RuleSet::with_defaults(DockerMode::Complete),
        manifest: manifest_input(),
        docker_enabled: false,
        tags: vec!["nightly".into()],
        host: "hx-desktop".into(),
        time: Some(time.parse::<Timestamp>().unwrap()),
    }
}

fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn key() -> RepoKey {
    RepoKey::from_bytes(KEY).unwrap()
}

fn raw_backends(repo: &Path) -> RepositoryBackends {
    BackendOptions::default()
        .repository(repo.to_str().unwrap())
        .to_backends()
        .unwrap()
}

fn open_raw(repo: &Path) -> Engine {
    let o = EngineOptions {
        open_mode: OpenMode::OpenExisting,
        ..EngineOptions::default()
    };
    Engine::open(&raw_backends(repo), &key(), &o, Arc::new(NullSink)).unwrap()
}

/// What snapshot `i` contains: its own blob, and two files shared by all (so the first pack, which
/// holds those, is only partly used once snapshots 0 and 1 are forgotten).
fn expected(i: u64) -> [(&'static str, Vec<u8>); 3] {
    [
        ("data/blob", noise(100 + i, BLOB_LEN)),
        ("data/common", noise(7, 200_000)),
        ("data/keep", noise(50, 300_000)),
    ]
}

struct Fx {
    repo: tempfile::TempDir,
    snaps: Vec<SnapshotId>,
    /// The pack files the attacker wrote.
    decoys: Vec<String>,
}

const TIMES: [&str; 4] = [
    "2026-01-01T00:00:00Z",
    "2026-01-02T00:00:00Z",
    "2026-01-03T00:00:00Z",
    "2026-01-04T00:00:00Z",
];

fn fixture() -> Fx {
    let src = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let o = EngineOptions {
        open_mode: OpenMode::OpenOrInit,
        ..EngineOptions::default()
    };
    let mut engine =
        Engine::open(&raw_backends(repo.path()), &key(), &o, Arc::new(NullSink)).unwrap();
    let mut snaps = Vec::new();
    for (i, t) in TIMES.iter().enumerate() {
        let _ = fs::remove_dir_all(src.path().join("data"));
        fs::create_dir_all(src.path().join("data")).unwrap();
        for (name, bytes) in expected(i as u64) {
            fs::write(src.path().join(name), bytes).unwrap();
        }
        snaps.push(
            engine
                .backup(&request(src.path(), t), &CancelToken::new())
                .unwrap()
                .snapshot_id,
        );
    }
    Fx {
        repo,
        snaps,
        decoys: Vec::new(),
    }
}

// ---------------------------------------------------------------------------------------------
// The attacker: a BACKUP worker with the password, inside the policy
// ---------------------------------------------------------------------------------------------

struct Attacker {
    /// Pack files the attacker wrote (the decoys).
    written: Mutex<Vec<String>>,
    be: Arc<Policed>,
    log: Arc<Mutex<Log>>,
    key: [u8; 64],
    repo: Repository<rustic_core::OpenStatus>,
}

fn key_bytes(m: &rustic_core::repofile::MasterKey) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(&m.encrypt);
    k[32..48].copy_from_slice(&m.mac.k);
    k[48..].copy_from_slice(&m.mac.r);
    k
}

impl Attacker {
    fn new(repo_dir: &Path) -> Self {
        let (be, log) = Policed::new(raw_backends(repo_dir).repository(), Job::Backup);
        let repo = Repository::new(
            &RepositoryOptions::default().no_cache(true),
            &RepositoryBackends::new(be.clone(), None),
        )
        .unwrap()
        .open(&Credentials::Password(KEY.to_owned()))
        .unwrap();
        let key = key_bytes(&repo.key());
        Self {
            written: Mutex::new(Vec::new()),
            be,
            log,
            key,
            repo,
        }
    }

    fn list(&self, t: FileType) -> Vec<Id> {
        self.be.list(t).unwrap()
    }

    fn read(&self, t: FileType, id: &Id) -> Vec<u8> {
        self.be.read_full(t, id).unwrap().to_vec()
    }

    fn put(&self, t: FileType, bytes: Vec<u8>) -> Id {
        let id = id_of(&bytes);
        self.be
            .write_bytes(t, &id, false, BytesList::from(bytes))
            .unwrap();
        if t == FileType::Pack {
            self.written
                .lock()
                .unwrap()
                .push(id.to_hex().as_str().to_owned());
        }
        id
    }

    fn remove(&self, t: FileType, id: &Id) {
        self.be.remove(t, id, false).unwrap();
    }

    /// Mirrors rustic's `Poly1305AES` file encryption; uncompressed JSON is accepted on read.
    fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&u64::try_from(plain.len()).unwrap().to_le_bytes());
        nonce[8..].copy_from_slice(&Sha256::digest(plain)[..8]);
        let mut out = Vec::with_capacity(plain.len() + 32);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let tag = Aes256CtrPoly1305Aes::new(GenericArray::from_slice(&self.key))
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &[], &mut out[16..])
            .unwrap();
        out.extend_from_slice(&tag);
        out
    }

    fn put_index(&self, v: &Value) -> Id {
        self.put(
            FileType::Index,
            self.encrypt(&serde_json::to_vec(v).unwrap()),
        )
    }

    /// The real index files, decrypted (the attacker has the key), as JSON.
    fn indexes(&self) -> Vec<(Id, Value)> {
        self.repo
            .stream_files::<IndexFile>()
            .unwrap()
            .map(|r| {
                let (id, f) = r.unwrap();
                (id.into_inner(), serde_json::to_value(&f).unwrap())
            })
            .collect()
    }

    /// Every pack entry of the real index files, by pack id.
    fn pack_entries(&self) -> Vec<Value> {
        self.indexes()
            .into_iter()
            .flat_map(|(_, v)| v["packs"].as_array().cloned().unwrap_or_default())
            .collect()
    }

    fn remove_all_indexes(&self) {
        for id in self.list(FileType::Index) {
            self.remove(FileType::Index, &id);
        }
    }

    /// A pack with the same (valid, encrypted) header as `real` and a corrupted first blob, whose id
    /// sorts after the real pack's id: when a blob is listed in two packs, rustic's prune counts it
    /// as used in the last pack it processes (`PackInfo::from_pack`) and the earlier copy as unused.
    fn decoy_pack(&self, real: &Id) -> Id {
        let bytes = self.read(FileType::Pack, real);
        for k in 1_u32.. {
            let mut d = bytes.clone();
            for (i, b) in k.to_le_bytes().iter().enumerate() {
                d[i] ^= b;
            }
            if id_of(&d).to_hex().as_str() > real.to_hex().as_str() {
                return self.put(FileType::Pack, d);
            }
        }
        unreachable!()
    }

    /// A pack entry for `entry`'s blobs and size under another pack id.
    fn entry_as(entry: &Value, id: &Id) -> Value {
        let mut e = entry.clone();
        e["id"] = json!(id.to_hex().as_str());
        e
    }

    /// The real data-pack entries (the attacker leaves tree packs alone: prune must still be able to
    /// read the trees to plan at all, and a corrupt tree makes it fail instead of delete).
    fn data_entries(&self) -> Vec<Value> {
        self.pack_entries()
            .into_iter()
            .filter(|e| e["blobs"][0]["type"] == "data")
            .collect()
    }

    fn tree_entries(&self) -> Vec<Value> {
        self.pack_entries()
            .into_iter()
            .filter(|e| e["blobs"][0]["type"] == "tree")
            .collect()
    }

    /// The data packs that hold blobs of snapshots that will be forgotten and of those that will be
    /// kept: the largest one (the first backup's, with the shared files). Prune would repack it,
    /// which reads (and so notices) a decoy; the other packs are fully used or fully unused.
    fn partly_used_pack(&self) -> String {
        self.data_entries()
            .iter()
            .max_by_key(|e| e["blobs"].as_array().unwrap().len())
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A decoy for the real data packs (all of them, or all but the partly used one): same blobs,
    /// other pack, corrupt data.
    fn decoys_for_data(&self, skip_partly_used: bool) -> Vec<Value> {
        let skip = self.partly_used_pack();
        self.data_entries()
            .iter()
            .filter(|e| !(skip_partly_used && e["id"].as_str().unwrap() == skip))
            .map(|e| {
                let real: Id = e["id"].as_str().unwrap().parse().unwrap();
                Self::entry_as(e, &self.decoy_pack(&real))
            })
            .collect()
    }

    /// The attack needed no `INDEX` removal: it works under mitigation (iii) as well.
    fn assert_no_index_removed(&self) {
        assert_eq!(self.log.lock().unwrap().removed_indexes, 0);
    }

    fn assert_in_policy(&self) {
        let l = self.log.lock().unwrap();
        assert!(
            l.denied.is_empty(),
            "the attack left the section 30 policy for BACKUP: {:?}",
            l.denied
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The legitimate FORGET_PRUNE and the assessment
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
struct Outcome {
    /// `None` when the prune ran to the end.
    prune_error: Option<String>,
    /// The prune was refused with `EngineError::Integrity`.
    prune_integrity: bool,
    /// Snapshots that were not forgotten.
    remaining: Vec<SnapshotId>,
    /// Snapshots whose restore failed or produced different bytes.
    restore_bad: Vec<SnapshotId>,
    check_ok: bool,
    check_findings: usize,
    removed_packs: usize,
    denied: Vec<String>,
    /// Pack reads and bytes read by the whole FORGET_PRUNE (headers, repacking, the data check).
    pack_reads: u64,
    pack_read_bytes: u64,
}

impl Outcome {
    fn data_lost(&self) -> bool {
        !self.restore_bad.is_empty() || !self.check_ok
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum How {
    /// `rustic_core`'s prune with `instant_delete`, as `Engine::prune` was before Q-S1.
    RusticPrune,
    /// `Engine::prune`.
    Engine,
}

/// What a legitimate `FORGET_PRUNE` does: privd picks the ids (the keep rules over its own
/// snapshots, the newest two protected), the worker deletes exactly those, then prunes.
/// `extra` are further ids privd decided to forget (forged snapshots it does not recognise).
fn forget_prune(fx: &Fx, how: How, extra: &[SnapshotId]) -> Outcome {
    let cancel = CancelToken::new();
    let mut fr = ForgetRequest::new(KeepRules {
        last: Some(2),
        ..KeepRules::default()
    });
    fr.now = Some("2026-02-01T00:00:00Z".parse().unwrap());
    fr.dry_run = true;
    let mut ids = open_raw(fx.repo.path())
        .forget(&fr, &cancel)
        .unwrap()
        .removed;
    ids.extend_from_slice(extra);

    let (be, log) = Policed::new(
        raw_backends(fx.repo.path()).repository(),
        Job::ForgetPrune(ids.clone()),
    );
    let o = EngineOptions {
        open_mode: OpenMode::OpenExisting,
        ..EngineOptions::default()
    };
    let engine = Engine::open_with_backend(be.clone(), &key(), &o, Arc::new(NullSink)).unwrap();
    // Delete exactly the spec ids with rustic (the engine has no delete-by-id yet).
    let raw = Repository::new(
        &RepositoryOptions::default().no_cache(true),
        &RepositoryBackends::new(be, None),
    )
    .unwrap()
    .open(&Credentials::Password(KEY.to_owned()))
    .unwrap();
    let rids: Vec<_> = ids
        .iter()
        .map(|i| {
            i.as_str()
                .parse::<rustic_core::repofile::SnapshotId>()
                .unwrap()
        })
        .collect();
    raw.delete_snapshots(&rids).unwrap();

    let mut prune_integrity = false;
    let prune_error = match how {
        How::Engine => engine.prune(&cancel).err().map(|e| {
            prune_integrity = matches!(e, EngineError::Integrity { .. });
            e.to_string()
        }),
        How::RusticPrune => {
            let opts = PruneOptions::default().instant_delete(true);
            raw.prune_plan(&opts)
                .and_then(|plan| raw.prune(&opts, plan))
                .err()
                .map(|e| e.display_log().to_string())
        }
    };
    drop(engine);
    let denied = log.lock().unwrap().denied.clone();
    let removed_packs = log.lock().unwrap().removed_packs.len();
    let (pack_reads, pack_read_bytes) = {
        let l = log.lock().unwrap();
        (l.pack_reads, l.pack_read_bytes)
    };

    let remaining: Vec<SnapshotId> = fx
        .snaps
        .iter()
        .filter(|s| !ids.contains(s))
        .cloned()
        .collect();
    let (check_ok, check_findings) = match open_raw(fx.repo.path()).check(ReadData::All, &cancel) {
        Ok(r) => (r.ok, r.findings.len()),
        Err(_) => (false, 1),
    };
    let mut restore_bad = Vec::new();
    for s in &remaining {
        if !restores_correctly(fx, s) {
            restore_bad.push(s.clone());
        }
    }
    Outcome {
        prune_error,
        prune_integrity,
        remaining,
        restore_bad,
        check_ok,
        check_findings,
        removed_packs,
        denied,
        pack_reads,
        pack_read_bytes,
    }
}

fn restores_correctly(fx: &Fx, snap: &SnapshotId) -> bool {
    let i = fx.snaps.iter().position(|s| s == snap).unwrap() as u64;
    let dst = tempfile::tempdir().unwrap();
    let mut rq = RestoreRequest::new(SnapshotSelector::Id(snap.clone()), dst.path());
    rq.ownership = Ownership::Skip;
    let Ok(mut engine) = Engine::open(
        &raw_backends(fx.repo.path()),
        &key(),
        &EngineOptions::default(),
        Arc::new(NullSink),
    ) else {
        return false;
    };
    // rustic_core 0.14.0 panics inside restore (restore.rs:657, an unwrap on the blob decryption)
    // when a pack holds corrupt data, instead of returning an error; both mean "did not restore".
    let restored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.restore(&rq, &CancelToken::new()).is_ok()
    }));
    if !restored.unwrap_or(false) {
        return false;
    }
    expected(i)
        .iter()
        .all(|(name, bytes)| fs::read(dst.path().join(name)).is_ok_and(|b| &b == bytes))
}

fn show(name: &str, how: How, o: &Outcome) {
    eprintln!(
        "{name} [{how:?}]: prune={} data_lost={} check_ok={} (findings {}) restore_bad={}/{} packs_removed={}",
        o.prune_error
            .as_deref()
            .map_or("ok".to_owned(), |e| format!(
                "ERR({})",
                e.chars().take(60).collect::<String>()
            )),
        o.data_lost(),
        o.check_ok,
        o.check_findings,
        o.restore_bad.len(),
        o.remaining.len(),
        o.removed_packs,
    );
}

/// Run `attack` on a fresh fixture, then a legitimate forget and prune the given way.
fn scenario(name: &str, how: How, attack: impl FnOnce(&Attacker, &Fx)) -> (Outcome, Fx) {
    let mut fx = fixture();
    let a = Attacker::new(fx.repo.path());
    attack(&a, &fx);
    a.assert_in_policy();
    fx.decoys = a.written.lock().unwrap().clone();
    drop(a);
    let o = forget_prune(&fx, how, &[]);
    assert!(
        o.denied.is_empty(),
        "the legitimate FORGET_PRUNE left its policy: {:?}",
        o.denied
    );
    show(name, how, &o);
    (o, fx)
}

// ---------------------------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------------------------

#[test]
fn baseline_without_attack_prune_is_safe_both_ways() {
    for how in [How::RusticPrune, How::Engine] {
        let (o, _) = scenario("baseline", how, |_, _| {});
        assert_eq!(o.prune_error, None);
        assert!(!o.data_lost(), "{o:?}");
        assert_eq!(o.remaining.len(), 2);
        assert!(
            o.removed_packs > 0,
            "prune freed the forgotten snapshots' packs"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// a. remove every INDEX; b. forged indexes that make blobs unfindable
// ---------------------------------------------------------------------------------------------

#[test]
fn a_removing_every_index_stops_rustic_prune_without_loss_and_engine_prune_heals() {
    let attack = |a: &Attacker, _: &Fx| a.remove_all_indexes();
    let (o, _) = scenario("a", How::RusticPrune, attack);
    assert!(
        o.prune_error.is_some(),
        "no index: prune cannot find the trees"
    );
    assert_eq!(o.removed_packs, 0, "nothing is deleted when the plan fails");
    assert!(
        !o.check_ok,
        "the repository stays unusable until the next repair index"
    );
    let (o, _) = scenario("a", How::Engine, attack);
    assert_eq!(
        o.prune_error, None,
        "the pack-header scan rebuilds the index"
    );
    assert!(!o.data_lost(), "{o:?}");
}

#[test]
fn b1_forged_index_with_bogus_blob_ids_for_real_packs_stops_prune_without_loss() {
    let attack = |a: &Attacker, _: &Fx| {
        let forged: Vec<Value> = a
            .pack_entries()
            .into_iter()
            .map(|mut e| {
                for (i, b) in e["blobs"].as_array_mut().unwrap().iter_mut().enumerate() {
                    b["id"] = json!(hex_of(&Sha256::digest(format!("bogus{i}"))));
                }
                e
            })
            .collect();
        a.remove_all_indexes();
        a.put_index(&json!({ "packs": forged }));
    };
    let (o, _) = scenario("b1", How::RusticPrune, attack);
    assert!(o.prune_error.is_some());
    assert_eq!(o.removed_packs, 0);
    let (o, _) = scenario("b1", How::Engine, attack);
    assert_eq!(o.prune_error, None);
    assert!(!o.data_lost(), "{o:?}");
}

#[test]
fn b2_forged_entry_for_a_real_pack_with_fewer_blobs_stops_prune_without_loss() {
    // The real indexes stay. The forged entry has an earlier time, so rustic keeps it and drops the
    // real entry of the same pack id: the pack's other blobs become unindexed.
    let attack = |a: &Attacker, _: &Fx| {
        let mut forged = Vec::new();
        for mut e in a.pack_entries() {
            e["blobs"].as_array_mut().unwrap().truncate(1);
            e["time"] = json!("2000-01-01T00:00:00Z");
            forged.push(e);
        }
        a.put_index(&json!({ "packs": forged }));
        a.assert_no_index_removed();
    };
    let (o, _) = scenario("b2", How::RusticPrune, attack);
    assert!(o.prune_error.is_some());
    assert_eq!(o.removed_packs, 0);
    let (o, _) = scenario("b2", How::Engine, attack);
    assert_eq!(o.prune_error, None);
    assert!(!o.data_lost(), "{o:?}");
}

#[test]
fn b3_forged_entry_with_a_wrong_pack_size_stops_prune_without_loss() {
    let attack = |a: &Attacker, _: &Fx| {
        let sizes = a.be.list_with_size(FileType::Pack).unwrap();
        let mut forged = Vec::new();
        for mut e in a.pack_entries() {
            let id: Id = e["id"].as_str().unwrap().parse().unwrap();
            let real = sizes.iter().find(|(i, _)| *i == id).unwrap().1;
            e["size"] = json!(real + 1);
            e["time"] = json!("2000-01-01T00:00:00Z");
            forged.push(e);
        }
        a.put_index(&json!({ "packs": forged }));
        a.assert_no_index_removed();
    };
    let (o, _) = scenario("b3", How::RusticPrune, attack);
    assert!(o.prune_error.is_some());
    assert_eq!(o.removed_packs, 0);
    let (o, _) = scenario("b3", How::Engine, attack);
    assert_eq!(o.prune_error, None);
    assert!(!o.data_lost(), "{o:?}");
}

// ---------------------------------------------------------------------------------------------
// c. decoy packs: the blobs of every real pack listed under a pack that holds garbage
// ---------------------------------------------------------------------------------------------

/// Only the decoy index remains: every real pack is unindexed, so rustic's prune deletes it.
fn attack_c1(a: &Attacker, _: &Fx) {
    let mut packs = a.tree_entries();
    packs.extend(a.decoys_for_data(false));
    a.remove_all_indexes();
    a.put_index(&json!({ "packs": packs }));
}

/// No index is removed: the decoy index is added, and its packs sort after the real ones, so
/// rustic counts the blobs as used in the decoys and the real packs as unused.
fn attack_c2(a: &Attacker, _: &Fx) {
    let decoys = a.decoys_for_data(true);
    a.put_index(&json!({ "packs": decoys }));
    a.assert_no_index_removed();
}

/// No index is removed and no id is chosen: the forged index marks each real pack as deleted with
/// an early time (rustic keeps the earliest entry per pack id) and lists the blobs in the decoy.
fn attack_c3(a: &Attacker, _: &Fx) {
    let entries = a.data_entries();
    let decoys = a.decoys_for_data(false);
    let marked: Vec<Value> = entries
        .iter()
        .map(|e| {
            let mut m = e.clone();
            m["blobs"] = json!([]);
            m["time"] = json!("2000-01-01T00:00:00Z");
            m
        })
        .collect();
    a.put_index(&json!({ "packs": decoys, "packs_to_delete": marked }));
    a.assert_no_index_removed();
}

/// The attacker writes only the decoy PACK files. The next legitimate BACKUP runs `repair index`,
/// which indexes them from their (valid) headers.
fn attack_c4(a: &Attacker, fx: &Fx) {
    let skip = a.partly_used_pack();
    for e in a.data_entries() {
        if e["id"].as_str().unwrap() == skip {
            continue;
        }
        let real: Id = e["id"].as_str().unwrap().parse().unwrap();
        let _ = a.decoy_pack(&real);
    }
    // The next BACKUP job (a different, honest worker) opens the repository and repairs the index.
    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("data")).unwrap();
    fs::write(src.path().join("data/blob"), noise(100 + 3, BLOB_LEN)).unwrap();
    fs::write(src.path().join("data/common"), noise(7, 200_000)).unwrap();
    fs::write(src.path().join("data/keep"), noise(50, 300_000)).unwrap();
    let mut e = open_raw(fx.repo.path());
    e.backup(
        &request(src.path(), "2026-01-04T12:00:00Z"),
        &CancelToken::new(),
    )
    .unwrap();
}

#[test]
fn c1_only_a_decoy_index_makes_rustic_prune_delete_every_real_pack() {
    let (o, _) = scenario("c1", How::RusticPrune, attack_c1);
    assert_eq!(
        o.prune_error, None,
        "the plan is consistent, so prune goes ahead"
    );
    assert!(o.removed_packs > 0);
    assert!(o.data_lost(), "DATA LOSS: {o:?}");
    assert_eq!(o.restore_bad.len(), o.remaining.len());
    assert!(!o.check_ok);
}

#[test]
fn c1_engine_prune_refuses_and_keeps_every_real_pack() {
    let (o, fx) = scenario("c1", How::Engine, attack_c1);
    assert!(
        o.prune_integrity,
        "a decoy copy fails verification: {:?}",
        o.prune_error
    );
    assert_eq!(o.removed_packs, 0);
    // The real packs are all still there: dropping the decoys and repairing restores everything.
    assert_recoverable(&fx, &o);
}

#[test]
fn c2_a_decoy_index_added_beside_the_real_ones_makes_rustic_prune_delete_real_packs() {
    let (o, _) = scenario("c2", How::RusticPrune, attack_c2);
    assert_eq!(o.prune_error, None);
    assert!(o.data_lost(), "DATA LOSS: {o:?}");
}

#[test]
fn c2_engine_prune_refuses_and_keeps_every_real_pack() {
    let (o, fx) = scenario("c2", How::Engine, attack_c2);
    assert!(o.prune_integrity, "{:?}", o.prune_error);
    assert_eq!(o.removed_packs, 0);
    assert_recoverable(&fx, &o);
}

#[test]
fn c3_marking_real_packs_deleted_makes_rustic_prune_delete_them_whatever_the_ids() {
    let (o, _) = scenario("c3", How::RusticPrune, attack_c3);
    assert_eq!(o.prune_error, None);
    assert!(o.data_lost(), "DATA LOSS: {o:?}");
}

#[test]
fn c3_engine_prune_refuses_and_keeps_every_real_pack() {
    let (o, fx) = scenario("c3", How::Engine, attack_c3);
    assert!(o.prune_integrity, "{:?}", o.prune_error);
    assert_eq!(o.removed_packs, 0);
    assert_recoverable(&fx, &o);
}

#[test]
fn c4_decoy_packs_alone_are_indexed_by_the_next_backup_and_rustic_prune_deletes_real_packs() {
    let (o, _) = scenario("c4", How::RusticPrune, attack_c4);
    assert_eq!(o.prune_error, None);
    assert!(o.data_lost(), "DATA LOSS: {o:?}");
}

#[test]
fn c4_engine_prune_refuses_and_keeps_every_real_pack() {
    let (o, fx) = scenario("c4", How::Engine, attack_c4);
    assert!(o.prune_integrity, "{:?}", o.prune_error);
    assert_eq!(o.removed_packs, 0);
    assert_recoverable(&fx, &o);
}

/// After a refused prune the real packs are intact: removing the packs the attacker wrote (a
/// `FORGET_PRUNE` job may remove `PACK` files) and re-indexing from the pack headers gives a
/// repository whose remaining snapshots all restore and whose data check passes.
fn assert_recoverable(fx: &Fx, o: &Outcome) {
    let be = raw_backends(fx.repo.path()).repository();
    for id in be.list(FileType::Pack).unwrap() {
        if fx.decoys.contains(&id.to_hex().as_str().to_owned()) {
            be.remove(FileType::Pack, &id, false).unwrap();
        }
    }
    let repo = Repository::new(
        &RepositoryOptions::default().no_cache(true),
        &raw_backends(fx.repo.path()),
    )
    .unwrap()
    .open(&Credentials::Password(KEY.to_owned()))
    .unwrap();
    repo.repair_index(&RepairIndexOptions::default().read_all(true), false)
        .unwrap();
    let report = open_raw(fx.repo.path())
        .check(ReadData::All, &CancelToken::new())
        .unwrap();
    assert!(report.ok, "{:?}", report.findings);
    for s in &o.remaining {
        assert!(restores_correctly(fx, s), "snapshot {s} after recovery");
    }
}

// ---------------------------------------------------------------------------------------------
// e. the repack path: offsets swapped inside a real, partly used pack
// ---------------------------------------------------------------------------------------------

/// The real entry of every pack is replaced (earlier time) by one whose blobs point at each
/// other's bytes: every location is a valid ciphertext, so repacking decrypts without error and
/// stores the wrong content under the blob id; the old pack is then deleted.
fn attack_e1(a: &Attacker, _: &Fx) {
    let mut forged = Vec::new();
    for mut e in a.data_entries() {
        let blobs = e["blobs"].as_array_mut().unwrap();
        if blobs.len() >= 2 {
            let n = blobs.len();
            let locs: Vec<Value> = blobs
                .iter()
                .map(|b| {
                    json!({ "offset": b["offset"], "length": b["length"],
                            "uncompressed_length": b["uncompressed_length"] })
                })
                .collect();
            for (i, b) in blobs.iter_mut().enumerate() {
                let l = &locs[(i + 1) % n];
                b["offset"] = l["offset"].clone();
                b["length"] = l["length"].clone();
                match l.get("uncompressed_length") {
                    Some(u) if !u.is_null() => b["uncompressed_length"] = u.clone(),
                    _ => {
                        b.as_object_mut().unwrap().remove("uncompressed_length");
                    }
                }
            }
        }
        e["time"] = json!("2000-01-01T00:00:00Z");
        forged.push(e);
    }
    a.put_index(&json!({ "packs": forged }));
    a.assert_no_index_removed();
}

#[test]
fn e1_swapped_blob_locations_make_rustic_prune_repack_wrong_bytes_under_a_blob_id() {
    let (o, _) = scenario("e1", How::RusticPrune, attack_e1);
    eprintln!("e1 rustic outcome: {o:?}");
    // Recorded, not asserted either way beyond "the outcome is what the doc says".
    assert!(
        o.data_lost() || o.prune_error.is_some(),
        "an attack that changes nothing is no attack: {o:?}"
    );
}

#[test]
fn e1_engine_prune_is_safe() {
    let (o, _) = scenario("e1", How::Engine, attack_e1);
    assert_eq!(
        o.prune_error, None,
        "the header scan restores the real locations"
    );
    assert!(!o.data_lost(), "{o:?}");
}

// ---------------------------------------------------------------------------------------------
// d. forged SNAPSHOT files
// ---------------------------------------------------------------------------------------------

fn forged_snapshot(a: &Attacker, mutate: impl FnOnce(&mut SnapshotFile)) -> SnapshotId {
    let mut snap = a.repo.get_all_snapshots().unwrap().remove(0);
    mutate(&mut snap);
    let id = a.put(
        FileType::Snapshot,
        a.encrypt(&serde_json::to_vec(&snap).unwrap()),
    );
    id.to_hex().as_str().parse().unwrap()
}

#[test]
fn d1_a_forged_snapshot_with_a_missing_tree_blocks_prune_until_privd_forgets_it() {
    // The forged snapshot is dated in the future, so keep-last keeps it; its tree does not exist.
    let with_forged = || {
        let fx = fixture();
        let a = Attacker::new(fx.repo.path());
        let forged = forged_snapshot(&a, |s| {
            s.tree = "ab".repeat(32).parse().unwrap();
            s.time = s.time.checked_add(jiff::Span::new().days(30)).unwrap();
            s.description = Some("forged".to_owned());
        });
        a.assert_in_policy();
        (fx, forged)
    };

    // privd takes its retention from the repository listing and does not forget the stranger:
    // prune cannot load the tree, and keeps failing until someone forgets that snapshot.
    for how in [How::RusticPrune, How::Engine] {
        let (fx, _) = with_forged();
        let o = forget_prune(&fx, how, &[]);
        show("d1", how, &o);
        assert!(o.prune_error.is_some(), "tree missing: {o:?}");
        assert_eq!(
            o.removed_packs, 0,
            "nothing is deleted, but nothing is freed either"
        );
    }

    // privd knows its own snapshots from its job records and puts the stranger in `forget`.
    let (fx, forged) = with_forged();
    let o = forget_prune(&fx, How::Engine, std::slice::from_ref(&forged));
    show("d1+forget", How::Engine, &o);
    assert_eq!(o.prune_error, None, "{o:?}");
    assert!(!o.data_lost(), "{o:?}");
}

#[test]
fn d2_a_forged_snapshot_on_an_old_tree_only_keeps_data_alive() {
    let fx = fixture();
    let a = Attacker::new(fx.repo.path());
    let old = a
        .repo
        .get_all_snapshots()
        .unwrap()
        .into_iter()
        .find(|s| s.id.to_hex().as_str() == fx.snaps[0].as_str())
        .unwrap()
        .tree;
    let _ = forged_snapshot(&a, |s| {
        s.tree = old;
        s.time = s.time.checked_add(jiff::Span::new().days(30)).unwrap();
    });
    a.assert_in_policy();
    drop(a);
    // The forged snapshot is the newest: keep-last 2 now keeps it and the real newest one, and the
    // real snapshots 0 to 2 are forgotten (privd must pick ids only among its own snapshots).
    let o = forget_prune(&fx, How::Engine, &[]);
    assert_eq!(o.prune_error, None, "{o:?}");
    assert!(!o.data_lost(), "{o:?}");
    assert!(
        o.remaining.len() < 2,
        "retention counted the stranger: {:?}",
        o.remaining
    );
}

#[test]
fn d3_forged_future_snapshots_displace_every_real_snapshot_in_engine_forget() {
    let fx = fixture();
    let a = Attacker::new(fx.repo.path());
    for n in 0..2 {
        let _ = forged_snapshot(&a, |s| {
            s.time = s.time.checked_add(jiff::Span::new().days(400 + n)).unwrap();
            s.description = Some(format!("forged {n}"));
        });
    }
    a.assert_in_policy();
    drop(a);
    let mut fr = ForgetRequest::new(KeepRules {
        last: Some(2),
        ..KeepRules::default()
    });
    fr.now = Some("2026-02-01T00:00:00Z".parse().unwrap());
    fr.dry_run = true;
    let plan = open_raw(fx.repo.path())
        .forget(&fr, &CancelToken::new())
        .unwrap();
    // The two forged snapshots fill both keep-last slots and both protected slots: all four real
    // snapshots are chosen for removal. A retention decision taken from the repository's own
    // listing is attacker-controlled.
    assert_eq!(plan.removed.len(), 4, "{plan:?}");
    for s in &fx.snaps {
        assert!(plan.removed.contains(s));
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluation of the other candidate mitigations of Q-S1
// ---------------------------------------------------------------------------------------------

/// Mitigation (iii), no `INDEX` removal for `BACKUP`: the attacks that do not remove indexes (b2,
/// b3, c2, c3, e1 assert that above) work all the same, so it closes nothing by itself. What the
/// removal is for: healing an index that lists a pack that no longer exists (after an interrupted
/// prune), which `repair index` does at the start of every backup.
#[test]
fn backup_repair_index_removes_indexes_only_to_heal_entries_of_missing_packs() {
    let fx = fixture();
    // An index file that lists a pack that does not exist (what an interrupted prune leaves).
    let a = Attacker::new(fx.repo.path());
    let mut stale = a.pack_entries().remove(0);
    stale["id"] = json!("cd".repeat(32));
    a.put_index(&json!({ "packs": [stale] }));
    drop(a);

    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("data")).unwrap();
    fs::write(src.path().join("data/blob"), noise(9, 10_000)).unwrap();

    let o = EngineOptions {
        open_mode: OpenMode::OpenExisting,
        ..EngineOptions::default()
    };
    let (be, log) = Policed::new(
        raw_backends(fx.repo.path()).repository(),
        Job::BackupNoIndexRemoval,
    );
    let mut engine = Engine::open_with_backend(be, &key(), &o, Arc::new(NullSink)).unwrap();
    let r = engine.backup(
        &request(src.path(), "2026-01-05T00:00:00Z"),
        &CancelToken::new(),
    );
    assert!(r.is_err(), "without INDEX removal the repair cannot heal");
    assert!(
        log.lock()
            .unwrap()
            .denied
            .iter()
            .any(|d| d.contains("remove Index")),
        "{:?}",
        log.lock().unwrap().denied
    );

    let (be, log) = Policed::new(raw_backends(fx.repo.path()).repository(), Job::Backup);
    let mut engine = Engine::open_with_backend(be, &key(), &o, Arc::new(NullSink)).unwrap();
    engine
        .backup(
            &request(src.path(), "2026-01-05T00:00:00Z"),
            &CancelToken::new(),
        )
        .unwrap();
    assert!(log.lock().unwrap().removed_indexes > 0);
    assert!(log.lock().unwrap().denied.is_empty());
}

/// Mitigation (ii) taken from rustic itself: without `instant_delete` prune only marks packs and
/// deletes them 23 hours later. The attack still succeeds, but the files are still there for a
/// day; nothing notices in that time unless something reads the data in between.
#[test]
fn c1_without_instant_delete_the_real_packs_are_marked_and_still_on_disk() {
    let mut fx = fixture();
    let before: Vec<Id> = raw_backends(fx.repo.path())
        .repository()
        .list(FileType::Pack)
        .unwrap();
    let a = Attacker::new(fx.repo.path());
    attack_c1(&a, &fx);
    fx.decoys = a.written.lock().unwrap().clone();
    drop(a);
    let (be, _) = Policed::new(
        raw_backends(fx.repo.path()).repository(),
        Job::ForgetPrune(Vec::new()),
    );
    let raw = Repository::new(
        &RepositoryOptions::default().no_cache(true),
        &RepositoryBackends::new(be, None),
    )
    .unwrap()
    .open(&Credentials::Password(KEY.to_owned()))
    .unwrap();
    let opts = PruneOptions::default();
    raw.prune_plan(&opts)
        .and_then(|plan| raw.prune(&opts, plan))
        .unwrap();
    let after: Vec<Id> = raw_backends(fx.repo.path())
        .repository()
        .list(FileType::Pack)
        .unwrap();
    for id in &before {
        assert!(
            after.contains(id),
            "pack {} was deleted at once",
            id.to_hex().as_str()
        );
    }
    // ... and the data is unreadable through the index until a repair index brings the packs back.
    let report = open_raw(fx.repo.path())
        .check(ReadData::All, &CancelToken::new())
        .unwrap();
    assert!(!report.ok);
}

/// A pack file with no readable header is in no index after `repair index`. rustic's prune deletes it
/// as unreferenced (harmless for junk, but the same code path deletes a real pack whose header read
/// failed). `Engine::prune` refuses instead: this is the price, a junk file written by the attacker
/// stops pruning until it is removed.
#[test]
fn a_junk_pack_blocks_engine_prune_and_is_deleted_by_rustic_prune() {
    let junk = || {
        let fx = fixture();
        let a = Attacker::new(fx.repo.path());
        let id = a.put(FileType::Pack, noise(1, 5_000));
        a.assert_in_policy();
        (fx, id)
    };
    let (fx, id) = junk();
    let o = forget_prune(&fx, How::Engine, &[]);
    assert!(
        o.prune_error
            .as_deref()
            .is_some_and(|e| e.contains("no readable header")),
        "{o:?}"
    );
    assert_eq!(o.removed_packs, 0);
    assert!(
        raw_backends(fx.repo.path())
            .repository()
            .list(FileType::Pack)
            .unwrap()
            .contains(&id)
    );
    let (fx, _) = junk();
    let o = forget_prune(&fx, How::RusticPrune, &[]);
    assert_eq!(o.prune_error, None, "{o:?}");
    assert!(!o.data_lost());
}

/// The cost of the check in the engine: one listing, one header read per pack and the index files
/// on top of what prune reads anyway.
#[test]
fn engine_prune_reads_pack_headers_only_on_a_healthy_repository() {
    let fx = fixture();
    let packs = raw_backends(fx.repo.path())
        .repository()
        .list_with_size(FileType::Pack)
        .unwrap();
    let total: u64 = packs.iter().map(|(_, s)| u64::from(*s)).sum();
    let rustic = forget_prune(&fx, How::RusticPrune, &[]);
    let fx2 = fixture();
    let engine = forget_prune(&fx2, How::Engine, &[]);
    eprintln!(
        "cost: {} packs, {total} bytes; rustic prune read {} bytes in {} reads, engine prune {} bytes in {} reads",
        packs.len(),
        rustic.pack_read_bytes,
        rustic.pack_reads,
        engine.pack_read_bytes,
        engine.pack_reads
    );
    assert_eq!(engine.prune_error, None);
    assert!(!engine.data_lost());
    let extra = engine
        .pack_read_bytes
        .saturating_sub(rustic.pack_read_bytes);
    assert!(
        extra * 20 < total,
        "header scan read {extra} bytes of {total}: it must not read pack data"
    );
    assert!(engine.pack_reads <= rustic.pack_reads + 2 * packs.len() as u64);
}

// ---------------------------------------------------------------------------------------------
// Availability: interrupted prunes, junk index files, killed or failed rebuilds (review of Q-S1)
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Faults {
    /// Panic at this pack read (1-based): a process killed in the middle of the header scan.
    panic_at_pack_read: Option<u64>,
    /// Fail this one pack read: a transient Drive error.
    error_at_pack_read: Option<u64>,
    /// Fail every pack read from this one on.
    error_from_pack_read: Option<u64>,
    /// Fail every pack removal: a Drive error while a prune deletes packs.
    fail_pack_remove: bool,
    pack_reads: u64,
}

/// A backend that injects faults into pack reads and removals.
struct Faulty {
    inner: Arc<dyn WriteBackend>,
    f: Mutex<Faults>,
}

impl Faulty {
    fn on_pack_read(&self) -> RusticResult<()> {
        let mut f = self.f.lock().unwrap();
        f.pack_reads += 1;
        let n = f.pack_reads;
        if f.panic_at_pack_read == Some(n) {
            drop(f);
            panic!("simulated kill at pack read {n}");
        }
        if f.error_at_pack_read == Some(n) || f.error_from_pack_read.is_some_and(|from| n >= from) {
            return Err(RusticError::new(
                ErrorKind::Backend,
                "simulated transient read error",
            ));
        }
        Ok(())
    }
}

impl ReadBackend for Faulty {
    fn location(&self) -> String {
        self.inner.location()
    }
    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        self.inner.warmup_path(tpe, id)
    }
    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        self.inner.list_with_size(tpe)
    }
    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        if tpe == FileType::Pack {
            self.on_pack_read()?;
        }
        self.inner.read_full(tpe, id)
    }
    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<Bytes> {
        if tpe == FileType::Pack {
            self.on_pack_read()?;
        }
        self.inner.read_partial(tpe, id, cacheable, offset, length)
    }
}

impl WriteBackend for Faulty {
    fn create(&self) -> RusticResult<()> {
        self.inner.create()
    }
    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        self.inner.write_bytes(tpe, id, cacheable, content)
    }
    fn remove(&self, tpe: FileType, id: &Id, cacheable: bool) -> RusticResult<()> {
        if tpe == FileType::Pack && self.f.lock().unwrap().fail_pack_remove {
            return Err(RusticError::new(
                ErrorKind::Backend,
                "simulated Drive error on delete",
            ));
        }
        self.inner.remove(tpe, id, cacheable)
    }
}

fn faulty_backend(fx: &Fx, f: Faults) -> Arc<Faulty> {
    Arc::new(Faulty {
        inner: raw_backends(fx.repo.path()).repository(),
        f: Mutex::new(f),
    })
}

fn engine_on(be: Arc<dyn WriteBackend>) -> Engine {
    let o = EngineOptions {
        open_mode: OpenMode::OpenExisting,
        ..EngineOptions::default()
    };
    Engine::open_with_backend(be, &key(), &o, Arc::new(NullSink)).unwrap()
}

fn rustic_repo(be: Arc<dyn WriteBackend>) -> Repository<rustic_core::OpenStatus> {
    Repository::new(
        &RepositoryOptions::default().no_cache(true),
        &RepositoryBackends::new(be, None),
    )
    .unwrap()
    .open(&Credentials::Password(KEY.to_owned()))
    .unwrap()
}

fn forget_oldest_two(fx: &Fx) {
    let raw = rustic_repo(raw_backends(fx.repo.path()).repository());
    let rids: Vec<_> = fx.snaps[..2]
        .iter()
        .map(|i| {
            i.as_str()
                .parse::<rustic_core::repofile::SnapshotId>()
                .unwrap()
        })
        .collect();
    raw.delete_snapshots(&rids).unwrap();
}

fn n_files(fx: &Fx, t: FileType) -> usize {
    raw_backends(fx.repo.path())
        .repository()
        .list(t)
        .unwrap()
        .len()
}

fn all_restore(fx: &Fx, snaps: &[SnapshotId]) -> bool {
    snaps.iter().all(|s| restores_correctly(fx, s))
}

/// H2: a prune interrupted after it repacked (a Drive error while it deletes the old packs) leaves
/// every repacked blob in two packs. The next prune must verify the copies, find them good and go
/// ahead, instead of refusing for good.
#[test]
fn h2_a_prune_interrupted_after_repacking_does_not_block_the_next_prune() {
    let fx = fixture();
    forget_oldest_two(&fx);
    let packs_before = n_files(&fx, FileType::Pack);
    let raw = rustic_repo(faulty_backend(
        &fx,
        Faults {
            fail_pack_remove: true,
            ..Faults::default()
        },
    ));
    // Force the repack of the partly used packs (what a prune of a real repository does).
    let opts = PruneOptions::default()
        .instant_delete(true)
        .max_repack(rustic_core::LimitOption::Unlimited)
        .max_unused(rustic_core::LimitOption::Percentage(0));
    let plan = raw.prune_plan(&opts).unwrap();
    assert!(plan.stats.size_sum().repack > 0, "the plan repacks");
    assert!(
        raw.prune(&opts, plan).is_err(),
        "interrupted by the Drive error"
    );
    drop(raw);
    assert!(
        n_files(&fx, FileType::Pack) > packs_before,
        "the repacked packs exist next to the old ones"
    );
    let remaining = fx.snaps[2..].to_vec();
    assert!(
        all_restore(&fx, &remaining),
        "restores work after the interruption"
    );

    let o = open_raw(fx.repo.path())
        .prune(&CancelToken::new())
        .map_err(|e| e.to_string());
    assert!(o.is_ok(), "the next prune goes ahead: {o:?}");
    let report = open_raw(fx.repo.path())
        .check(ReadData::All, &CancelToken::new())
        .unwrap();
    assert!(report.ok, "{:?}", report.findings);
    assert!(all_restore(&fx, &remaining));
    assert!(
        n_files(&fx, FileType::Pack) <= packs_before,
        "the extra copies are gone"
    );
}

/// H2: the same repository with a decoy among the copies is still refused (c1 to c4 above assert
/// the same for the decoy scenarios); here the decoy is the second copy of a repacked blob.
#[test]
fn h2_a_corrupt_copy_among_honest_duplicates_is_refused_naming_the_pack() {
    let mut fx = fixture();
    let a = Attacker::new(fx.repo.path());
    attack_c2(&a, &fx);
    fx.decoys = a.written.lock().unwrap().clone();
    drop(a);
    let err = open_raw(fx.repo.path())
        .prune(&CancelToken::new())
        .unwrap_err();
    let EngineError::Integrity { finding } = err else {
        panic!("not an integrity error: {err}");
    };
    assert!(
        fx.decoys.iter().any(|d| finding.contains(&d[..64])),
        "the finding names a decoy pack: {finding}"
    );
}

/// H1: junk INDEX files (hash-valid names, undecryptable or malformed content), written within the
/// BACKUP policy, must not block restore, check, backup or prune.
#[test]
fn h1_junk_index_files_block_neither_restore_nor_check_nor_backup_nor_prune() {
    let fx = fixture();
    let real_indexes = n_files(&fx, FileType::Index);
    let a = Attacker::new(fx.repo.path());
    let _ = a.put(FileType::Index, noise(3, 500));
    let _ = a.put(FileType::Index, noise(4, 5));
    let _ = a.put(FileType::Index, a.encrypt(b"{ not an index"));
    a.assert_in_policy();
    drop(a);
    assert_eq!(
        n_files(&fx, FileType::Index),
        real_indexes + 3,
        "three junk files and the real index files"
    );

    // Read-only jobs leave the junk alone and work.
    assert!(all_restore(&fx, &fx.snaps), "restore with junk index files");
    let report = open_raw(fx.repo.path())
        .check(ReadData::All, &CancelToken::new())
        .unwrap();
    assert!(report.ok, "{:?}", report.findings);
    assert_eq!(
        n_files(&fx, FileType::Index),
        real_indexes + 3,
        "a read-only job removes nothing"
    );

    // A backup (BACKUP policy) removes it.
    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("data")).unwrap();
    for (name, bytes) in expected(3) {
        fs::write(src.path().join(name), bytes).unwrap();
    }
    let (be, log) = Policed::new(raw_backends(fx.repo.path()).repository(), Job::Backup);
    let mut engine = engine_on(be);
    engine
        .backup(
            &request(src.path(), "2026-01-05T00:00:00Z"),
            &CancelToken::new(),
        )
        .unwrap();
    assert!(log.lock().unwrap().denied.is_empty());
    assert!(
        n_files(&fx, FileType::Index) <= real_indexes + 1,
        "the junk is gone (the backup wrote one index file)"
    );

    // And so does a prune (FORGET_PRUNE policy), when junk is written again.
    let a = Attacker::new(fx.repo.path());
    let _ = a.put(FileType::Index, noise(5, 700));
    drop(a);
    let (be, log) = Policed::new(
        raw_backends(fx.repo.path()).repository(),
        Job::ForgetPrune(Vec::new()),
    );
    engine_on(be).prune(&CancelToken::new()).unwrap();
    assert!(log.lock().unwrap().denied.is_empty());
    let report = open_raw(fx.repo.path())
        .check(ReadData::All, &CancelToken::new())
        .unwrap();
    assert!(report.ok, "{:?}", report.findings);
    assert!(all_restore(&fx, &fx.snaps));
}

/// M1: a process killed in the middle of the header scan of the rebuild must leave the old index
/// in place, so restores still work.
#[test]
fn m1_a_kill_during_the_header_scan_leaves_the_repository_restorable() {
    let fx = fixture();
    let before = n_files(&fx, FileType::Index);
    let e = engine_on(faulty_backend(
        &fx,
        Faults {
            panic_at_pack_read: Some(2),
            ..Faults::default()
        },
    ));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.prune(&CancelToken::new()).is_ok()
    }));
    assert!(r.is_err(), "the simulated kill happened");
    assert_eq!(
        n_files(&fx, FileType::Index),
        before,
        "no index file was removed"
    );
    assert!(all_restore(&fx, &fx.snaps));
    let report = open_raw(fx.repo.path())
        .check(ReadData::None, &CancelToken::new())
        .unwrap();
    assert!(report.ok, "{:?}", report.findings);
    // And the next prune simply works.
    open_raw(fx.repo.path()).prune(&CancelToken::new()).unwrap();
    assert!(all_restore(&fx, &fx.snaps));
}

/// M1: one transient error on a header read must neither drop the pack from the index nor leave
/// the repository unrestorable: the rebuild reads the missing header again.
#[test]
fn m1_one_transient_header_read_error_is_retried_and_loses_nothing() {
    let fx = fixture();
    let e = engine_on(faulty_backend(
        &fx,
        Faults {
            error_at_pack_read: Some(1),
            ..Faults::default()
        },
    ));
    e.prune(&CancelToken::new()).unwrap();
    drop(e);
    assert!(all_restore(&fx, &fx.snaps));
    let report = open_raw(fx.repo.path())
        .check(ReadData::All, &CancelToken::new())
        .unwrap();
    assert!(report.ok, "{:?}", report.findings);
}

/// M1: headers that stay unreadable: the prune is refused, nothing is deleted, the old index files
/// are all still there and every restore works.
#[test]
fn m1_headers_that_stay_unreadable_refuse_the_prune_and_keep_the_old_index() {
    let fx = fixture();
    let index_before = raw_backends(fx.repo.path())
        .repository()
        .list(FileType::Index)
        .unwrap();
    let packs_before = n_files(&fx, FileType::Pack);
    let e = engine_on(faulty_backend(
        &fx,
        Faults {
            error_from_pack_read: Some(1),
            ..Faults::default()
        },
    ));
    let err = e.prune(&CancelToken::new()).unwrap_err();
    assert!(matches!(err, EngineError::Integrity { .. }), "{err}");
    drop(e);
    let index_after = raw_backends(fx.repo.path())
        .repository()
        .list(FileType::Index)
        .unwrap();
    let mut a = index_before.clone();
    let mut b = index_after.clone();
    a.sort();
    b.sort();
    assert_eq!(
        a, b,
        "the old index files stay and the files the rebuild wrote are removed"
    );
    assert_eq!(n_files(&fx, FileType::Pack), packs_before);
    assert!(all_restore(&fx, &fx.snaps));
}

// ---------------------------------------------------------------------------------------------
// The invariant behind the duplicate verification (second review of Q-S1)
// ---------------------------------------------------------------------------------------------

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// One pack header entry (rustic's binary form) for blob `b` (an index JSON entry) stored `len`
/// bytes long; compressed blobs keep their declared uncompressed length.
fn header_entry(b: &Value, len: u32) -> Vec<u8> {
    let tree = b["type"] == "tree";
    let mut e = Vec::new();
    match b.get("uncompressed_length").and_then(Value::as_u64) {
        Some(u) => {
            e.push(if tree { 3 } else { 2 });
            e.extend_from_slice(&len.to_le_bytes());
            e.extend_from_slice(&u32::try_from(u).unwrap().to_le_bytes());
        }
        None => {
            e.push(if tree { 1 } else { 0 });
            e.extend_from_slice(&len.to_le_bytes());
        }
    }
    e.extend_from_slice(&unhex(b["id"].as_str().unwrap()));
    e
}

/// What a forged pack lists for each blob of the real pack it imitates.
#[derive(Clone, Copy, Debug)]
enum Layout {
    /// A byte-exact copy of the real ciphertext: it verifies.
    Good,
    /// 64 bytes of junk.
    Junk,
    /// The same blob twice in one pack, the good copy first.
    GoodThenJunk,
    /// The same blob twice in one pack, the junk first.
    JunkThenGood,
}

/// A pack with `layout` for every blob of `target`, a filler blob so that its id can be varied, and
/// an id that sorts after (or before) the real pack's. Returns its id.
fn forged_pack(a: &Attacker, target: &Value, layout: Layout, after_real: bool) -> Id {
    let b_id: Id = target["id"].as_str().unwrap().parse().unwrap();
    let raw = a.read(FileType::Pack, &b_id);
    for seed in 1_u64.. {
        let mut body = Vec::new();
        let mut header = Vec::new();
        for b in target["blobs"].as_array().unwrap() {
            let off = b["offset"].as_u64().unwrap() as usize;
            let len = b["length"].as_u64().unwrap() as usize;
            let good = |body: &mut Vec<u8>, header: &mut Vec<u8>| {
                body.extend_from_slice(&raw[off..off + len]);
                header.extend(header_entry(b, u32::try_from(len).unwrap()));
            };
            let junk = |body: &mut Vec<u8>, header: &mut Vec<u8>| {
                body.extend_from_slice(&noise(seed * 7919 + off as u64, 64));
                header.extend(header_entry(b, 64));
            };
            match layout {
                Layout::Good => good(&mut body, &mut header),
                Layout::Junk => junk(&mut body, &mut header),
                Layout::GoodThenJunk => {
                    good(&mut body, &mut header);
                    junk(&mut body, &mut header);
                }
                Layout::JunkThenGood => {
                    junk(&mut body, &mut header);
                    good(&mut body, &mut header);
                }
            }
        }
        // A filler blob (a fake id) gives every seed another pack id.
        body.extend_from_slice(&noise(seed, 64));
        header.push(0);
        header.extend_from_slice(&64_u32.to_le_bytes());
        header.extend_from_slice(&Sha256::digest(format!("filler{seed}")));
        let enc = a.encrypt(&header);
        body.extend_from_slice(&enc);
        body.extend_from_slice(&u32::try_from(enc.len()).unwrap().to_le_bytes());
        let gt = id_of(&body).to_hex().as_str() > b_id.to_hex().as_str();
        if gt == after_real {
            return a.put(FileType::Pack, body);
        }
    }
    unreachable!()
}

/// The smallest real data pack (its blobs are all needed by a snapshot that stays).
fn smallest_data_pack(a: &Attacker) -> Value {
    a.data_entries()
        .into_iter()
        .min_by_key(|e| {
            e["blobs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b["length"].as_u64().unwrap())
                .sum::<u64>()
        })
        .unwrap()
}

/// After a refused prune the real packs are all there; with the attacker's packs removed and the
/// index rebuilt, everything restores.
fn assert_refused_and_recoverable(
    fx: &Fx,
    real_packs: &[Id],
    r: Result<(), EngineError>,
    what: &str,
) {
    assert!(
        matches!(r, Err(EngineError::Integrity { .. })),
        "{what}: expected Integrity, got {r:?}"
    );
    let be = raw_backends(fx.repo.path()).repository();
    let now = be.list(FileType::Pack).unwrap();
    for p in real_packs {
        assert!(
            now.contains(p),
            "{what}: real pack {} was removed",
            p.to_hex().as_str()
        );
    }
    for id in &now {
        if fx.decoys.contains(&id.to_hex().as_str().to_owned()) {
            be.remove(FileType::Pack, id, false).unwrap();
        }
    }
    rustic_repo(be)
        .repair_index(&RepairIndexOptions::default().read_all(true), false)
        .unwrap();
    assert!(
        all_restore(fx, &fx.snaps[2..]),
        "{what}: restores after recovery"
    );
}

/// The invariant, generically: whatever a decoy pack lists for a real pack's blobs (a good copy and
/// junk in one pack or in two, junk first or last, ids sorting either way), the prune ends in
/// `Integrity` and removes no real pack.
#[test]
fn xs_adversarial_duplicate_layouts_never_remove_a_real_pack() {
    for (name, layouts) in [
        ("good-then-junk", vec![Layout::GoodThenJunk]),
        ("junk-then-good", vec![Layout::JunkThenGood]),
        (
            "good copy in one pack, junk in another",
            vec![Layout::Good, Layout::Junk],
        ),
    ] {
        for after_real in [true, false] {
            let mut fx = fixture();
            forget_oldest_two(&fx);
            let a = Attacker::new(fx.repo.path());
            let target = smallest_data_pack(&a);
            let real: Vec<Id> = a.list(FileType::Pack);
            for l in &layouts {
                let _ = forged_pack(&a, &target, *l, after_real);
            }
            a.assert_in_policy();
            fx.decoys = a.written.lock().unwrap().clone();
            drop(a);
            let r = open_raw(fx.repo.path())
                .prune(&CancelToken::new())
                .map(|_| ());
            assert_refused_and_recoverable(
                &fx,
                &real,
                r,
                &format!("{name}, after_real={after_real}"),
            );
        }
    }
}

/// XS1 of the second review: a decoy that lists each blob of a real pack twice (a verbatim copy
/// first, then junk) with an id after the real pack's, next to a big pack so that the plan keeps
/// the decoy. One verified copy per pack used to be enough to let the real pack be deleted.
#[test]
fn xs1_same_pack_duplicate_hides_junk_behind_a_verified_copy() {
    let mut fx = fixture();
    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("big")).unwrap();
    fs::write(src.path().join("big/f"), noise(999, 24 << 20)).unwrap();
    open_raw(fx.repo.path())
        .backup(
            &request(src.path(), "2026-01-05T00:00:00Z"),
            &CancelToken::new(),
        )
        .unwrap();
    forget_oldest_two(&fx);
    let a = Attacker::new(fx.repo.path());
    let target = smallest_data_pack(&a);
    let real: Vec<Id> = a.list(FileType::Pack);
    let _ = forged_pack(&a, &target, Layout::GoodThenJunk, true);
    a.assert_in_policy();
    fx.decoys = a.written.lock().unwrap().clone();
    drop(a);
    let r = open_raw(fx.repo.path())
        .prune(&CancelToken::new())
        .map(|_| ());
    assert_refused_and_recoverable(&fx, &real, r, "xs1");
}

/// M3: a decoy copy whose plaintext is a zstd bomb (a few KB that expand to 128 MiB) while the
/// header declares 100 bytes must be refused without expanding it.
#[test]
fn m3_a_zstd_bomb_copy_is_refused_by_its_declared_length() {
    let mut fx = fixture();
    let a = Attacker::new(fx.repo.path());
    let target = smallest_data_pack(&a);
    let blob = target["blobs"][0].clone();
    let bomb = zstd::bulk::compress(&vec![0_u8; 128 << 20], 3).unwrap();
    assert!(bomb.len() < 1 << 20);
    let ct = a.encrypt(&bomb);
    let mut b = blob.clone();
    b["uncompressed_length"] = json!(100);
    let mut header = header_entry(&b, u32::try_from(ct.len()).unwrap());
    // header_entry writes the declared length of `b`; make it a compressed data entry.
    assert_eq!(header[0], 2);
    header.shrink_to_fit();
    let mut body = ct.clone();
    let enc = a.encrypt(&header);
    body.extend_from_slice(&enc);
    body.extend_from_slice(&u32::try_from(enc.len()).unwrap().to_le_bytes());
    let _ = a.put(FileType::Pack, body);
    a.assert_in_policy();
    fx.decoys = a.written.lock().unwrap().clone();
    drop(a);
    let started = std::time::Instant::now();
    let r = open_raw(fx.repo.path())
        .prune(&CancelToken::new())
        .map(|_| ());
    assert!(matches!(r, Err(EngineError::Integrity { .. })), "{r:?}");
    assert!(started.elapsed().as_secs() < 60);
}
