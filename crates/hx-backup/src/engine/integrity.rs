//! Index trust (docs/ipc.md section 36, decision 10): what the engine does so that an index
//! written by a compromised `BACKUP` worker cannot make a prune delete live data, and so that junk
//! or an interrupted repair cannot make the repository unusable.
//!
//! * [`IndexGuard`] wraps the repository backend. It can hide index files from listings (junk
//!   files that cannot be decrypted), and defer the removal of index files so that a rebuild writes
//!   the new index before the old ones go (a kill or a read error in between leaves the old index).
//! * [`Engine::prepare_index`] finds index files that cannot be read and hides or removes them.
//! * [`Engine::rebuild_index_from_headers`] is `repair index --read-all-packs` with that order.
//! * [`Engine::verify_index_before_prune`] adds the checks that make prune safe: every pack file is
//!   in an index, and every copy of a blob that is stored in more than one pack decrypts, decompresses
//!   and hashes to its id.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use aes256ctr_poly1305aes::{
    Aes256CtrPoly1305Aes,
    aead::{Aead, generic_array::GenericArray},
};
use bytes::Bytes;
use rustic_core::repofile::{IndexFile, IndexId, PackId};
use rustic_core::{
    BlobId, BytesList, FileType, Id, ReadBackend, RepairIndexOptions, RusticResult, WriteBackend,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{CancelToken, Engine, EngineError, Phase, rustic};

/// The most duplicated blob data a prune reads to verify, in bytes (all copies together). Beyond it
/// the prune is refused: a repository with that much duplication needs an operator.
pub const MAX_DUPLICATE_VERIFY_BYTES: u64 = 2 << 30;

/// Longest single ranged read when verifying duplicates.
const MAX_RUN_BYTES: u64 = 8 << 20;

#[derive(Default)]
struct GuardState {
    /// Index files that are left out of listings.
    hidden: HashSet<Id>,
    /// Index removals are recorded, not executed.
    defer: bool,
    deferred: Vec<Id>,
    /// Index files written while deferring.
    written: HashSet<Id>,
    /// `prepare_index` has run (hiding) / (removing).
    scanned_hide: bool,
    scanned_remove: bool,
}

/// The repository backend as the engine hands it to rustic.
pub(super) struct IndexGuard {
    inner: Arc<dyn WriteBackend>,
    state: Mutex<GuardState>,
}

impl IndexGuard {
    pub(super) fn new(inner: Arc<dyn WriteBackend>) -> Self {
        Self {
            inner,
            state: Mutex::new(GuardState::default()),
        }
    }

    fn st(&self) -> std::sync::MutexGuard<'_, GuardState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn begin_defer(&self) {
        let mut s = self.st();
        s.defer = true;
        s.deferred.clear();
        s.written.clear();
    }

    fn end_defer(&self) -> (Vec<Id>, HashSet<Id>) {
        let mut s = self.st();
        s.defer = false;
        (
            std::mem::take(&mut s.deferred),
            std::mem::take(&mut s.written),
        )
    }
}

impl ReadBackend for IndexGuard {
    fn location(&self) -> String {
        self.inner.location()
    }
    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        self.inner.warmup_path(tpe, id)
    }
    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        let mut l = self.inner.list_with_size(tpe)?;
        if tpe == FileType::Index {
            let s = self.st();
            if !s.hidden.is_empty() {
                l.retain(|(id, _)| !s.hidden.contains(id));
            }
        }
        Ok(l)
    }
    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
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
        self.inner.read_partial(tpe, id, cacheable, offset, length)
    }
}

impl WriteBackend for IndexGuard {
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
        self.inner.write_bytes(tpe, id, cacheable, content)?;
        if tpe == FileType::Index {
            let mut s = self.st();
            if s.defer {
                let _ = s.written.insert(*id);
            }
        }
        Ok(())
    }
    fn remove(&self, tpe: FileType, id: &Id, cacheable: bool) -> RusticResult<()> {
        if tpe == FileType::Index {
            let mut s = self.st();
            if s.defer {
                s.deferred.push(*id);
                return Ok(());
            }
        }
        self.inner.remove(tpe, id, cacheable)
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One stored copy of a blob.
#[derive(Clone, Copy)]
struct Stored {
    pack: PackId,
    offset: u32,
    length: u32,
    uncompressed: Option<NonZeroU32>,
}

/// Does `bytes` (a blob as stored in a pack) decrypt, decompress and hash to `id`?
fn copy_verifies(key: &[u8; 64], bytes: &[u8], id: &Id, uncompressed: Option<NonZeroU32>) -> bool {
    if bytes.len() < 32 {
        return false;
    }
    let cipher = Aes256CtrPoly1305Aes::new(GenericArray::from_slice(key));
    let Ok(plain) = cipher.decrypt(GenericArray::from_slice(&bytes[..16]), &bytes[16..]) else {
        return false;
    };
    let plain = match uncompressed {
        Some(n) => match zstd::stream::decode_all(&plain[..]) {
            Ok(d) if d.len() == n.get() as usize => d,
            _ => return false,
        },
        None => plain,
    };
    hex(&Sha256::digest(&plain)) == id.to_hex().as_str()
}

impl Engine {
    /// Find index files that cannot be read although the backend returns them (junk written by a
    /// compromised worker, or damage), and either remove them (`remove`: jobs that may write; they
    /// hold no data, the pack headers hold everything) or leave them out of every listing (read-only
    /// jobs). A backend that fails to read a file is an error, not junk.
    ///
    /// Done once per engine and mode; costs one read of every index file.
    pub(super) fn prepare_index(&self, remove: bool) -> Result<(), EngineError> {
        {
            let s = self.guard.st();
            if (remove && s.scanned_remove) || (!remove && (s.scanned_hide || s.scanned_remove)) {
                return Ok(());
            }
        }
        let repo = self.repo()?;
        let ids: Vec<IndexId> = repo
            .list::<IndexId>()
            .map_err(rustic("listing index files"))?
            .collect();
        let mut bad = Vec::new();
        for id in ids {
            if repo.get_file::<IndexFile>(&id).is_ok() {
                continue;
            }
            let raw = id.into_inner();
            self.guard
                .inner
                .read_full(FileType::Index, &raw)
                .map_err(rustic("reading an index file"))?;
            bad.push(raw);
        }
        if remove {
            for id in &bad {
                tracing::warn!(index = %id.to_hex().as_str(), "removing an index file that cannot be read");
                self.guard
                    .inner
                    .remove(FileType::Index, id, false)
                    .map_err(rustic("removing an unreadable index file"))?;
            }
            let mut s = self.guard.st();
            s.scanned_remove = true;
            for id in &bad {
                let _ = s.hidden.remove(id);
            }
        } else {
            let mut s = self.guard.st();
            s.scanned_hide = true;
            s.hidden.extend(bad);
        }
        Ok(())
    }

    /// One `repair index` whose removals of old index files are held back.
    fn repair_pass(&self, read_all: bool) -> Result<(Vec<Id>, HashSet<Id>), EngineError> {
        self.guard.begin_defer();
        let r = self
            .repo()?
            .repair_index(&RepairIndexOptions::default().read_all(read_all), false);
        let held = self.guard.end_defer();
        r.map_err(rustic("repairing the index"))?;
        Ok(held)
    }

    /// Remove the index files a repair replaced, except the ones it wrote.
    fn remove_replaced(&self, deferred: &[Id], written: &HashSet<Id>) -> Result<(), EngineError> {
        let once: HashSet<&Id> = deferred.iter().filter(|i| !written.contains(*i)).collect();
        for id in once {
            self.guard
                .inner
                .remove(FileType::Index, id, false)
                .map_err(rustic("removing a replaced index file"))?;
        }
        Ok(())
    }

    /// `repair index` for a backup (packs of an interrupted run become part of the index), with the
    /// old index files removed only after the new one is written.
    pub(super) fn repair_index_for_backup(&self) -> Result<(), EngineError> {
        self.prepare_index(true)?;
        let (deferred, written) = self.repair_pass(false)?;
        self.remove_replaced(&deferred, &written)
    }

    fn pack_ids_on_disk(&self) -> Result<HashSet<PackId>, EngineError> {
        Ok(self
            .repo()?
            .list::<PackId>()
            .map_err(rustic("listing packs"))?
            .collect())
    }

    fn packs_in(&self, files: &HashSet<Id>) -> Result<HashSet<PackId>, EngineError> {
        let repo = self.repo()?;
        let mut out = HashSet::new();
        for id in files {
            let f: IndexFile = repo
                .get_file(&IndexId::from(*id))
                .map_err(rustic("reading the index"))?;
            out.extend(
                f.packs
                    .iter()
                    .chain(&f.packs_to_delete)
                    .chain(&f.packs_to_recover)
                    .map(|p| p.id),
            );
        }
        Ok(out)
    }

    /// `repair index --read-all-packs`: the index says what the pack headers say. The new index is
    /// written first and the old files are removed only when it covers every pack file; a pack whose
    /// header could not be read gets one more full pass, and if it still cannot be read nothing is
    /// removed and the prune is refused.
    fn rebuild_index_from_headers(&self, cancel: &CancelToken) -> Result<(), EngineError> {
        self.shared.set_phase(Phase::RepairIndex);
        let mut all_deferred = Vec::new();
        let mut missing = None;
        for _ in 0..2 {
            let (deferred, written) = self.repair_pass(true)?;
            all_deferred.extend(deferred);
            let covered = self.packs_in(&written)?;
            let on_disk = self.pack_ids_on_disk()?;
            missing = on_disk.difference(&covered).next().copied();
            if missing.is_none() {
                self.remove_replaced(&all_deferred, &written)?;
                // Files written by a first pass that a second one replaced are in `all_deferred`.
                return Ok(());
            }
            cancel.check()?;
        }
        // Give up: the old index files stay, and so do the files this call wrote (they are valid).
        let pack = missing.map_or_else(String::new, |p| p.to_hex().as_str().to_owned());
        Err(EngineError::Integrity {
            finding: format!("pack {pack} has no readable header and is in no index"),
        })
    }

    /// Everything [`Engine::prune`] needs to be true before it plans. See its documentation.
    pub(super) fn verify_index_before_prune(
        &self,
        cancel: &CancelToken,
    ) -> Result<(), EngineError> {
        self.prepare_index(true)?;
        cancel.check()?;
        self.rebuild_index_from_headers(cancel)?;
        cancel.check()?;

        let repo = self.repo()?;
        let on_disk = self.pack_ids_on_disk()?;
        let mut indexed: HashSet<PackId> = HashSet::with_capacity(on_disk.len());
        let mut first: HashMap<BlobId, Stored> = HashMap::new();
        let mut dups: HashMap<BlobId, Vec<Stored>> = HashMap::new();
        for file in repo
            .stream_files::<IndexFile>()
            .map_err(rustic("reading the index"))?
        {
            let (_, file) = file.map_err(rustic("reading the index"))?;
            for pack in file
                .packs
                .iter()
                .chain(&file.packs_to_delete)
                .chain(&file.packs_to_recover)
            {
                indexed.insert(pack.id);
                for b in &pack.blobs {
                    let c = Stored {
                        pack: pack.id,
                        offset: b.location.offset,
                        length: b.location.length,
                        uncompressed: b.location.uncompressed_length,
                    };
                    match first.entry(b.id) {
                        std::collections::hash_map::Entry::Vacant(v) => {
                            let _ = v.insert(c);
                        }
                        std::collections::hash_map::Entry::Occupied(o) => {
                            let f = *o.get();
                            if f.pack == c.pack {
                                continue;
                            }
                            let list = dups.entry(b.id).or_insert_with(|| vec![f]);
                            if list.iter().all(|x| x.pack != c.pack) {
                                list.push(c);
                            }
                        }
                    }
                }
            }
        }
        drop(first);
        if let Some(p) = on_disk.difference(&indexed).next() {
            return Err(EngineError::Integrity {
                finding: format!(
                    "pack {} is in no index ({} such packs)",
                    p.to_hex().as_str(),
                    on_disk.difference(&indexed).count()
                ),
            });
        }
        self.verify_duplicate_copies(&dups, cancel)
    }

    /// Read every copy of every blob that is stored in more than one pack and check that it
    /// decrypts, decompresses and hashes to its id. A decoy pack listing a real pack's blobs fails
    /// here; a second honest copy (an interrupted prune leaves one) passes and is harmless.
    fn verify_duplicate_copies(
        &self,
        dups: &HashMap<BlobId, Vec<Stored>>,
        cancel: &CancelToken,
    ) -> Result<(), EngineError> {
        if dups.is_empty() {
            return Ok(());
        }
        let total: u64 = dups
            .values()
            .flat_map(|v| v.iter())
            .map(|c| u64::from(c.length))
            .sum();
        if total > MAX_DUPLICATE_VERIFY_BYTES {
            return Err(EngineError::Integrity {
                finding: format!(
                    "{} blobs are stored in more than one pack ({total} bytes of copies, over the {MAX_DUPLICATE_VERIFY_BYTES} byte verification limit)",
                    dups.len()
                ),
            });
        }
        tracing::warn!(
            blobs = dups.len(),
            bytes = total,
            "blobs are stored in more than one pack: verifying every copy"
        );
        self.shared.set_phase(Phase::ReadData);
        let m = self.repo()?.key();
        let mut key = Zeroizing::new([0u8; 64]);
        key[..32].copy_from_slice(&m.encrypt);
        key[32..48].copy_from_slice(&m.mac.k);
        key[48..].copy_from_slice(&m.mac.r);

        let mut by_pack: HashMap<PackId, Vec<(Stored, BlobId)>> = HashMap::new();
        for (id, copies) in dups {
            for c in copies {
                by_pack.entry(c.pack).or_default().push((*c, *id));
            }
        }
        let bad = |pack: PackId, why: &str| EngineError::Integrity {
            finding: format!(
                "pack {} holds a copy of a blob that is also stored elsewhere, and it {why}",
                pack.to_hex().as_str()
            ),
        };
        for (pack, mut copies) in by_pack {
            cancel.check()?;
            copies.sort_by_key(|(c, _)| c.offset);
            let mut i = 0;
            while i < copies.len() {
                // One ranged read for a run of adjacent copies.
                let start = u64::from(copies[i].0.offset);
                let mut end = start + u64::from(copies[i].0.length);
                let mut j = i + 1;
                while j < copies.len()
                    && u64::from(copies[j].0.offset) == end
                    && end + u64::from(copies[j].0.length) - start <= MAX_RUN_BYTES
                {
                    end += u64::from(copies[j].0.length);
                    j += 1;
                }
                let (Ok(off), Ok(len)) = (u32::try_from(start), u32::try_from(end - start)) else {
                    return Err(bad(pack, "lies outside the pack"));
                };
                let data = self
                    .guard
                    .inner
                    .read_partial(FileType::Pack, &pack, false, off, len)
                    .map_err(|_| bad(pack, "cannot be read"))?;
                if data.len() as u64 != end - start {
                    return Err(bad(pack, "is shorter than the index says"));
                }
                for (c, id) in &copies[i..j] {
                    let from = (u64::from(c.offset) - start) as usize;
                    let part = &data[from..from + c.length as usize];
                    if !copy_verifies(&key, part, id, c.uncompressed) {
                        return Err(bad(pack, "does not decrypt to that blob"));
                    }
                }
                i = j;
            }
        }
        Ok(())
    }
}
