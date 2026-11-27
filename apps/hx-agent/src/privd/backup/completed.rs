//! privd's own record of the backups it completed, retention, and the `FORGET_PRUNE` spec builder
//! (ipc.md section 35 and section 36 decision 10).
//!
//! **Retention reads only from this record.** The repository is writable by anyone who holds a
//! repository key (a compromised `BACKUP` worker does), so a listing of it is not evidence: two
//! forged snapshots dated in the future would displace every real backup from the keep rules and
//! the floor. [`forget_list`] therefore takes the record and nothing else: a snapshot that privd
//! did not record is neither counted nor forgotten, and a lost record forgets nothing.

use std::path::Path;

use bytes::Bytes;
use hx_ipc::repo::pb;
use hx_ipc::repo::{ID_LEN, MAX_FORGET};
use serde::{Deserialize, Serialize};

use super::slot::{FORMAT, RecordError, hex, parse_hex32};
use crate::privd::state::write_atomic;
use crate::privd::timefmt::civil;

/// One backup privd completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedBackup {
    /// The snapshot's id, 64 lower-case hex digits.
    pub snapshot_id: String,
    /// The job that made it, 32 hex digits.
    pub job_id: String,
    /// privd's clock when the job's result was accepted, Unix seconds.
    pub time_unix: u64,
    /// `files_new` of the job.
    pub files_new: u64,
    /// `files_changed`.
    pub files_changed: u64,
    /// `files_unmodified`.
    pub files_unmodified: u64,
    /// `bytes_processed`.
    pub bytes_processed: u64,
    /// `bytes_added`.
    pub bytes_added: u64,
    /// `entries_unreadable`: reported as a warning count, the backup is a success.
    pub warnings: u64,
}

impl CompletedBackup {
    /// The snapshot id as bytes, if the entry is well formed.
    pub fn id(&self) -> Option<[u8; ID_LEN]> {
        parse_hex32(&self.snapshot_id)
    }
}

/// `completed.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedRecord {
    /// Always [`FORMAT`].
    pub format: u32,
    /// The backups, oldest first by the order they were added.
    pub backups: Vec<CompletedBackup>,
}

impl Default for CompletedRecord {
    fn default() -> Self {
        Self {
            format: FORMAT,
            backups: Vec::new(),
        }
    }
}

impl CompletedRecord {
    /// Reads `completed.json`; none yet is an empty record, a file that does not parse (or has
    /// an entry that is not well formed) is [`RecordError::Corrupt`] and is left alone.
    pub fn load(path: &Path) -> Result<Self, RecordError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(RecordError::Io {
                    what: "completed.json",
                    source,
                });
            }
        };
        let r: Self =
            serde_json::from_slice(&bytes).map_err(|_| RecordError::Corrupt("completed.json"))?;
        if r.format != FORMAT
            || r.backups.len() > MAX_FORGET
            || r.backups.iter().any(|b| b.id().is_none())
        {
            return Err(RecordError::Corrupt("completed.json"));
        }
        Ok(r)
    }

    /// Writes it atomically (0600).
    pub fn store(&self, path: &Path) -> Result<(), RecordError> {
        let bytes = serde_json::to_vec(self).map_err(|_| RecordError::Corrupt("completed.json"))?;
        write_atomic(path, &bytes, 0o600).map_err(|source| RecordError::Io {
            what: "completed.json",
            source,
        })
    }

    /// Adds a backup. At most 4 096 entries: past that the oldest *record* is dropped (the
    /// snapshot stays in the repository and is never forgotten: unrecorded means untouchable).
    pub fn add(&mut self, entry: CompletedBackup) {
        if self
            .backups
            .iter()
            .any(|b| b.snapshot_id == entry.snapshot_id)
        {
            return;
        }
        self.backups.push(entry);
        while self.backups.len() > MAX_FORGET {
            self.backups.remove(0);
        }
    }

    /// Removes the entries named by `ids` (after a `FORGET_PRUNE` that named them succeeded).
    pub fn remove(&mut self, ids: &[[u8; ID_LEN]]) {
        self.backups
            .retain(|b| !b.id().is_some_and(|id| ids.contains(&id)));
    }

    /// Whether `id` is recorded.
    pub fn contains(&self, id: &[u8; ID_LEN]) -> bool {
        self.backups.iter().any(|b| b.id().as_ref() == Some(id))
    }
}

/// An entry built from an accepted `JobResult` of a `BACKUP`.
pub fn entry_from_result(
    job_id: &str,
    now_unix: u64,
    r: &pb::JobResult,
) -> Option<CompletedBackup> {
    if r.snapshot_id.len() != ID_LEN {
        return None;
    }
    Some(CompletedBackup {
        snapshot_id: hex(&r.snapshot_id),
        job_id: job_id.to_string(),
        time_unix: now_unix,
        files_new: r.files_new,
        files_changed: r.files_changed,
        files_unmodified: r.files_unmodified,
        bytes_processed: r.bytes_processed,
        bytes_added: r.bytes_added,
        warnings: r.entries_unreadable,
    })
}

/// The retention rules (architecture section 9.7). Each count keeps the newest backup of each of
/// the most recent buckets that have one; `last` keeps the newest backups outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// The latest N backups.
    pub last: usize,
    /// One per UTC day for N days.
    pub daily: usize,
    /// One per ISO week (Monday first) for N weeks.
    pub weekly: usize,
    /// One per UTC month for N months.
    pub monthly: usize,
}

impl Retention {
    /// A backup every 12 h: the latest 14, 4 weekly and 6 monthly.
    pub const EVERY_12H: Self = Self {
        last: 14,
        daily: 0,
        weekly: 4,
        monthly: 6,
    };
    /// A backup every 24 h: 7 daily, 4 weekly and 6 monthly.
    pub const EVERY_24H: Self = Self {
        last: 0,
        daily: 7,
        weekly: 4,
        monthly: 6,
    };
}

/// The backups that are always kept: the two newest recorded ones (architecture section 9.7).
pub const FLOOR: usize = 2;

/// Which recorded backups to forget: every recorded entry kept by neither the floor of the two
/// newest nor any retention rule, oldest first. **Only recorded entries are ever returned.**
pub fn forget_list(record: &CompletedRecord, retention: &Retention) -> Vec<[u8; ID_LEN]> {
    // Newest first; the order they were added breaks ties between equal times.
    let mut order: Vec<usize> = (0..record.backups.len()).collect();
    order.sort_by(|a, b| {
        record.backups[*b]
            .time_unix
            .cmp(&record.backups[*a].time_unix)
            .then(b.cmp(a))
    });
    let mut keep = vec![false; record.backups.len()];
    for i in order.iter().take(FLOOR.max(retention.last)) {
        keep[*i] = true;
    }
    type KeyOf = fn(u64) -> u64;
    let buckets: [(usize, KeyOf); 3] = [
        (retention.daily, |t| t / 86_400),
        (retention.weekly, |t| (t / 86_400 + 3) / 7),
        (retention.monthly, |t| {
            let (y, m, ..) = civil(t);
            u64::try_from(y).unwrap_or(0) * 12 + u64::from(m)
        }),
    ];
    for (n, key_of) in buckets {
        let mut seen: Vec<u64> = Vec::new();
        for i in &order {
            if seen.len() >= n {
                break;
            }
            let key = key_of(record.backups[*i].time_unix);
            if !seen.contains(&key) {
                seen.push(key);
                keep[*i] = true;
            }
        }
    }
    order
        .iter()
        .rev()
        .filter(|i| !keep[**i])
        .filter_map(|i| record.backups[*i].id())
        .collect()
}

/// The `FORGET_PRUNE` spec of ipc.md section 28, with `forget` taken from the record only.
pub fn forget_prune_spec(record: &CompletedRecord, retention: &Retention) -> pb::ForgetPruneSpec {
    pb::ForgetPruneSpec {
        forget: forget_list(record, retention)
            .into_iter()
            .map(|id| Bytes::copy_from_slice(&id))
            .collect(),
        instant: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;
    // 2026-11-02 00:00:00 UTC, a Monday.
    const MONDAY: u64 = 1_793_577_600;

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn entry(n: u8, t: u64) -> CompletedBackup {
        CompletedBackup {
            snapshot_id: hex(&id(n)),
            job_id: "0".repeat(32),
            time_unix: t,
            files_new: 1,
            files_changed: 2,
            files_unmodified: 3,
            bytes_processed: 4,
            bytes_added: 5,
            warnings: 0,
        }
    }

    fn record(entries: &[(u8, u64)]) -> CompletedRecord {
        let mut r = CompletedRecord::default();
        for (n, t) in entries {
            r.add(entry(*n, *t));
        }
        r
    }

    #[test]
    fn the_floor_keeps_the_two_newest_whatever_the_rules_say() {
        let none = Retention {
            last: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
        };
        let r = record(&[(1, 100), (2, 200), (3, 300), (4, 400)]);
        assert_eq!(forget_list(&r, &none), [id(1), id(2)]);
        let r = record(&[(1, 100), (2, 200)]);
        assert!(forget_list(&r, &none).is_empty());
        assert!(forget_list(&CompletedRecord::default(), &none).is_empty());
    }

    #[test]
    fn keep_last_and_the_buckets_keep_the_newest_of_each() {
        // Two backups a day for 10 days: ids 1..=20, oldest first.
        let r = record(
            &(0..20)
                .map(|i| (i as u8 + 1, MONDAY + (i / 2) * DAY + (i % 2) * 43_200))
                .collect::<Vec<_>>(),
        );
        let forget = forget_list(
            &r,
            &Retention {
                last: 0,
                daily: 3,
                weekly: 0,
                monthly: 0,
            },
        );
        // Kept: the newest of each of the last 3 days (ids 20, 18, 16) and the floor (20, 19).
        let kept: Vec<u8> = (1..=20).filter(|n| !forget.contains(&id(*n))).collect();
        assert_eq!(kept, [16, 18, 19, 20]);
    }

    #[test]
    fn weekly_buckets_start_on_monday_and_monthly_buckets_are_utc_months() {
        // Sunday 1 Nov 2026 (week of 26 Oct), Monday 2 Nov, Tuesday 3 Nov, and 31 Oct (Saturday).
        let sun = MONDAY - DAY;
        let sat = MONDAY - 2 * DAY;
        let r = record(&[(1, sat), (2, sun), (3, MONDAY), (4, MONDAY + DAY)]);
        let weekly = Retention {
            last: 0,
            daily: 0,
            weekly: 2,
            monthly: 0,
        };
        // Weeks: [Sat, Sun] (Oct 26 to Nov 1) and [Mon, Tue]. Newest of each: 2 and 4. Floor: 4, 3.
        let kept: Vec<u8> = (1..=4)
            .filter(|n| !forget_list(&r, &weekly).contains(&id(*n)))
            .collect();
        assert_eq!(kept, [2, 3, 4]);
        let monthly = Retention {
            last: 0,
            daily: 0,
            weekly: 0,
            monthly: 2,
        };
        // Months: October (newest: 2, the Sunday 1 Nov is November!). Sat 31 Oct is October, Sun 1
        // Nov is November, so the newest of November is 4 and of October is 1.
        let kept: Vec<u8> = (1..=4)
            .filter(|n| !forget_list(&r, &monthly).contains(&id(*n)))
            .collect();
        assert_eq!(kept, [1, 3, 4]);
    }

    #[test]
    fn only_recorded_ids_are_ever_returned() {
        // The repository may hold forged snapshots dated in the future. privd never recorded them:
        // they are not in the record, so they cannot displace anything and cannot be named.
        let forged = id(0xee);
        let r = record(&[(1, 100), (2, 200), (3, 300), (4, 400), (5, 500)]);
        let spec = forget_prune_spec(&r, &Retention::EVERY_24H);
        assert!(spec.instant);
        assert!(spec.forget.iter().all(|f| f.as_ref() != forged));
        assert!(
            spec.forget
                .iter()
                .all(|f| r.contains(&f.as_ref().try_into().unwrap()))
        );
        // With 5 recorded backups all inside the daily rule's reach nothing is forgotten, and with
        // a tight rule only recorded ones are.
        let tight = Retention {
            last: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
        };
        let spec = forget_prune_spec(&r, &tight);
        assert_eq!(spec.forget.len(), 3);
        assert!(
            spec.forget
                .iter()
                .all(|f| r.contains(&f.as_ref().try_into().unwrap()))
        );
        // A lost record forgets nothing.
        assert!(
            forget_prune_spec(&CompletedRecord::default(), &tight)
                .forget
                .is_empty()
        );
    }

    #[test]
    fn the_record_round_trips_rejects_corruption_and_caps_its_size() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("completed.json");
        assert_eq!(
            CompletedRecord::load(&p).unwrap(),
            CompletedRecord::default()
        );
        let r = record(&[(1, 100), (2, 200)]);
        r.store(&p).unwrap();
        assert_eq!(CompletedRecord::load(&p).unwrap(), r);
        std::fs::write(&p, "{").unwrap();
        assert!(CompletedRecord::load(&p).is_err());
        let mut bad = r.clone();
        bad.backups[0].snapshot_id = "xyz".into();
        std::fs::write(&p, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(CompletedRecord::load(&p).is_err());
        // The cap drops the oldest record only.
        let mut big = CompletedRecord::default();
        for i in 0..(MAX_FORGET + 5) {
            let mut e = entry(1, i as u64);
            e.snapshot_id = hex(&[
                (i % 256) as u8,
                (i / 256) as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
            ]);
            big.add(e);
        }
        assert_eq!(big.backups.len(), MAX_FORGET);
        assert_eq!(big.backups[0].time_unix, 5);
    }

    #[test]
    fn removing_forgotten_ids_and_duplicate_additions() {
        let mut r = record(&[(1, 100), (2, 200), (3, 300)]);
        r.add(entry(2, 999));
        assert_eq!(r.backups.len(), 3);
        r.remove(&[id(1), id(9)]);
        assert!(!r.contains(&id(1)));
        assert!(r.contains(&id(2)));
    }

    #[test]
    fn the_entry_carries_the_counts_and_the_warning() {
        let r = pb::JobResult {
            ok: true,
            snapshot_id: Bytes::copy_from_slice(&id(7)),
            files_new: 9,
            entries_unreadable: 4,
            ..Default::default()
        };
        let e = entry_from_result(&"a".repeat(32), 55, &r).unwrap();
        assert_eq!((e.files_new, e.warnings, e.time_unix), (9, 4, 55));
        assert_eq!(e.id(), Some(id(7)));
        assert!(entry_from_result("x", 1, &pb::JobResult::default()).is_none());
    }
}
