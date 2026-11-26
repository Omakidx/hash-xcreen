//! Every number of `docs/ipc.md` Part 3 that a codec or a peer needs: sizes, counts and the
//! time limits (which this crate never enforces: it has no clock and never sleeps, so the I/O
//! layers of privd, the worker and the Drive helper use these constants).

use std::time::Duration;

use super::pb;

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;

// ----- version and framing (section 25, section 26) -----

/// Protocol version spoken on both links (`Hello` / `HelloAck`): a different major ends the
/// session.
pub const VERSION_MAJOR: u32 = 1;
/// Minor version.
pub const VERSION_MINOR: u32 = 0;

/// Kind byte of a protobuf [`pb::RepoFrame`].
pub const KIND_MESSAGE: u8 = 1;
/// Kind byte of a raw secret frame (privd to worker only).
pub const KIND_SECRET: u8 = 2;
/// Kind byte of a data frame (both links, both directions).
pub const KIND_DATA: u8 = 3;

/// Maximum `length` of a kind-1 frame (kind byte plus body).
pub const MAX_MESSAGE_LENGTH: u32 = 65_536;
/// Maximum `length` of a kind-2 frame.
pub const MAX_SECRET_LENGTH: u32 = 8_192;
/// Bytes of a data frame body before the payload: `stream_id` (u64 LE) and `flags` (u8).
pub const DATA_HEADER_LEN: usize = 9;
/// Largest data frame payload.
pub const MAX_DATA_PAYLOAD: usize = 1_048_576;
/// Maximum `length` of a kind-3 frame: kind byte, header and a full payload (1 048 586).
pub const MAX_DATA_LENGTH: u32 = (1 + DATA_HEADER_LEN + MAX_DATA_PAYLOAD) as u32;
/// Bytes a writer sends before the payload of a data frame: length prefix, kind byte and header
/// (what [`super::encode_data_header`] returns).
pub const DATA_FRAME_HEADER_LEN: usize = crate::frame::PREFIX_LEN + DATA_HEADER_LEN;
/// The `END` bit of a data frame's `flags`; every other bit must be zero.
pub const FLAG_END: u8 = 0b0000_0001;

/// Outstanding repository requests per link.
pub const MAX_OUTSTANDING_REQUESTS: usize = 8;
/// Of those, at most this many writes.
pub const MAX_OUTSTANDING_WRITES: usize = 4;

// ----- objects (section 25) -----

/// Largest object: a 64 MiB pack plus one 8 MiB chunk, rounded up.
pub const MAX_OBJECT_SIZE: u32 = 96 * MIB;
/// Write cap of `CONFIG`.
pub const MAX_CONFIG_SIZE: u32 = 64 * KIB;
/// Write cap of `KEY`.
pub const MAX_KEY_SIZE: u32 = 64 * KIB;
/// Write cap of `SNAPSHOT`.
pub const MAX_SNAPSHOT_SIZE: u32 = 4 * MIB;
/// Write cap of `INDEX` and `PACK`.
pub const MAX_INDEX_PACK_SIZE: u32 = MAX_OBJECT_SIZE;
/// Entries in one `ListPage`.
pub const MAX_LIST_PAGE_ENTRIES: usize = 1_024;
/// Entries in one whole listing.
pub const MAX_LIST_ENTRIES: u32 = 1_000_000;
/// Length of an object id, a snapshot id and a rustic key id.
pub const ID_LEN: usize = 32;
/// Length of a job id.
pub const JOB_ID_LEN: usize = 16;
/// Length of `OpenRepo.server_id`.
pub const SERVER_ID_LEN: usize = 16;

/// The cap on the size of one object of `ty`, for a write, a read answer or a list entry.
/// `None` for [`pb::ObjectType::Unspecified`].
pub fn max_object_size(ty: pb::ObjectType) -> Option<u32> {
    use pb::ObjectType as T;
    match ty {
        T::Unspecified => None,
        T::Config => Some(MAX_CONFIG_SIZE),
        T::Key => Some(MAX_KEY_SIZE),
        T::Snapshot => Some(MAX_SNAPSHOT_SIZE),
        T::Index | T::Pack => Some(MAX_INDEX_PACK_SIZE),
    }
}

// ----- messages (section 27, section 28) -----

/// Maximum length of `HelloAck.software`, as privd's `Hello.software`.
pub const MAX_SOFTWARE_LEN: usize = 64;
/// Snapshots in one `JobResult` (the frame size allows fewer, about 600).
pub const MAX_SNAPSHOTS: usize = 4_096;
/// Snapshot ids in `ForgetPruneSpec.forget`.
pub const MAX_FORGET: usize = 4_096;
/// Entries in `BackupSpec.excludes`.
pub const MAX_EXCLUDES: usize = 256;
/// Longest exclude, in bytes.
pub const MAX_EXCLUDE_LEN: usize = 4_096;
/// Entries in `KeysSpec.remove_key_ids`.
pub const MAX_REMOVE_KEY_IDS: usize = 4;
/// Entries in `JobResult.key_ids`.
pub const MAX_KEY_IDS: usize = 4;
/// Secret slots on one job.
pub const MAX_SECRET_SLOTS: usize = 2;
/// Shortest secret.
pub const MIN_SECRET_BYTES: usize = 16;
/// Longest secret.
pub const MAX_SECRET_BYTES: usize = 1_024;
/// Tags on a `BACKUP` spec or a snapshot entry.
pub const MAX_TAGS: usize = 4;
/// Longest tag.
pub const MAX_TAG_LEN: usize = 64;
/// Longest text field of the manifest input (`hx_backup::manifest::MAX_TEXT_BYTES`).
pub const MAX_TEXT_LEN: usize = 128;
/// Container configuration entries (`hx_backup::manifest::MAX_CONFIG_ENTRIES`).
pub const MAX_CONFIG_ENTRIES: usize = 256;
/// Longest container configuration key (`hx_backup::manifest::MAX_CONFIG_KEY_BYTES`).
pub const MAX_CONFIG_KEY_LEN: usize = 128;
/// Longest container configuration value (`hx_backup::manifest::MAX_CONFIG_VALUE_BYTES`).
pub const MAX_CONFIG_VALUE_LEN: usize = 1_024;
/// Longest `OpenRepo.folder`.
pub const MAX_FOLDER_LEN: usize = 128;
/// Largest `JobResult.manifest`: what a 64 KiB frame can carry with the rest of the result.
pub const MAX_MANIFEST_BYTES: usize = 61_440;

/// `INIT`: the compression level.
pub const INIT_COMPRESSION: u32 = 3;
/// `INIT`: `datapack_size_limit`, 64 MiB.
pub const INIT_DATAPACK_SIZE_LIMIT: u32 = 64 * MIB;
/// `INIT`: `treepack_size_limit`, 16 MiB.
pub const INIT_TREEPACK_SIZE_LIMIT: u32 = 16 * MIB;

/// `Progress` frames per second at most (the sender paces itself; this crate has no clock).
pub const MAX_PROGRESS_PER_SECOND: u32 = 2;

// ----- time limits (section 24, 26, 29, 32): for the I/O layers -----

/// privd connects to the worker's socket, retrying at this interval...
pub const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(200);
/// ...for at most this long after the helper starts.
pub const CONNECT_RETRY_WINDOW: Duration = Duration::from_secs(30);
/// privd sends `Hello` within this long of connecting.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// The helper must reach `HelloAck` within this long of its start.
pub const HELPER_ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// privd sends `Ping` this often on both links.
pub const PING_INTERVAL: Duration = Duration::from_secs(15);
/// A peer silent for this long is dead.
pub const PEER_SILENCE_TIMEOUT: Duration = Duration::from_secs(45);
/// The worker exits after this long without anything from privd.
pub const WORKER_SILENCE_TIMEOUT: Duration = Duration::from_secs(60);
/// After `Cancel` the worker answers `JobResult{CANCELLED}` within this long.
pub const CANCEL_GRACE: Duration = Duration::from_secs(30);
/// privd guarantees every request an answer within this long, not counting a daily-limit pause.
pub const REQUEST_ANSWER_BUDGET: Duration = Duration::from_secs(30 * 60);
/// The Drive helper's daily-limit pause is this long, then a probe...
pub const DAILY_LIMIT_PAUSE: Duration = Duration::from_secs(60 * 60);
/// ...at most this many times per session.
pub const MAX_DAILY_LIMIT_PAUSES: u32 = 26;
/// The Drive helper exits this long after the last connection closes.
pub const DRIVE_IDLE_EXIT: Duration = Duration::from_secs(60);
/// The Drive helper may cache the lease for at most this long.
pub const LEASE_CACHE_MAX: Duration = Duration::from_secs(60);
/// After a takeover the new owner starts no write job for this long.
pub const TAKEOVER_QUIET_PERIOD: Duration = Duration::from_secs(2 * 60);
/// First retry delay of the Drive helper (doubling, equal jitter).
pub const RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Longest retry delay.
pub const RETRY_MAX: Duration = Duration::from_secs(64);
/// Retries per request.
pub const MAX_RETRIES: u32 = 8;

/// The Drive helper's per-attempt timeout for a transfer of `bytes`: 60 s plus 4 s per MiB
/// (rounded up).
pub fn attempt_timeout(bytes: u64) -> Duration {
    let mib = bytes.div_ceil(1024 * 1024);
    Duration::from_secs(60 + 4 * mib)
}

/// The deadline of a job of `kind` (section 32). `None` for [`pb::JobKind::Unspecified`].
pub fn job_deadline(kind: pb::JobKind) -> Option<Duration> {
    use pb::JobKind as K;
    let minutes = |m: u64| Duration::from_secs(m * 60);
    Some(match kind {
        K::Unspecified => return None,
        K::Init => minutes(30),
        K::Keys | K::Snapshots | K::RestorePlan => minutes(10),
        K::Check | K::ForgetPrune => minutes(6 * 60),
        K::Restore => minutes(12 * 60),
        K::Backup => minutes(30 * 60),
    })
}
