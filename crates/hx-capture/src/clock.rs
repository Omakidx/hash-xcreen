use rustix::time::{ClockId, clock_gettime};

/// `CLOCK_MONOTONIC` in nanoseconds. Same clock and unit as `hx_codec::mono_ns`, so
/// timestamps from capture and encode can be subtracted directly (and compared across
/// processes on the same kernel).
pub fn mono_ns() -> u64 {
    let ts = clock_gettime(ClockId::Monotonic);
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}
