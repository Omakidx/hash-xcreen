//! A cheap structural pre-scan of protobuf bodies, run **before** `prost` decodes them.
//!
//! `prost` allocates one element per occurrence of a repeated field, and a nested message
//! element is far larger than its two-byte encoding (an empty `SecretSlot` is 2 bytes on the
//! wire and about 100 bytes in memory), so a 64 KiB body full of empty elements decodes to
//! megabytes before any count limit could be checked on the result. This scan walks the wire
//! format only (no allocation, no recursion beyond the fixed schema paths below) and rejects a
//! body whose repeated fields exceed their contract counts.
//!
//! The scan is strict: a truncated field, an over-long varint, a group wire type or a length
//! that overruns the buffer is an error, which the callers report as a decode failure
//! (a violation).

use crate::error::FrameError;

#[derive(Clone, Copy)]
struct Field<'a> {
    number: u32,
    wire: u8,
    data: &'a [u8],
}

fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = *buf.get(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(n)?;
    let s = buf.get(*pos..end)?;
    *pos = end;
    Some(s)
}

fn malformed() -> FrameError {
    FrameError::Decode("malformed protobuf wire format".into())
}

/// Visits every top-level field of `buf`; an error from `f` stops the walk.
fn walk<'a>(
    buf: &'a [u8],
    mut f: impl FnMut(Field<'a>) -> Result<(), FrameError>,
) -> Result<(), FrameError> {
    let mut pos = 0;
    while pos < buf.len() {
        let tag = varint(buf, &mut pos).ok_or_else(malformed)?;
        let number = u32::try_from(tag >> 3).map_err(|_| malformed())?;
        let wire = (tag & 7) as u8;
        let data: &[u8] = match wire {
            0 => {
                let start = pos;
                varint(buf, &mut pos).ok_or_else(malformed)?;
                &buf[start..pos]
            }
            1 => take(buf, &mut pos, 8).ok_or_else(malformed)?,
            5 => take(buf, &mut pos, 4).ok_or_else(malformed)?,
            2 => {
                let len = usize::try_from(varint(buf, &mut pos).ok_or_else(malformed)?)
                    .map_err(|_| malformed())?;
                take(buf, &mut pos, len).ok_or_else(malformed)?
            }
            _ => return Err(malformed()),
        };
        f(Field { number, wire, data })?;
    }
    Ok(())
}

/// Calls `f` on the body of every length-delimited occurrence of `field` (several occurrences
/// of an embedded message are merged by protobuf, so callers sum over all of them). Nothing is
/// collected: the scan itself allocates nothing.
fn each_sub<'a>(
    buf: &'a [u8],
    field: u32,
    mut f: impl FnMut(&'a [u8]) -> Result<(), FrameError>,
) -> Result<(), FrameError> {
    walk(buf, |x| {
        if x.number == field && x.wire == 2 {
            f(x.data)
        } else {
            Ok(())
        }
    })
}

/// Number of elements of repeated field `field` in `buf`. `packed_varint` counts the varints
/// inside a packed occurrence (and a plain varint occurrence as one); otherwise every
/// occurrence is one element (messages, strings, bytes).
fn count(buf: &[u8], field: u32, packed_varint: bool) -> Result<usize, FrameError> {
    let mut n = 0usize;
    walk(buf, |f| {
        if f.number != field {
            return Ok(());
        }
        if packed_varint && f.wire == 2 {
            // Each packed varint ends at a byte without the continuation bit.
            n = n.saturating_add(f.data.iter().filter(|b| **b & 0x80 == 0).count());
        } else if f.wire == 2 || f.wire == 0 {
            n = n.saturating_add(1);
        } else {
            return Err(FrameError::Decode("unexpected wire type".into()));
        }
        Ok(())
    })?;
    Ok(n)
}

/// Sum of `count(inner, field)` over every occurrence of the nested message `outer_field`.
fn count_in(buf: &[u8], outer_field: u32, field: u32, packed: bool) -> Result<usize, FrameError> {
    let mut total = 0usize;
    each_sub(buf, outer_field, |inner| {
        total = total.saturating_add(count(inner, field, packed)?);
        Ok(())
    })?;
    Ok(total)
}

fn too_many(what: &'static str) -> FrameError {
    FrameError::Invalid(what)
}

/// privd `Frame`: `request`(3) holds `secret_slots`(3, at most `max_slots`) and, in
/// `setup_host`(15), `extra_host_addresses`(4) with at most 16 `addresses`(1).
pub(crate) fn check_privd_frame(frame_body: &[u8], max_slots: usize) -> Result<(), FrameError> {
    each_sub(frame_body, 3, |req| {
        if count(req, 3, false)? > max_slots {
            return Err(too_many("secret_slots: too many"));
        }
        each_sub(req, 15, |host| {
            if count_in(host, 4, 1, false)? > 16 {
                return Err(too_many("setup_host.extra_host_addresses: too many"));
            }
            Ok(())
        })
    })
}

/// Admin `Frame`: `request`(3) holds `secret_slots`(3, at most `max_slots`).
pub(crate) fn check_admin_frame(frame_body: &[u8], max_slots: usize) -> Result<(), FrameError> {
    each_sub(frame_body, 3, |req| {
        if count(req, 3, false)? > max_slots {
            return Err(too_many("secret_slots: too many"));
        }
        Ok(())
    })
}

/// Link `SessionToGateway`: `info`(1) holds `codecs`(3, packed or not, at most `max_codecs`).
pub(crate) fn check_session_message(body: &[u8], max_codecs: usize) -> Result<(), FrameError> {
    if count_in(body, 1, 3, true)? > max_codecs {
        return Err(too_many("info.codecs: too many"));
    }
    Ok(())
}

/// Link `GatewayToSession`: `frame_feedback`(7) holds `results`(1, at most `max_results`).
pub(crate) fn check_gateway_message(body: &[u8], max_results: usize) -> Result<(), FrameError> {
    if count_in(body, 7, 1, false)? > max_results {
        return Err(too_many("frame_feedback.results: too many"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_elements_and_rejects_malformed_input() {
        assert_eq!(count(&[0x1a, 0, 0x1a, 0], 3, false).unwrap(), 2);
        assert_eq!(
            count(&[0x1a, 3, 1, 1, 1], 3, true).unwrap(),
            3,
            "packed varints"
        );
        assert_eq!(
            count(&[0x18, 1, 0x18, 1], 3, true).unwrap(),
            2,
            "unpacked varints"
        );
        assert!(count(&[0x1a, 5, 1], 3, false).is_err(), "length overruns");
        assert!(count(&[0x80], 3, false).is_err(), "truncated tag");
        assert!(count(&[0x0b], 1, false).is_err(), "group");
        assert!(count(&[0xff; 11], 1, false).is_err(), "over-long varint");
    }
}
