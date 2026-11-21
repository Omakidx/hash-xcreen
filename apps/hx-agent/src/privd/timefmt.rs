//! UTC time formatting and parsing without a date crate (snapshot names, audit timestamps,
//! Incus `created_at`).

const SECS_PER_DAY: u64 = 86_400;

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day, hour, minute, second)` of a Unix time in UTC.
pub fn civil(unix: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix / SECS_PER_DAY) as i64;
    let rem = unix % SECS_PER_DAY;
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// `2026-11-21T10:15:00Z`.
pub fn rfc3339(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `20261121T101500Z`, the timestamp segment of a snapshot name (`[0-9TZ-]+`).
pub fn snapshot_stamp(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)` into Unix seconds. Anything else is
/// `None`.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || !s.is_ascii() {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<u32>().ok();
    if b[4] != b'-'
        || b[7] != b'-'
        || !(b[10] == b'T' || b[10] == b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (s.get(0..4)?.parse::<i64>().ok()?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let end = frac
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(frac.len());
        if end == 0 {
            return None;
        }
        rest = &frac[end..];
    }
    let offset: i64 = match rest {
        "Z" | "z" => 0,
        r if r.len() == 6
            && (r.starts_with('+') || r.starts_with('-'))
            && r.as_bytes()[3] == b':' =>
        {
            let hh = r.get(1..3)?.parse::<i64>().ok()?;
            let mm = r.get(4..6)?.parse::<i64>().ok()?;
            let v = hh * 3600 + mm * 60;
            if r.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    let t = days * SECS_PER_DAY as i64 + i64::from(h * 3600 + mi * 60 + sec) - offset;
    u64::try_from(t).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_795_256_100), "2026-11-21T10:15:00Z");
        assert_eq!(snapshot_stamp(1_795_256_100), "20261121T101500Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn parse_round_trips_and_handles_offsets() {
        for t in [0u64, 1, 86_399, 951_782_400, 1_795_256_100, 4_102_444_800] {
            assert_eq!(parse_rfc3339(&rfc3339(t)), Some(t));
        }
        assert_eq!(
            parse_rfc3339("2026-11-21T11:15:00.123456789+01:00"),
            Some(1_795_256_100)
        );
        assert_eq!(
            parse_rfc3339("2026-11-21T10:15:00-00:00"),
            Some(1_795_256_100)
        );
        for bad in [
            "",
            "garbage",
            "2026-13-01T00:00:00Z",
            "2026-11-21T10:15:00",
            "2026-11-21T10:15:00.Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
