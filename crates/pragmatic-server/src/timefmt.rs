//! Wall-clock times: Unix time and RFC 3339 text in UTC.
//!
//! The server stamps records with wall-clock times only as information.
//! Leases and every other deadline use the monotonic clock
//! ([`std::time::Instant`]), because a wall clock can jump. Times in JSON
//! are RFC 3339 in UTC with a `Z` suffix and whole seconds, which sort as
//! text in time order.

use std::time::{SystemTime, UNIX_EPOCH};

/// Nanoseconds since the Unix epoch, the unit of a journal entry's `at`.
pub fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Seconds since the Unix epoch.
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The current time as RFC 3339.
pub fn now_rfc3339() -> String {
    rfc3339(now_unix_secs())
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day number (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Unix nanoseconds as RFC 3339 (whole seconds).
pub fn rfc3339_ns(unix_ns: u64) -> String {
    rfc3339((unix_ns / 1_000_000_000) as i64)
}

/// Parse RFC 3339: `YYYY-MM-DDTHH:MM:SS`, an optional fraction (ignored),
/// and `Z` or a `±HH:MM` offset. Returns Unix seconds.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = text.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' {
        return None;
    }
    if b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let rb = rest.as_bytes();
            if rest.len() != 6 || rb[3] != b':' {
                return None;
            }
            let oh: i64 = rest[1..3].parse().ok()?;
            let om: i64 = rest[4..6].parse().ok()?;
            if oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    // Reject dates that do not exist (February 30th) by round-tripping.
    if civil_from_days(days) != (y, mo as u32, d as u32) {
        return None;
    }
    Some(days * 86_400 + h * 3600 + mi * 60 + s - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_849_600), "2026-10-13T00:00:00Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn round_trips() {
        for t in [
            0i64,
            1,
            59,
            86_399,
            86_400,
            951_782_400,
            1_791_849_645,
            4_102_444_800,
        ] {
            assert_eq!(parse_rfc3339(&rfc3339(t)), Some(t));
        }
    }

    #[test]
    fn offsets_and_fractions() {
        assert_eq!(parse_rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00.123456Z"), Some(0));
        assert_eq!(parse_rfc3339("1969-12-31T19:00:00-05:00"), Some(0));
    }

    #[test]
    fn malformed_text_is_refused() {
        for bad in [
            "",
            "2026-10-13",
            "2026-10-13 00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-13T24:00:00Z",
            "2026-10-13T00:00:00",
            "2026-10-13T00:00:00.Z",
            "2026-10-13T00:00:00+0100",
            "+026-10-13T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
