//! UTC timestamps as RFC 3339 text, without a date library.
//!
//! Evidence reports times from signed structures (a TSA's `genTime`, a
//! witness's cosignature timestamp) and journal entries carry `at` in Unix
//! nanoseconds. Both are shown to people as `2026-10-13T12:00:00Z`, which
//! needs only the proleptic Gregorian calendar: the conversion below is the
//! standard days-from-civil algorithm, exact for every `i64` second count a
//! journal or token can hold.

/// `YYYY-MM-DDTHH:MM:SS[.fffffffff]Z` for a Unix time. The fraction is
/// printed only when `nanos` is not zero, with trailing zeros removed.
pub fn rfc3339(unix_secs: i64, nanos: u32) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, secs / 60 % 60, secs % 60);
    let mut out = format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}");
    if nanos > 0 {
        let frac = format!("{:09}", nanos.min(999_999_999));
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

/// [`rfc3339`] for a journal `at` (Unix nanoseconds).
pub fn rfc3339_nanos(at: u64) -> String {
    rfc3339((at / 1_000_000_000) as i64, (at % 1_000_000_000) as u32)
}

/// The current time, to the second, as RFC 3339.
pub fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339(secs, 0)
}

/// True for the shape [`rfc3339`] writes: `YYYY-MM-DDTHH:MM:SS`, an
/// optional fraction of one to nine digits, and `Z`, with the date and time
/// fields in range. Evidence accepts only UTC so that two bundles never
/// spell the same instant two ways.
pub fn is_rfc3339_utc(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() < 20 || b[b.len() - 1] != b'Z' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = text.get(r)?;
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let seps = b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':';
    let fields = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    );
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) = fields else {
        return false;
    };
    let in_range = (1..=12).contains(&mo)
        && d >= 1
        && d <= days_in_month(y as i64, mo)
        && h < 24
        && mi < 60
        && s < 60;
    let frac = &text[19..text.len() - 1];
    let frac_ok = frac.is_empty()
        || (frac.len() >= 2
            && frac.len() <= 10
            && frac.starts_with('.')
            && frac[1..].bytes().all(|c| c.is_ascii_digit()));
    seps && in_range && frac_ok
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `(year, month, day)` for days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400, 0), "2000-02-29T00:00:00Z");
        assert_eq!(
            rfc3339(1_791_888_202, 250_000_000),
            "2026-10-13T10:43:22.25Z"
        );
        assert_eq!(rfc3339(-1, 0), "1969-12-31T23:59:59Z");
        assert_eq!(rfc3339(4_102_444_800, 1), "2100-01-01T00:00:00.000000001Z");
        assert_eq!(rfc3339_nanos(1_500_000_000), "1970-01-01T00:00:01.5Z");
    }

    #[test]
    fn shape_check() {
        for ok in [
            "2026-10-13T10:43:22Z",
            "2026-10-13T10:43:22.5Z",
            "2024-02-29T00:00:00.123456789Z",
        ] {
            assert!(is_rfc3339_utc(ok), "{ok}");
            let _ = ok;
        }
        for bad in [
            "2026-10-13T10:43:22",
            "2026-10-13 10:43:22Z",
            "2026-13-01T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-10-13T24:00:00Z",
            "2026-10-13T10:43:22.Z",
            "2026-10-13T10:43:22+00:00",
            "2026-10-13T10:43:22.1234567890Z",
        ] {
            assert!(!is_rfc3339_utc(bad), "{bad}");
        }
        assert!(is_rfc3339_utc(&now_rfc3339()));
    }
}
