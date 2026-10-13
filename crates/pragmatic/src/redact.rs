//! Detect and redact personal data and secrets in free text.
//!
//! Journals hold whatever agents saw and said: prompts, completions, tool
//! inputs and outputs. Pragmatic Server shows that content to auditors and
//! operators who are not entitled to the personal data or credentials in
//! it, so content is served through [`redact`] unless the viewer may see it
//! raw. Redaction is a view, never a write: the journal keeps the original
//! bytes, and the hash chain still verifies.
//!
//! The core crate is zero-dependency, so there is no regex engine here.
//! Each detector is a hand-written scanner over the UTF-8 bytes that
//! accepts one structured format and then validates it the way the issuer
//! would (Luhn for cards, ISO 7064 mod 97 for IBANs, area rules for SSNs,
//! octet ranges for IPv4). That gives two properties a regex set would not
//! promise:
//!
//! - **Linear time.** Every scan is single-pass over the input and every
//!   candidate is bounded in length or consumed once, so no input can
//!   trigger backtracking blowups. Server-side redaction runs on untrusted
//!   text, so this is a safety property, not a speed one.
//! - **UTF-8 safe ranges.** Every match starts and ends on an ASCII byte or
//!   at the end of the text, so every [`Match`] range is on a `char`
//!   boundary and can be sliced directly.
//!
//! Detectors favor precision on numbers (a bare 9- or 10-digit run is an
//! order id or a Unix timestamp far more often than an SSN or a phone
//! number, so those formats need separators or a `+`) and recall on
//! secrets (a credential is worth hiding even when it is malformed).
//! Overlapping matches from different detectors are resolved
//! leftmost-longest.

use std::collections::HashMap;

/// What a detector looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `local@domain.tld`, ASCII only.
    Email,
    /// E.164 (`+` and 10 to 15 digits, optionally grouped) and North
    /// American formats with separators (`(555) 123-4567`, `555-123-4567`,
    /// `555.123.4567`, `1-555-123-4567`).
    Phone,
    /// US Social Security numbers written `AAA-GG-SSSS` or `AAA GG SSSS`,
    /// excluding numbers the SSA never issues.
    Ssn,
    /// 13 to 19 digit card numbers, optionally grouped with spaces or
    /// dashes, with a known issuer prefix and a valid Luhn check digit.
    PaymentCard,
    /// IBANs in upper case, compact or grouped with spaces, with the
    /// registered length for their country and valid mod 97 check digits.
    Iban,
    /// Dotted-quad IPv4 addresses.
    Ipv4,
    /// API keys with an `sk-` prefix (OpenAI, Anthropic `sk-ant-` and
    /// project keys `sk-proj-`) and Stripe-style `sk_live_`, `sk_test_`,
    /// `rk_live_`, `rk_test_` keys.
    ApiKey,
    /// AWS access key ids (`AKIA` or `ASIA` and 16 more characters).
    AwsAccessKey,
    /// GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`).
    GithubToken,
    /// Slack tokens (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`).
    SlackToken,
    /// JSON Web Tokens (compact JWS or JWE starting with `eyJ`).
    Jwt,
    /// The credential after `Bearer ` (the word itself is kept).
    BearerToken,
    /// PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----` through
    /// the matching `END` line, or to the end of the key body if the block
    /// was truncated).
    PrivateKey,
}

impl Kind {
    /// Every detector.
    pub const ALL: [Kind; 13] = [
        Kind::Email,
        Kind::Phone,
        Kind::Ssn,
        Kind::PaymentCard,
        Kind::Iban,
        Kind::Ipv4,
        Kind::ApiKey,
        Kind::AwsAccessKey,
        Kind::GithubToken,
        Kind::SlackToken,
        Kind::Jwt,
        Kind::BearerToken,
        Kind::PrivateKey,
    ];

    /// Detectors for personal data.
    pub const PERSONAL: [Kind; 6] = [
        Kind::Email,
        Kind::Phone,
        Kind::Ssn,
        Kind::PaymentCard,
        Kind::Iban,
        Kind::Ipv4,
    ];

    /// Detectors for credentials.
    pub const SECRETS: [Kind; 7] = [
        Kind::ApiKey,
        Kind::AwsAccessKey,
        Kind::GithubToken,
        Kind::SlackToken,
        Kind::Jwt,
        Kind::BearerToken,
        Kind::PrivateKey,
    ];

    /// Stable lowercase name, for configuration files and APIs.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Phone => "phone",
            Kind::Ssn => "ssn",
            Kind::PaymentCard => "payment_card",
            Kind::Iban => "iban",
            Kind::Ipv4 => "ipv4",
            Kind::ApiKey => "api_key",
            Kind::AwsAccessKey => "aws_access_key",
            Kind::GithubToken => "github_token",
            Kind::SlackToken => "slack_token",
            Kind::Jwt => "jwt",
            Kind::BearerToken => "bearer_token",
            Kind::PrivateKey => "private_key",
        }
    }

    /// The inverse of [`Kind::name`].
    pub fn from_name(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The text [`redact`] substitutes for a match, e.g. `[email]`.
    pub fn placeholder(self) -> &'static str {
        match self {
            Kind::Email => "[email]",
            Kind::Phone => "[phone]",
            Kind::Ssn => "[ssn]",
            Kind::PaymentCard => "[payment_card]",
            Kind::Iban => "[iban]",
            Kind::Ipv4 => "[ipv4]",
            Kind::ApiKey => "[api_key]",
            Kind::AwsAccessKey => "[aws_access_key]",
            Kind::GithubToken => "[github_token]",
            Kind::SlackToken => "[slack_token]",
            Kind::Jwt => "[jwt]",
            Kind::BearerToken => "[bearer_token]",
            Kind::PrivateKey => "[private_key]",
        }
    }

    /// Tie-break when two detectors claim exactly the same span: the more
    /// specific format wins (a JWT sent as a bearer token is labelled a
    /// JWT).
    fn priority(self) -> u8 {
        match self {
            Kind::BearerToken => 1,
            _ => 0,
        }
    }
}

/// One detected span: `text[start..end]` is the matched content. Both
/// offsets are byte offsets on `char` boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Match {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

impl Match {
    /// `start..end`.
    pub fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }
}

/// Find every match of the given kinds, in order, without overlaps.
///
/// When matches from different detectors overlap, the one that starts
/// first wins, then the longer one (leftmost-longest). Passing an empty
/// slice finds nothing; pass [`Kind::ALL`] for everything.
pub fn find(text: &str, kinds: &[Kind]) -> Vec<Match> {
    let b = text.as_bytes();
    let mut candidates = Vec::new();
    for kind in Kind::ALL {
        if kinds.contains(&kind) {
            detect(kind, b, &mut candidates);
        }
    }
    candidates.sort_by(|x, y| {
        x.start
            .cmp(&y.start)
            .then(y.end.cmp(&x.end))
            .then(x.kind.priority().cmp(&y.kind.priority()))
    });
    let mut out: Vec<Match> = Vec::with_capacity(candidates.len());
    let mut taken = 0;
    for m in candidates {
        if m.start >= taken {
            taken = m.end;
            out.push(m);
        }
    }
    debug_assert!(out
        .iter()
        .all(|m| text.is_char_boundary(m.start) && text.is_char_boundary(m.end)));
    out
}

/// Replace every match with its kind's placeholder (`[email]`, ...).
///
/// Returns the redacted text and the matches, whose offsets refer to the
/// original `text`.
pub fn redact(text: &str, kinds: &[Kind]) -> (String, Vec<Match>) {
    let matches = find(text, kinds);
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in &matches {
        out.push_str(&text[last..m.start]);
        out.push_str(m.kind.placeholder());
        last = m.end;
    }
    out.push_str(&text[last..]);
    (out, matches)
}

fn detect(kind: Kind, b: &[u8], out: &mut Vec<Match>) {
    match kind {
        Kind::Email => emails(b, out),
        Kind::Phone => phones(b, out),
        Kind::Ssn => ssns(b, out),
        Kind::PaymentCard => cards(b, out),
        Kind::Iban => ibans(b, out),
        Kind::Ipv4 => ipv4s(b, out),
        Kind::ApiKey => prefixed(
            b,
            out,
            Kind::ApiKey,
            &[b"sk-", b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"],
            is_key_char,
            |body| body.len() >= 20 && body.iter().any(u8::is_ascii_digit),
        ),
        Kind::AwsAccessKey => aws_keys(b, out),
        Kind::GithubToken => {
            prefixed(
                b,
                out,
                Kind::GithubToken,
                &[b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"],
                |c| c.is_ascii_alphanumeric(),
                |body| body.len() >= 36,
            );
            prefixed(
                b,
                out,
                Kind::GithubToken,
                &[b"github_pat_"],
                is_word,
                |body| body.len() >= 22,
            );
        }
        Kind::SlackToken => prefixed(
            b,
            out,
            Kind::SlackToken,
            &[b"xoxa-", b"xoxb-", b"xoxp-", b"xoxr-"],
            |c| c.is_ascii_alphanumeric() || c == b'-',
            |body| body.len() >= 10,
        ),
        Kind::Jwt => jwts(b, out),
        Kind::BearerToken => bearer_tokens(b, out),
        Kind::PrivateKey => private_keys(b, out),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn is_key_char(c: u8) -> bool {
    is_word(c) || c == b'-'
}

fn is_digit_at(b: &[u8], i: usize) -> bool {
    b.get(i).is_some_and(u8::is_ascii_digit)
}

/// Length of the run of `pred` bytes starting at `i`.
fn run(b: &[u8], i: usize, pred: impl Fn(u8) -> bool) -> usize {
    b[i.min(b.len())..].iter().take_while(|&&c| pred(c)).count()
}

/// True if a number starting at `i` is not glued to a preceding word or
/// number: the previous byte is not a word character or `+`, and is not a
/// `-`, `.`, `/` or `,` that continues a digit sequence (so `2024-01-15`
/// and `10.0.0.1` are never split into smaller numbers).
fn number_starts_at(b: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let p = b[i - 1];
    if is_word(p) || p == b'+' {
        return false;
    }
    !(matches!(p, b'-' | b'.' | b'/' | b',') && i >= 2 && b[i - 2].is_ascii_digit())
}

/// True if a number ending at `end` is not glued to what follows: the next
/// byte is not a word character, and is not a `-`, `.`, `/` or `,` that
/// continues the digits.
fn number_ends_at(b: &[u8], end: usize) -> bool {
    match b.get(end) {
        None => true,
        Some(&c) if is_word(c) => false,
        Some(b'-' | b'.' | b'/' | b',') => !is_digit_at(b, end + 1),
        Some(_) => true,
    }
}

/// Parse exactly `n` digits at `i`; return their value.
fn digits_exact(b: &[u8], i: usize, n: usize) -> Option<u32> {
    let s = b.get(i..i + n)?;
    if !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0, |acc, &c| acc * 10 + (c - b'0') as u32))
}

/// Scan for tokens that start with one of `prefixes` (at a word boundary)
/// and continue with a run of `body` bytes accepted by `valid`.
fn prefixed(
    b: &[u8],
    out: &mut Vec<Match>,
    kind: Kind,
    prefixes: &[&[u8]],
    body: impl Fn(u8) -> bool,
    valid: impl Fn(&[u8]) -> bool,
) {
    let mut i = 0;
    while i < b.len() {
        let at_boundary = i == 0 || !is_key_char(b[i - 1]);
        let prefix = prefixes.iter().find(|p| b[i..].starts_with(p));
        if let (true, Some(p)) = (at_boundary, prefix) {
            let start = i + p.len();
            let len = run(b, start, &body);
            if valid(&b[start..start + len]) {
                out.push(Match {
                    kind,
                    start: i,
                    end: start + len,
                });
            }
            // The run cannot contain another boundary-anchored token.
            i = start + len.max(1);
            continue;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

fn is_local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'-'
}

/// Anchor on each `@`, extend left over the local part and right over the
/// domain. Neither run can cross another `@`, so every byte is visited by
/// at most two anchors (the one before it and the one after it) and the
/// scan stays linear.
fn emails(b: &[u8], out: &mut Vec<Match>) {
    let mut taken = 0;
    for at in 0..b.len() {
        if b[at] != b'@' || at < taken {
            continue;
        }
        let mut start = at;
        while start > taken && is_local_char(b[start - 1]) {
            start -= 1;
        }
        while start < at && b[start] == b'.' {
            start += 1;
        }
        if start == at {
            continue;
        }
        let limit = at + 1 + run(b, at + 1, is_domain_char);
        if let Some(end) = domain_end(b, at + 1, limit) {
            out.push(Match {
                kind: Kind::Email,
                start,
                end,
            });
            taken = end;
        }
    }
}

/// The end of the longest prefix of `b[from..limit]` that is a host name of
/// at least two labels ending in an alphabetic TLD of two or more letters.
/// Trailing dots and hyphens (sentence punctuation) are never included.
fn domain_end(b: &[u8], from: usize, limit: usize) -> Option<usize> {
    let mut best = None;
    let mut labels = 0;
    let mut start = from;
    while start < limit {
        let len = run(&b[..limit], start, |c| c != b'.');
        let label = &b[start..start + len];
        let valid = !label.is_empty()
            && label.len() <= 63
            && label[0] != b'-'
            && label[label.len() - 1] != b'-';
        if !valid {
            break;
        }
        labels += 1;
        if labels >= 2 && label.len() >= 2 && label.iter().all(u8::is_ascii_alphabetic) {
            best = Some(start + len);
        }
        start += len + 1;
    }
    best
}

// ---------------------------------------------------------------------------
// Phone numbers
// ---------------------------------------------------------------------------

fn phones(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let anchor = c == b'+' || c == b'(' || c.is_ascii_digit();
        if anchor && number_starts_at(b, i) {
            let end = if c == b'+' {
                e164(b, i + 1)
            } else {
                north_american(b, i)
            };
            if let Some(end) = end {
                out.push(Match {
                    kind: Kind::Phone,
                    start: i,
                    end,
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

fn is_phone_sep(c: u8) -> bool {
    matches!(c, b' ' | b'-' | b'.')
}

/// `+` then 10 to 15 digits in groups separated by single spaces, dashes
/// or dots, where a group may be parenthesized (`+44 (0)20 7946 0958`).
/// `i` is just past the `+`. Groups that would push the total past 15
/// digits are left out rather than failing the whole number.
fn e164(b: &[u8], i: usize) -> Option<usize> {
    if !is_digit_at(b, i) {
        return None;
    }
    let mut k = i;
    let mut digits = 0;
    let mut end = i;
    loop {
        // One group: digits, or `(digits)`.
        let (len, group_end) = if b.get(k) == Some(&b'(') {
            let len = run(b, k + 1, |c| c.is_ascii_digit());
            if len == 0 || b.get(k + 1 + len) != Some(&b')') {
                break;
            }
            (len, k + len + 2)
        } else {
            let len = run(b, k, |c| c.is_ascii_digit());
            if len == 0 {
                break;
            }
            (len, k + len)
        };
        if digits + len > 15 {
            if digits == 0 {
                return None; // one unbroken run longer than any phone number
            }
            break;
        }
        digits += len;
        end = group_end;
        k = group_end;
        // A separator, or a parenthesized group glued to the previous one.
        match b.get(k) {
            Some(&c) if is_phone_sep(c) && matches!(b.get(k + 1), Some(b'0'..=b'9' | b'(')) => {
                k += 1
            }
            Some(b'(') => {}
            Some(b'0'..=b'9') if b[k - 1] == b')' => {}
            _ => break,
        }
    }
    (digits >= 10 && number_ends_at(b, end)).then_some(end)
}

/// `[1 sep] (AAA) EEE-NNNN` or `[1 sep] AAA sep EEE sep NNNN` with one
/// consistent separator from space, dash and dot.
fn north_american(b: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    let country_code = b[k] == b'1'
        && b.get(k + 1).is_some_and(|&c| is_phone_sep(c))
        && matches!(b.get(k + 2), Some(b'0'..=b'9' | b'('));
    if country_code {
        k += 2;
    }
    let end = if b.get(k) == Some(&b'(') {
        digits_exact(b, k + 1, 3)?;
        if b.get(k + 4) != Some(&b')') {
            return None;
        }
        k += 5;
        if b.get(k) == Some(&b' ') {
            k += 1;
        }
        digits_exact(b, k, 3)?;
        if !b.get(k + 3).is_some_and(|&c| is_phone_sep(c)) {
            return None;
        }
        digits_exact(b, k + 4, 4)?;
        k + 8
    } else {
        digits_exact(b, k, 3)?;
        let sep = *b.get(k + 3).filter(|&&c| is_phone_sep(c))?;
        digits_exact(b, k + 4, 3)?;
        if b.get(k + 7) != Some(&sep) {
            return None;
        }
        digits_exact(b, k + 8, 4)?;
        k + 12
    };
    number_ends_at(b, end).then_some(end)
}

// ---------------------------------------------------------------------------
// US Social Security numbers
// ---------------------------------------------------------------------------

fn ssns(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 11 <= b.len() {
        if b[i].is_ascii_digit() && number_starts_at(b, i) {
            if let Some(end) = ssn_at(b, i) {
                out.push(Match {
                    kind: Kind::Ssn,
                    start: i,
                    end,
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

fn ssn_at(b: &[u8], i: usize) -> Option<usize> {
    let area = digits_exact(b, i, 3)?;
    let sep = *b.get(i + 3).filter(|&&c| c == b'-' || c == b' ')?;
    let group = digits_exact(b, i + 4, 2)?;
    if b.get(i + 6) != Some(&sep) {
        return None;
    }
    let serial = digits_exact(b, i + 7, 4)?;
    let end = i + 11;
    // The SSA never issues area 000, 666 or 900-999, group 00 or serial
    // 0000, so those are not SSNs (and 9xx-xx-xxxx are ITINs).
    let issued = area != 0 && area != 666 && area < 900 && group != 0 && serial != 0;
    (issued && number_ends_at(b, end)).then_some(end)
}

// ---------------------------------------------------------------------------
// Payment cards
// ---------------------------------------------------------------------------

fn cards(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_digit() && number_starts_at(b, i)) {
            i += 1;
            continue;
        }
        let (found, consumed) = card_at(b, i);
        if let Some(end) = found {
            out.push(Match {
                kind: Kind::PaymentCard,
                start: i,
                end,
            });
        }
        i = consumed.max(i + 1);
    }
}

/// Read a run of digits starting at `i`, optionally grouped by one kind of
/// separator (space or dash). Returns the end of the longest prefix that
/// ends at a group boundary and is a plausible card number, plus how far
/// the scan read (so the caller never rescans the run).
fn card_at(b: &[u8], i: usize) -> (Option<usize>, usize) {
    let mut digits = [0u8; 19];
    let mut count = 0;
    // (digit count, end offset) at each group boundary.
    let mut boundaries: Vec<(usize, usize)> = Vec::new();
    let mut sep: Option<u8> = None;
    let mut k = i;
    loop {
        let len = run(b, k, |c| c.is_ascii_digit());
        if count + len > 19 {
            // Too long to be a card from here on; skip the rest of the run.
            k += len;
            break;
        }
        digits[count..count + len].copy_from_slice(&b[k..k + len]);
        count += len;
        k += len;
        boundaries.push((count, k));
        match b.get(k) {
            Some(&c)
                if (c == b' ' || c == b'-')
                    && is_digit_at(b, k + 1)
                    && sep.is_none_or(|s| s == c) =>
            {
                sep = Some(c);
                k += 1;
            }
            _ => break,
        }
    }
    // Candidates end at group boundaries, longest first. An unbroken run
    // has one boundary (or none if it overflowed), so it must be a card in
    // full; a grouped run may be followed by more numbers
    // (`4111 1111 1111 1111 2025`).
    let found = boundaries
        .iter()
        .rev()
        .find(|&&(n, end)| {
            (13..=19).contains(&n)
                && number_ends_at(b, end)
                && issuer_accepts(&digits[..n])
                && luhn_valid(&digits[..n])
        })
        .map(|&(_, end)| end);
    (found, k)
}

/// Luhn (mod 10) check over ASCII digits.
fn luhn_valid(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &c)| {
            let d = (c - b'0') as u32;
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Known issuer (IIN) prefixes and the lengths each network issues.
fn issuer_accepts(digits: &[u8]) -> bool {
    let n = digits.len();
    let prefix = |len: usize| {
        digits[..len]
            .iter()
            .fold(0u32, |acc, &c| acc * 10 + (c - b'0') as u32)
    };
    let (p1, p2, p3, p4) = (prefix(1), prefix(2), prefix(3), prefix(4));
    let visa = p1 == 4 && matches!(n, 13 | 16 | 19);
    let mastercard = ((51..=55).contains(&p2) || (2221..=2720).contains(&p4)) && n == 16;
    let amex = (p2 == 34 || p2 == 37) && n == 15;
    let discover = (p4 == 6011 || (644..=649).contains(&p3) || p2 == 65) && (16..=19).contains(&n);
    let unionpay = p2 == 62 && (16..=19).contains(&n);
    let jcb = (3528..=3589).contains(&p4) && (16..=19).contains(&n);
    let diners =
        ((300..=305).contains(&p3) || matches!(p2, 36 | 38 | 39)) && (14..=19).contains(&n);
    let maestro = (p2 == 50 || (56..=69).contains(&p2)) && (13..=19).contains(&n);
    visa || mastercard || amex || discover || unionpay || jcb || diners || maestro
}

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------

/// IBAN lengths by country, from the SWIFT IBAN registry (89 countries),
/// sorted by country code.
#[rustfmt::skip]
const IBAN_LENGTHS: [(&[u8; 2], usize); 89] = [
    (b"AD", 24), (b"AE", 23), (b"AL", 28), (b"AT", 20), (b"AZ", 28), (b"BA", 20),
    (b"BE", 16), (b"BG", 22), (b"BH", 22), (b"BI", 27), (b"BR", 29), (b"BY", 28),
    (b"CH", 21), (b"CR", 22), (b"CY", 28), (b"CZ", 24), (b"DE", 22), (b"DJ", 27),
    (b"DK", 18), (b"DO", 28), (b"EE", 20), (b"EG", 29), (b"ES", 24), (b"FI", 18),
    (b"FK", 18), (b"FO", 18), (b"FR", 27), (b"GB", 22), (b"GE", 22), (b"GI", 23),
    (b"GL", 18), (b"GR", 27), (b"GT", 28), (b"HN", 28), (b"HR", 21), (b"HU", 28),
    (b"IE", 22), (b"IL", 23), (b"IQ", 23), (b"IS", 26), (b"IT", 27), (b"JO", 30),
    (b"KW", 30), (b"KZ", 20), (b"LB", 28), (b"LC", 32), (b"LI", 21), (b"LT", 20),
    (b"LU", 20), (b"LV", 21), (b"LY", 25), (b"MC", 27), (b"MD", 24), (b"ME", 22),
    (b"MK", 19), (b"MN", 20), (b"MR", 27), (b"MT", 31), (b"MU", 30), (b"NI", 28),
    (b"NL", 18), (b"NO", 15), (b"OM", 23), (b"PK", 24), (b"PL", 28), (b"PS", 29),
    (b"PT", 25), (b"QA", 29), (b"RO", 24), (b"RS", 22), (b"RU", 33), (b"SA", 24),
    (b"SC", 31), (b"SD", 18), (b"SE", 24), (b"SI", 19), (b"SK", 24), (b"SM", 27),
    (b"SO", 23), (b"ST", 25), (b"SV", 28), (b"TL", 23), (b"TN", 24), (b"TR", 26),
    (b"UA", 29), (b"VA", 22), (b"VG", 24), (b"XK", 20), (b"YE", 30),
];

fn iban_length(country: &[u8]) -> Option<usize> {
    IBAN_LENGTHS
        .iter()
        .find(|(code, _)| code[..] == *country)
        .map(|&(_, len)| len)
}

fn ibans(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 4 <= b.len() {
        let starts = (i == 0 || !is_word(b[i - 1]))
            && b[i].is_ascii_uppercase()
            && b[i + 1].is_ascii_uppercase()
            && b[i + 2].is_ascii_digit()
            && b[i + 3].is_ascii_digit();
        if starts {
            if let Some(end) = iban_at(b, i) {
                out.push(Match {
                    kind: Kind::Iban,
                    start: i,
                    end,
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

/// Collect exactly the registered number of characters for the country,
/// allowing single spaces between them (the print format groups by four,
/// some countries group differently), then check the boundary and the
/// mod 97 check digits.
fn iban_at(b: &[u8], i: usize) -> Option<usize> {
    let want = iban_length(&b[i..i + 2])?;
    let mut chars = [0u8; 34];
    let mut n = 0;
    let mut k = i;
    while n < want {
        let c = *b.get(k)?;
        if c.is_ascii_uppercase() || c.is_ascii_digit() {
            chars[n] = c;
            n += 1;
            k += 1;
        } else if c == b' '
            && n >= 4
            && b.get(k + 1)
                .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            k += 1;
        } else {
            return None;
        }
    }
    if b.get(k).is_some_and(|&c| is_word(c)) {
        return None;
    }
    iban_checksum_ok(&chars[..want]).then_some(k)
}

/// ISO 13616 / ISO 7064 MOD 97-10: move the first four characters to the
/// end, read letters as 10..35, and the number must be 1 mod 97.
fn iban_checksum_ok(iban: &[u8]) -> bool {
    let (head, tail) = iban.split_at(4);
    let mut rem = 0u32;
    for &c in tail.iter().chain(head) {
        rem = if c.is_ascii_digit() {
            (rem * 10 + (c - b'0') as u32) % 97
        } else {
            (rem * 100 + (c - b'A' + 10) as u32) % 97
        };
    }
    rem == 1
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

fn ipv4s(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !(is_word(b[i - 1]) || b[i - 1] == b'.')) {
            if let Some(end) = ipv4_at(b, i) {
                out.push(Match {
                    kind: Kind::Ipv4,
                    start: i,
                    end,
                });
                i = end;
                continue;
            }
            // Skip the rest of this digit run: an address cannot start
            // inside it.
            i += run(b, i, |c| c.is_ascii_digit());
            continue;
        }
        i += 1;
    }
}

/// Four decimal octets `0..=255` without leading zeros (which some
/// resolvers read as octal), not followed by a fifth component.
fn ipv4_at(b: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    for part in 0..4 {
        if part > 0 {
            if b.get(k) != Some(&b'.') {
                return None;
            }
            k += 1;
        }
        let len = run(b, k, |c| c.is_ascii_digit());
        if len == 0 || len > 3 || (len > 1 && b[k] == b'0') {
            return None;
        }
        if digits_exact(b, k, len)? > 255 {
            return None;
        }
        k += len;
    }
    let glued = match b.get(k) {
        Some(&c) if is_word(c) => true,
        Some(b'.') => is_digit_at(b, k + 1),
        _ => false,
    };
    (!glued).then_some(k)
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

fn aws_keys(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 20 <= b.len() {
        let anchored = (i == 0 || !b[i - 1].is_ascii_alphanumeric())
            && (b[i..].starts_with(b"AKIA") || b[i..].starts_with(b"ASIA"));
        if anchored {
            let body = &b[i + 4..i + 20];
            let ok = body
                .iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                && !b.get(i + 20).is_some_and(u8::is_ascii_alphanumeric);
            if ok {
                out.push(Match {
                    kind: Kind::AwsAccessKey,
                    start: i,
                    end: i + 20,
                });
                i += 20;
                continue;
            }
        }
        i += 1;
    }
}

fn is_b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// `eyJ` header, then two or four more dot-separated base64url segments
/// (JWS has three in all, JWE five). A JWS signature may be empty (an
/// unsecured JWT), and so may a JWE encrypted key (direct encryption).
fn jwts(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 3 <= b.len() {
        let anchored =
            b[i..].starts_with(b"eyJ") && (i == 0 || !(is_b64url(b[i - 1]) || b[i - 1] == b'.'));
        if !anchored {
            i += 1;
            continue;
        }
        // Lengths and end offsets of up to five segments.
        let mut lens = [0usize; 5];
        let mut ends = [0usize; 5];
        let mut count = 0;
        let mut k = i;
        loop {
            lens[count] = run(b, k, is_b64url);
            k += lens[count];
            ends[count] = k;
            count += 1;
            if count == 5 || b.get(k) != Some(&b'.') {
                break;
            }
            k += 1;
        }
        let header_ok = lens[0] >= 10;
        let jwe = count == 5 && lens[2..].iter().all(|&n| n > 0);
        let jws = count >= 3 && lens[1] >= 2;
        let end = match (header_ok, jwe, jws) {
            (true, true, _) => Some(ends[4]),
            (true, false, true) => Some(ends[2]),
            _ => None,
        };
        match end {
            Some(end) => {
                out.push(Match {
                    kind: Kind::Jwt,
                    start: i,
                    end,
                });
                i = end;
            }
            None => i += lens[0].max(1),
        }
    }
}

fn is_bearer_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

/// `Bearer` (any case) at a word boundary, whitespace, then an RFC 6750
/// `b64token`. Only the token is matched, so redaction keeps `Bearer`
/// readable. Tokens shorter than 16 characters or without a digit are
/// taken to be prose ("bearer tokens are...").
fn bearer_tokens(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 6 < b.len() {
        let anchored =
            (i == 0 || !is_word(b[i - 1])) && b[i..i + 6].eq_ignore_ascii_case(b"bearer");
        if !anchored {
            i += 1;
            continue;
        }
        let gap = run(b, i + 6, |c| c == b' ' || c == b'\t');
        if gap == 0 {
            i += 6;
            continue;
        }
        let start = i + 6 + gap;
        let mut end = start + run(b, start, is_bearer_char);
        end += run(b, end, |c| c == b'=');
        let token = &b[start..end];
        if token.len() >= 16 && token.iter().any(u8::is_ascii_digit) {
            out.push(Match {
                kind: Kind::BearerToken,
                start,
                end,
            });
        }
        i = end.max(i + 6);
    }
}

const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_END: &[u8] = b"-----END ";
const PEM_DASHES: &[u8] = b"-----";

/// The label of a PEM boundary line whose prefix (`-----BEGIN ` or
/// `-----END `) ends at `i`: upper-case letters, digits and spaces up to
/// the closing dashes, at most 64 bytes. Returns the label and the offset
/// just past the closing dashes.
fn pem_label(b: &[u8], i: usize) -> Option<(&[u8], usize)> {
    let len = run(b, i, |c| {
        c.is_ascii_uppercase() || c.is_ascii_digit() || c == b' '
    });
    if len == 0 || len > 64 || !b[i + len..].starts_with(PEM_DASHES) {
        return None;
    }
    Some((&b[i..i + len], i + len + PEM_DASHES.len()))
}

/// Where the body of a PEM block without an `END` line (a truncated paste)
/// ends: base64 characters and line breaks, including the escaped `\n`
/// and `\r` of a key pasted inside a JSON string. Trailing line breaks
/// are left out of the match.
fn truncated_key_end(b: &[u8], body: usize) -> usize {
    let mut k = body;
    loop {
        match b.get(k) {
            Some(&c)
                if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'\r' | b'\n') =>
            {
                k += 1
            }
            Some(b'\\') if matches!(b.get(k + 1), Some(b'n' | b'r')) => k += 2,
            _ => break,
        }
    }
    loop {
        if k > body && matches!(b[k - 1], b'\r' | b'\n') {
            k -= 1;
        } else if k >= body + 2 && b[k - 2] == b'\\' && matches!(b[k - 1], b'n' | b'r') {
            k -= 2;
        } else {
            return k;
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Private key blocks. Every `END` line is indexed once up front, so
/// pairing each `BEGIN` with its `END` is a binary search instead of a
/// rescan of the rest of the text.
fn private_keys(b: &[u8], out: &mut Vec<Match>) {
    let mut ends: HashMap<&[u8], Vec<(usize, usize)>> = HashMap::new();
    for i in 0..b.len() {
        if b[i..].starts_with(PEM_END) {
            if let Some((label, after)) = pem_label(b, i + PEM_END.len()) {
                ends.entry(label).or_default().push((i, after));
            }
        }
    }
    let mut i = 0;
    while i < b.len() {
        if !b[i..].starts_with(PEM_BEGIN) {
            i += 1;
            continue;
        }
        let Some((label, body)) = pem_label(b, i + PEM_BEGIN.len()) else {
            i += 1;
            continue;
        };
        if !contains(label, b"PRIVATE KEY") {
            i = body;
            continue;
        }
        let closing = ends.get(label).and_then(|v| {
            let at = v.partition_point(|&(start, _)| start < body);
            v.get(at).map(|&(_, after)| after)
        });
        let end = closing.unwrap_or_else(|| truncated_key_end(b, body));
        out.push(Match {
            kind: Kind::PrivateKey,
            start: i,
            end,
        });
        i = end.max(i + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matched substrings for one kind.
    fn hits(text: &str, kind: Kind) -> Vec<&str> {
        find(text, &[kind])
            .iter()
            .map(|m| &text[m.range()])
            .collect()
    }

    fn assert_finds(kind: Kind, text: &str, expected: &str) {
        assert_eq!(hits(text, kind), [expected], "{kind:?} in {text:?}");
    }

    fn assert_none(kind: Kind, text: &str) {
        assert_eq!(hits(text, kind), Vec::<&str>::new(), "{kind:?} in {text:?}");
    }

    #[test]
    fn detects_emails() {
        for (text, want) in [
            (
                "contact john.smith+tag@example.co.uk today",
                "john.smith+tag@example.co.uk",
            ),
            ("<a@b.io>", "a@b.io"),
            ("write to a@example.com.", "a@example.com"),
            (
                "key=user_1@mail-server.example.org,",
                "user_1@mail-server.example.org",
            ),
            ("mailto:Jane.Doe@Example.COM", "Jane.Doe@Example.COM"),
            ("..x@example.com", "x@example.com"),
            (
                "\u{e9}l\u{e8}ve: x@example.fr \u{2192} merci",
                "x@example.fr",
            ),
        ] {
            assert_finds(Kind::Email, text, want);
        }
        for text in [
            "user@localhost",
            "@example.com",
            "a@b",
            "a@b.c",
            "a@-b.com",
            "a@b..com",
            "2024@10.15",
            "foo@bar",
            "x@example.c0m",
            "not an email: @ @@ a@",
        ] {
            assert_none(Kind::Email, text);
        }
        assert_eq!(hits("a@b.io,c@d.io", Kind::Email), ["a@b.io", "c@d.io"]);
    }

    #[test]
    fn detects_phones() {
        for (text, want) in [
            ("call +1 (555) 123-4567 now", "+1 (555) 123-4567"),
            ("+44 20 7946 0958", "+44 20 7946 0958"),
            ("+44 (0)20 7946 0958.", "+44 (0)20 7946 0958"),
            ("tel:+15551234567", "+15551234567"),
            ("+33 1 23 45 67 89", "+33 1 23 45 67 89"),
            ("(555) 123-4567", "(555) 123-4567"),
            ("(555)123-4567", "(555)123-4567"),
            ("555-123-4567.", "555-123-4567"),
            ("555.123.4567", "555.123.4567"),
            ("555 123 4567", "555 123 4567"),
            ("1-555-123-4567", "1-555-123-4567"),
            ("+1 555 123 4567 12345", "+1 555 123 4567"),
        ] {
            assert_finds(Kind::Phone, text, want);
        }
        for text in [
            "2024-01-15",
            "2024-01-15T10:30:00+05:30",
            "1.2.3.4",
            "v10.0.19041",
            "123e4567-e89b-12d3-a456-426614174000",
            "12345678-1234-1234-1234-123456789012",
            "5551234567",
            "1791900000",
            "+1234567",
            "+1234567890123456",
            "555-123-4567-890",
            "192.168.100.200",
            "ISBN 978-3-16-148410-0",
            "555-123.4567",
            "x555-123-4567",
            "3.14159265358979",
        ] {
            assert_none(Kind::Phone, text);
        }
    }

    #[test]
    fn detects_ssns() {
        assert_finds(Kind::Ssn, "SSN: 078-05-1120.", "078-05-1120");
        assert_finds(Kind::Ssn, "ssn 123 45 6789", "123 45 6789");
        assert_finds(Kind::Ssn, "(899-99-9999)", "899-99-9999");
        for text in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "999-99-9999",
            "123-00-4567",
            "123-45-0000",
            "123456789",
            "123-45-67890",
            "1123-45-6789",
            "123-45-6789-1",
            "123-45 6789",
            "x123-45-6789",
            "2024-12-31",
        ] {
            assert_none(Kind::Ssn, text);
        }
    }

    #[test]
    fn detects_payment_cards() {
        for (text, want) in [
            ("4111 1111 1111 1111", "4111 1111 1111 1111"),
            (
                "card: 4111-1111-1111-1111, exp 12/29",
                "4111-1111-1111-1111",
            ),
            ("4111111111111111", "4111111111111111"),
            ("5555555555554444", "5555555555554444"),
            ("2223003122003222", "2223003122003222"),
            ("378282246310005", "378282246310005"),
            ("3782 822463 10005", "3782 822463 10005"),
            ("6011111111111117", "6011111111111117"),
            ("3530111333300000", "3530111333300000"),
            ("30569309025904", "30569309025904"),
            ("4222222222222", "4222222222222"),
            ("6200000000000005", "6200000000000005"),
            ("4111 1111 1111 1111 2029", "4111 1111 1111 1111"),
            ("\u{1f4b3}4111111111111111\u{1f4b3}", "4111111111111111"),
        ] {
            assert_finds(Kind::PaymentCard, text, want);
        }
        for text in [
            "4111111111111112",
            "4111 1111 1111 1112",
            "1234567812345670",
            "0000000000000000",
            "41111111111111111111",
            "4111 1111 1111 111",
            "1791900000000",
            "9999999999999995",
            "4111-1111 1111-1111",
            "x4111111111111111",
            "4111111111111111x",
            "3.4111111111111111",
        ] {
            assert_none(Kind::PaymentCard, text);
        }
    }

    #[test]
    fn luhn() {
        assert!(luhn_valid(b"79927398713"));
        assert!(!luhn_valid(b"79927398710"));
        assert!(luhn_valid(b"4111111111111111"));
    }

    #[test]
    fn detects_ibans() {
        for (text, want) in [
            (
                "IBAN: GB82 WEST 1234 5698 7654 32.",
                "GB82 WEST 1234 5698 7654 32",
            ),
            ("GB82WEST12345698765432", "GB82WEST12345698765432"),
            (
                "DE89 3704 0044 0532 0130 00 and more",
                "DE89 3704 0044 0532 0130 00",
            ),
            ("IE64 IRCE 9205 0112 3456 78", "IE64 IRCE 9205 0112 3456 78"),
            (
                "BI13 20001 10001 00001234567 89",
                "BI13 20001 10001 00001234567 89",
            ),
            ("NO9386011117947", "NO9386011117947"),
            (
                "FR14 2004 1010 0505 0001 3M02 606 THE END",
                "FR14 2004 1010 0505 0001 3M02 606",
            ),
        ] {
            assert_finds(Kind::Iban, text, want);
        }
        for text in [
            "GB82 WEST 1234 5698 7654 33",
            "GB82WEST1234569876543",
            "GB82WEST123456987654321",
            "XX82WEST12345698765432",
            "gb82west12345698765432",
            "GB82WEST12345698765432X",
            "GB82  WEST 1234 5698 7654 32",
            "AGB82WEST12345698765432",
        ] {
            assert_none(Kind::Iban, text);
        }
    }

    #[test]
    fn iban_table_is_sorted_and_unique() {
        assert!(IBAN_LENGTHS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(IBAN_LENGTHS.iter().all(|&(_, n)| (15..=34).contains(&n)));
    }

    #[test]
    fn detects_ipv4() {
        for (text, want) in [
            ("host 192.168.0.1 up", "192.168.0.1"),
            ("10.0.0.255:8080", "10.0.0.255"),
            ("ip=8.8.8.8,", "8.8.8.8"),
            ("0.0.0.0", "0.0.0.0"),
            ("255.255.255.255.", "255.255.255.255"),
            ("[127.0.0.1]", "127.0.0.1"),
            ("10.1.2.3/24", "10.1.2.3"),
        ] {
            assert_finds(Kind::Ipv4, text, want);
        }
        for text in [
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4.5",
            "01.2.3.4",
            "1.2.3.04",
            "v1.2.3.4",
            "1.2.3.4a",
            "2001:db8::1",
            "1.2.3.1000",
            "a.1.2.3.4",
        ] {
            assert_none(Kind::Ipv4, text);
        }
    }

    #[test]
    fn detects_api_keys() {
        for key in [
            "sk-proj-abc123def456ghi789jkl012mno345",
            "sk-ant-api03-AbCdEf0123456789_xyz-AbCdEfGh",
            "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL",
            "sk_live_51Hx0aBcDeFgHiJkLmNoPq",
        ] {
            assert_finds(Kind::ApiKey, &format!("key=\"{key}\";"), key);
        }
        for text in [
            "sk-learn",
            "task-abc123def456ghi789jkl012",
            "sk-this-is-not-a-real-key-at-all",
            "sk-12345",
            "ask-abc123def456ghi789jkl012mno",
        ] {
            assert_none(Kind::ApiKey, text);
        }
    }

    #[test]
    fn detects_aws_access_keys() {
        assert_finds(
            Kind::AwsAccessKey,
            "id AKIAIOSFODNN7EXAMPLE.",
            "AKIAIOSFODNN7EXAMPLE",
        );
        assert_finds(
            Kind::AwsAccessKey,
            "\"ASIAY34FZKBOKMUTVV7A\"",
            "ASIAY34FZKBOKMUTVV7A",
        );
        for text in [
            "AKIAIOSFODNN7EXAMPL",
            "XAKIAIOSFODNN7EXAMPLE",
            "AKIAIOSFODNN7EXAMPLE1",
            "akiaiosfodnn7example",
            "AKIAIOSFODNN7EXAMPLe",
        ] {
            assert_none(Kind::AwsAccessKey, text);
        }
    }

    #[test]
    fn detects_github_tokens() {
        let classic = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        assert_finds(Kind::GithubToken, &format!("token: {classic}"), classic);
        let fine = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234";
        assert_finds(Kind::GithubToken, fine, fine);
        assert_finds(
            Kind::GithubToken,
            "gho_0123456789abcdefghijABCDEFGHIJ012345",
            "gho_0123456789abcdefghijABCDEFGHIJ012345",
        );
        assert_none(Kind::GithubToken, "ghp_short");
        assert_none(
            Kind::GithubToken,
            "xghp_0123456789abcdefghijABCDEFGHIJ012345",
        );
        assert_none(Kind::GithubToken, "github_pat_tooshort");
    }

    #[test]
    fn detects_slack_tokens() {
        let bot = concat!("xo", "xb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx");
        assert_finds(Kind::SlackToken, &format!("SLACK_TOKEN={bot}"), bot);
        assert_finds(
            Kind::SlackToken,
            concat!("xo", "xp-1234567890-abc"),
            concat!("xo", "xp-1234567890-abc"),
        );
        assert_none(Kind::SlackToken, concat!("xo", "xz-1234567890abcdef"));
        assert_none(Kind::SlackToken, concat!("xo", "xb-123"));
    }

    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn detects_jwts() {
        assert_finds(Kind::Jwt, &format!("token={JWT}&x=1"), JWT);
        assert_finds(Kind::Jwt, &format!("{JWT}."), JWT);
        let unsecured = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";
        assert_finds(Kind::Jwt, &format!("{unsecured} done"), unsecured);
        let jwe = "eyJhbGciOiJSU0EtT0FFUCJ9.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZ.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji.XFBoMYUZodetZdvTiFvSkQ";
        assert_finds(Kind::Jwt, jwe, jwe);
        for text in [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJhbGciOiJIUzI1NiJ9.",
            "eyJ.x.y",
            "neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
            "eyJhbGciOiJIUzI1NiJ9..sig",
        ] {
            assert_none(Kind::Jwt, text);
        }
    }

    #[test]
    fn detects_bearer_tokens() {
        assert_finds(
            Kind::BearerToken,
            "Authorization: Bearer abc123def456ghi789jkl\r\n",
            "abc123def456ghi789jkl",
        );
        assert_finds(
            Kind::BearerToken,
            "bearer  0123456789abcdef0123==;",
            "0123456789abcdef0123==",
        );
        assert_finds(
            Kind::BearerToken,
            "BEARER\tdGhpcyBpcyBhIHRva2VuMTIz",
            "dGhpcyBpcyBhIHRva2VuMTIz",
        );
        for text in [
            "Bearer token",
            "the Bearer authentication scheme",
            "Bearer abc123",
            "Bearer\nabc123def456ghi789jkl",
            "Bearerabc123def456ghi789jkl",
            "xBearer abc123def456ghi789jkl",
        ] {
            assert_none(Kind::BearerToken, text);
        }
        // A JWT sent as a bearer token is reported once, as a JWT.
        let text = format!("Authorization: Bearer {JWT}");
        let found = find(&text, &Kind::ALL);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Jwt);
        assert_eq!(&text[found[0].range()], JWT);
    }

    #[test]
    fn detects_private_keys() {
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
        ] {
            let block = format!("-----BEGIN {label}-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n-----END {label}-----");
            let text = format!("config:\n{block}\nrest");
            assert_finds(Kind::PrivateKey, &text, &block);
        }
        // Truncated: the body is still hidden.
        let truncated = "key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n";
        assert_finds(
            Kind::PrivateKey,
            truncated,
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7",
        );
        // Truncated inside a JSON string, with escaped line breaks.
        let json = r#"{"key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nBKcwggSj\n"#;
        assert_finds(
            Kind::PrivateKey,
            json,
            r"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nBKcwggSj",
        );
        // A mismatched END does not close the block.
        let mismatched = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        assert_finds(
            Kind::PrivateKey,
            mismatched,
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA",
        );
        // Two blocks pair up in order.
        let two = "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\nmid\n-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----";
        assert_eq!(find(two, &[Kind::PrivateKey]).len(), 2);
        assert!(redact(two, &[Kind::PrivateKey]).0 == "[private_key]\nmid\n[private_key]");
        for text in [
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
            "-----BEGIN private key-----",
        ] {
            assert_none(Kind::PrivateKey, text);
        }
    }

    #[test]
    fn redacts_mixed_text() {
        let text = "Mail john@example.com or call +1 555 123 4567; card 4111 1111 1111 1111, \
                    ssn 078-05-1120, from 10.0.0.1 with AKIAIOSFODNN7EXAMPLE.";
        let (redacted, matches) = redact(text, &Kind::ALL);
        assert_eq!(
            redacted,
            "Mail [email] or call [phone]; card [payment_card], ssn [ssn], from [ipv4] with [aws_access_key]."
        );
        let kinds: Vec<Kind> = matches.iter().map(|m| m.kind).collect();
        assert_eq!(
            kinds,
            [
                Kind::Email,
                Kind::Phone,
                Kind::PaymentCard,
                Kind::Ssn,
                Kind::Ipv4,
                Kind::AwsAccessKey
            ]
        );
        // Only the requested kinds are touched.
        let (only_email, _) = redact(text, &[Kind::Email]);
        assert!(only_email.contains("[email]") && only_email.contains("4111 1111 1111 1111"));
        assert_eq!(redact(text, &[]).0, text);
        assert_eq!(redact("", &Kind::ALL), (String::new(), vec![]));
    }

    #[test]
    fn overlaps_resolve_leftmost_longest() {
        // An email whose local part is digits must not also leak a phone.
        let text = "555-123-4567@example.com";
        let found = find(text, &Kind::ALL);
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].kind, found[0].start, found[0].end),
            (Kind::Email, 0, text.len())
        );
        let ordered = find("b@x.io 10.0.0.1 a@y.io", &Kind::ALL);
        assert!(ordered.windows(2).all(|w| w[0].end <= w[1].start));
    }

    #[test]
    fn ranges_are_char_boundaries() {
        let text = "\u{1f600}john@example.com\u{e9}\u{2192}+44 20 7946 0958\u{4e2d}4111111111111111\u{feff}\
                    192.168.1.1\u{1f600}AKIAIOSFODNN7EXAMPLE\u{e9}078-05-1120\u{301}";
        let found = find(text, &Kind::ALL);
        assert_eq!(found.len(), 6, "{found:?}");
        for m in &found {
            assert!(text.is_char_boundary(m.start) && text.is_char_boundary(m.end));
        }
        let (redacted, _) = redact(text, &Kind::ALL);
        assert!(redacted.starts_with("\u{1f600}[email]\u{e9}\u{2192}[phone]\u{4e2d}[payment_card]"));
    }

    #[test]
    fn names_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_name(kind.name()), Some(kind));
            assert_eq!(kind.placeholder(), format!("[{}]", kind.name()));
        }
        assert_eq!(Kind::from_name("nope"), None);
        let mut both: Vec<Kind> = Kind::PERSONAL.into_iter().chain(Kind::SECRETS).collect();
        both.dedup();
        assert_eq!(both, Kind::ALL);
    }

    #[test]
    fn adversarial_inputs_stay_linear() {
        // Each of these would take quadratic (or worse) time in a naive
        // backtracking matcher. At 200 KB, quadratic work would take far
        // longer than the test harness allows; linear work is instant.
        let n = 100_000;
        let inputs = [
            "a@".repeat(n),
            "a.".repeat(n) + "@",
            "@".to_string() + &"a.".repeat(n),
            "1-".repeat(n),
            "1 ".repeat(n),
            "1.".repeat(n),
            "+1 ".repeat(n),
            "(1".repeat(n),
            "9".repeat(2 * n),
            "4111 ".repeat(n),
            "GB82 ".repeat(n),
            "AKIA".repeat(n),
            "eyJ.".repeat(n),
            "eyJaaaaaaaaaa.".repeat(n / 4),
            "Bearer ".repeat(n / 2),
            "sk-".repeat(n),
            "-----BEGIN PRIVATE KEY-----".repeat(n / 10),
            "-----BEGIN A PRIVATE KEY-----\n-----END B PRIVATE KEY-----\n".repeat(n / 20),
            "-----END PRIVATE KEY-----".repeat(n / 10),
        ];
        for input in &inputs {
            let found = find(input, &Kind::ALL);
            assert!(found.windows(2).all(|w| w[0].end <= w[1].start));
        }
    }
}
