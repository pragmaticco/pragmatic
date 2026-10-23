//! Detect and redact personal data and secrets in free text.
//!
//! Journals hold whatever agents saw and said: prompts, completions, tool
//! inputs and outputs. Stet Server shows that content to auditors and
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
//! - **UTF-8 safe ranges.** Every match starts and ends on a `char`
//!   boundary, so every [`Match`] range can be sliced directly.
//!
//! Detectors favor precision on numbers (a bare 9- or 10-digit run is an
//! order id or a Unix timestamp far more often than an SSN or a phone
//! number, and `768 768 3072` is more often a tensor shape, so those
//! formats need separators, a `+` or a nearby word such as "phone" or
//! "SSN") and recall on secrets (a credential is worth hiding even when it
//! is malformed). Matches that overlap are merged, so redaction never
//! leaves part of a detected value visible.
//!
//! # Scope
//!
//! Phone numbers are found in two forms: E.164 with a leading `+`, and
//! North American numbers with separators. Domestic formats without a
//! country code (`020 7946 0958`, `06 12 34 56 78`), the `00`
//! international prefix and E.164 numbers shorter than 10 digits
//! (`+46 8 123 456`) are not detected: without the `+` they cannot be told
//! apart from other grouped numbers. Digit groups in phone numbers, cards,
//! SSNs and IBANs may be separated by spaces, including the no-break
//! spaces U+00A0 and U+202F that French and other locales use and that
//! text copied from web pages and PDFs often carries.
//!
//! Binary attachments (images, documents, audio) are never scanned as
//! text: [`binary`] finds them in JSON slots and describes each by media
//! type, size and SHA-256 instead. A streamed model reply holds its text in
//! deltas of a few characters, where no detector sees a value split across
//! them: [`stream`] puts that text back together.

pub mod binary;
pub mod stream;

use std::collections::HashMap;

/// What a detector looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `local@domain.tld`. The local part may hold apostrophes and
    /// non-ASCII letters (`o'brien@`, `jöhn@`); the domain is ASCII with an
    /// alphabetic TLD of two or more letters. Image and source file names
    /// (`logo@2x.png`), `user@host:path` remotes and matrix products such
    /// as `x@self.weight` are not emails.
    Email,
    /// E.164 (`+` and 10 to 15 digits, optionally grouped; exactly 11 for
    /// `+1`) and North American formats with separators
    /// (`(555) 123-4567`, `555-123-4567`, `555.123.4567`,
    /// `1-555-123-4567`). Space-separated North American numbers
    /// (`555 123 4567`) also need a nearby word such as "phone", "tel" or
    /// "call". See the module documentation for what is out of scope.
    Phone,
    /// US Social Security numbers written `AAA-GG-SSSS`, or `AAA GG SSSS`
    /// after the word "SSN" or "social security", excluding numbers the SSA
    /// never issues.
    Ssn,
    /// 13 to 19 digit card numbers with a known issuer prefix and a valid
    /// Luhn check digit, unbroken or grouped the way cards are printed
    /// (fours with a shorter last group, or 4-6-5 and 4-6-4) with spaces or
    /// dashes.
    PaymentCard,
    /// IBANs in upper case, compact or grouped with spaces, with the
    /// registered length for their country and valid mod 97 check digits.
    Iban,
    /// Dotted-quad IPv4 addresses.
    Ipv4,
    /// API keys with a known prefix: `sk-` (OpenAI, Anthropic `sk-ant-`,
    /// project keys `sk-proj-`), Stripe-style `sk_live_`, `sk_test_`,
    /// `rk_live_` and `rk_test_`, Google `AIza`, Hugging Face `hf_` and
    /// GitLab `glpat-`.
    ApiKey,
    /// AWS access key ids (`AKIA` or `ASIA` and 16 more characters). The
    /// id is not secret on its own; the secret access key and session
    /// token next to it are found by [`Kind::Credential`].
    AwsAccessKey,
    /// GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`).
    GithubToken,
    /// Slack tokens (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxe-`, `xoxe.`,
    /// `xapp-`) and the secret path of incoming webhook URLs
    /// (`hooks.slack.com/services/...`).
    SlackToken,
    /// JSON Web Tokens (compact JWS or JWE starting with `eyJ`).
    Jwt,
    /// The credential after `Bearer ` (the word itself is kept).
    BearerToken,
    /// PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----` through
    /// the matching `END` line, or through the rest of the key body if the
    /// block was truncated).
    PrivateKey,
    /// A credential found by its context rather than its format: the value
    /// of a credential-named key (`password=...`, `"SecretAccessKey": "..."`,
    /// `AWS_SESSION_TOKEN=...`, `X-Api-Key: ...`, `--token ...`), the
    /// credentials of an `Authorization` header or the `Basic` scheme, and
    /// the password in a URL (`postgres://user:password@host`). Only the
    /// value is matched, so the key stays readable.
    Credential,
}

impl Kind {
    /// Every detector.
    pub const ALL: [Kind; 14] = [
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
        Kind::Credential,
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
    pub const SECRETS: [Kind; 8] = [
        Kind::ApiKey,
        Kind::AwsAccessKey,
        Kind::GithubToken,
        Kind::SlackToken,
        Kind::Jwt,
        Kind::BearerToken,
        Kind::PrivateKey,
        Kind::Credential,
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
            Kind::Credential => "credential",
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
            Kind::Credential => "[credential]",
        }
    }

    /// Tie-break when two detectors claim exactly the same span: the more
    /// specific format wins (a JWT sent as a bearer token is labelled a
    /// JWT, and a bearer token in an `Authorization` header a bearer
    /// token).
    fn priority(self) -> u8 {
        match self {
            Kind::BearerToken => 1,
            Kind::Credential => 2,
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
/// Matches that overlap are merged into one that covers their union and
/// takes the kind of the one that starts first (the longer one if both
/// start at the same byte, the more specific one if they also end at the
/// same byte). A match that only partly overlaps another is therefore
/// never dropped, and redacting the result never leaves part of a
/// detected value visible: in `+1 4111 1111 1111 1111`, the phone number
/// detector stops partway through the card, and the whole run is one
/// match. Passing an empty slice finds nothing; pass [`Kind::ALL`] for
/// everything.
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
    for m in candidates {
        match out.last_mut() {
            Some(last) if m.start < last.end => last.end = last.end.max(m.end),
            _ => out.push(m),
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
        Kind::ApiKey => {
            prefixed(
                b,
                out,
                Kind::ApiKey,
                &[b"sk-"],
                is_key_char,
                has_key_segment,
            );
            prefixed(
                b,
                out,
                Kind::ApiKey,
                &[b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"],
                is_key_char,
                |body| body.len() >= 20 && body.iter().any(u8::is_ascii_digit),
            );
            prefixed(b, out, Kind::ApiKey, &[b"AIza"], is_key_char, |body| {
                body.len() == 35
            });
            prefixed(
                b,
                out,
                Kind::ApiKey,
                &[b"hf_"],
                |c| c.is_ascii_alphanumeric(),
                |body| body.len() >= 30,
            );
            prefixed(b, out, Kind::ApiKey, &[b"glpat-"], is_key_char, |body| {
                body.len() >= 20
            });
        }
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
        Kind::SlackToken => {
            prefixed(
                b,
                out,
                Kind::SlackToken,
                &[
                    b"xoxa-", b"xoxb-", b"xoxp-", b"xoxr-", b"xoxe-", b"xoxe.", b"xapp-",
                ],
                |c| c.is_ascii_alphanumeric() || c == b'-',
                |body| body.len() >= 10,
            );
            slack_webhooks(b, out);
        }
        Kind::Jwt => jwts(b, out),
        Kind::BearerToken => bearer_tokens(b, out),
        Kind::PrivateKey => private_keys(b, out),
        Kind::Credential => {
            keyed_secrets(b, out);
            basic_credentials(b, out);
            url_passwords(b, out);
        }
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

/// Length of the run of digits starting at `i`, reading at most `max`.
fn digit_run(b: &[u8], i: usize, max: usize) -> usize {
    b[i.min(b.len())..]
        .iter()
        .take(max)
        .take_while(|c| c.is_ascii_digit())
        .count()
}

/// The kind of separator between digit groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sep {
    /// A space, U+00A0 NO-BREAK SPACE or U+202F NARROW NO-BREAK SPACE.
    Space,
    Dash,
    Dot,
}

/// Length of a space-like separator at `k` (see [`Sep::Space`]), or 0.
/// Both no-break spaces are multi-byte, and a match never ends inside
/// one, so ranges stay on `char` boundaries.
fn space_len(b: &[u8], k: usize) -> usize {
    match b.get(k..) {
        Some([b' ', ..]) => 1,
        Some([0xc2, 0xa0, ..]) => 2,
        Some([0xe2, 0x80, 0xaf, ..]) => 3,
        _ => 0,
    }
}

/// The digit-group separator at `k` and its length in bytes.
fn sep_at(b: &[u8], k: usize) -> Option<(Sep, usize)> {
    match b.get(k)? {
        b'-' => Some((Sep::Dash, 1)),
        b'.' => Some((Sep::Dot, 1)),
        _ => match space_len(b, k) {
            0 => None,
            n => Some((Sep::Space, n)),
        },
    }
}

/// True if a number starting at `i` is not glued to a preceding word or
/// number: the previous byte is not a word character or `+`, and is not a
/// `-`, `.` or `/` that continues a digit sequence (so `2024-01-15` and
/// `10.0.0.1` are never split into smaller numbers). A comma is not glue:
/// `1,078-05-1120,4111111111111111` is a CSV row, and a thousands group
/// is too short to form any of the numbers detected here.
fn number_starts_at(b: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let p = b[i - 1];
    if is_word(p) || p == b'+' {
        return false;
    }
    !(matches!(p, b'-' | b'.' | b'/') && i >= 2 && b[i - 2].is_ascii_digit())
}

/// True if a number ending at `end` is not glued to what follows: the next
/// byte is not a word character, and is not a `-`, `.` or `/` that
/// continues the digits.
fn number_ends_at(b: &[u8], end: usize) -> bool {
    match b.get(end) {
        None => true,
        Some(&c) if is_word(c) => false,
        Some(b'-' | b'.' | b'/') => !is_digit_at(b, end + 1),
        Some(_) => true,
    }
}

/// [`number_ends_at`], and the digits are not the hours of a time or the
/// host of a port (`... 4567 10:30` must not take the `10`).
fn phone_ends_at(b: &[u8], end: usize) -> bool {
    number_ends_at(b, end) && !(b.get(end) == Some(&b':') && is_digit_at(b, end + 1))
}

/// Parse exactly `n` digits at `i`; return their value.
fn digits_exact(b: &[u8], i: usize, n: usize) -> Option<u32> {
    let s = b.get(i..i + n)?;
    if !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0, |acc, &c| acc * 10 + (c - b'0') as u32))
}

/// Words that mark a space-separated number as a phone number.
const PHONE_WORDS: &[&[u8]] = &[
    b"phone",
    b"tel",
    b"call",
    b"mobile",
    b"cell",
    b"fax",
    b"sms",
    b"whatsapp",
    b"contact",
];

/// Words that mark a space-separated number as an SSN.
const SSN_WORDS: &[&[u8]] = &[b"ssn", b"social security", b"ss#"];

/// True if one of `words` (lower-case ASCII) starts a word in the 32 bytes
/// before `i` on the same line, ignoring case. The window is fixed, so the
/// check is constant time.
fn has_context(b: &[u8], i: usize, words: &[&[u8]]) -> bool {
    let mut from = i.saturating_sub(32);
    if let Some(nl) = b[from..i].iter().rposition(|&c| c == b'\n') {
        from += nl + 1;
    }
    words.iter().any(|w| {
        (from..i.saturating_sub(w.len() - 1)).any(|j| {
            b[j..j + w.len()].eq_ignore_ascii_case(w) && (j == 0 || !b[j - 1].is_ascii_alphabetic())
        })
    })
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
        if !prefixes.iter().any(|p| p[0] == b[i]) {
            i += 1;
            continue;
        }
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

/// An `sk-` key body: some `-`-separated segment is at least 16
/// characters and mixes letters and digits, as the random part of every
/// such key does. Kebab-case names (`sk-test-environment-2024-q1-config`)
/// have only short segments.
fn has_key_segment(body: &[u8]) -> bool {
    body.split(|&c| c == b'-').any(|seg| {
        seg.len() >= 16
            && seg.iter().any(u8::is_ascii_digit)
            && seg.iter().any(u8::is_ascii_alphabetic)
    })
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

/// File extensions that are not top-level domains, so `name@x.png` is a
/// file name. Real country codes that double as extensions (`.py`, `.rs`,
/// `.md`, `.sh`) are left out: addresses there exist.
const FILE_EXTENSIONS: &[&[u8]] = &[
    b"png", b"jpg", b"jpeg", b"gif", b"svg", b"webp", b"ico", b"bmp", b"tif", b"tiff", b"avif",
    b"heic", b"js", b"mjs", b"cjs", b"jsx", b"ts", b"tsx", b"json", b"yaml", b"yml", b"toml",
    b"txt", b"csv", b"tsv", b"lock", b"log", b"html", b"htm", b"css", b"scss", b"xml", b"pdf",
    b"ini", b"cfg", b"conf", b"exe", b"dll", b"wasm", b"gz", b"tgz",
];

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
        let start = local_start(b, at, taken);
        if start == at {
            continue;
        }
        let limit = at + 1 + run(b, at + 1, is_domain_char);
        if let Some(end) = domain_end(b, at + 1, limit) {
            if !is_code_at(b, at, end) {
                out.push(Match {
                    kind: Kind::Email,
                    start,
                    end,
                });
                taken = end;
            }
        }
    }
}

/// Where the local part ending at the `@` at `at` begins, looking no
/// further back than `floor`: ASCII letters, digits, `.`, `_`, `%`, `+`
/// and `-`, apostrophes (`o'brien`) and non-ASCII letters and digits
/// (`jöhn`, as RFC 6531 allows). Leading dots and apostrophes are left out
/// (`'a@b.io'`). The other RFC 5322 characters, such as `/`, `=`, `?` and
/// `&`, are left out on purpose: they delimit URLs and query strings
/// (`?to=a@b.io`) far more often than they appear in addresses.
fn local_start(b: &[u8], at: usize, floor: usize) -> usize {
    let mut start = at;
    while start > floor {
        let c = b[start - 1];
        if is_local_char(c) || c == b'\'' {
            start -= 1;
            continue;
        }
        if c >= 0x80 {
            // Step back over one whole character.
            let mut s = start - 1;
            while s > floor && b[s] & 0xc0 == 0x80 {
                s -= 1;
            }
            let ch = std::str::from_utf8(&b[s..start])
                .ok()
                .and_then(|t| t.chars().next());
            if ch.is_some_and(char::is_alphanumeric) {
                start = s;
                continue;
            }
        }
        break;
    }
    while start < at && matches!(b[start], b'.' | b'\'') {
        start += 1;
    }
    start
}

/// The end of the longest prefix of `b[from..limit]` that is a host name of
/// at least two labels ending in an alphabetic TLD of two or more letters.
/// Trailing dots and hyphens (sentence punctuation) are never included,
/// and a last label such as `com--thanks` ends the address after `com`.
fn domain_end(b: &[u8], from: usize, limit: usize) -> Option<usize> {
    let mut limit = limit;
    while limit > from && matches!(b[limit - 1], b'.' | b'-') {
        limit -= 1;
    }
    let mut best = None;
    let mut labels = 0;
    let mut start = from;
    while start < limit {
        let len = run(&b[..limit], start, |c| c != b'.');
        let label = &b[start..start + len];
        if label.is_empty() || label.len() > 63 || label[0] == b'-' {
            break;
        }
        labels += 1;
        let alpha = run(label, 0, |c| c.is_ascii_alphabetic());
        if labels >= 2 && alpha >= 2 && (alpha == len || label[alpha] == b'-') {
            best = Some(start + alpha);
        }
        if label[len - 1] == b'-' {
            break;
        }
        start += len + 1;
    }
    best
}

/// True for an `@` that is code or a file name rather than an address:
/// image variants (`logo@2x.png`), file names (`a@b.json`),
/// `user@host:path` remotes (`git@github.com:org/repo.git`) and matrix
/// products on a receiver (`x@self.weight`, `q@this.k`).
fn is_code_at(b: &[u8], at: usize, end: usize) -> bool {
    let domain = &b[at + 1..end];
    let first = domain.split(|&c| c == b'.').next().unwrap_or_default();
    let tld = domain.rsplit(|&c| c == b'.').next().unwrap_or_default();
    let scale = first.len() >= 2
        && first[first.len() - 1].eq_ignore_ascii_case(&b'x')
        && first[..first.len() - 1].iter().all(u8::is_ascii_digit);
    let receiver = [&b"self"[..], b"this", b"cls"]
        .iter()
        .any(|r| first.eq_ignore_ascii_case(r));
    let file = FILE_EXTENSIONS.iter().any(|e| tld.eq_ignore_ascii_case(e));
    let remote =
        b.get(end) == Some(&b':') && b.get(end + 1).is_some_and(|c| !c.is_ascii_whitespace());
    scale || receiver || file || remote
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

/// `+` then 10 to 15 digits in groups separated by single separators,
/// where a group may be parenthesized (`+44 (0)20 7946 0958`). `i` is just
/// past the `+`. A number with country code 1 (North America) has exactly
/// 11 digits and an area code starting with 2 to 9.
///
/// The match ends after the last group that leaves a plausible number not
/// glued to what follows, so a date, address or time after the number is
/// left out (`+44 20 7946 0958 10.0.0.1`). If the groups run into one that
/// would push the number past 15 digits, the groups before it are taken
/// (`+1-555-123-4567-12345`).
fn e164(b: &[u8], i: usize) -> Option<usize> {
    if !is_digit_at(b, i) {
        return None;
    }
    let nanp = b[i] == b'1';
    let fits = |digits: usize| {
        if nanp {
            digits == 11
        } else {
            (10..=15).contains(&digits)
        }
    };
    let mut k = i;
    let mut digits = 0;
    let mut second = None; // the second digit: a North American area code's first
    let mut best = None;
    let mut last = None;
    let mut overflow = false;
    loop {
        // One group: digits, or `(digits)`.
        let (from, len, group_end) = if b.get(k) == Some(&b'(') {
            let len = run(b, k + 1, |c| c.is_ascii_digit());
            if len == 0 || b.get(k + 1 + len) != Some(&b')') {
                break;
            }
            (k + 1, len, k + len + 2)
        } else {
            let len = run(b, k, |c| c.is_ascii_digit());
            if len == 0 {
                break;
            }
            (k, len, k + len)
        };
        if digits + len > 15 {
            if digits == 0 {
                return None; // one unbroken run longer than any phone number
            }
            overflow = true;
            break;
        }
        if second.is_none() && digits + len >= 2 {
            second = Some(b[from + 1 - digits]);
        }
        digits += len;
        k = group_end;
        last = Some((digits, group_end));
        if fits(digits) && phone_ends_at(b, group_end) {
            best = Some(group_end);
        }
        // A separator, or a parenthesized group glued to the previous one.
        match sep_at(b, k) {
            Some((_, n)) if matches!(b.get(k + n), Some(b'0'..=b'9' | b'(')) => k += n,
            None if b.get(k) == Some(&b'(') => {}
            None if is_digit_at(b, k) && b[k - 1] == b')' => {}
            _ => break,
        }
    }
    if nanp && !matches!(second, Some(b'2'..=b'9')) {
        return None;
    }
    best.or(match last {
        Some((d, end)) if overflow && fits(d) => Some(end),
        _ => None,
    })
}

/// `[1 sep] (AAA) EEE sep NNNN` or `[1 sep] AAA sep EEE sep NNNN` with one
/// consistent separator, where the area code starts with 2 to 9 as every
/// North American area code does. Space-separated numbers without
/// parentheses also need one of [`PHONE_WORDS`] just before them.
fn north_american(b: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    if b[k] == b'1' {
        if let Some((_, n)) = sep_at(b, k + 1) {
            if matches!(b.get(k + 1 + n), Some(b'0'..=b'9' | b'(')) {
                k += 1 + n;
            }
        }
    }
    let (area_at, end, spaced) = if b.get(k) == Some(&b'(') {
        digits_exact(b, k + 1, 3)?;
        if b.get(k + 4) != Some(&b')') {
            return None;
        }
        let mut e = k + 5;
        e += space_len(b, e);
        digits_exact(b, e, 3)?;
        let (_, n) = sep_at(b, e + 3)?;
        digits_exact(b, e + 3 + n, 4)?;
        (k + 1, e + 7 + n, false)
    } else {
        digits_exact(b, k, 3)?;
        let (sep, n) = sep_at(b, k + 3)?;
        digits_exact(b, k + 3 + n, 3)?;
        let (sep2, n2) = sep_at(b, k + 6 + n)?;
        if sep2 != sep {
            return None;
        }
        digits_exact(b, k + 6 + n + n2, 4)?;
        (k, k + 10 + n + n2, sep == Sep::Space)
    };
    if !matches!(b[area_at], b'2'..=b'9') {
        return None;
    }
    if spaced && !has_context(b, i, PHONE_WORDS) {
        return None;
    }
    phone_ends_at(b, end).then_some(end)
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

/// `AAA-GG-SSSS`, or `AAA GG SSSS` after one of [`SSN_WORDS`]
/// (`batch 512 64 2048` is not an SSN).
fn ssn_at(b: &[u8], i: usize) -> Option<usize> {
    let area = digits_exact(b, i, 3)?;
    let (sep, n) = sep_at(b, i + 3).filter(|&(s, _)| s != Sep::Dot)?;
    let group = digits_exact(b, i + 3 + n, 2)?;
    let (sep2, n2) = sep_at(b, i + 5 + n)?;
    if sep2 != sep {
        return None;
    }
    let serial = digits_exact(b, i + 5 + n + n2, 4)?;
    let end = i + 9 + n + n2;
    // The SSA never issues area 000, 666 or 900-999, group 00 or serial
    // 0000, so those are not SSNs (and 9xx-xx-xxxx are ITINs).
    let issued = area != 0 && area != 666 && area < 900 && group != 0 && serial != 0;
    if sep == Sep::Space && !has_context(b, i, SSN_WORDS) {
        return None;
    }
    (issued && number_ends_at(b, end)).then_some(end)
}

// ---------------------------------------------------------------------------
// Payment cards
// ---------------------------------------------------------------------------

/// Try a card at every number start. After a miss the scan moves on to the
/// next group rather than past the whole run, so a card after a short
/// number (`qty 2 4111 1111 1111 1111`) or after another card is still
/// found. Each attempt reads at most 19 digits, so the scan stays linear.
fn cards(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_digit() && number_starts_at(b, i)) {
            i += 1;
            continue;
        }
        match card_at(b, i) {
            Some(end) => {
                out.push(Match {
                    kind: Kind::PaymentCard,
                    start: i,
                    end,
                });
                i = end;
            }
            None => i += run(b, i, |c| c.is_ascii_digit()),
        }
    }
}

/// The longest card number starting at `i`: unbroken, or digit groups
/// separated by one kind of separator (spaces or dashes), ending at a group
/// boundary. A group that would take the number past 19 digits is not
/// read, so the caller can try it as the start of the next number
/// (`7 4111111111111111 1229`).
fn card_at(b: &[u8], i: usize) -> Option<usize> {
    // No network issues numbers starting with 0, 1, 7 or 9 (see
    // `issuer_accepts`), so most digit runs are dismissed without reading.
    if !matches!(b[i], b'2'..=b'6' | b'8') {
        return None;
    }
    let mut digits = [0u8; 19];
    let mut count = 0;
    // Size and end offset of each group read.
    let mut groups = [(0usize, 0usize); 19];
    let mut ngroups = 0;
    let mut sep: Option<Sep> = None;
    let mut k = i;
    loop {
        let len = digit_run(b, k, 20 - count);
        if len == 0 || count + len > 19 {
            break;
        }
        digits[count..count + len].copy_from_slice(&b[k..k + len]);
        count += len;
        k += len;
        groups[ngroups] = (len, k);
        ngroups += 1;
        match sep_at(b, k) {
            Some((s, n))
                if s != Sep::Dot && is_digit_at(b, k + n) && sep.is_none_or(|x| x == s) =>
            {
                sep = Some(s);
                k += n;
            }
            _ => break,
        }
    }
    // Candidates end at group boundaries, longest first: a grouped number
    // may be followed by more numbers (`4111 1111 1111 1111 2029`).
    let sizes = groups.map(|(len, _)| len);
    let mut n = count;
    for g in (1..=ngroups).rev() {
        let end = groups[g - 1].1;
        if (13..=19).contains(&n)
            && card_grouping(&sizes[..g])
            && number_ends_at(b, end)
            && issuer_accepts(&digits[..n])
            && luhn_valid(&digits[..n])
        {
            return Some(end);
        }
        n -= groups[g - 1].0;
    }
    None
}

/// The groupings cards are printed with: unbroken; fours with a last group
/// of one to four (4-4-4-4, 4-4-4-1, 4-4-4-4-3, ...); 4-6-5 (American
/// Express) and 4-6-4 (Diners Club). A row of single digits
/// (`4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1`) is not a card.
fn card_grouping(sizes: &[usize]) -> bool {
    match sizes {
        [] => false,
        [_] => true,
        [4, 6, 5] | [4, 6, 4] => true,
        [init @ .., last] => init.iter().all(|&g| g == 4) && (1..=4).contains(last),
    }
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
    let (p1, p2, p3, p4, p6) = (prefix(1), prefix(2), prefix(3), prefix(4), prefix(6));
    let long = (16..=19).contains(&n);
    let visa = p1 == 4 && matches!(n, 13 | 16 | 19);
    let mastercard = ((51..=55).contains(&p2) || (2221..=2720).contains(&p4)) && n == 16;
    let amex = (p2 == 34 || p2 == 37) && n == 15;
    let discover = (p4 == 6011 || (644..=649).contains(&p3) || p2 == 65) && long;
    // UnionPay 62 and 81, and RuPay 81 and 82.
    let unionpay = matches!(p2, 62 | 81 | 82) && long;
    let rupay = (p2 == 60 || p2 == 65 || p3 == 508) && n == 16;
    let jcb = (3528..=3589).contains(&p4) && long;
    let diners =
        ((300..=305).contains(&p3) || matches!(p2, 36 | 38 | 39)) && (14..=19).contains(&n);
    let mir = (2200..=2204).contains(&p4) && long;
    let verve = ((506_099..=506_198).contains(&p6) || (650_002..=650_027).contains(&p6)) && long;
    let maestro = matches!(
        p4,
        5018 | 5020 | 5038 | 5893 | 6304 | 6759 | 6761 | 6762 | 6763
    );
    visa || mastercard
        || amex
        || discover
        || unionpay
        || rupay
        || jcb
        || diners
        || mir
        || verve
        || maestro
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
/// allowing single spaces (or no-break spaces) between them (the print
/// format groups by four, some countries group differently), then check
/// the boundary and the mod 97 check digits.
fn iban_at(b: &[u8], i: usize) -> Option<usize> {
    let want = iban_length(&b[i..i + 2])?;
    let mut chars = [0u8; 34];
    let mut n = 0;
    let mut k = i;
    while n < want {
        let c = *b.get(k)?;
        let space = space_len(b, k);
        if c.is_ascii_uppercase() || c.is_ascii_digit() {
            chars[n] = c;
            n += 1;
            k += 1;
        } else if space > 0
            && n >= 4
            && b.get(k + space)
                .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            k += space;
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
/// taken to be prose ("bearer tokens are..."). A rejected token is
/// examined again as an anchor, so a doubled scheme
/// (`Bearer Bearer <token>`) still hides the token.
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
            i = end;
        } else {
            i = start;
        }
    }
}

/// `Basic` (any case) at a word boundary, whitespace, then base64 that
/// decodes to `user-id:password` (RFC 7617). The decoded colon is what
/// tells a credential from prose ("Basic authentication").
fn basic_credentials(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i + 5 < b.len() {
        let anchored = (i == 0 || !is_word(b[i - 1])) && b[i..i + 5].eq_ignore_ascii_case(b"basic");
        if !anchored {
            i += 1;
            continue;
        }
        let gap = run(b, i + 5, |c| c == b' ' || c == b'\t');
        if gap == 0 {
            i += 5;
            continue;
        }
        let start = i + 5 + gap;
        let mut end = start
            + run(b, start, |c| {
                c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
            });
        end += run(b, end, |c| c == b'=').min(2);
        let glued = b.get(end).is_some_and(|&c| is_key_char(c) || c == b'=');
        if !glued && base64_has_colon(&b[start..end]) {
            out.push(Match {
                kind: Kind::Credential,
                start,
                end,
            });
            i = end;
        } else {
            i = start;
        }
    }
}

/// True if `s` is standard base64 (padded or not) whose decoded bytes
/// contain a `:`.
fn base64_has_colon(s: &[u8]) -> bool {
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    let data = &s[..s.len() - pad];
    if data.len() < 4 || data.len() % 4 == 1 || (pad > 0 && !s.len().is_multiple_of(4)) {
        return false;
    }
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in data {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return false,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if (acc >> bits) & 0xff == b':' as u32 {
                return true;
            }
            acc &= (1 << bits) - 1;
        }
    }
    false
}

/// The secret path of Slack incoming webhook URLs
/// (`https://hooks.slack.com/services/T.../B.../...`). The host stays
/// readable.
fn slack_webhooks(b: &[u8], out: &mut Vec<Match>) {
    const HOOK: &[u8] = b"hooks.slack.com/services/";
    let mut i = 0;
    while i + HOOK.len() <= b.len() {
        if !b[i..].starts_with(HOOK) {
            i += 1;
            continue;
        }
        let start = i + HOOK.len();
        let end = start + run(b, start, |c| is_key_char(c) || c == b'/');
        if end - start >= 16 {
            out.push(Match {
                kind: Kind::SlackToken,
                start,
                end,
            });
        }
        i = end;
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

/// Length of a line break at `k`: a raw `\r` or `\n`, or an escaped one
/// inside a string literal (`\n`, `\\n`, ... with any number of
/// backslashes).
fn line_break(b: &[u8], k: usize) -> Option<usize> {
    match b.get(k)? {
        b'\r' | b'\n' => Some(1),
        b'\\' => {
            let n = run(b, k, |c| c == b'\\');
            matches!(b.get(k + n), Some(b'n' | b'r')).then_some(n + 1)
        }
        _ => None,
    }
}

fn is_base64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')
}

/// Where the body of a PEM block without a matching `END` line (a
/// truncated paste) ends. The body is read line by line, where a line
/// break may be raw or escaped (see [`line_break`]):
///
/// - leading spaces and tabs (YAML or code indentation) are skipped, and
///   blank lines are covered;
/// - `Name: value` header lines (`Proc-Type`, `DEK-Info`) are covered
///   while they come before the base64;
/// - a line of base64 runs, possibly separated by spaces (a key whose line
///   breaks were collapsed), is covered;
/// - a base64 line that ends at a quote, at a PEM boundary or at the end of
///   the text is covered and ends the body (the string holding the key
///   was closed or cut off);
/// - any other line (prose, the next key of a config file) ends the body
///   before it.
///
/// Trailing blank lines are left out of the match.
fn truncated_key_end(b: &[u8], body: usize) -> usize {
    let mut k = body;
    let mut end = body;
    let mut in_headers = true;
    loop {
        if let Some(n) = line_break(b, k) {
            k += n;
            continue;
        }
        let content = k + run(b, k, |c| c == b' ' || c == b'\t');
        let name = run(b, content, |c| c.is_ascii_alphanumeric() || c == b'-');
        let header = in_headers
            && name > 0
            && b[content].is_ascii_alphabetic()
            && b.get(content + name) == Some(&b':');
        if header {
            let mut e = content + name + 1;
            while e < b.len() && line_break(b, e).is_none() && !matches!(b[e], b'"' | b'\'') {
                e += 1;
            }
            end = e;
            k = e;
            if line_break(b, k).is_none() {
                return end;
            }
            continue;
        }
        // Base64 runs separated by spaces or tabs.
        let mut line = content;
        let mut e = content;
        loop {
            let n = run(b, e, is_base64_char);
            if n == 0 {
                break;
            }
            e += n;
            line = e;
            e += run(b, e, |c| c == b' ' || c == b'\t');
        }
        if line == content {
            // Nothing on this line: a blank line, or the end of the body.
            if e < b.len() && line_break(b, e).is_some() && e > k {
                k = e;
                continue;
            }
            return end;
        }
        in_headers = false;
        if let Some(n) = line_break(b, e) {
            end = line;
            k = e + n;
            continue;
        }
        let closed = e == b.len()
            || matches!(b[e], b'"' | b'\'')
            || b[e..].starts_with(PEM_DASHES)
            || (b[e] == b'\\'
                && matches!(b.get(e + run(b, e, |c| c == b'\\')), Some(b'"' | b'\'')));
        return if closed { line } else { end };
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

// ---------------------------------------------------------------------------
// Credentials found by context
// ---------------------------------------------------------------------------

/// Key names whose value is a credential, in lower case without
/// separators. A key matches when its name ends with one of these at the
/// start of a word, after `_`, `-` or `.`, or at a lower-to-upper case
/// change: `DB_PASSWORD`, `clientSecret`, `X-Api-Key`, `aws_session_token`
/// and `SecretAccessKey` all match; `bypass`, `nonsecret` and `max_tokens`
/// do not.
const SECRET_KEYS: &[&[u8]] = &[
    b"password",
    b"passwd",
    b"passphrase",
    b"secret",
    b"secretkey",
    b"secretaccesskey",
    b"privatekey",
    b"token",
    b"apikey",
    b"credential",
    b"authorization",
];

/// Values that say there is no secret.
const NOT_SECRETS: &[&[u8]] = &[b"null", b"none", b"nil", b"true", b"false", b"undefined"];

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
}

/// True if the identifier `id` ends with `key` (see [`SECRET_KEYS`]),
/// ignoring ASCII case and `_`, `-` and `.`.
fn ends_with_key(id: &[u8], key: &[u8]) -> bool {
    let is_sep = |c: u8| matches!(c, b'_' | b'-' | b'.');
    let mut j = id.len();
    for &want in key.iter().rev() {
        while j > 0 && is_sep(id[j - 1]) {
            j -= 1;
        }
        if j == 0 || !id[j - 1].eq_ignore_ascii_case(&want) {
            return false;
        }
        j -= 1;
    }
    j == 0
        || is_sep(id[j - 1])
        || (id[j].is_ascii_uppercase()
            && (id[j - 1].is_ascii_lowercase() || id[j - 1].is_ascii_digit()))
}

/// Values of credential-named keys. Each identifier is examined once, and
/// the scan resumes after any value that was read, whether or not it was
/// taken, so no byte is read as part of two values and the scan is linear
/// (`token:token:token:...` is one rejected value, not many).
fn keyed_secrets(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 0;
    while i < b.len() {
        if !is_ident(b[i]) || (i > 0 && is_ident(b[i - 1])) {
            i += 1;
            continue;
        }
        let id_end = i + run(b, i, is_ident);
        let id = &b[i..id_end];
        let Some(&key) = SECRET_KEYS.iter().find(|key| ends_with_key(id, key)) else {
            i = id_end;
            continue;
        };
        let (value, resume) = keyed_value(b, i, id_end, key == b"authorization");
        if let Some((start, end)) = value {
            out.push(Match {
                kind: Kind::Credential,
                start,
                end,
            });
        }
        i = resume.max(id_end);
    }
}

/// The value after a credential-named key at `id_start..id_end`: the key
/// (quoted, possibly with escaped quotes, or bare), optional spaces, `=` or
/// `:` (or a space after a `--flag`), optional spaces, then the value.
///
/// A quoted value is taken whole, up to its closing quote or the end of
/// the line. An unquoted value runs to whitespace or punctuation that ends
/// a value in code, URLs and config files. Unquoted values that are not
/// secrets are skipped: `null`, `true` and friends, references
/// (`$TOKEN`, `%(password)s`), code (`token = get_token()`,
/// `password: str`), and, unless written `key=value` with no spaces, words
/// with no digit, symbol or inner capital, such as the `token` in
/// `self.token = token`.
///
/// Returns the value's range, if it is a credential, and where scanning
/// resumes: after the value read, or after the key if there was none.
fn keyed_value(
    b: &[u8],
    id_start: usize,
    id_end: usize,
    auth: bool,
) -> (Option<(usize, usize)>, usize) {
    let mut k = id_end;
    // The closing quote of a quoted key: `"key"`, `\"key\"`.
    let q = k + run(b, k, |c| c == b'\\');
    if matches!(b.get(q), Some(b'"' | b'\'')) {
        k = q + 1;
    }
    let before = run(b, k, |c| c == b' ' || c == b'\t');
    k += before;
    let flag = b[id_start..].starts_with(b"--");
    let sep = match b.get(k) {
        Some(&c @ (b'=' | b':')) if b.get(k + 1) != Some(&c) => {
            k += 1;
            c
        }
        _ if flag && before > 0 => b' ',
        _ => return (None, id_end),
    };
    let after = run(b, k, |c| c == b' ' || c == b'\t');
    k += after;
    let tight = sep == b'=' && before == 0 && after == 0;

    // A quoted value, possibly with escaped quotes: `"v"`, `\"v\"`.
    let bs = run(b, k, |c| c == b'\\');
    if let Some(&quote @ (b'"' | b'\'')) = b.get(k + bs) {
        let start = k + bs + 1;
        let end = quoted_end(b, start, quote, bs);
        let v = &b[start..end];
        let value = if auth {
            auth_credential(b, start, end).0
        } else {
            (!v.is_empty() && !is_reference(v)).then_some((start, end))
        };
        return (value, end);
    }
    if auth {
        // `f"Bearer {token}"`: a string prefix, so the value is code.
        let prefix = run(b, k, |c| b"fbruFBRU".contains(&c));
        if (1..=2).contains(&prefix) && matches!(b.get(k + prefix), Some(b'"' | b'\'')) {
            return (None, k);
        }
        return auth_credential(b, k, b.len());
    }
    let end = k + run(b, k, |c| {
        !c.is_ascii_whitespace()
            && !matches!(
                c,
                b'"' | b'\''
                    | b'`'
                    | b','
                    | b';'
                    | b'&'
                    | b'('
                    | b')'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'<'
                    | b'>'
                    | b'\\'
            )
    });
    let v = &b[k..end];
    let identifier = v
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && v.iter().all(|&c| is_word(c) || c == b'.');
    // A call, an index, a generic or a string prefix (`get_token()`,
    // `env[...]`, `Option<String>`, `f"..."`), or a variable passed on
    // (`api_key=api_key`, `connect(password=pw)`; a value with a digit,
    // as in `(password=hunter2)`, is still taken).
    let code = matches!(b.get(end), Some(b'(' | b'[' | b'<' | b'`'))
        || (v.len() <= 2
            && v.iter().all(|c| b"fbruFBRU".contains(c))
            && matches!(b.get(end), Some(b'"' | b'\'')))
        || (identifier && v.eq_ignore_ascii_case(&b[id_start..id_end]))
        || (identifier && b.get(end) == Some(&b')') && !v.iter().any(u8::is_ascii_digit));
    let plausible = tight || (v.len() >= 4 && looks_secret(v));
    let skip = v.is_empty()
        || code
        || is_reference(v)
        || NOT_SECRETS.iter().any(|w| v.eq_ignore_ascii_case(w))
        || !plausible;
    ((!skip).then_some((k, end)), end)
}

/// The end of a quoted value starting at `start`: the closing `quote`
/// preceded by the same number of backslashes `bs` as the opening one, or
/// the end of the line if the string is not closed on it. With `bs == 0`,
/// backslash escapes inside the value are skipped.
fn quoted_end(b: &[u8], start: usize, quote: u8, bs: usize) -> usize {
    let mut k = start;
    while k < b.len() {
        match b[k] {
            b'\n' | b'\r' => break,
            b'\\' => {
                let n = run(b, k, |c| c == b'\\');
                if bs > 0 && n == bs && b.get(k + n) == Some(&quote) {
                    return k;
                }
                k += n;
                if bs == 0 && n % 2 == 1 && k < b.len() && !matches!(b[k], b'\n' | b'\r') {
                    k += 1;
                }
            }
            c if c == quote && bs == 0 => return k,
            _ => k += 1,
        }
    }
    k
}

/// `${TOKEN}`, `$TOKEN`, `{{ secret }}`, `<your-api-key>`, `%(password)s`:
/// a reference to a secret, not a secret.
fn is_reference(v: &[u8]) -> bool {
    matches!(v.first(), Some(b'$' | b'{' | b'<' | b'%'))
}

/// A digit, a symbol, a non-ASCII byte or a capital after the first
/// letter: what a password or key has and an identifier or prose word
/// usually does not.
fn looks_secret(v: &[u8]) -> bool {
    v.iter()
        .any(|&c| c.is_ascii_digit() || c >= 0x80 || b"!@#$%^*+=?~|/".contains(&c))
        || (v[1..].iter().any(u8::is_ascii_uppercase) && v.iter().any(u8::is_ascii_lowercase))
}

/// Scheme names that can stand alone in an `Authorization` value.
const AUTH_SCHEMES: &[&[u8]] = &[b"bearer", b"basic", b"token", b"digest", b"negotiate"];

/// The credentials in an `Authorization` value at `k..limit`: the word
/// after the scheme (`Bearer abc`, `token abc`, `Basic dXNl...`), or the
/// only word when there is no scheme. A repeated scheme
/// (`Bearer Bearer abc`) is skipped. Also returns the end of the last word
/// read, where scanning resumes.
fn auth_credential(b: &[u8], k: usize, limit: usize) -> (Option<(usize, usize)>, usize) {
    let word = |s: usize| {
        s + run(&b[..limit], s, |c| {
            !c.is_ascii_whitespace() && !matches!(c, b'"' | b'\'' | b'\\' | b',' | b';')
        })
    };
    let is_scheme =
        |s: usize, e: usize| AUTH_SCHEMES.iter().any(|w| b[s..e].eq_ignore_ascii_case(w));
    let mut start = k;
    let mut end = word(start);
    let mut read = end;
    // Every word followed by another one is a scheme; the last is the
    // credential. At most the scheme and one repeat are skipped.
    for _ in 0..2 {
        let gap = run(&b[..limit], end, |c| c == b' ' || c == b'\t');
        let next = word(end + gap);
        read = read.max(next);
        let more = gap > 0 && next > end + gap;
        if !(end > start && more && (start == k || is_scheme(start, end))) {
            break;
        }
        start = end + gap;
        end = next;
    }
    let value = &b[start..end];
    let empty = value.is_empty()
        || is_reference(value)
        || NOT_SECRETS.iter().any(|w| value.eq_ignore_ascii_case(w))
        || (start == k && is_scheme(start, end));
    ((!empty).then_some((start, end)), read)
}

/// The password in a URL's userinfo (`scheme://user:password@host`),
/// whatever the host looks like. The authority ends at the first `/`, `?`,
/// `#`, whitespace or quote; the last `@` in it ends the userinfo, so a
/// password with a raw `@` is still covered.
fn url_passwords(b: &[u8], out: &mut Vec<Match>) {
    let mut i = 1;
    while i + 3 <= b.len() {
        if !(b[i..].starts_with(b"://") && b[i - 1].is_ascii_alphanumeric()) {
            i += 1;
            continue;
        }
        let auth = i + 3;
        let end = auth
            + run(b, auth, |c| {
                !c.is_ascii_whitespace()
                    && !c.is_ascii_control()
                    && !matches!(
                        c,
                        b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'`' | b'\\'
                    )
            });
        let authority = &b[auth..end];
        if let Some(at) = authority.iter().rposition(|&c| c == b'@') {
            if let Some(colon) = authority[..at].iter().position(|&c| c == b':') {
                if colon + 1 < at {
                    out.push(Match {
                        kind: Kind::Credential,
                        start: auth + colon + 1,
                        end: auth + at,
                    });
                }
            }
        }
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
            ("call 555 123 4567", "555 123 4567"),
            ("Phone: 555\u{a0}123\u{a0}4567", "555\u{a0}123\u{a0}4567"),
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
            "555 123 4567",
            "123-456-7890",
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
            concat!("sk-", "proj-abc123def456ghi789jkl012mno345"),
            concat!("sk-", "ant-api03-AbCdEf0123456789_xyz-AbCdEfGh"),
            concat!("sk-", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL"),
            concat!("sk_", "live_51Hx0aBcDeFgHiJkLmNoPq"),
        ] {
            assert_finds(Kind::ApiKey, &format!("key=\"{key}\";"), key);
        }
        for text in [
            "sk-learn",
            "task-abc123def456ghi789jkl012",
            concat!("sk-", "this-is-not-a-real-key-at-all"),
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
            concat!("AKI", "AIOSFODNN7EXAMPLE"),
        );
        assert_finds(
            Kind::AwsAccessKey,
            "\"ASIAY34FZKBOKMUTVV7A\"",
            concat!("ASI", "AY34FZKBOKMUTVV7A"),
        );
        for text in [
            concat!("AKI", "AIOSFODNN7EXAMPL"),
            "XAKIAIOSFODNN7EXAMPLE",
            concat!("AKI", "AIOSFODNN7EXAMPLE1"),
            "akiaiosfodnn7example",
            concat!("AKI", "AIOSFODNN7EXAMPLe"),
        ] {
            assert_none(Kind::AwsAccessKey, text);
        }
    }

    #[test]
    fn detects_github_tokens() {
        let classic = concat!("ghp", "_0123456789abcdefghijABCDEFGHIJ012345");
        assert_finds(Kind::GithubToken, &format!("token: {classic}"), classic);
        let fine = concat!(
            "git",
            "hub_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
        );
        assert_finds(Kind::GithubToken, fine, fine);
        assert_finds(
            Kind::GithubToken,
            concat!("gho", "_0123456789abcdefghijABCDEFGHIJ012345"),
            concat!("gho", "_0123456789abcdefghijABCDEFGHIJ012345"),
        );
        assert_none(Kind::GithubToken, "ghp_short");
        assert_none(
            Kind::GithubToken,
            "xghp_0123456789abcdefghijABCDEFGHIJ012345",
        );
        assert_none(Kind::GithubToken, concat!("git", "hub_pat_tooshort"));
    }

    #[test]
    fn detects_slack_tokens() {
        let bot = concat!(
            "xox",
            "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        );
        assert_finds(Kind::SlackToken, &format!("SLACK_TOKEN={bot}"), bot);
        assert_finds(
            Kind::SlackToken,
            concat!("xox", "p-1234567890-abc"),
            concat!("xox", "p-1234567890-abc"),
        );
        assert_none(Kind::SlackToken, concat!("xox", "z-1234567890abcdef"));
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

    /// The redacted text for every kind.
    fn redacted(text: &str) -> String {
        redact(text, &Kind::ALL).0
    }

    /// `prefix` with a Luhn check digit appended.
    fn luhn_complete(prefix: &str) -> String {
        (0..10)
            .map(|d| format!("{prefix}{d}"))
            .find(|n| luhn_valid(n.as_bytes()))
            .unwrap()
    }

    #[test]
    fn commas_separate_numbers() {
        assert_eq!(
            redacted("1,John Doe,078-05-1120,4111111111111111,555-123-4567"),
            "1,John Doe,[ssn],[payment_card],[phone]"
        );
        assert_eq!(
            redacted("[4111111111111111,5555555555554444]"),
            "[[payment_card],[payment_card]]"
        );
        assert_eq!(redacted("555-123-4567,555-987-6543"), "[phone],[phone]");
        assert_eq!(redacted("078-05-1120,078-05-1121"), "[ssn],[ssn]");
        assert_eq!(redacted("+15551234567,+15559876543"), "[phone],[phone]");
        // Thousands separators still do not make a number.
        assert_eq!(redacted("1,234,567,890 rows"), "1,234,567,890 rows");
    }

    #[test]
    fn cards_are_found_after_other_numbers() {
        for (text, want) in [
            (
                "4111111111111111 5555555555554444 378282246310005",
                "[payment_card] [payment_card] [payment_card]",
            ),
            ("qty 2 4111 1111 1111 1111", "qty 2 [payment_card]"),
            ("7 4111111111111111 1229", "7 [payment_card] 1229"),
            (
                "13 Oct 2024 4111 1111 1111 1111",
                "13 Oct 2024 [payment_card]",
            ),
            (
                "+44 20 7946 0958 4111111111111111",
                "[phone] [payment_card]",
            ),
            (
                "4111 1111 1111 1111 5555 5555 5555 4444",
                "[payment_card] [payment_card]",
            ),
        ] {
            assert_eq!(redacted(text), want, "{text:?}");
        }
        // Every card in a long space-separated list.
        let list: Vec<&str> = (0..20_000)
            .map(|i| ["4111111111111111", "5555555555554444", "378282246310005"][i % 3])
            .collect();
        let found = find(&list.join(" "), &[Kind::PaymentCard]);
        assert_eq!(found.len(), list.len());
    }

    #[test]
    fn overlapping_matches_are_merged() {
        // The phone detector stops partway into the card; the union is
        // redacted, so no card digits stay visible.
        for text in [
            "+1 555 123 4567 4111 1111 1111 1111",
            "+1 4111 1111 1111 1111",
            "+44 20 4111 1111 1111 1111",
        ] {
            let out = redacted(text);
            assert!(!out.contains("1111"), "{text:?} -> {out:?}");
        }
        // A bearer token glued to a PEM block: the key body is covered.
        let text = "Bearer abc123def456ghi789jkl-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----";
        assert_eq!(redacted(text), "Bearer [bearer_token]");
        // Merged matches keep the kind of the one that starts first, and
        // never overlap or touch out of order.
        let found = find(text, &Kind::ALL);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::BearerToken);
        assert_eq!(found[0].end, text.len());
    }

    #[test]
    fn phone_numbers_stop_before_what_follows() {
        for (text, want) in [
            ("+44 20 7946 0958 10.0.0.1", "+44 20 7946 0958"),
            ("+44 20 7946 0958 13-10-2024", "+44 20 7946 0958"),
            ("+1-555-123-4567-12345", "+1-555-123-4567"),
            ("+1 555 123 4567 10:30", "+1 555 123 4567"),
            ("+44 20 7946 0958 10:30", "+44 20 7946 0958"),
            ("at 10:30 call 555-123-4567", "555-123-4567"),
        ] {
            assert_finds(Kind::Phone, text, want);
        }
        assert_eq!(redacted("+44 20 7946 0958 10.0.0.1"), "[phone] [ipv4]");
        // North American numbers have 11 digits and an area code from 2.
        for text in ["+1234567890123", "+11234567890", "+1 055 123 4567"] {
            assert_none(Kind::Phone, text);
        }
    }

    #[test]
    fn truncated_private_keys_hide_the_whole_body() {
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7";
        // Indented, as in YAML or code; the next key stays visible.
        let yaml = "key: |\n  -----BEGIN PRIVATE KEY-----\n  MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n  BKcwggSjAgEAAoIBAQC7\nnext: value";
        assert_eq!(redacted(yaml), "key: |\n  [private_key]\nnext: value");
        // Encrypted, with RFC 1421 headers and a blank line.
        let encrypted = format!(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,5E1E5D2F1C6A7B8C\n\n{body}"
        );
        assert_eq!(redacted(&encrypted), "[private_key]");
        // Double-escaped inside JSON in JSON.
        let double =
            r#"{"cfg":"{\"key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkq\\nBKcwggSj\\n"#;
        assert_eq!(redacted(double), r#"{"cfg":"{\"key\":\"[private_key]\\n"#);
        // A closed string: the last line ends at the quote.
        let closed = r#"{"key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nBKcwggSj", "n": 1}"#;
        assert_eq!(redacted(closed), r#"{"key":"[private_key]", "n": 1}"#);
        // Line breaks collapsed to spaces.
        let flat = "key -----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkq BKcwggSj";
        assert_eq!(redacted(flat), "key [private_key]");
        // Windows line endings, cut off mid-line.
        let crlf = "-----BEGIN EC PRIVATE KEY-----\r\nMHcCAQEEIIrYSSNQFaA2Hwf1\r\nBKcwgg";
        assert_eq!(redacted(crlf), "[private_key]");
        // Prose after the body is not swallowed.
        let prose = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nThe server failed to start.\n";
        assert_eq!(
            redacted(prose),
            "[private_key]\nThe server failed to start.\n"
        );
    }

    #[test]
    fn aws_credentials_are_hidden() {
        let json = r#"{"AccessKeyId":"ASIAY34FZKBOKMUTVV7A","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQ==","Expiration":"2026-10-13T12:00:00Z"}"#;
        assert_eq!(
            redacted(json),
            r#"{"AccessKeyId":"[aws_access_key]","SecretAccessKey":"[credential]","SessionToken":"[credential]","Expiration":"2026-10-13T12:00:00Z"}"#
        );
        let env = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nexport AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEJr//wEaCXVz\n";
        assert_eq!(
            redacted(env),
            "export AWS_ACCESS_KEY_ID=[aws_access_key]\nexport AWS_SECRET_ACCESS_KEY=[credential]\nexport AWS_SESSION_TOKEN=[credential]\n"
        );
        let ini = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        assert_eq!(
            redacted(ini),
            "[default]\naws_access_key_id = [aws_access_key]\naws_secret_access_key = [credential]\n"
        );
    }

    #[test]
    fn keyed_credentials() {
        for (text, want) in [
            ("password=hunter2", "hunter2"),
            ("DB_PASSWORD=changeme", "changeme"),
            ("password: s3cr3t!", "s3cr3t!"),
            ("  db_password: Hunter2\n", "Hunter2"),
            (r#"{"client_secret": "abc def"}"#, "abc def"),
            (r#"{'api_key': 'xyz'}"#, "xyz"),
            (r#"{\"apiKey\":\"k-123\"}"#, "k-123"),
            (r#"{"token":"a\"b"}"#, r#"a\"b"#),
            (
                "GET /cb?code=1&access_token=ya29.a0Af-x_Y&x=1",
                "ya29.a0Af-x_Y",
            ),
            ("gh auth login --token ghx123abc456", "ghx123abc456"),
            ("--password=hunter2", "hunter2"),
            ("X-Api-Key: 0123abcd", "0123abcd"),
            (
                r#"curl -H "X-Api-Key: 9f8e7d6c5b4a" https://x.io"#,
                "9f8e7d6c5b4a",
            ),
            ("user=bob,token=abc123,ts=1", "abc123"),
            ("login failed (password=hunter2)", "hunter2"),
            ("passphrase = \"correct horse\"", "correct horse"),
            (
                "PRIVATE_KEY=0x4c0883a69102937d6231471b5dbb6204fe51296",
                "0x4c0883a69102937d6231471b5dbb6204fe51296",
            ),
            ("Authorization: token abc123def", "abc123def"),
            (
                r#""authorization": "Digest-less-credential""#,
                "Digest-less-credential",
            ),
            (
                "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==",
                "dXNlcjpwYXNzd29yZDEyMw==",
            ),
        ] {
            assert_finds(Kind::Credential, text, want);
        }
        for text in [
            "self.token = token",
            "token = get_token()",
            "def login(password: str):",
            "password: str",
            "pub token: String,",
            "max_tokens: 1024",
            r#""token_type": "Bearer""#,
            "token: null",
            "secret = False",
            r#"password = os.environ["DB_PASSWORD"]"#,
            "secret = ${SECRET}",
            r#"api_key: "{{ .Values.apiKey }}""#,
            r#""password": """#,
            "bypass=1",
            "nonsecret: abc123",
            "Enter your password: ",
            "The token: we rotate it weekly",
            "if password == other:",
            "Token::new()",
            "Authorization: Bearer",
            r#"headers = {"Authorization": f"Bearer {token}"}"#,
            r#""Authorization": "Bearer ${TOKEN}""#,
            "client = OpenAI(api_key=api_key)",
            "connect(user=u, password=pw)",
        ] {
            assert_none(Kind::Credential, text);
        }
    }

    #[test]
    fn url_passwords() {
        for (text, want) in [
            (
                "postgres://admin:s3cretPW@localhost:5432/app",
                "postgres://admin:[credential]@localhost:5432/app",
            ),
            (
                "redis://:hunter2pass@10.0.0.5:6379",
                "redis://:[credential]@[ipv4]:6379",
            ),
            (
                "postgresql://app:Sup3rS3cret@db:5432/app",
                "postgresql://app:[credential]@db:5432/app",
            ),
            (
                "https://bob:Tr0ub4dor&3x@api.example.com/v1",
                "https://bob:[credential]/v1",
            ),
            (
                "amqp://u:p@ss@broker/vhost",
                "amqp://u:[credential]@broker/vhost",
            ),
        ] {
            assert_eq!(redacted(text), want, "{text:?}");
        }
        for text in [
            "https://example.com/a@b",
            "ssh://git@host/repo",
            "https://user:@host/",
            "see http://x.io:8080/path",
        ] {
            assert_none(Kind::Credential, text);
        }
    }

    #[test]
    fn more_credential_formats() {
        assert_eq!(
            redacted("Authorization: Basic dXNlcjpwYXNzd29yZDEyMw=="),
            "Authorization: Basic [credential]"
        );
        assert_eq!(
            redacted("curl -H 'Authorization: token abc123def456'"),
            "curl -H 'Authorization: token [credential]'"
        );
        assert_eq!(
            redacted("x-api-key: sk_abc12345678"),
            "x-api-key: [credential]"
        );
        assert_none(Kind::Credential, "Basic authentication is deprecated");
        assert_none(Kind::Credential, "Basic dGhpcyBpcyBwcm9zZQ==");
        for key in [
            concat!("AIz", "aSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"),
            concat!("hf_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"),
            concat!("glp", "at-xxxxxxxxxxxxxxxxxxxx"),
        ] {
            assert_finds(Kind::ApiKey, &format!("key: {key}\n"), key);
        }
        assert_none(Kind::ApiKey, concat!("AIz", "aSyD-tooShort"));
        for token in [
            concat!("xap", "p-1-A0123456789-1234567890123-abcdef"),
            concat!("xox", "e-1-My0xLTEyMzQ1Njc4OTA"),
            concat!("xox", concat!("e.xo", "xp-1-Mi0yLTEyMzQ1Njc4OTA")),
        ] {
            assert_finds(Kind::SlackToken, token, token);
        }
        assert_eq!(
            redacted(concat!("POST https://ho", "oks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX ok")),
            concat!("POST https://ho", "oks.slack.com/services/[slack_token] ok")
        );
    }

    #[test]
    fn doubled_bearer_scheme_still_hides_the_token() {
        let text = "Authorization: Bearer Bearer abc123def456ghi789jkl";
        assert_finds(Kind::BearerToken, text, "abc123def456ghi789jkl");
        assert_finds(Kind::Credential, text, "abc123def456ghi789jkl");
        assert_eq!(
            redacted(text),
            "Authorization: Bearer Bearer [bearer_token]"
        );
    }

    #[test]
    fn email_edges() {
        for (text, want) in [
            ("john@example.com--thanks", "john@example.com"),
            ("a@example.com-", "a@example.com"),
            ("j\u{f6}hn@example.com", "j\u{f6}hn@example.com"),
            ("o'brien@example.com", "o'brien@example.com"),
            ("'a@b.io'", "a@b.io"),
            ("\u{5f20}\u{4f1f}@example.cn", "\u{5f20}\u{4f1f}@example.cn"),
            ("x@corp.co-op.com", "x@corp.co-op.com"),
            ("Contact: a@b.com: ok", "a@b.com"),
        ] {
            assert_finds(Kind::Email, text, want);
        }
        for text in [
            "logo@2x.png",
            "icon@3x.webp",
            "font@latest.json",
            "h = x@self.weight",
            "git@github.com:org/repo.git",
            "\u{2192}@example.com",
        ] {
            assert_none(Kind::Email, text);
        }
    }

    #[test]
    fn no_break_spaces_separate_groups() {
        for (kind, text) in [
            (Kind::Phone, "+33\u{a0}1\u{a0}23\u{a0}45\u{a0}67\u{a0}89"),
            (
                Kind::Phone,
                "+33\u{202f}1\u{202f}23\u{202f}45\u{202f}67\u{202f}89",
            ),
            (Kind::PaymentCard, "4111\u{a0}1111\u{a0}1111\u{a0}1111"),
            (
                Kind::PaymentCard,
                "4111\u{202f}1111\u{202f}1111\u{202f}1111",
            ),
            (
                Kind::Iban,
                "GB82\u{a0}WEST\u{a0}1234\u{a0}5698\u{a0}7654\u{a0}32",
            ),
        ] {
            assert_finds(kind, &format!("x {text} y"), text);
        }
        assert_finds(
            Kind::Ssn,
            "SSN 078\u{a0}05\u{a0}1120.",
            "078\u{a0}05\u{a0}1120",
        );
    }

    #[test]
    fn more_card_networks() {
        for prefix in [
            "220000000000000",    // Mir
            "220412345678901",    // Mir
            "810012345678901",    // UnionPay
            "820012345678901",    // RuPay
            "630400000000000",    // Maestro
            "675912345678901234", // Maestro, 19 digits
        ] {
            let card = luhn_complete(prefix);
            assert_finds(Kind::PaymentCard, &card, &card);
        }
        // The old blanket Maestro ranges (50, 56-69) are gone.
        for prefix in [
            "560000000000000",
            "580000000000000",
            "690000000000000",
            "5000000000000",
        ] {
            assert_none(Kind::PaymentCard, &luhn_complete(prefix));
        }
    }

    #[test]
    fn precision_on_numbers_and_code() {
        for text in [
            "shape: 768 768 3072",
            "dims 128 256 1024",
            "120 456 3890 file.txt",
        ] {
            assert_none(Kind::Phone, text);
        }
        assert_none(Kind::Ssn, "batch 512 64 2048");
        assert_none(Kind::Ssn, "123 45 6789");
        assert_none(Kind::PaymentCard, "[4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1]");
        assert_none(Kind::PaymentCard, "4 1111 1111 1111 111");
        assert_none(
            Kind::ApiKey,
            concat!("sk-", "test-environment-2024-q1-config"),
        );
        // Realistic card groupings still match.
        for text in [
            "4111 1111 1111 1111",
            "3782 822463 10005",
            "4222 2222 2222 2",
        ] {
            assert_finds(Kind::PaymentCard, text, text);
        }
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
            "-----BEGIN PRIVATE KEY-----\n".to_string() + &"A \\\\".repeat(n / 4),
            "1 ".repeat(n / 4) + "4111111111111111",
            "1\u{a0}".repeat(n / 4),
            "password=".repeat(n / 4),
            "password=$".repeat(n / 4),
            "token:".repeat(n / 4),
            "password: ".repeat(n / 4),
            "\"password\":\"".repeat(n / 4),
            "password: \"$".to_string() + &"password: \\\"$".repeat(n / 4),
            "Authorization: $".to_string() + &"Authorization:$".repeat(n / 4),
            "Authorization: Bearer $".to_string() + &"Authorization:$".repeat(n / 4),
            "Authorization: ".repeat(n / 4),
            "Authorization: Bearer ".repeat(n / 4),
            "Basic ".repeat(n / 4),
            "Basic dXNl".repeat(n / 4),
            "a://".repeat(n / 4),
            "a://b:c@".repeat(n / 4),
            concat!("ho", "oks.slack.com/services/").repeat(n / 10),
            "x@".repeat(n / 4) + "a.png",
            "Bearer Bearer ".repeat(n / 4),
            "phone 1 ".repeat(n / 4),
        ];
        for input in &inputs {
            let found = find(input, &Kind::ALL);
            assert!(found.windows(2).all(|w| w[0].end <= w[1].start));
        }
    }
}
