//! Showing one slot: its state, its commitment, and its content when it
//! has some.
//!
//! Content is shown as text, pretty-printed when it is JSON. Binary values
//! inside JSON (images, documents, audio) are replaced by a summary of
//! media type, size and SHA-256 using [`pragmatic::redact::binary`], and a
//! slot that is not UTF-8 is summarized as a whole, so a page never inlines
//! base64. Text is cut at [`MAX_INLINE`] bytes. Erased, withheld and ref
//! slots say what they are; a ref links to the slot it repeats instead of
//! showing the same content again, so a conversation whose every request
//! repeats the earlier messages does not grow its page quadratically.

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{Content, SlotMeta, SlotState};
use pragmatic::redact::binary;

use crate::html::{esc, pretty_json};

/// The most bytes of a slot's text a page shows.
pub const MAX_INLINE: usize = 64 * 1024;

/// The detail block of slot `k` of an entry.
pub fn slot_html(label: &str, meta: &SlotMeta, content: &Content) -> String {
    let commitment = hex_encode(&meta.commitment);
    let state = match meta.state {
        SlotState::Sealed => "sealed",
        SlotState::Erased => "erased",
        SlotState::Withheld => "withheld",
        SlotState::Ref => "ref",
    };
    let size = match content {
        Content::Sealed(v) => format!(" \u{b7} {} bytes", v.len()),
        _ => String::new(),
    };
    let mut out = format!(
        "<div class=\"lbl\">{} \u{b7} {state}{size}</div>",
        esc(label)
    );
    let deduplicated = match (meta.state, meta.ref_target) {
        (SlotState::Ref, Some((c, s))) => {
            out.push_str(&format!(
                "<div class=\"kv\">deduplicated: the same content as <a href=\"#c{c}\">#{c}</a> slot {s}</div>"
            ));
            true
        }
        _ => false,
    };
    out.push_str(&match content {
        Content::Sealed(_) if deduplicated => String::new(),
        Content::Sealed(v) => sealed_html(v.as_bytes()),
        Content::Erased => gone(
            "erased: the content and its salt were dropped; the commitment below still \
             binds what was here, and every chain hash still verifies",
        ),
        Content::Withheld => gone(
            "withheld from this bundle: only the commitment is included, so the chain \
             verifies without the content",
        ),
    });
    out.push_str(&format!(
        "<div class=\"kv\">commitment <b title=\"{commitment}\">{}</b></div>",
        &commitment[..16]
    ));
    out
}

fn gone(why: &str) -> String {
    format!("<pre class=\"gone\">{}</pre>", esc(why))
}

/// A value that is not a slot (a format 1 entry's prompt, outcome,
/// argument or result) shown as a slot's content is: binary summarized,
/// JSON pretty-printed, newlines kept, cut at [`MAX_INLINE`].
pub(crate) fn value_html(label: &str, bytes: &[u8]) -> String {
    format!(
        "<div class=\"lbl\">{} \u{b7} {} bytes</div>{}",
        esc(label),
        bytes.len(),
        sealed_html(bytes)
    )
}

/// The display of content that is present.
fn sealed_html(bytes: &[u8]) -> String {
    let scanned = binary::scan(bytes);
    let Some(text) = scanned.text else {
        let f = &scanned.binary[0];
        return gone(&format!(
            "binary content, not shown: {}, {} bytes, sha256 {}",
            f.media_type,
            f.bytes,
            hex_encode(&f.sha256)
        ));
    };
    let mut out = String::new();
    let shown = if text.len() <= MAX_INLINE {
        pretty_json(&text).unwrap_or(text.clone())
    } else {
        text.clone()
    };
    let (cut, truncated) = truncate(&shown, MAX_INLINE);
    if scanned.incomplete {
        out.push_str(
            "<div class=\"kv\">this content starts like JSON but could not be read to its end, \
             so it was not fully scanned for attachments: base64 in it may be shown as text</div>",
        );
    }
    out.push_str(&format!("<pre>{}</pre>", esc(cut)));
    if truncated {
        out.push_str(&format!(
            "<div class=\"kv\">showing the first 64 KiB of {} bytes</div>",
            shown.len()
        ));
    }
    for f in &scanned.binary {
        out.push_str(&format!(
            "<div class=\"kv\">binary at <b>{}</b>: {}, {} bytes, sha256 {} (not shown)</div>",
            esc(&f.pointer),
            esc(&f.media_type),
            f.bytes,
            hex_encode(&f.sha256)
        ));
    }
    out
}

/// `s` cut to at most `max` bytes on a character boundary.
pub fn truncate(s: &str, max: usize) -> (&str, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic::encoding::base64_encode;
    use pragmatic::Value;

    fn meta(state: SlotState) -> SlotMeta {
        SlotMeta {
            commitment: [0xab; 32],
            state,
            ref_target: (state == SlotState::Ref).then_some((3, 1)),
        }
    }

    #[test]
    fn content_is_escaped_and_json_pretty_printed() {
        let v = Value::from(r#"{"html":"<script>alert(1)</script>"}"#);
        let h = slot_html("arg", &meta(SlotState::Sealed), &Content::Sealed(v));
        assert!(h.contains("&lt;script&gt;"));
        assert!(!h.contains("<script>"));
        assert!(h.contains("{\n  &quot;html&quot;"));
    }

    #[test]
    fn binary_is_summarized_never_inlined() {
        let big = base64_encode(&vec![7u8; 200_000]);
        let body =
            format!(r#"{{"source":{{"type":"base64","media_type":"image/png","data":"{big}"}}}}"#);
        let h = slot_html(
            "part",
            &meta(SlotState::Sealed),
            &Content::Sealed(body.into()),
        );
        assert!(!h.contains(&big[..100]));
        assert!(h.contains("image/png, 200000 bytes"));
        let raw = Content::Sealed(Value::new(vec![0xff, 0xfe, 0x00]));
        let h = slot_html("value", &meta(SlotState::Sealed), &raw);
        assert!(h.contains("binary content, not shown: application/octet-stream, 3 bytes"));
    }

    #[test]
    fn long_text_is_cut() {
        let long = "é".repeat(40_000);
        let h = slot_html(
            "body",
            &meta(SlotState::Sealed),
            &Content::Sealed(long.into()),
        );
        assert!(h.contains("showing the first 64 KiB of 80000 bytes"));
        assert!(h.len() < 70_000);
    }

    #[test]
    fn states_say_what_they_are() {
        assert!(slot_html("x", &meta(SlotState::Erased), &Content::Erased).contains("erased:"));
        assert!(
            slot_html("x", &meta(SlotState::Withheld), &Content::Withheld)
                .contains("withheld from")
        );
        let r = slot_html(
            "x",
            &meta(SlotState::Ref),
            &Content::Sealed("repeated message".into()),
        );
        assert!(r.contains("href=\"#c3\"") && r.contains("the same content"));
        assert!(
            !r.contains("repeated message"),
            "a ref links, never repeats"
        );
    }

    #[test]
    fn unread_json_is_flagged() {
        let h = slot_html(
            "x",
            &meta(SlotState::Sealed),
            &Content::Sealed("[1, 2".into()),
        );
        assert!(h.contains("could not be read to its end"));
        let v = value_html("outcome", b"line one\nline two");
        assert!(v.contains("outcome \u{b7} 17 bytes") && v.contains("line one\nline two"));
    }
}
