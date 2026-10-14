//! Showing one slot in an expanded row: its label, state, size and
//! address for erasure, its content when it has some, and its commitment.
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
use pragmatic::journal::{Content, Cursor, SlotMeta, SlotState};
use pragmatic::redact::binary;

use crate::html::{esc, pretty_json_html};
use crate::text;

/// The most bytes of a slot's text a page shows.
pub const MAX_INLINE: usize = 64 * 1024;

/// Where a slot is, for its address and for refs.
#[derive(Clone, Copy, Debug)]
pub struct SlotAt<'a> {
    pub cursor: Cursor,
    pub slot: u8,
    /// The label of the slot (`response body`, `argument`).
    pub label: &'a str,
}

/// A ref's target: the link to its row (escaped HTML) and its label.
#[derive(Clone, Debug)]
pub struct RefTarget {
    pub link: String,
    pub label: String,
}

/// The detail block of one slot of an entry.
pub fn slot_html(
    at: SlotAt<'_>,
    meta: &SlotMeta,
    content: &Content,
    target: Option<&RefTarget>,
) -> String {
    let commitment = hex_encode(&meta.commitment);
    let state = match meta.state {
        SlotState::Sealed => "sealed",
        SlotState::Erased => "erased",
        SlotState::Withheld => "withheld",
        SlotState::Ref => "ref",
    };
    let size = match content {
        Content::Sealed(v) => format!(" \u{b7} {} bytes", text::count(v.len() as u64)),
        _ => String::new(),
    };
    let mut out = format!(
        "<p class=\"slot-l caps\">{} \u{b7} {state}{size} \u{b7} slot {}:{}</p>",
        esc(at.label),
        at.cursor,
        at.slot
    );
    let deduplicated = match (meta.state, meta.ref_target) {
        (SlotState::Ref, Some((c, s))) => {
            let words = match target {
                Some(t) => format!("{}, {}", t.link, esc(&t.label)),
                None => format!("<span class=\"m\">#{c}</span>, slot {s}"),
            };
            out.push_str(&format!(
                "<p class=\"gone\">The same content as {words}: shown there, not repeated.</p>"
            ));
            true
        }
        _ => false,
    };
    out.push_str(&match content {
        Content::Sealed(_) if deduplicated => String::new(),
        Content::Sealed(v) => sealed_html(v.as_bytes()),
        Content::Erased => gone(
            "Erased: the content and its salt were dropped. The commitment below still binds \
             what was here, and every chain hash still verifies.",
        ),
        Content::Withheld => gone(
            "Withheld from this view: only the commitment is shown, so the chain still \
             verifies.",
        ),
    });
    out.push_str(&format!(
        "<p class=\"commit\">commitment <span title=\"{commitment}\">{}</span></p>",
        &commitment[..16]
    ));
    out
}

fn gone(why: &str) -> String {
    format!("<p class=\"gone\">{}</p>", esc(why))
}

/// A value that is not a slot (a format 1 entry's prompt, outcome,
/// argument or result) shown as a slot's content is: binary summarized,
/// JSON pretty-printed, newlines kept, cut at [`MAX_INLINE`].
pub(crate) fn value_html(label: &str, bytes: &[u8]) -> String {
    format!(
        "<p class=\"slot-l caps\">{} \u{b7} {} bytes</p>{}",
        esc(label),
        text::count(bytes.len() as u64),
        sealed_html(bytes)
    )
}

/// The display of content that is present.
fn sealed_html(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return gone("Empty: the slot was recorded with no content.");
    }
    let scanned = binary::scan(bytes);
    let Some(textual) = scanned.text else {
        let f = &scanned.binary[0];
        return gone(&format!(
            "Binary content, not shown: {}, {} bytes, sha256 {}.",
            f.media_type,
            text::count(f.bytes),
            hex_encode(&f.sha256)
        ));
    };
    let mut out = String::new();
    if scanned.incomplete {
        out.push_str(
            "<p class=\"slot-n\">This content starts like JSON but could not be read to its \
             end, so it was not fully scanned for attachments: base64 in it may be shown as \
             text.</p>",
        );
    }
    if textual.len() <= MAX_INLINE {
        match pretty_json_html(&textual) {
            Some(html) => out.push_str(&format!("<pre class=\"json\">{html}</pre>")),
            None => out.push_str(&format!("<pre>{}</pre>", esc(&textual))),
        }
    } else {
        // Too long to pretty-print: the first 64 KiB as recorded.
        let shown = textual;
        let (cut, _) = truncate(&shown, MAX_INLINE);
        out.push_str(&format!("<pre>{}</pre>", esc(cut)));
        out.push_str(&format!(
            "<p class=\"slot-n\">Showing the first 64 KiB of {} bytes.</p>",
            text::count(shown.len() as u64)
        ));
    }
    for f in &scanned.binary {
        out.push_str(&format!(
            "<p class=\"slot-n\">Binary content at <span class=\"m\">{}</span>, not shown: {}, \
             {} bytes, sha256 <span class=\"m\">{}</span>.</p>",
            esc(&f.pointer),
            esc(&f.media_type),
            text::count(f.bytes),
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

    const AT: SlotAt<'static> = SlotAt {
        cursor: 5,
        slot: 1,
        label: "response body",
    };

    #[test]
    fn content_is_escaped_and_json_pretty_printed() {
        let v = Value::from(r#"{"html":"<script>alert(1)</script>"}"#);
        let h = slot_html(AT, &meta(SlotState::Sealed), &Content::Sealed(v), None);
        assert!(h.contains("&lt;script&gt;"));
        assert!(!h.contains("<script>"));
        assert!(h.contains("{\n  <span class=\"jk\">&quot;html&quot;</span>"));
        assert!(h.contains("response body \u{b7} sealed \u{b7} 36 bytes \u{b7} slot 5:1"));
    }

    #[test]
    fn binary_is_summarized_never_inlined() {
        let big = base64_encode(&vec![7u8; 200_000]);
        let body =
            format!(r#"{{"source":{{"type":"base64","media_type":"image/png","data":"{big}"}}}}"#);
        let h = slot_html(
            AT,
            &meta(SlotState::Sealed),
            &Content::Sealed(body.into()),
            None,
        );
        assert!(!h.contains(&big[..100]));
        assert!(h.contains("image/png, 200,000 bytes"));
        let raw = Content::Sealed(Value::new(vec![0xff, 0xfe, 0x00]));
        let h = slot_html(AT, &meta(SlotState::Sealed), &raw, None);
        assert!(h.contains("Binary content, not shown: application/octet-stream, 3 bytes"));
    }

    #[test]
    fn long_text_is_cut() {
        let long = "é".repeat(40_000);
        let h = slot_html(
            AT,
            &meta(SlotState::Sealed),
            &Content::Sealed(long.into()),
            None,
        );
        assert!(h.contains("Showing the first 64 KiB of 80,000 bytes."));
        assert!(h.len() < 70_000);
    }

    #[test]
    fn states_say_what_they_are() {
        assert!(
            slot_html(AT, &meta(SlotState::Erased), &Content::Erased, None)
                .contains("Erased: the content and its salt were dropped")
        );
        assert!(
            slot_html(AT, &meta(SlotState::Withheld), &Content::Withheld, None)
                .contains("Withheld from this view")
        );
        let target = RefTarget {
            link: "<a class=\"m\" href=\"#c3\">#3</a>".into(),
            label: "request part 1".into(),
        };
        let r = slot_html(
            AT,
            &meta(SlotState::Ref),
            &Content::Sealed("repeated message".into()),
            Some(&target),
        );
        assert!(r.contains("href=\"#c3\"") && r.contains("The same content as"));
        assert!(r.contains("request part 1"));
        assert!(
            !r.contains("repeated message"),
            "a ref links, never repeats"
        );
    }

    #[test]
    fn unread_json_is_flagged() {
        let h = slot_html(
            AT,
            &meta(SlotState::Sealed),
            &Content::Sealed("[1, 2".into()),
            None,
        );
        assert!(h.contains("could not be read to its end"));
        let v = value_html("outcome", b"line one\nline two");
        assert!(v.contains("outcome \u{b7} 17 bytes") && v.contains("line one\nline two"));
    }
}
