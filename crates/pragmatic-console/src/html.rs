//! The page frame every view shares: escaping, the stylesheet, the
//! masthead and the document skeleton with its Content-Security-Policy.
//!
//! Journal and bundle content is untrusted: a prompt, a tool result or a
//! bundle field can hold markup written to attack whoever opens the page.
//! So every piece of text that is not a literal in this crate goes through
//! [`esc`], pages carry no script at all, and the policy forbids loading
//! anything (scripts, frames, fonts, remote images): the only image is the
//! mark, inlined as a data URI. A page therefore makes no network request
//! when it is opened, and is safe to attach to an incident ticket.

use std::sync::OnceLock;

use pragmatic::encoding::base64_encode;
use pragmatic::json::Json;

/// Escape text for HTML element content and quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The policy every page carries: nothing may be loaded or run, styles are
/// inline, the one image is a data URI, and no form can submit anywhere.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; img-src data:; \
     style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";

/// The Pragmatic mark, recolored to ink for light surfaces.
const MARK_INK_PNG: &[u8] = include_bytes!("../assets/mark-ink.png");

/// The mark as a self-contained data URI (header and favicon).
pub fn mark_uri() -> &'static str {
    static U: OnceLock<String> = OnceLock::new();
    U.get_or_init(|| format!("data:image/png;base64,{}", base64_encode(MARK_INK_PNG)))
}

/// Console stylesheet: paper-and-ink palette, terminal density.
const STYLE: &str = r#"
  :root {
    --bg: #f9f8f6; --tint: #f0eee8; --hover: #edeae2; --ink: #0d0c0b;
    --muted: #6f6a60; --faint: #a39d92; --hair: #e2dfd7; --rule: #0d0c0b;
    --warn: #e9e2cf;
    --mono: ui-monospace, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--ink);
         font: 13px/1.55 var(--mono); -webkit-font-smoothing: antialiased; }
  a { color: inherit; }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 0 28px 64px; }
  @media (max-width: 720px) { .wrap { padding: 0 16px 48px; } }

  .mast { display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
          padding: 14px 0 12px; border-bottom: 1px solid var(--rule); }
  .mast img { width: 16px; height: 16px; display: block; }
  .mast .word { font: 600 13px/1 var(--sans); letter-spacing: .01em;
                text-decoration: none; }
  .mast .sect { color: var(--faint); overflow-wrap: anywhere; }
  .mast .right { margin-left: auto; color: var(--muted); font-size: 12px; }

  .facts { display: flex; flex-wrap: wrap; gap: 6px 26px;
           padding: 10px 0; border-bottom: 1px solid var(--hair);
           font-size: 12px; color: var(--muted); margin-bottom: 22px; }
  .facts b { color: var(--ink); font-weight: 600; }
  .alarm { color: var(--ink); font-weight: 700; background: var(--warn);
           padding: 0 5px; }
  .alarms { margin: -10px 0 22px; font-size: 12px; }
  .alarms div { padding: 3px 0; }

  h2 { font: 600 10px/1 var(--sans); letter-spacing: .18em;
       text-transform: uppercase; color: var(--faint); margin: 26px 0 8px; }
  p.lede { color: var(--muted); font-size: 12px; max-width: 80ch; margin-bottom: 10px; }

  .pill { display: inline-block; font: 600 10px/1.2 var(--sans);
          letter-spacing: .06em; text-transform: uppercase; padding: 1px 5px;
          border: 1px solid var(--faint); color: var(--muted); }
  .pill.ok { border-color: var(--ink); color: var(--ink); }
  .pill.bad { background: var(--ink); border-color: var(--ink); color: var(--bg); }
  .pill.warn { background: var(--warn); border-color: var(--warn); color: var(--ink); }

  .cols, details.ev > summary { display: grid;
      grid-template-columns: 96px 44px 72px 210px minmax(0, 1fr) 88px;
      gap: 0 14px; }
  .cols { padding: 0 10px 6px; font: 600 10px/1 var(--sans);
          letter-spacing: .18em; text-transform: uppercase; color: var(--faint); }
  details.ev { border-bottom: 1px solid var(--hair); }
  details.ev > summary { padding: 6px 10px; cursor: pointer; list-style: none;
                         align-items: baseline; }
  details.ev > summary::-webkit-details-marker { display: none; }
  details.ev > summary:hover { background: var(--hover); }
  details.ev[open] > summary { background: var(--tint); }
  details.ev.meta > summary { color: var(--muted); }
  .t, .cur { color: var(--faint); font-size: 12px; }
  .lane { color: var(--muted); white-space: nowrap; overflow: hidden; }
  .lane i { display: inline-block; width: 9px; height: 1.1em;
            border-left: 1px solid var(--faint); vertical-align: -2px; }
  .evt { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .evt.quiet { font-weight: 400; color: var(--muted); }
  .sum { color: var(--muted); white-space: nowrap; overflow: hidden;
         text-overflow: ellipsis; }
  .h { color: var(--faint); font-size: 11px; text-align: right; }
  @media (max-width: 860px) {
    .cols { display: none; }
    details.ev > summary { grid-template-columns: 40px 1fr; }
    details.ev > summary .t, details.ev > summary .lane,
    details.ev > summary .h { display: none; }
    details.ev > summary .sum { grid-column: 1 / -1; white-space: normal; }
  }
  .detail { padding: 10px 10px 18px 10px; border-top: 1px solid var(--hair); }
  .detail .lbl { font: 600 10px/1 var(--sans); letter-spacing: .18em;
                 text-transform: uppercase; color: var(--faint); margin: 14px 0 5px; }
  .detail pre { white-space: pre-wrap; word-break: break-word;
                background: var(--tint); border-left: 2px solid var(--ink);
                padding: 10px 14px; font: 12.5px/1.6 var(--mono); }
  .detail .gone { color: var(--muted); border-left: 2px dashed var(--faint);
                  padding: 6px 14px; background: none; }
  .kv { color: var(--muted); font-size: 12px; margin-top: 6px; overflow-wrap: anywhere; }
  .kv b { color: var(--ink); font-weight: 600; }

  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { font: 600 10px/1 var(--sans); letter-spacing: .18em;
       text-transform: uppercase; color: var(--faint); text-align: left;
       padding: 0 14px 6px 10px; }
  th.r, td.r { text-align: right; padding-right: 10px; }
  td { padding: 7px 14px 7px 10px; border-top: 1px solid var(--hair);
       vertical-align: top; overflow-wrap: anywhere; }
  tr.run:hover td { background: var(--hover); }
  td.name a { font-weight: 600; text-decoration: none; }
  td .faint, .faint { color: var(--faint); font-size: 11px; }
  .scroll { overflow-x: auto; }
  .empty { padding: 22px 10px; color: var(--muted); border-top: 1px solid var(--hair); }

  .verdict { border: 2px solid var(--ink); padding: 14px 18px; margin: 4px 0 18px; }
  .verdict .v { font: 700 18px/1.2 var(--sans); letter-spacing: .04em; }
  .verdict.bad { background: var(--ink); color: var(--bg); }
  .verdict.warn { background: var(--warn); border-color: var(--warn); }
  .verdict p { margin-top: 6px; font-size: 12.5px; }

  form.inline { display: inline; }
  .forms { display: flex; flex-wrap: wrap; gap: 14px 28px; margin: 6px 0 18px; }
  .forms form { border: 1px solid var(--hair); padding: 10px 12px; font-size: 12px; }
  .forms label { display: block; color: var(--muted); margin: 6px 0 2px; }
  input, select, button { font: 12px/1.4 var(--mono); color: var(--ink); background: var(--bg);
                          border: 1px solid var(--faint); padding: 3px 6px; }
  button { cursor: pointer; border-color: var(--ink); }
  button.link { border: none; padding: 0; text-decoration: underline; background: none; }
  .notice { border-left: 2px solid var(--ink); padding: 6px 12px; margin: 0 0 16px;
            background: var(--tint); font-size: 12px; }
  .secret { font-weight: 700; overflow-wrap: anywhere; }
  .nav a, .nav button.link { margin-left: 12px; }

  .foot { margin-top: 34px; padding-top: 10px; border-top: 1px solid var(--hair);
          color: var(--faint); font-size: 11px; display: flex; flex-wrap: wrap; gap: 6px 24px; }
"#;

/// How a live console frames its pages (Pragmatic Server): a policy that
/// lets its own forms submit, a navigation bar, and a footer naming the
/// viewer and the licensee. Pages without a frame (exported files, the
/// CLI's console) keep [`CONTENT_SECURITY_POLICY`], which allows no form at
/// all.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The Content-Security-Policy of the page's meta tag. Still forbids
    /// loading or running anything.
    pub csp: &'a str,
    /// Escaped HTML for the masthead's right side (links, a sign-out form).
    pub nav: &'a str,
    /// Escaped HTML at the start of the footer.
    pub footer: &'a str,
}

/// The policy of a live console's pages: as [`CONTENT_SECURITY_POLICY`],
/// except that forms may submit to the console's own origin.
pub const CONSOLE_POLICY: &str = "default-src 'none'; img-src data:; \
     style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// A complete page. `title` and `body` must already be escaped HTML.
pub fn page(title: &str, body: &str) -> String {
    page_framed(title, body, None)
}

/// [`page`] in a live console's [`Frame`].
pub fn page_framed(title: &str, body: &str, frame: Option<&Frame<'_>>) -> String {
    let (csp, footer) = match frame {
        Some(f) => (f.csp, format!("<span>{}</span>", f.footer)),
        None => (CONTENT_SECURITY_POLICY, String::new()),
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<link rel="icon" type="image/png" href="{mark}">
<style>{STYLE}</style>
</head>
<body>
<div class="wrap">
{body}
<div class="foot">
  {footer}<span>append-only, hash-chained; replay reads the journal, never the model</span>
  <span>pragmatic {version}</span>
</div>
</div>
</body>
</html>
"#,
        mark = mark_uri(),
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// One-line header: mark, wordmark, section path, right-aligned context.
/// `home` links the wordmark (the run index of a live console) when given.
/// `section` and `right` must already be escaped.
pub fn masthead(home: Option<&str>, section: &str, right: &str) -> String {
    let word = match home {
        Some(h) => format!(r#"<a class="word" href="{}">pragmatic</a>"#, esc(h)),
        None => r#"<span class="word">pragmatic</span>"#.to_string(),
    };
    format!(
        r#"<div class="mast"><img src="{}" alt="">{word}<span class="sect">/ {section}</span><span class="right">{right}</span></div>"#,
        mark_uri()
    )
}

/// `<pre>` of escaped text.
pub fn pre(text: &str) -> String {
    format!("<pre>{}</pre>", esc(text))
}

/// A labeled block.
pub fn block(label: &str, inner: &str) -> String {
    format!("<div class=\"lbl\">{}</div>{inner}", esc(label))
}

/// A pill. `class` is one of the literals `ok`, `bad`, `warn` or empty.
pub fn pill(class: &str, text: &str) -> String {
    format!("<span class=\"pill {class}\">{}</span>", esc(text))
}

/// Indented JSON for display, or `None` if `text` is not JSON.
pub fn pretty_json(text: &str) -> Option<String> {
    let doc = Json::parse(text).ok()?;
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    write_pretty(&mut out, &doc, 0);
    Some(out)
}

fn write_pretty(out: &mut String, v: &Json, depth: usize) {
    let pad = |out: &mut String, d: usize| {
        out.push('\n');
        out.extend(std::iter::repeat_n("  ", d));
    };
    match v {
        Json::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                pad(out, depth + 1);
                write_pretty(out, item, depth + 1);
            }
            pad(out, depth);
            out.push(']');
        }
        Json::Object(members) if !members.is_empty() => {
            out.push('{');
            for (i, (k, item)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                pad(out, depth + 1);
                out.push_str(&Json::String(k.clone()).to_string());
                out.push_str(": ");
                write_pretty(out, item, depth + 1);
            }
            pad(out, depth);
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_markup_and_attributes() {
        assert_eq!(
            esc(r#"<img src=x onerror='a'>&"#),
            "&lt;img src=x onerror=&#39;a&#39;&gt;&amp;"
        );
        assert_eq!(esc("\"q\""), "&quot;q&quot;");
    }

    #[test]
    fn pages_load_nothing() {
        let p = page("t", "<p>x</p>");
        assert!(p.contains("Content-Security-Policy"));
        assert!(p.contains("default-src 'none'"));
        assert!(!p.contains("<script"));
        assert!(!p.contains("http://") && !p.contains("https://"));
    }

    #[test]
    fn framed_pages_allow_their_own_forms_and_still_load_nothing() {
        let frame = Frame {
            csp: CONSOLE_POLICY,
            nav: "<a href=\"/console\">runs</a>",
            footer: "licensed to Example Corp",
        };
        let p = page_framed("t", "<p>x</p>", Some(&frame));
        assert!(p.contains("form-action 'self'"));
        assert!(p.contains("default-src 'none'"));
        assert!(p.contains("licensed to Example Corp"));
        assert!(!p.contains("<script"));
        assert!(page("t", "").contains("form-action 'none'"));
    }

    #[test]
    fn pretty_prints_json() {
        assert_eq!(
            pretty_json(r#"{"a":[1,{"b":null}],"c":{}}"#).unwrap(),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {}\n}"
        );
        assert!(pretty_json("nope").is_none());
    }
}
