//! Self-contained HTML replay console: one run's journal as a dense,
//! technical event log. No external requests (the mark is a data URI), so an
//! exported page opens anywhere and is safe to attach to an incident ticket.

use std::sync::OnceLock;

use pragmatic::journal::{Content, EffectOutcome, Entry, Event, Journal};
use pragmatic::sha256::hex;

use crate::view;

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Minimal base64 (standard alphabet, padded) - keeps the CLI zero-dep.
fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The Pragmatic mark, recolored to ink for light surfaces.
const MARK_INK_PNG: &[u8] = include_bytes!("../assets/mark-ink.png");

/// The mark as a self-contained data URI (header + favicon).
pub fn mark_uri() -> &'static str {
    static U: OnceLock<String> = OnceLock::new();
    U.get_or_init(|| format!("data:image/png;base64,{}", b64(MARK_INK_PNG)))
}

/// Console stylesheet: paper-and-ink brand palette, terminal density.
const STYLE: &str = r#"
  :root {
    --bg: #f9f8f6; --tint: #f0eee8; --hover: #edeae2; --ink: #0d0c0b;
    --muted: #6f6a60; --faint: #a39d92; --hair: #e2dfd7; --rule: #0d0c0b;
    --mono: ui-monospace, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--ink);
         font: 13px/1.55 var(--mono); -webkit-font-smoothing: antialiased; }
  a { color: inherit; }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 0 28px 64px; }

  /* header: one line of identity, one line of facts */
  .mast { display: flex; align-items: center; gap: 10px;
          padding: 14px 0 12px; border-bottom: 1px solid var(--rule); }
  .mast img { width: 16px; height: 16px; display: block; }
  .mast a.word { font: 600 13px/1 var(--sans); letter-spacing: .01em;
                 text-decoration: none; }
  .mast .sect { color: var(--faint); }
  .mast .right { margin-left: auto; color: var(--muted); font-size: 12px; }

  .facts { display: flex; flex-wrap: wrap; gap: 6px 26px;
           padding: 10px 0; border-bottom: 1px solid var(--hair);
           font-size: 12px; color: var(--muted); margin-bottom: 26px; }
  .facts b { color: var(--ink); font-weight: 600; }
  .alarm { color: var(--ink); font-weight: 700; background: #e9e2cf;
           padding: 0 5px; }

  /* column captions */
  .cols { display: grid; grid-template-columns: 46px 160px 1fr 100px;
          gap: 0 18px; padding: 0 10px 6px;
          font: 600 10px/1 var(--sans); letter-spacing: .18em;
          text-transform: uppercase; color: var(--faint); }

  /* event rows */
  details.ev { border-bottom: 1px solid var(--hair); }
  details.ev > summary { display: grid;
      grid-template-columns: 46px 160px 1fr 100px; gap: 0 18px;
      padding: 7px 10px; cursor: pointer; list-style: none;
      align-items: baseline; }
  details.ev > summary::-webkit-details-marker { display: none; }
  details.ev > summary:hover { background: var(--hover); }
  details.ev[open] > summary { background: var(--tint); }
  .cur { color: var(--faint); }
  .evt { font-weight: 600; }
  .evt.quiet { font-weight: 400; color: var(--muted); }
  .sum { color: var(--muted); white-space: nowrap; overflow: hidden;
         text-overflow: ellipsis; }
  .sum b { color: var(--ink); font-weight: 600; }
  .h { color: var(--faint); font-size: 11px; text-align: right; }
  .detail { padding: 10px 10px 18px 74px; }
  .detail .lbl { font: 600 10px/1 var(--sans); letter-spacing: .18em;
                 text-transform: uppercase; color: var(--faint);
                 margin: 12px 0 5px; }
  .detail pre { white-space: pre-wrap; word-break: break-word;
                background: var(--tint); border-left: 2px solid var(--ink);
                padding: 10px 14px; font: 12.5px/1.6 var(--mono); }
  .detail .kv { color: var(--muted); font-size: 12px; margin-top: 12px; }
  .detail .kv b { color: var(--ink); }

  /* index table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { font: 600 10px/1 var(--sans); letter-spacing: .18em;
       text-transform: uppercase; color: var(--faint); text-align: left;
       padding: 0 18px 6px 10px; }
  th.r, td.r { text-align: right; padding-right: 10px; }
  td { padding: 8px 18px 8px 10px; border-top: 1px solid var(--hair); }
  tr.run:hover td { background: var(--hover); }
  td.name a { font-weight: 600; text-decoration: none; }
  td .dim { color: var(--muted); }
  td .faint { color: var(--faint); font-size: 11px; }
  .empty { padding: 22px 10px; color: var(--muted);
           border-top: 1px solid var(--hair); }

  .foot { margin-top: 34px; padding-top: 10px; border-top: 1px solid var(--hair);
          color: var(--faint); font-size: 11px; display: flex; gap: 24px; }
  .foot a { text-decoration: none; color: var(--muted); }
"#;

pub fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" type="image/png" href="{mark}">
<style>{STYLE}</style>
</head>
<body>
<div class="wrap">
{body}
<div class="foot">
  <span>append-only · hash-chained · replay reads the journal, never the model</span>
  <span><a href="https://github.com/pragmaticco/pragmatic">pragmatic {version}</a></span>
</div>
</div>
</body>
</html>
"#,
        mark = mark_uri(),
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// One-line header: mark, wordmark, section, right-aligned context.
pub fn masthead(section: &str, right: &str) -> String {
    format!(
        r#"<div class="mast"><img src="{}" alt=""><a class="word" href="/">pragmatic</a>
<span class="sect">/ {section}</span><span class="right">{right}</span></div>"#,
        mark_uri()
    )
}

struct Row {
    evt: String,
    quiet: bool,
    summary: String,
    detail: String,
}

fn detail_block(label: &str, text: &str) -> String {
    format!("<div class=\"lbl\">{label}</div><pre>{}</pre>", esc(text))
}

fn kv(text: &str) -> String {
    format!("<div class=\"kv\">{text}</div>")
}

/// The console row of one entry: label, one-line summary, and the full
/// content of every slot in the detail view.
fn row(entry: &Entry) -> Row {
    let event = &entry.event;
    let mut detail = String::new();
    let (quiet, note) = match event {
        Event::DrawIntent { provenance, parts } => {
            for (k, p) in parts.iter().enumerate() {
                detail.push_str(&detail_block(
                    &format!("request part {k}"),
                    &view::content_full(p),
                ));
            }
            (
                true,
                format!(
                    "model call intent, durable <b>before</b> the call · provenance <b>{}</b>",
                    esc(provenance)
                ),
            )
        }
        Event::DrawResult {
            intent,
            meta,
            head,
            body,
        } => {
            detail.push_str(&detail_block("response", &view::content_full(body)));
            if !matches!(head, Content::Sealed(v) if v.is_empty()) {
                detail.push_str(&detail_block("response head", &view::content_full(head)));
            }
            detail.push_str(&detail_block("meta", meta));
            (
                false,
                format!(
                    "response to the intent at cursor <b>{intent}</b> · replay serves it \
                     without calling the model"
                ),
            )
        }
        Event::ChannelRecv { value, .. } => {
            detail.push_str(&detail_block("value", &view::content_full(value)));
            (false, String::new())
        }
        Event::EffectIntent { arg, .. } => {
            detail.push_str(&detail_block("argument", &view::content_full(arg)));
            (
                true,
                "write-ahead intent, durable <b>before</b> the effect runs; an intent \
                 without a result marks a crash inside the effect window"
                    .to_string(),
            )
        }
        Event::EffectResult {
            intent,
            outcome,
            payload,
            ..
        } => {
            if let Some(p) = payload {
                detail.push_str(&detail_block(
                    if *outcome == EffectOutcome::Failed {
                        "failure"
                    } else {
                        "result"
                    },
                    &view::content_full(p),
                ));
            }
            let what = match outcome {
                EffectOutcome::Ok => {
                    "replay returns this result; the effect is not performed again"
                }
                EffectOutcome::Failed => "replay fails the effect again with this message",
                EffectOutcome::Compensated => {
                    "written off by recovery; the run performed the effect again under a new intent"
                }
            };
            (
                false,
                format!("result of the intent at cursor <b>{intent}</b> · {what}"),
            )
        }
        Event::Clock { nanos } => (
            true,
            format!("journaled clock read: replay sees <b>{nanos}</b>, not the current time"),
        ),
        Event::Program { name, .. } => (
            true,
            format!(
                "program identity: replay checks the running program against <b>{}</b>",
                esc(name)
            ),
        ),
        Event::Fork { .. } => (
            true,
            "parallel region: each child runs on its own branch".to_string(),
        ),
        Event::Marker { name } => (true, format!("this run took patch <b>{}</b>", esc(name))),
        Event::Note {
            kind,
            data,
            payload,
        } => {
            detail.push_str(&detail_block("data", data));
            for (k, p) in payload.iter().enumerate() {
                detail.push_str(&detail_block(
                    &format!("payload {k}"),
                    &view::content_full(p),
                ));
            }
            (
                true,
                format!("note <b>{}</b> on the meta branch", esc(kind)),
            )
        }
        Event::Random { value, .. } => {
            detail.push_str(&detail_block("value", &view::content_full(value)));
            (true, "journaled random draw".to_string())
        }
        Event::Refusal { fault, .. } => (
            true,
            format!(
                "refused without touching the world; replay raises <b>{}</b> again",
                esc(fault)
            ),
        ),
        _ => (false, "format 1 entry (read-only)".to_string()),
    };
    if !note.is_empty() {
        detail.push_str(&kv(&note));
    }
    let branch = if entry.branch.is_empty() {
        String::new()
    } else {
        format!("[{}] ", esc(&view::branch_label(&entry.branch)))
    };
    Row {
        evt: view::label(event),
        quiet,
        summary: format!("{branch}{}", esc(&view::summary(event, 72))),
        detail,
    }
}

pub fn render(run_id: &str, journal: &Journal) -> String {
    let report = journal.audit();
    let head = hex(&journal.head());
    let open_intents = view::open_intents(journal).len();
    let draws = view::draws(journal);
    let effects = view::effects_committed(journal);

    let mut entries = String::new();
    for e in journal.entries() {
        let r = row(e);
        let hash = hex(&e.hash);
        entries.push_str(&format!(
            "<details class=\"ev\"><summary>\
               <span class=\"cur\">{cursor:03}</span>\
               <span class=\"evt{quiet}\">{evt}</span>\
               <span class=\"sum\">{summary}</span>\
               <span class=\"h\" title=\"{hash}\">{hash10}</span>\
             </summary><div class=\"detail\">{detail}\
               <div class=\"kv\">entry hash <b>{hash}</b></div>\
             </div></details>\n",
            cursor = e.cursor,
            quiet = if r.quiet { " quiet" } else { "" },
            evt = esc(&r.evt),
            summary = r.summary,
            hash = hash,
            hash10 = &hash[..10],
            detail = r.detail,
        ));
    }

    let chain = if report.is_ok() {
        "journal <b>verified</b>".to_string()
    } else {
        format!(
            "<span class=\"alarm\">{}</span>",
            esc(&view::verify_line(&report))
        )
    };
    let open = if open_intents > 0 {
        format!(
            "<div><span class=\"alarm\">{open_intents} OPEN INTENT(S)</span> - interrupted by a \
             crash; resume decides them</div>"
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"{mast}
<div class="facts">
  <div>run <b>{run}</b></div>
  <div>format <b>{format}</b></div>
  <div><b>{count}</b> entries</div>
  <div><b>{draws}</b> model calls</div>
  <div><b>{effects}</b> effects committed</div>
  <div>{chain}</div>
  {open}
  <div>head <b title="{head}">{head_short}</b></div>
</div>
<div class="cols"><span>cur</span><span>event</span><span>summary - click to expand</span><span style="text-align:right">hash</span></div>
{entries}"#,
        mast = masthead("runs", &esc(run_id)),
        run = esc(run_id),
        format = journal.format(),
        count = journal.len(),
        head_short = &head[..16],
    );
    page(&format!("{} · pragmatic", esc(run_id)), &body)
}
