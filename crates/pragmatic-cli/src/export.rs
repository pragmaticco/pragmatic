//! Self-contained HTML replay console: one run's journal as a dense,
//! technical event log. No external requests (the mark is a data URI), so an
//! exported page opens anywhere and is safe to attach to an incident ticket.

use std::sync::OnceLock;

use pragmatic::journal_v1::{Event, Journal};
use pragmatic::sha256::hex;

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
  .cols { display: grid; grid-template-columns: 46px 132px 1fr 100px;
          gap: 0 18px; padding: 0 10px 6px;
          font: 600 10px/1 var(--sans); letter-spacing: .18em;
          text-transform: uppercase; color: var(--faint); }

  /* event rows */
  details.ev { border-bottom: 1px solid var(--hair); }
  details.ev > summary { display: grid;
      grid-template-columns: 46px 132px 1fr 100px; gap: 0 18px;
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

fn clip(s: &str, n: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() > n {
        let cut: String = s.chars().take(n).collect();
        format!("{cut}…")
    } else {
        s
    }
}

struct Row {
    evt: &'static str,
    quiet: bool,
    summary: String,
    detail: String,
}

fn detail_block(label: &str, text: &str) -> String {
    format!("<div class=\"lbl\">{label}</div><pre>{}</pre>", esc(text))
}

fn row(event: &Event) -> Row {
    match event {
        Event::Program { name, hash } => Row {
            evt: "program",
            quiet: true,
            summary: format!("<b>{}</b> source={}", esc(name), esc(hash)),
            detail: format!(
                "<div class=\"kv\">program identity - replay fails at this cursor with \
                 <b>JournalDesync</b> if the source hash of <b>{}</b> no longer matches</div>",
                esc(name)
            ),
        },
        Event::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => Row {
            evt: "oracle.draw",
            quiet: false,
            summary: format!(
                "{} <b>→</b> {}",
                esc(&clip(&prompt.as_str(), 60)),
                esc(&clip(&outcome.as_str(), 48))
            ),
            detail: format!(
                "{}{}<div class=\"kv\">provenance <b>{}</b> · replay serves this outcome \
                 without calling the model</div>",
                detail_block("prompt", &prompt.as_str()),
                detail_block("realized outcome", &outcome.as_str()),
                esc(provenance),
            ),
        },
        Event::ChannelRecv { channel, value } => Row {
            evt: "chan.recv",
            quiet: false,
            summary: format!(
                "<b>{}</b> ? {}",
                esc(channel),
                esc(&clip(&value.as_str(), 72))
            ),
            detail: detail_block("value", &value.as_str()),
        },
        Event::EffectIntent { name, arg } => Row {
            evt: "effect.intent",
            quiet: true,
            summary: format!("<b>{}</b>({})", esc(name), esc(&clip(&arg.as_str(), 64))),
            detail: format!(
                "{}<div class=\"kv\">write-ahead intent - journaled durable <b>before</b> \
                 the effect runs; an intent without a matching commit marks a crash inside \
                 the effect window</div>",
                detail_block("argument", &arg.as_str())
            ),
        },
        Event::EffectCommit { name, result } => Row {
            evt: "effect.commit",
            quiet: false,
            summary: format!(
                "<b>{}</b> → {}",
                esc(name),
                esc(&clip(&result.as_str(), 64))
            ),
            detail: format!(
                "{}<div class=\"kv\">replay returns this result; the effect is not \
                 re-performed</div>",
                detail_block("result", &result.as_str())
            ),
        },
        Event::EffectCompensated { name } => Row {
            evt: "effect.comp",
            quiet: false,
            summary: format!("<b>{}</b> rolled back", esc(name)),
            detail: "<div class=\"kv\">saga compensation - closes the open intent; replay \
                     will not double-undo</div>"
                .to_string(),
        },
        Event::Clock { nanos } => Row {
            evt: "clock",
            quiet: true,
            summary: format!("{nanos} ns"),
            detail: format!(
                "<div class=\"kv\">journaled clock read - replay sees <b>{nanos}</b>, \
                 not the current time</div>"
            ),
        },
    }
}

pub fn render(run_id: &str, journal: &Journal) -> String {
    let verified = journal.verify().is_ok();
    let head = journal
        .head()
        .map(|h| hex(&h))
        .unwrap_or_else(|| "-".to_string());
    let dangling = journal.dangling_intents().len();
    let draws = journal
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::OracleDraw { .. }))
        .count();
    let effects = journal
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::EffectCommit { .. }))
        .count();

    let mut entries = String::new();
    for e in journal.entries() {
        let r = row(&e.event);
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
            evt = r.evt,
            summary = r.summary,
            hash = hash,
            hash10 = &hash[..10],
            detail = r.detail,
        ));
    }

    let chain = if verified {
        "chain <b>verified</b>".to_string()
    } else {
        "<span class=\"alarm\">CHAIN BROKEN</span>".to_string()
    };
    let open = if dangling > 0 {
        format!("<div><span class=\"alarm\">{dangling} OPEN INTENT(S)</span> - crashed mid-effect; resume with a recovery policy</div>")
    } else {
        String::new()
    };

    let body = format!(
        r#"{mast}
<div class="facts">
  <div>run <b>{run}</b></div>
  <div><b>{count}</b> steps</div>
  <div><b>{draws}</b> oracle draws</div>
  <div><b>{effects}</b> effects committed</div>
  <div>{chain}</div>
  {open}
  <div>head <b title="{head}">{head_short}</b></div>
</div>
<div class="cols"><span>cur</span><span>event</span><span>summary - click to expand</span><span style="text-align:right">hash</span></div>
{entries}"#,
        mast = masthead("runs", &esc(run_id)),
        run = esc(run_id),
        count = journal.len(),
        head_short = &head[..head.len().min(16)],
    );
    page(&format!("{} · pragmatic", esc(run_id)), &body)
}
