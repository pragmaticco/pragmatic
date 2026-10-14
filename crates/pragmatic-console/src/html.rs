//! The page frame every view shares: escaping, the stylesheet, the
//! masthead, the footer and the document skeleton with its
//! Content-Security-Policy, and the small parts pages are made of
//! (diamonds, tags, notices, data lists).
//!
//! Journal and bundle content is untrusted: a prompt, a tool result or a
//! bundle field can hold markup written to attack whoever opens the page.
//! So every piece of text that is not a literal in this crate goes through
//! [`esc`], pages carry no script at all, and the policy forbids loading
//! anything but the console's own fonts (scripts, frames, remote images
//! and remote fonts are refused): the mark is inline SVG and the favicon a
//! data URI. A single-file page carries its fonts inline, so it makes no
//! network request when it is opened and is safe to attach to an incident
//! ticket.
//!
//! The look is the website's: warm paper and ink, leaves of a lighter
//! paper laid on the page, hairline rules, EB Garamond for words and IBM
//! Plex Mono for data, the brand's diamond as the only icon, and one
//! colour, terracotta, kept for trouble.

use pragmatic::json::Json;

use crate::fonts::font_faces;
pub use crate::fonts::Fonts;

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

/// The policy of a single-file page (an exported run, an evidence report):
/// nothing may be loaded or run, styles are inline, the favicon is a data
/// URI, the fonts are inlined, and no form can submit anywhere.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; img-src data:; \
     font-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";

/// The policy of `pragmatic serve`'s pages: as [`CONTENT_SECURITY_POLICY`],
/// except that fonts come from the console's own origin.
pub const SERVE_POLICY: &str = "default-src 'none'; img-src data:; \
     font-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";

/// The policy of a live console's pages (Pragmatic Server): fonts from its
/// own origin, and forms that submit only to the console itself. It still
/// runs no script and loads nothing from anywhere else.
pub const CONSOLE_POLICY: &str = "default-src 'none'; img-src data:; \
     font-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; \
     frame-ancestors 'none'";

/// The Pragmatic mark: a square with a diamond, as on the website.
pub const MARK: &str = "<svg class=\"mark\" viewBox=\"0 0 100 100\" aria-hidden=\"true\">\
     <rect class=\"ms\" width=\"100\" height=\"100\"/>\
     <rect class=\"md\" x=\"30\" y=\"30\" width=\"40\" height=\"40\" transform=\"rotate(45 50 50)\"/>\
     </svg>";

/// The favicon: the mark as an SVG data URI.
const FAVICON: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' \
     viewBox='0 0 100 100'%3E%3Crect width='100' height='100' fill='%231a1712'/%3E\
     %3Crect x='30' y='30' width='40' height='40' fill='%23f9f7f1' \
     transform='rotate(45 50 50)'/%3E%3C/svg%3E";

/// The drawn arrow of the website's primary links, as a CSS mask.
const ARROW_MASK: &str = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' \
     viewBox='0 0 16 10'%3E%3Cpath d='M0 5h14.6M10.6 1l4 4-4 4' fill='none' stroke='%23000' \
     stroke-width='1.1'/%3E%3C/svg%3E\")";

/// The chevron of a select, as a CSS mask.
const CHEVRON_MASK: &str = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' \
     viewBox='0 0 10 6'%3E%3Cpath d='M.5.5l4.5 4.5 4.5-4.5' fill='none' stroke='%23000' \
     stroke-width='1.1'/%3E%3C/svg%3E\")";

/// The stylesheet, after the font faces. `ARROW` and `CHEVRON` are
/// replaced by their masks.
const STYLE: &str = r###"
:root {
  --paper: #f2efe6; --leaf: #f9f7f1; --band: #f5f2ea; --hover: #efede7;
  --ink: #1a1712;
  --ink-70: rgba(26,23,18,.72); --ink-64: rgba(26,23,18,.64); --ink-50: rgba(26,23,18,.5);
  --ink-30: rgba(26,23,18,.32); --ink-12: rgba(26,23,18,.13);
  --wash: rgba(26,23,18,.045); --press: rgba(26,23,18,.08); --shade: rgba(26,23,18,.08);
  --alarm: #b65a34; --alarm-ink: #a34a26; --alarm-wash: rgba(182,90,52,.07);
  --alarm-press: #8e3f1f; --on-alarm: #f9f7f1;
  --lift-1: 0 0 0 1px var(--ink-12), 0 1px 2px rgba(64,46,22,.04),
            0 12px 26px -12px rgba(64,46,22,.12), 0 30px 60px -30px rgba(64,46,22,.16);
  --lift-2: 0 0 0 1px var(--ink-12), 0 1px 2px rgba(64,46,22,.05),
            0 14px 30px -12px rgba(64,46,22,.15), 0 34px 68px -30px rgba(64,46,22,.2);
  --serif: 'EB Garamond', 'Garamond Fallback', Garamond, Georgia, serif;
  --mono: 'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  --ease: cubic-bezier(.2,.6,.2,1);
  --gut: clamp(16px, 4vw, 40px);
  --link-rule: var(--ink-30);
  --step: 18px;
  color-scheme: light;
}
@media screen and (prefers-color-scheme: dark) {
  :root {
    --paper: #1a1712; --leaf: #211d17; --band: #27221b; --hover: #2b2721;
    --ink: #f2efe6;
    --ink-70: rgba(242,239,230,.78); --ink-64: rgba(242,239,230,.64); --ink-50: rgba(242,239,230,.5);
    --ink-30: rgba(242,239,230,.28); --ink-12: rgba(242,239,230,.16);
    --wash: rgba(242,239,230,.05); --press: rgba(242,239,230,.09); --shade: rgba(0,0,0,.35);
    --alarm: #cf7c55; --alarm-ink: #d98a63; --alarm-wash: rgba(207,124,85,.10);
    --alarm-press: #e49d79; --on-alarm: #1a1712;
    --lift-1: 0 0 0 1px rgba(242,239,230,.08), 0 12px 26px -12px rgba(0,0,0,.5);
    --lift-2: 0 0 0 1px rgba(242,239,230,.08), 0 12px 26px -12px rgba(0,0,0,.5);
    color-scheme: dark;
  }
}

* { margin: 0; padding: 0; box-sizing: border-box; }
html { -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body { min-height: 100vh; display: flex; flex-direction: column; background: var(--paper);
       color: var(--ink); font-family: var(--serif); font-weight: 400; font-size: 17px;
       line-height: 1.6; overflow-wrap: break-word; }
::selection { background: var(--ink); color: var(--paper); }
b, strong, th, h1, h2, h3, dt, summary { font-weight: 400; }
:focus-visible { outline: 1px solid currentColor; outline-offset: 3px; }
main:focus { outline: none; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.skip { position: absolute; top: 12px; left: var(--gut); z-index: 30; padding: 6px 14px 8px;
        background: var(--ink); color: var(--paper); font-style: italic; font-size: 17px; line-height: 1.3; }
.skip:not(:focus) { width: 1px; height: 1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.mark { display: block; flex: none; }
.mark .ms { fill: var(--ink); }
.mark .md { fill: var(--paper); }
.m { font-family: var(--mono); font-style: normal; letter-spacing: 0; font-variant-numeric: tabular-nums; }
.q, .s { font-style: italic; font-family: var(--serif); }
td.m .s, .dl dd .s { font-size: 14.5px; }
h1.title .m { font-size: .74em; letter-spacing: -.01em; color: var(--ink-70); }
.nw { white-space: nowrap; }
.lede .m, .notice .m, .facts .m, .empty .m, .caveat .m, .under .m { font-size: .8em; }
.ink { color: var(--ink); }
.dim { color: var(--ink-64); }
.alarm, .alarm .m { color: var(--alarm-ink); }
.nc { text-transform: none; letter-spacing: 0; }

/* Links: a quiet resting line; on hover or focus a full-strength line
   draws over it from left to right. Ids keep upright mono. */
a { color: inherit; font-style: italic; text-decoration: none; padding-bottom: 1px;
    background-image: linear-gradient(currentColor, currentColor), linear-gradient(var(--link-rule), var(--link-rule));
    background-repeat: no-repeat; background-position: 0 100%, 0 100%; background-size: 0 1px, 100% 1px;
    transition: background-size .45s var(--ease); }
a.m, .m a { font-style: normal; }
a:focus-visible { background-size: 100% 1px, 100% 1px; }
@media (hover: hover) and (pointer: fine) { a:hover { background-size: 100% 1px, 100% 1px; } }
a.go { position: relative; margin-right: 26px; }
a.go::after { content: ''; position: absolute; left: calc(100% + 9px); top: 50%; width: 16px; height: 10px;
              margin-top: -4px; background: currentColor; -webkit-mask: ARROW center / contain no-repeat;
              mask: ARROW center / contain no-repeat; transition: transform .35s var(--ease); }
@media (hover: hover) and (pointer: fine) { a.go:hover::after { transform: translateX(4px); } }

/* The diamond: the brand's mark and the console's only icon. */
.dm { display: inline-block; flex: none; width: 6px; height: 6px; background: currentColor;
      transform: rotate(45deg); vertical-align: .12em; margin-right: 9px; }
.dm.o { background: transparent; box-shadow: inset 0 0 0 1.2px currentColor; }
.dm.lg { width: 7px; height: 7px; }
.dm.br { animation: breathe 1.8s ease-in-out infinite; }
@keyframes breathe { 0%, 100% { opacity: 1; transform: rotate(45deg) scale(1); }
                     50% { opacity: .3; transform: rotate(45deg) scale(.7); } }

/* Tags: a fixed attribute, boxed small mono capitals. */
.tag { display: inline-block; flex: none; padding: 4px 6px 3px 7px; font-family: var(--mono);
       font-style: normal; font-size: 10px; line-height: 1; letter-spacing: .12em; text-transform: uppercase;
       color: var(--ink-64); box-shadow: inset 0 0 0 1px var(--ink-30); white-space: nowrap; vertical-align: .15em; }
.caps { font-family: var(--mono); font-style: normal; font-size: 10px; line-height: 1.6; letter-spacing: .1em;
        text-transform: uppercase; color: var(--ink-64); }

/* ── Masthead ── */
.mast { border-bottom: 1px solid var(--ink-12); }
.mast-in { max-width: calc(1240px + 2 * var(--gut)); margin: 0 auto; padding: 0 var(--gut); min-height: 60px;
           display: flex; flex-wrap: wrap; align-items: center; column-gap: 28px; }
.brand { display: flex; align-items: center; gap: 12px; font-style: normal; font-size: 20px; line-height: 1;
         white-space: nowrap; background: none; padding: 0; }
.brand .mark { width: 20px; height: 20px; }
.brand span { transform: translateY(-1px); }
.crumbs { display: flex; align-items: baseline; gap: 10px; min-width: 0; font-size: 16.5px; line-height: 1.3;
          color: var(--ink-64); white-space: nowrap; }
.crumbs a { font-style: normal; background-size: 0 1px, 0 1px; }
@media (hover: hover) and (pointer: fine) { .crumbs a:hover { background-size: 100% 1px, 0 1px; } }
.crumbs .sep { color: var(--ink-30); }
.crumbs .cur { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
.crumbs .cur.m { font-size: 13px; color: var(--ink-70); }
.mast-r { margin-left: auto; display: flex; align-items: baseline; gap: 28px; min-width: 0; }
.nav { display: flex; gap: 28px; align-items: baseline; }
.nav a { position: relative; font-style: normal; font-size: 16.5px; line-height: 1.3; color: var(--ink-64);
         white-space: nowrap; background: none; transition: color .25s; }
.nav a::after { content: ''; position: absolute; left: 0; right: 0; bottom: .05em; height: 1px; background: currentColor;
                transform: scaleX(0); transform-origin: left center; transition: transform .4s var(--ease); }
.nav a[aria-current] { color: var(--ink); }
.nav a[aria-current]::after { content: none; }
.nav a[aria-current]::before { content: ''; position: absolute; left: -14px; top: 50%; width: 5px; height: 5px;
                               margin-top: -2.5px; background: currentColor; transform: rotate(45deg); }
.nav a:focus-visible::after { transform: scaleX(1); }
@media (hover: hover) and (pointer: fine) { .nav a:hover { color: var(--ink); } .nav a:hover::after { transform: scaleX(1); } }
.out { display: inline; }
.src { font-family: var(--mono); font-size: 12px; color: var(--ink-64); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.src-note { font-style: italic; font-size: 15px; color: var(--ink-64); white-space: nowrap; }
@media (max-width: 759px) {
  .mast-in { padding-top: 10px; padding-bottom: 2px; row-gap: 2px; column-gap: 16px; }
  .crumbs { flex: 1; overflow: hidden; }
  .crumbs .up, .crumbs .sep { display: none; }
  .mast-r { display: contents; }
  .mast-r .nav { order: 5; flex-basis: 100%; overflow-x: auto; padding: 6px 0 10px 14px; margin-left: -14px;
                 background: linear-gradient(to left, var(--paper) 30%, transparent) right / 40px 100% no-repeat local,
                             linear-gradient(to left, var(--shade), transparent) right / 14px 100% no-repeat scroll; }
  .mast-r .src-note { display: none; }
  .mast-r .src { max-width: 40vw; }
}

/* ── Page ── */
main { flex: 1 0 auto; width: 100%; max-width: calc(1240px + 2 * var(--gut)); margin: 0 auto;
       padding: 28px var(--gut) 0; container: main / inline-size; }
.page-h { margin: 4px 0 20px; display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 20px; }
h1.title { font-size: 32px; line-height: 1.12; letter-spacing: -.012em; text-wrap: balance; }
.lede { font-size: 17px; line-height: 1.6; color: var(--ink-70); max-width: 66ch; text-wrap: pretty; }
.page-h .lede { font-style: italic; font-size: 16px; color: var(--ink-64); }
.sect + .sect { margin-top: 32px; }
.rhead { display: flex; align-items: center; gap: 13px; padding-top: 16px; margin-bottom: 8px;
         border-top: 1px solid var(--ink-12); font-style: italic; font-size: 18px; color: var(--ink-64); }
.rhead::before { content: ''; width: 7px; height: 7px; background: var(--ink); transform: rotate(45deg); flex: none; }
.rhead + .lede { margin-bottom: 16px; }

/* Notices: a sentence about the page, on a strip with a rule. */
.notice { margin: 0 0 16px; padding: 10px 16px 11px; background: var(--leaf); border-left: 2px solid var(--ink);
          font-style: italic; font-size: 15.5px; line-height: 1.5; color: var(--ink-70); box-shadow: 0 0 0 1px var(--ink-12); }
.notice.bad { border-left-color: var(--alarm); color: var(--alarm-ink); }
.sheet .notice { margin: 12px 0 0; box-shadow: none; background: var(--band); }

/* ── The run page ── */
.run-grid { display: grid; gap: 24px; align-items: start; }
.side { display: grid; gap: 16px; align-content: start; min-width: 0; }
@container main (min-width: 940px) { .run-grid { grid-template-columns: minmax(0, 1fr) 320px; } }
@container main (min-width: 640px) and (max-width: 939px) { .side { grid-template-columns: 1fr 1fr; } }

.sheet { position: relative; min-width: 0; background: var(--leaf); box-shadow: var(--lift-1); container: sheet / inline-size; }
.sh-head { padding: 20px 22px 16px; }
.sh-title { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; }
h1.rid { font-family: var(--mono); font-size: 18px; line-height: 1.3; letter-spacing: -.01em; overflow-wrap: anywhere; }
.badge { font-style: italic; font-size: 17px; line-height: 1.3; white-space: nowrap; }
.badge.lg { font-size: 26px; }
.badge.lg .dm { width: 9px; height: 9px; margin-right: 12px; vertical-align: .18em; }
.facts { margin-top: 6px; font-size: 16px; line-height: 1.5; color: var(--ink-64); }
.facts .n { font-family: var(--mono); font-size: 13px; color: var(--ink); font-variant-numeric: tabular-nums; }
.facts .alarm .n { color: var(--alarm-ink); }
.facts .tag { margin-left: 6px; }
.state { margin-top: 2px; font-style: italic; font-size: 15.5px; line-height: 1.5; color: var(--ink-64); }
.state .m { font-size: 12.5px; color: var(--ink-70); }
.state .dm { margin-right: 8px; }

.cols { position: sticky; top: 0; z-index: 3; display: flex; justify-content: space-between; gap: 16px;
        padding: 8px 22px 7px 46px; background: var(--leaf); border-top: 1px solid var(--ink-12);
        border-bottom: 1px solid var(--ink-12); }
.cols .c-hash { display: none; }
.pager { padding: 10px 22px 11px 46px; border-bottom: 1px solid var(--ink-12); font-style: italic; font-size: 15px;
         line-height: 1.5; color: var(--ink-64); }
.pager.end { border-bottom: 0; border-top: 1px solid var(--ink-12); padding-bottom: 14px; }
.pager .m { font-size: 12px; }
.pager a.go { color: var(--ink); }

.tl { position: relative; padding: 6px 0 10px; }
.tl::before { content: ''; position: absolute; left: 24px; top: 0; bottom: 0; width: 1px; background: var(--ink-12); }
.grp-label { position: relative; padding: 14px 22px 4px 46px; }
.rows { list-style: none; }
.row { position: relative; --d: 0; --bg: var(--leaf);
       --rails: repeating-linear-gradient(to right, var(--ink-12) 0 1px, transparent 1px var(--step)) 24px 0 / calc((var(--d) + 1) * var(--step)) 100% no-repeat;
       background: var(--rails); }
.row.d1 { --d: 1; } .row.d2 { --d: 2; } .row.d3 { --d: 3; } .row.d4 { --d: 4; } .row.d5 { --d: 5; } .row.d6 { --d: 6; }
.sum { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: "t tm" "k h";
       column-gap: 16px; align-items: baseline; padding: 8px 22px 9px calc(46px + var(--d) * var(--step));
       list-style: none; background: var(--rails), var(--bg); }
summary.sum { cursor: pointer; }
summary.sum::-webkit-details-marker { display: none; }
summary.sum::marker { content: ''; }
summary.sum:focus-visible { outline-offset: -1px; }
.sum::before { content: ''; position: absolute; left: calc(21px + var(--d) * var(--step)); top: 16px; width: 7px; height: 7px;
               background: var(--ink); transform: rotate(45deg); box-shadow: 0 0 0 3px var(--bg); }
.sum > span[id] { position: absolute; top: 0; left: 0; scroll-margin-top: 44px; }
.sum .t { grid-area: t; min-width: 0; font-size: 17px; line-height: 24px; text-wrap: pretty; overflow-wrap: anywhere; }
.sum .t .m { font-size: 13px; color: var(--ink-70); }
.sum .t .s, .sum .t .q { font-style: italic; color: var(--ink-70); }
.sum .t .alarm, .sum .t .alarm .m, .sum .t .alarm .s { color: var(--alarm-ink); }
.sum .t a { font-style: inherit; }
.sum .t .rm { font-style: normal; }
.ar { display: inline-block; width: 15px; height: 9px; margin: 0 5px 0 3px; background: var(--ink-64);
      -webkit-mask: ARROW center / contain no-repeat; mask: ARROW center / contain no-repeat; }
.sum .tt { background-image: linear-gradient(currentColor, currentColor); background-repeat: no-repeat;
           background-position: 0 100%; background-size: 0 1px; transition: background-size .45s var(--ease);
           -webkit-box-decoration-break: clone; box-decoration-break: clone; }
.sum .k, .sum .tm, .sum .h { font-family: var(--mono); font-size: 11.5px; color: var(--ink-64); font-variant-numeric: tabular-nums; }
.sum .k { grid-area: k; min-width: 0; line-height: 18px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sum .tm { grid-area: tm; justify-self: end; line-height: 24px; white-space: nowrap; }
.sum .h { grid-area: h; justify-self: end; line-height: 18px; white-space: nowrap; }
@media (hover: hover) and (pointer: fine) {
  summary.sum:hover { --bg: var(--hover); }
  summary.sum:hover .tt { background-size: 100% 1px; }
}
summary.sum:focus-visible .tt { background-size: 100% 1px; }
details[open] > summary.sum { --bg: var(--band); }
.row:has(.sum > span:target) .sum { --bg: var(--hover); }
.row:has(.sum > span:target) .sum::before { box-shadow: 0 0 0 3px var(--bg), 0 0 0 4px var(--ink-30); }

/* Markers (see the design: what each diamond means). */
.mk-ring .sum::before { box-shadow: 0 0 0 3px var(--bg), 0 0 0 4px var(--ink-30); }
.mk-hollow .sum::before, .mk-breathe .sum::before { background: var(--bg); box-shadow: inset 0 0 0 1.5px var(--ink), 0 0 0 3px var(--bg); }
.mk-big .sum::before, .mk-alarm-big .sum::before { left: calc(20px + var(--d) * var(--step)); top: 15px; width: 9px; height: 9px; }
.mk-alarm .sum::before, .mk-alarm-big .sum::before { background: var(--alarm); }
.mk-alarm-hollow .sum::before { background: var(--bg); box-shadow: inset 0 0 0 1.5px var(--alarm), 0 0 0 3px var(--bg); }
.mk-breathe .sum::before { animation: breathe 1.8s ease-in-out infinite; }
/* An attempt that stopped without an end: the website's crash row. */
.crash > .sum { background: linear-gradient(to right, var(--alarm-wash), transparent 85%), var(--rails), var(--leaf); }
.crash::after { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--alarm); }
.crash .t { color: var(--alarm-ink); }
.derived .t { grid-column: 1 / -1; }

.detail { margin: 0 22px 8px calc(46px + var(--d) * var(--step)); padding: 14px 18px 18px; background: var(--band);
          border-top: 1px solid var(--ink-12); }
.ent + .ent { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--ink-12); }
.ent-h { font-family: var(--mono); font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
.ent-h .dim { margin-left: 10px; }
.ent-w { margin-top: 3px; font-style: italic; font-size: 15px; line-height: 1.5; color: var(--ink-64); }
.dl { display: grid; grid-template-columns: minmax(0, 150px) minmax(0, 1fr); column-gap: 12px; margin-top: 10px;
      font-family: var(--mono); font-size: 11.5px; line-height: 20px; }
.dl dt { color: var(--ink-64); }
.dl dd { min-width: 0; overflow-wrap: anywhere; }
.dl dd .q, .dl dd.q { font-family: var(--serif); font-style: italic; font-size: 14.5px; color: var(--ink-64); }
.dl .hr { grid-column: 1 / -1; height: 1px; background: var(--ink-12); margin: 6px 0 7px; }
.dl .res { display: flex; align-items: center; }
.slot-l { margin: 16px 0 6px; overflow-wrap: anywhere; }
pre { margin: 0; padding: 12px 16px; max-height: 28em; overflow: auto; background: var(--leaf);
      border-left: 1px solid var(--ink-12); font-family: var(--mono); font-size: 12px; line-height: 1.65;
      color: var(--ink); white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 2; }
pre.json { color: var(--ink-64); }
pre .jk, pre .jv { color: var(--ink); }
pre .js { color: var(--ink-70); }
.gone { padding: 10px 14px 11px; border: 1px dashed var(--ink-30); font-style: italic; font-size: 15px;
        line-height: 1.5; color: var(--ink-64); }
.slot-n { margin-top: 6px; font-style: italic; font-size: 14.5px; line-height: 1.5; color: var(--ink-64); }
.slot-n .m { font-size: 11.5px; }
.commit { margin-top: 6px; font-family: var(--mono); font-size: 11px; color: var(--ink-64); }

.chain { display: flex; flex-wrap: wrap; align-items: baseline; column-gap: 7px; padding: 13px 22px 15px;
         border-top: 1px solid var(--ink-12); background: var(--band); font-size: 16px; line-height: 1.4; }
.chain .dm { align-self: center; width: 7px; height: 7px; margin: 0 5px 0 2px; }
.chain .s { color: var(--ink-70); }
.chain .m { font-size: 12px; color: var(--ink-64); }
.chain.alarm .s { color: var(--alarm-ink); }

@container sheet (max-width: 600px) {
  .sum .tm, .cols .c-time { display: none; }
  .cols .c-hash { display: inline; }
}
@container sheet (max-width: 480px) {
  .chain .m { display: none; }
  .sum { grid-template-areas: "t t" "k h"; column-gap: 10px; }
  .sum .k, .sum .h { font-size: 11px; }
  .facts .br { display: block; height: 0; overflow: hidden; }
  .facts .br + .sp { display: none; }
  .row { --step: 12px; }
}
@container sheet (max-width: 340px) {
  .sh-head { padding: 18px 16px 14px; }
  .cols, .grp-label, .pager { padding-left: 42px; padding-right: 16px; }
  .tl::before { left: 21px; }
  .row { --rails: repeating-linear-gradient(to right, var(--ink-12) 0 1px, transparent 1px var(--step)) 21px 0 / calc((var(--d) + 1) * var(--step)) 100% no-repeat; }
  .sum { grid-template-columns: minmax(0, 1fr); grid-template-areas: "t" "k" "h"; padding: 8px 16px 9px calc(42px + var(--d) * var(--step)); }
  .sum::before { left: calc(18px + var(--d) * var(--step)); }
  .mk-big .sum::before, .mk-alarm-big .sum::before { left: calc(17px + var(--d) * var(--step)); }
  .sum .h { justify-self: start; }
  .detail { margin: 0 12px 8px 30px; padding: 12px 12px 14px; }
  .dl { grid-template-columns: minmax(0, 1fr); }
  .chain { padding: 13px 16px 14px; }
}

/* ── Leaves: the side cards ── */
.card { position: relative; min-width: 0; background: var(--leaf); box-shadow: var(--lift-1); }
.card-h { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; padding: 14px 18px 12px;
          border-bottom: 1px solid var(--ink-12); }
.card-t { display: flex; align-items: baseline; gap: 10px; min-width: 0; font-style: italic; font-size: 17px; line-height: 1.3; }
.card-t::before { content: ''; flex: none; width: 6px; height: 6px; background: var(--ink); transform: rotate(45deg); }
.card-t.o::before { background: transparent; box-shadow: inset 0 0 0 1.2px currentColor; }
.card-t.alarm::before { background: transparent; box-shadow: inset 0 0 0 1.2px var(--alarm); }
.card-h .note { font-family: var(--mono); font-size: 11px; color: var(--ink-64); white-space: nowrap; }
.card-b { padding: 12px 18px 16px; }
.card-f { padding: 12px 18px 15px; border-top: 1px solid var(--ink-12); background: var(--band); }
.card-b > p, .card-f > p { font-size: 15.5px; line-height: 1.5; color: var(--ink-70); }
.card-b > * + p, .card-f > * + p, .card-f > p + .cmd { margin-top: 8px; }
.card-b .note, .card-f .note { font-style: italic; font-size: 14.5px; color: var(--ink-64); }
.card-b p .m, .card-f p .m { font-size: 11.5px; }
.card .dl { margin-top: 0; grid-template-columns: minmax(0, 136px) minmax(0, 1fr); column-gap: 8px; font-size: 10.5px; line-height: 19px; }
.card .dl.n { grid-template-columns: minmax(0, 74px) minmax(0, 1fr); }
.card .dl dd .s { font-family: var(--serif); font-style: italic; font-size: 14.5px; color: var(--ink-64); }
.cmd { display: block; font-family: var(--mono); font-size: 11.5px; line-height: 1.6; color: var(--ink); overflow-wrap: anywhere; }
.card-f .lbl { display: flex; align-items: center; justify-content: space-between; gap: 10px; font-style: italic;
               font-size: 15.5px; color: var(--ink); }
.card-f .dls { list-style: none; margin-top: 6px; display: grid; gap: 2px; font-size: 15.5px; line-height: 1.5; }
.anchor .card-h { border-bottom: 0; align-items: flex-start; padding-bottom: 13px; }
.anchor .card-t::before { align-self: flex-start; margin-top: .5em; }
.rule { position: relative; height: 1px; background: var(--ink-12); }
.rule > span { position: absolute; left: 0; top: 0; bottom: 0; background: var(--ink); }
.ops { list-style: none; padding: 8px 0 4px; }
.op { display: grid; grid-template-columns: 14px minmax(0, 1fr) auto; column-gap: 8px; align-items: baseline; padding: 6px 18px; }
.op > i { width: 6px; height: 6px; align-self: center; justify-self: center; background: var(--ink); transform: rotate(45deg); }
.op > i.o { background: transparent; box-shadow: inset 0 0 0 1.2px var(--ink); }
.op > i.a { background: var(--alarm); }
.op .nm { font-size: 16px; line-height: 1.35; overflow-wrap: anywhere; }
.op .st { font-family: var(--mono); font-size: 11px; color: var(--ink-64); white-space: nowrap; }
.op .root { grid-column: 2 / -1; font-style: italic; font-size: 14px; line-height: 1.4; color: var(--ink-64); }
.anchor .card-b { padding-top: 10px; }
.attempts { list-style: none; margin-top: 2px; }
.attempts li { display: grid; grid-template-columns: minmax(0, 1fr) auto; column-gap: 10px; padding: 6px 0;
               font-size: 15px; line-height: 1.4; border-top: 1px solid var(--ink-12); }
.attempts li:first-child { border-top: 0; }
.attempts .m { font-size: 11px; }
.attempts .out { font-style: italic; color: var(--ink-70); text-align: right; }
.attempts .who { grid-column: 1 / -1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-64); }
.card-f .cmd + .lbl { margin-top: 10px; }
.card-f .note { margin-top: 8px; }
.card .caps, .card-b > p.caps { display: block; margin: 14px 0 2px; font-size: 10px; line-height: 1.6; color: var(--ink-64); }

/* ── Forms ── */
.fields { display: grid; gap: 14px; }
.field label, .field .lbl { display: block; margin-bottom: 4px; font-style: italic; font-size: 15px; line-height: 1.4; color: var(--ink-64); }
.field .hint { margin-top: 4px; font-style: italic; font-size: 14px; line-height: 1.45; color: var(--ink-64); }
.field .hint .m { font-size: 12px; }
.field .err { margin-top: 4px; font-style: italic; font-size: 14.5px; color: var(--alarm-ink); }
input[type=text], input[type=password], input:not([type]), select {
  display: block; width: 100%; min-height: 38px; padding: 7px 10px; border: 0; border-radius: 0; background: var(--leaf);
  color: var(--ink); box-shadow: inset 0 0 0 1px var(--ink-30); font-family: var(--serif); font-size: 16px; line-height: 1.4;
  -webkit-appearance: none; appearance: none; }
input.m, select.m { font-family: var(--mono); font-size: 13px; }
input:focus, select:focus { outline: none; box-shadow: inset 0 0 0 1.5px var(--ink); }
input[aria-invalid=true] { box-shadow: inset 0 0 0 1px var(--alarm); }
select { padding-right: 28px; cursor: pointer; }
.sel { position: relative; }
.sel::after { content: ''; position: absolute; right: 11px; bottom: 16px; width: 10px; height: 6px; background: var(--ink-64);
              -webkit-mask: CHEVRON center / contain no-repeat; mask: CHEVRON center / contain no-repeat; pointer-events: none; }
.cbox { display: flex; align-items: baseline; gap: 9px; font-size: 16px; line-height: 1.4; cursor: pointer; }
.cbox input { flex: none; width: 16px; height: 16px; accent-color: var(--ink); transform: translateY(2px); }
.actions { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 24px; margin-top: 18px; }
.btn { display: inline-flex; align-items: center; justify-content: center; min-height: 36px; padding: 8px 18px 9px;
       border: 0; border-radius: 0; background: transparent; color: var(--ink); box-shadow: inset 0 0 0 1px var(--ink);
       font-family: var(--serif); font-style: normal; font-size: 16px; line-height: 1.25; cursor: pointer; white-space: nowrap; }
.btn:hover { background: var(--wash); }
.btn:active { background: var(--press); }
.btn:disabled { color: var(--ink-50); box-shadow: inset 0 0 0 1px var(--ink-30); cursor: default; }
.btn.danger { color: var(--alarm-ink); box-shadow: inset 0 0 0 1px var(--alarm); }
.btn.danger:hover { background: var(--alarm-wash); }
.btn.fill { color: var(--on-alarm); background: var(--alarm-ink); box-shadow: none; }
.btn.fill:hover { background: var(--alarm-press); }
.btn.sm { min-height: 28px; padding: 4px 12px 5px; font-size: 14.5px; }
.lkb { position: relative; padding: 0 0 1px; border: 0; background: none; color: inherit; cursor: pointer;
       font-family: var(--serif); font-style: italic; font-size: 16.5px; line-height: 1.3; white-space: nowrap;
       background-image: linear-gradient(currentColor, currentColor), linear-gradient(var(--link-rule), var(--link-rule));
       background-repeat: no-repeat; background-position: 0 100%, 0 100%; background-size: 0 1px, 100% 1px;
       transition: background-size .45s var(--ease); }
.lkb::before { content: ''; position: absolute; inset: -12px -8px; }
.lkb:focus-visible { background-size: 100% 1px, 100% 1px; }
@media (hover: hover) and (pointer: fine) { .lkb:hover { background-size: 100% 1px, 100% 1px; } }
@media (pointer: coarse) {
  .btn, .btn.sm { min-height: 44px; }
  summary.sum { min-height: 44px; }
  .nav a { padding: 10px 0; }
}

/* ── Tables ── */
.tsheet { position: relative; background: var(--leaf); box-shadow: var(--lift-1); min-width: 0; }
.band { padding: 14px 18px; background: var(--band); border-bottom: 1px solid var(--ink-12); }
.tscroll { overflow-x: auto;
           background: linear-gradient(to right, var(--leaf) 30%, transparent) left / 40px 100% no-repeat local,
                       linear-gradient(to left, var(--leaf) 30%, transparent) right / 40px 100% no-repeat local,
                       linear-gradient(to right, var(--shade), transparent) left / 14px 100% no-repeat scroll,
                       linear-gradient(to left, var(--shade), transparent) right / 14px 100% no-repeat scroll; }
table { width: 100%; border-collapse: collapse; }
th { padding: 10px 12px 8px; text-align: left; vertical-align: bottom; border-bottom: 1px solid var(--ink-12); white-space: nowrap; }
td { padding: 11px 12px; vertical-align: baseline; border-top: 1px solid var(--ink-12); font-size: 16px; line-height: 1.45; }
tbody tr:first-child td { border-top: 0; }
th:first-child, td:first-child { padding-left: 18px; }
th:last-child, td:last-child { padding-right: 18px; }
td.m, td .m { font-size: 12.5px; }
td.r, th.r { text-align: right; }
td.dim, td .dim { color: var(--ink-64); }
td.mk { width: 1px; padding-right: 0; }
td.mk .dm { margin-right: 0; vertical-align: .1em; }
td.clip { max-width: 24ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td.nw { white-space: nowrap; }
td .note { display: block; font-style: italic; font-size: 14px; color: var(--ink-64); }
td form { display: inline; }
tbody tr:hover { background: var(--wash); }
tr.revoked td { color: var(--ink-64); }
.tfoot { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 8px 24px;
         padding: 12px 18px 14px; border-top: 1px solid var(--ink-12); background: var(--band); font-size: 15.5px; }
.tfoot .note { font-style: italic; color: var(--ink-64); }
.tfoot .pg { display: flex; gap: 24px; align-items: baseline; }
.empty { display: flex; align-items: baseline; padding: 40px 22px 44px; font-style: italic; font-size: 17px;
         line-height: 1.5; color: var(--ink-64); }
.empty > .dm { align-self: center; margin-right: 12px; }
.empty .m { font-size: 13px; color: var(--ink-70); }
@media (max-width: 759px) {
  .stack thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
  .stack, .stack tbody, .stack tr, .stack td { display: block; }
  .stack tr { padding: 14px 16px; border-top: 1px solid var(--ink-12); }
  .stack tbody tr:first-child { border-top: 0; }
  .stack td { border: 0; padding: 2px 0; }
  .stack td:first-child, .stack td:last-child { padding-left: 0; padding-right: 0; }
  .stack td.mk { display: none; }
  .stack td.r { text-align: left; }
  .stack td.clip { max-width: none; white-space: normal; }
  .stack td.head { padding-bottom: 6px; font-size: 17px; }
  .stack td.head.m { font-size: 13.5px; }
  .stack td[data-label]::before { content: attr(data-label); display: inline-block; min-width: 116px;
      margin-right: 10px; font-family: var(--mono); font-style: normal; font-size: 10px; letter-spacing: .1em;
      text-transform: uppercase; color: var(--ink-64); }
  .stack td:empty { display: none; }
}

/* The filter bar */
.filters .row1 { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px 16px; }
.filters .fq { flex: 0 1 280px; min-width: 200px; }
.filters .fs { flex: 0 1 190px; }
.filters details { margin-top: 10px; }
.filters summary { display: inline; cursor: pointer; list-style: none; font-style: italic; font-size: 15.5px;
                   color: var(--ink-70); padding-bottom: 1px;
                   background: linear-gradient(var(--link-rule), var(--link-rule)) 0 100% / 100% 1px no-repeat; }
.filters summary::-webkit-details-marker { display: none; }
.filters .more { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px 16px; margin-top: 12px; }
.filters .clear { margin-left: 16px; font-size: 15.5px; }
@media (max-width: 639px) {
  .filters .row1 { display: grid; }
  .filters .fq, .filters .fs { min-width: 0; }
  .filters .btn { width: 100%; }
  .filters .more { grid-template-columns: minmax(0, 1fr); }
}

/* Cards that stand alone in the middle of a page: sign in,
   confirmations, errors. */
.solo { width: 100%; margin: 24px auto 0; background: var(--leaf); box-shadow: var(--lift-2); padding: 32px; }
.solo.w420 { max-width: 420px; }
.solo.w560 { max-width: 560px; }
.solo.w640 { max-width: 640px; }
.solo .lbl { display: flex; align-items: center; margin-bottom: 10px; }
.solo .lbl.alarm { color: var(--alarm-ink); }
.solo h1.title + * { margin-top: 12px; }
.solo .lede + .lede { margin-top: 10px; }
.solo .ledger { list-style: none; margin-top: 18px; border-top: 1px solid var(--ink-12); }
.solo .ledger li { padding: 7px 0; border-bottom: 1px solid var(--ink-12); font-size: 15.5px; line-height: 1.45; overflow-wrap: anywhere; }
.solo .ledger .m { font-size: 12px; }
.solo .err-line { display: flex; align-items: baseline; margin: 0 0 14px; font-style: italic; font-size: 15.5px; color: var(--alarm-ink); }
.solo .fields { margin-top: 22px; }
.lockup { display: flex; align-items: center; gap: 13px; }
.lockup .mark { width: 29px; height: 29px; }
.lockup span { font-size: 27.5px; line-height: 1; transform: translateY(-2px); }
.lockup-sub { margin: 6px 0 26px 42px; font-style: italic; font-size: 15.5px; color: var(--ink-64); }
.center main { padding-top: max(28px, 7vh); }
.under { max-width: 420px; margin: 16px auto 0; text-align: center; font-style: italic; font-size: 15px; color: var(--ink-64); }
.center .notice { width: 100%; max-width: 420px; margin: 24px auto 0; }
.center .notice + .solo { margin-top: 12px; }
.issued { margin-bottom: 24px; padding: 20px 22px 22px; background: var(--leaf); box-shadow: var(--lift-2); border-left: 2px solid var(--ink); }
.issued .t { font-style: italic; font-size: 17px; }
.issued .t .m { font-size: 13px; }
.issued p { margin-top: 6px; font-size: 15.5px; color: var(--ink-70); }
.secret { display: block; margin-top: 12px; padding: 10px 12px; background: var(--band); font-family: var(--mono);
          font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; -webkit-user-select: all; user-select: all; }
.formcard { margin-top: 24px; }
.formcard .card-b { padding: 16px 18px 18px; }
.grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px 16px; }
.grid3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px 16px; }
.span2 { grid-column: span 2; }
@media (max-width: 639px) {
  .grid2, .grid3 { grid-template-columns: minmax(0, 1fr); }
  .span2 { grid-column: auto; }
  .solo { padding: 24px 20px; }
}

/* The evidence report. */
.verdict { padding: 24px; }
.verdict .exit { margin-left: 14px; font-family: var(--mono); font-size: 12px; color: var(--ink-64); }
.verdict .lede { margin-top: 10px; }
.verdict .facts { margin-top: 14px; }
.caveat { margin-top: 14px; font-style: italic; font-size: 15.5px; line-height: 1.55; color: var(--ink-64); max-width: 80ch; }
.anc { padding: 14px 18px; border-top: 1px solid var(--ink-12); }
.anc:first-child { border-top: 0; }
.anc > p { font-size: 15.5px; line-height: 1.5; }
.anc .ops { padding: 6px 0 0; }
.anc .op { padding: 5px 0; }

/* ── Footer ── */
.foot { flex: none; width: 100%; max-width: calc(1240px + 2 * var(--gut)); margin: 48px auto 0; padding: 0 var(--gut); }
.foot-in { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 32px; padding: 18px 0 28px;
           border-top: 1px solid var(--ink-12); font-style: italic; font-size: 15px; line-height: 1.5; color: var(--ink-64); }
.foot-in .m { font-size: 12px; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
@media (forced-colors: active) {
  .dm, .sum::before, .card-t::before, .op > i, .rhead::before, .nav a[aria-current]::before {
    forced-color-adjust: none; background: CanvasText; box-shadow: none !important; border: 1px solid CanvasText; }
  .dm.o, .mk-hollow .sum::before, .mk-alarm-hollow .sum::before, .mk-breathe .sum::before, .card-t.o::before, .op > i.o {
    background: Canvas; }
  .crash::after { background: none; border-left: 2px solid CanvasText; }
  .rule > span { background: none; border-top: 1px solid CanvasText; }
  .tag { border: 1px solid CanvasText; box-shadow: none; }
  .btn { border: 1px solid ButtonText; }
}
@media print {
  :root { --paper: #fff; --leaf: #fff; --band: #fff; --hover: #fff; }
  @page { margin: 16mm; }
  .sheet, .card, .tsheet, .solo, .notice, .issued { box-shadow: none; border: 1px solid var(--ink-12); }
  .mast .nav, .out, .skip, form, .btn, .erase, .filters { display: none !important; }
  .run-grid { display: block; }
  .side { display: grid; grid-template-columns: 1fr 1fr; margin-top: 16px; }
  .row, .op, .dl, .attempts li { break-inside: avoid; }
  .grp-label, .card-h { break-after: avoid; }
  .crash > .sum, .crash::after { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .cols { position: static; }
  a { background: none; }
  pre { max-height: none; overflow: visible; }
}
"###;

/// The page's stylesheet: font faces, then the rules.
pub fn stylesheet(fonts: Fonts<'_>) -> String {
    let mut css = font_faces(fonts);
    css.push_str(
        &STYLE
            .replace("ARROW", ARROW_MASK)
            .replace("CHEVRON", CHEVRON_MASK),
    );
    css
}

/// How a page is framed: its policy, where it gets its fonts, where the
/// wordmark and "Runs" link, what sits on the masthead's right, and the
/// start of its footer.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The Content-Security-Policy of the page's meta tag.
    pub csp: &'a str,
    pub fonts: Fonts<'a>,
    /// The runs list, which the wordmark and the breadcrumb's "Runs" link
    /// to; without one (an exported file) they are plain text.
    pub home: Option<&'a str>,
    /// Escaped HTML for the masthead's right side (navigation and a
    /// sign-out form, or the source directory).
    pub nav: &'a str,
    /// Escaped HTML at the start of the footer (who is signed in, the
    /// licensee, when a file was exported).
    pub footer: &'a str,
}

impl Frame<'static> {
    /// The frame of a single-file page: the strict policy, inline fonts,
    /// no links home.
    pub const FILE: Frame<'static> = Frame {
        csp: CONTENT_SECURITY_POLICY,
        fonts: Fonts::Inline,
        home: None,
        nav: "",
        footer: "",
    };
}

/// The parts of one page.
#[derive(Debug, Default)]
pub struct Page<'a> {
    /// The page's name, plain text: `refund-20417`, `Runs`, `Sign in`.
    pub title: &'a str,
    /// The masthead, from [`masthead`] (escaped HTML), or empty.
    pub masthead: String,
    /// The content of `<main>` (escaped HTML).
    pub main: String,
    /// The skip link's target and words.
    pub skip: Option<(&'a str, &'a str)>,
    /// A class for `<body>`: `center` for a page of one card.
    pub class: &'a str,
    /// Reload the page after this many seconds (only "the server is
    /// starting").
    pub refresh: Option<u32>,
}

/// A complete document in a frame.
pub fn document(frame: &Frame<'_>, page: &Page<'_>) -> String {
    let skip = page
        .skip
        .map(|(target, words)| {
            format!(
                "<a class=\"skip\" href=\"#{}\">{}</a>\n",
                esc(target),
                esc(words)
            )
        })
        .unwrap_or_default();
    let refresh = page
        .refresh
        .map(|s| format!("<meta http-equiv=\"refresh\" content=\"{s}\">\n"))
        .unwrap_or_default();
    let footer_left = if frame.footer.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", frame.footer)
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\n\
         <meta name=\"referrer\" content=\"same-origin\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n{refresh}\
         <title>{title} \u{b7} Pragmatic</title>\n\
         <link rel=\"icon\" type=\"image/svg+xml\" href=\"{FAVICON}\">\n\
         <style>{css}</style>\n</head>\n<body class=\"{class}\">\n{skip}{mast}\n\
         <main id=\"main\" tabindex=\"-1\">\n{main}\n</main>\n\
         <footer class=\"foot\"><div class=\"foot-in\">{footer_left}\
         <p>Append-only and hash-chained; replay reads the journal, never the model \u{b7} \
         <span class=\"m\">pragmatic {version}</span></p></div></footer>\n</body>\n</html>\n",
        // A policy is the caller's literal; it can hold no markup.
        csp = frame.csp.replace(['"', '<', '>', '&'], ""),
        title = esc(page.title),
        css = stylesheet(frame.fonts),
        class = esc(page.class),
        mast = page.masthead,
        main = page.main,
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// One step of the breadcrumb after the wordmark.
#[derive(Clone, Copy, Debug)]
pub struct Crumb<'a> {
    /// Plain text.
    pub text: &'a str,
    pub href: Option<&'a str>,
    /// Data (a run id) rather than a word: set in mono.
    pub mono: bool,
}

impl<'a> Crumb<'a> {
    /// A word of the console's, linked when `href` is given.
    pub fn word(text: &'a str, href: Option<&'a str>) -> Self {
        Crumb {
            text,
            href,
            mono: false,
        }
    }

    /// A recorded id, such as a run id.
    pub fn id(text: &'a str, href: Option<&'a str>) -> Self {
        Crumb {
            text,
            href,
            mono: true,
        }
    }
}

/// The masthead: the mark and wordmark (linked to `home` when given), the
/// breadcrumb, and `right` (escaped HTML) at the far end. The last crumb is
/// the current page; the ones before it drop away on a narrow screen.
pub fn masthead(home: Option<&str>, crumbs: &[Crumb<'_>], right: &str) -> String {
    let brand = match home {
        Some(h) => format!(
            "<a class=\"brand\" href=\"{}\">{MARK}<span>Pragmatic</span></a>",
            esc(h)
        ),
        None => format!("<span class=\"brand\">{MARK}<span>Pragmatic</span></span>"),
    };
    let mut trail = String::new();
    for (i, c) in crumbs.iter().enumerate() {
        let last = i + 1 == crumbs.len();
        if i > 0 {
            trail.push_str("<span class=\"sep\" aria-hidden=\"true\">/</span>");
        }
        let class = match (last, c.mono) {
            (true, true) => "cur m",
            (true, false) => "cur",
            (false, true) => "up m",
            (false, false) => "up",
        };
        let current = if last { " aria-current=\"page\"" } else { "" };
        trail.push_str(&match c.href {
            Some(h) if !last => format!(
                "<a class=\"{class}\" href=\"{}\">{}</a>",
                esc(h),
                esc(c.text)
            ),
            _ => format!("<span class=\"{class}\"{current}>{}</span>", esc(c.text)),
        });
    }
    format!(
        "<header class=\"mast\"><div class=\"mast-in\">{brand}\
         <nav class=\"crumbs\" aria-label=\"Breadcrumb\">{trail}</nav>\
         <div class=\"mast-r\">{right}</div></div></header>"
    )
}

/// The masthead's right side for a page read from a directory: the
/// directory in mono, and for `pragmatic serve` that it follows live runs.
pub fn source_note(source: &str, live: bool) -> String {
    let note = if live {
        "<span class=\"src-note\">refresh to follow live runs</span>"
    } else {
        ""
    };
    format!("<span class=\"src\">{}</span>{note}", esc(source))
}

/// A diamond: `filled`, or hollow; in alarm colour when `alarm`.
pub fn diamond(filled: bool, alarm: bool) -> &'static str {
    match (filled, alarm) {
        (true, false) => "<i class=\"dm\" aria-hidden=\"true\"></i>",
        (false, false) => "<i class=\"dm o\" aria-hidden=\"true\"></i>",
        (true, true) => "<i class=\"dm alarm\" aria-hidden=\"true\"></i>",
        (false, true) => "<i class=\"dm o alarm\" aria-hidden=\"true\"></i>",
    }
}

/// A tag: a fixed attribute such as `Preview`. `text` is a literal.
pub fn tag(text: &str) -> String {
    format!("<span class=\"tag\">{}</span>", esc(text))
}

/// A notice: a sentence about the page (escaped HTML), with a terracotta
/// rule when it reports a refusal or an alarm.
pub fn notice(html: &str, alarm: bool) -> String {
    let (class, role) = if alarm {
        ("notice bad", "alert")
    } else {
        ("notice", "status")
    };
    format!("<p class=\"{class}\" role=\"{role}\">{html}</p>")
}

/// Mono data, escaped.
pub fn mono(text: &str) -> String {
    format!("<span class=\"m\">{}</span>", esc(text))
}

/// A data list from `(label, value)` pairs; values are escaped HTML. An
/// empty label draws a hairline.
pub fn data_list(class: &str, rows: &[(&str, String)]) -> String {
    let mut out = format!("<dl class=\"dl {class}\">");
    for (k, v) in rows {
        if k.is_empty() {
            out.push_str("<div class=\"hr\"></div>");
            continue;
        }
        out.push_str(&format!("<dt>{}</dt><dd>{v}</dd>", esc(k)));
    }
    out.push_str("</dl>");
    out
}

/// An empty state: a hollow diamond and a sentence (escaped HTML).
pub fn empty(html: &str) -> String {
    format!(
        "<p class=\"empty\">{}<span>{html}</span></p>",
        diamond(false, false)
    )
}

/// A card that stands alone in the middle of a page (an error): a hollow
/// diamond and a label in small capitals, a title and a body. `label` is a
/// literal; `title` and `body` are escaped HTML.
pub fn solo_card(label: &str, title: &str, body: &str) -> String {
    format!(
        "<section class=\"solo w560\" aria-labelledby=\"solo-t\"><p class=\"lbl caps\">{}{}</p>\
         <h1 class=\"title\" id=\"solo-t\">{title}</h1>{body}</section>",
        diamond(false, false),
        esc(label)
    )
}

/// Indented JSON for display, or `None` if `text` is not JSON.
pub fn pretty_json(text: &str) -> Option<String> {
    let doc = Json::parse(text).ok()?;
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    write_pretty(&mut out, &doc, 0, false);
    Some(out)
}

/// Indented JSON as escaped HTML with its keys, strings and other values
/// marked for the stylesheet, or `None` if `text` is not JSON.
pub fn pretty_json_html(text: &str) -> Option<String> {
    let doc = Json::parse(text).ok()?;
    let mut out = String::with_capacity(text.len() * 2);
    write_pretty(&mut out, &doc, 0, true);
    Some(out)
}

fn write_pretty(out: &mut String, v: &Json, depth: usize, html: bool) {
    let pad = |out: &mut String, d: usize| {
        out.push('\n');
        out.extend(std::iter::repeat_n("  ", d));
    };
    let scalar = |out: &mut String, text: &str, class: &str| {
        if html {
            out.push_str(&format!("<span class=\"{class}\">{}</span>", esc(text)));
        } else {
            out.push_str(text);
        }
    };
    match v {
        Json::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                pad(out, depth + 1);
                write_pretty(out, item, depth + 1, html);
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
                scalar(out, &Json::String(k.clone()).to_string(), "jk");
                out.push_str(": ");
                write_pretty(out, item, depth + 1, html);
            }
            pad(out, depth);
            out.push('}');
        }
        Json::String(_) => scalar(out, &v.to_string(), "js"),
        Json::Array(_) | Json::Object(_) => out.push_str(&v.to_string()),
        other => scalar(out, &other.to_string(), "jv"),
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

    fn sample(frame: &Frame<'_>) -> String {
        document(
            frame,
            &Page {
                title: "t",
                main: "<p>x</p>".into(),
                ..Page::default()
            },
        )
    }

    #[test]
    fn pages_load_nothing_but_their_own_fonts() {
        let p = sample(&Frame::FILE);
        assert!(p.contains("Content-Security-Policy"));
        assert!(p.contains("default-src 'none'; img-src data:; font-src data:;"));
        assert!(p.contains("form-action 'none'"));
        assert!(!p.contains("<script"));
        assert!(!p.contains("rel=\"stylesheet\""));
        // The only addresses are the SVG namespace inside data URIs and the
        // licence and authors in a CSS comment; nothing is fetched.
        for (i, _) in p.match_indices("://") {
            let before = &p[i.saturating_sub(48)..i];
            assert!(
                before.contains("xmlns=")
                    || before.contains("Font License")
                    || before.contains("Authors ("),
                "{}",
                &p[i.saturating_sub(48)..(i + 40).min(p.len())]
            );
        }
        assert!(p.contains("url(data:font/woff2;base64,"));
    }

    #[test]
    fn framed_pages_allow_their_own_forms_and_fonts_and_still_run_nothing() {
        let frame = Frame {
            csp: CONSOLE_POLICY,
            fonts: Fonts::Served("/console/assets/"),
            home: Some("/console"),
            nav: "<nav class=\"nav\"><a href=\"/console\">Runs</a></nav>",
            footer: "Licensed to Example Corp",
        };
        let p = sample(&frame);
        assert!(p.contains("form-action 'self'"));
        assert!(p.contains("font-src 'self'"));
        assert!(p.contains("Licensed to Example Corp"));
        assert!(p.contains("url(/console/assets/eb-garamond-latin."));
        assert!(!p.contains("base64,d09GMg"), "served fonts are not inlined");
        assert!(!p.contains("<script"));
        for policy in [CONTENT_SECURITY_POLICY, SERVE_POLICY, CONSOLE_POLICY] {
            assert!(policy.starts_with("default-src 'none'"));
            assert!(!policy.contains("script-src"));
            assert!(!policy.contains("http"));
            assert!(!policy.contains("unsafe-eval"));
        }
    }

    #[test]
    fn the_masthead_escapes_and_marks_the_current_page() {
        let m = masthead(
            Some("\"><x>"),
            &[Crumb::word("Runs", Some("/r")), Crumb::id("<id>", None)],
            "",
        );
        assert!(m.contains("href=\"&quot;&gt;&lt;x&gt;\""));
        assert!(m.contains("<span class=\"cur m\" aria-current=\"page\">&lt;id&gt;</span>"));
        assert!(m.contains("<a class=\"up\" href=\"/r\">Runs</a>"));
    }

    #[test]
    fn pretty_prints_json() {
        assert_eq!(
            pretty_json(r#"{"a":[1,{"b":null}],"c":{}}"#).unwrap(),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {}\n}"
        );
        assert!(pretty_json("nope").is_none());
        assert_eq!(
            pretty_json_html(r#"{"<k>":"</pre><script>"}"#).unwrap(),
            "{\n  <span class=\"jk\">&quot;&lt;k&gt;&quot;</span>: \
             <span class=\"js\">&quot;&lt;/pre&gt;&lt;script&gt;&quot;</span>\n}"
        );
    }
}
