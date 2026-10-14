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
        push_escaped(&mut out, c);
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
  --field: rgba(26,23,18,.55);
  --lift-1: 0 0 0 1px var(--ink-12), 0 1px 2px rgba(64,46,22,.04),
            0 12px 26px -12px rgba(64,46,22,.12), 0 30px 60px -30px rgba(64,46,22,.16);
  --lift-2: 0 0 0 1px var(--ink-12), 0 1px 2px rgba(64,46,22,.05),
            0 14px 30px -12px rgba(64,46,22,.15), 0 34px 68px -30px rgba(64,46,22,.2);
  --serif: 'EB Garamond', 'Garamond Fallback', Garamond, Georgia, serif;
  --mono: 'IBM Plex Mono', 'Mono Fallback', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  --ease: cubic-bezier(.2,.6,.2,1);
  --gut: clamp(16px, 4vw, 40px);
  --link-rule: var(--ink-30);
  --step: 18px;
  --side: 372px;
  /* Paper, always, as on the website: the console has no dark scheme. */
  color-scheme: light;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
html { -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body { min-height: 100vh; display: flex; flex-direction: column; background: var(--paper);
       color: var(--ink); font-family: var(--serif); font-weight: 400; font-size: 17px;
       line-height: 1.6; overflow-wrap: break-word; }
::selection { background: var(--ink); color: var(--paper); }
b, strong, th, h1, h2, h3, dt, summary { font-weight: 400; }
:focus-visible { outline: 1px solid currentColor; outline-offset: 3px; }
.btn:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
main:focus { outline: none; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.skip { position: absolute; top: 12px; left: var(--gut); z-index: 30; padding: 6px 14px 8px;
        background: var(--ink); color: var(--paper); font-style: italic; font-size: 17px; line-height: 1.3; }
.skip:not(:focus) { width: 1px; height: 1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.mark { display: block; flex: none; }
.mark .ms { fill: var(--ink); }
.mark .md { fill: var(--paper); }
/* Data: IBM Plex Mono, upright, isolated from the text around it so
   right-to-left letters in recorded data cannot reorder a line. */
.m { font-family: var(--mono); font-style: normal; letter-spacing: 0; font-variant-numeric: tabular-nums;
     unicode-bidi: isolate; }
.q, .s { font-style: italic; font-family: var(--serif); }
td.m .s, .dl dd .s { font-size: 14.5px; }
h1.title .m { font-size: .74em; letter-spacing: -.01em; color: var(--ink-70); }
.nw { white-space: nowrap; }
.lede .m, .notice .m, .empty .m, .caveat .m, .under .m, .state .m { font-size: .8em; }
.ink { color: var(--ink); }
.dim { color: var(--ink-64); }
.alarm, .alarm .m { color: var(--alarm-ink); }
.nc { text-transform: none; letter-spacing: 0; }
/* Numbers in a line of words: Garamond's own lining figures, in ink. */
.n { color: var(--ink); font-variant-numeric: lining-nums tabular-nums; }

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
/* The read-back ring, repeated in the words that explain it. */
.dm.rb { width: 5px; height: 5px; margin: 0 9px 0 4px; background: var(--ink); vertical-align: .14em;
         box-shadow: 0 0 0 2.5px var(--bg, var(--leaf)), 0 0 0 3.5px var(--ink-30); }
@keyframes breathe { 0%, 100% { opacity: 1; transform: rotate(45deg) scale(1); }
                     50% { opacity: .3; transform: rotate(45deg) scale(.7); } }

/* Tags: a fixed attribute, boxed small mono capitals. */
.tag { display: inline-block; flex: none; padding: 4px 6px 3px 7px; font-family: var(--mono);
       font-style: normal; font-size: 11px; line-height: 1; letter-spacing: .1em; text-transform: uppercase;
       color: var(--ink-64); box-shadow: inset 0 0 0 1px var(--ink-30); white-space: nowrap; vertical-align: .15em; }
.caps { font-family: var(--mono); font-style: normal; font-size: 11px; line-height: 1.6; letter-spacing: .1em;
        text-transform: uppercase; color: var(--ink-64); }

/* ── Masthead: the website's, on the paper with no rule ── */
.mast-in { max-width: calc(1240px + 2 * var(--gut)); margin: 0 auto; padding: 0 var(--gut); min-height: 76px;
           display: flex; flex-wrap: wrap; align-items: center; column-gap: 28px; }
.brand { display: flex; align-items: center; gap: 12px; font-style: normal; font-size: 21px; line-height: 1;
         white-space: nowrap; background: none; padding: 0; }
.brand .mark { width: 21px; height: 21px; }
.brand span { transform: translateY(-1px); }
.crumbs { display: flex; align-items: baseline; gap: 12px; min-width: 0; margin-left: -16px; font-size: 16.5px;
          line-height: 1.3; color: var(--ink-64); white-space: nowrap; }
.crumbs .c { display: flex; align-items: baseline; gap: 12px; min-width: 0; }
.crumbs a { font-style: normal; background-size: 0 1px, 0 1px; }
@media (hover: hover) and (pointer: fine) { .crumbs a:hover { background-size: 100% 1px, 0 1px; color: var(--ink); } }
.crumbs .sep { color: var(--ink-30); }
.crumbs .cur > :last-child { min-width: 0; overflow: hidden; text-overflow: ellipsis; color: var(--ink-70); }
.crumbs .m { font-size: 13.5px; }
.mast-r { margin-left: auto; display: flex; align-items: baseline; gap: 30px; min-width: 0; }
.nav { display: flex; gap: 28px; align-items: baseline; }
.nav a { position: relative; font-style: normal; font-size: 16.5px; line-height: 1.3; color: var(--ink-70);
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
.mast-note { font-style: italic; font-size: 15px; color: var(--ink-64); white-space: nowrap; }
/* Where the navigation does not fit beside the breadcrumb, it takes a
   strip of its own under it that scrolls sideways. */
@media (max-width: 959px) {
  .mast-in { min-height: 0; padding-top: 16px; padding-bottom: 4px; row-gap: 4px; column-gap: 0; }
  .brand { margin-right: 26px; }
  .crumbs { flex: 1; overflow: hidden; }
  .mast-r { display: contents; }
  .mast-r .nav { order: 5; flex: 0 0 auto; width: calc(100% + 2 * var(--gut)); overflow-x: auto; scrollbar-width: none;
                 margin: 4px calc(-1 * var(--gut)) 0; padding: 8px var(--gut) 8px calc(var(--gut) + 14px);
                 background: linear-gradient(to left, var(--paper) 30%, transparent) right / 40px 100% no-repeat local,
                             linear-gradient(to left, var(--shade), transparent) right / 14px 100% no-repeat scroll; }
  .mast-r .nav::-webkit-scrollbar { display: none; }
  .mast-r .out { order: 4; margin-left: auto; }
}
@media (max-width: 759px) {
  .crumbs .up { display: none; }
  .mast-note { display: none; }
}

/* ── Page ── */
main { flex: 1 0 auto; width: 100%; max-width: calc(1240px + 2 * var(--gut)); margin: 0 auto;
       padding: 12px var(--gut) 0; container: main / inline-size; }
.page-h { margin: 12px 0 22px; display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 20px; }
h1.title { font-size: 32px; line-height: 1.12; letter-spacing: -.012em; text-wrap: balance; }
.lede { font-size: 17px; line-height: 1.6; color: var(--ink-70); max-width: 66ch; text-wrap: pretty; }
.page-h .facts, .page-h .lede { margin: 0; font-size: 16px; color: var(--ink-64); }
.page-h .lede { font-style: italic; }
.page-h + .lede { margin: -10px 0 22px; }
.sect + .sect { margin-top: 36px; }
.rhead { display: flex; align-items: center; gap: 13px; padding-top: 16px; margin-bottom: 8px;
         border-top: 1px solid var(--ink-12); font-style: italic; font-size: 18px; color: var(--ink-64); }
.rhead::before { content: ''; width: 7px; height: 7px; background: var(--ink); transform: rotate(45deg); flex: none; }
.rhead + .lede { margin-bottom: 16px; }

/* Notices: a sentence about the page, on a strip with a rule. */
.notice { margin: 0 0 16px; padding: 10px 16px 11px; background: var(--leaf); border-left: 2px solid var(--ink);
          font-style: italic; font-size: 15.5px; line-height: 1.5; color: var(--ink-70); box-shadow: 0 0 0 1px var(--ink-12); }
.notice.bad { border-left-color: var(--alarm); color: var(--alarm-ink); }
.sheet .notice { margin: 12px 0 0; box-shadow: none; background: var(--band); }

/* ── The run page: one sheet, and the side column beside it ── */
.run-grid { display: grid; gap: 24px; align-items: start; }
.side { display: grid; gap: 16px; align-content: start; align-items: start; min-width: 0; }
.side > .stick { display: grid; gap: 16px; min-width: 0; }
@container main (min-width: 940px) {
  .run-grid { grid-template-columns: minmax(0, 1fr) clamp(320px, 30cqi, var(--side)); }
  /* The side column runs the sheet's length; its last part (the attempts
     and failures to jump to) stays in view while a long timeline scrolls. */
  .side { align-self: stretch; grid-template-rows: auto; }
}
@media (min-height: 640px) {
  @container main (min-width: 940px) {
    .side > .stick { position: sticky; top: 16px; max-height: calc(100vh - 32px); overflow-y: auto;
                     scrollbar-width: thin; margin: -10px -10px 0; padding: 10px 10px 40px; }
    .side > .stick:has(details[open]) { position: static; max-height: none; overflow: visible; }
  }
}
/* Under the sheet, between 640px and 940px: the cards in two columns that
   fill from the top, so no card is stretched or left alone. */
@container main (min-width: 640px) and (max-width: 939px) {
  .side { display: block; column-count: 2; column-gap: 16px; }
  .side > .stick { display: block; }
  .side .card, .side .erase { break-inside: avoid; margin-bottom: 16px; }
}
@container main (max-width: 639px) {
  .side .erase { margin-top: 0; }
}

.sheet { position: relative; min-width: 0; background: var(--leaf); box-shadow: var(--lift-1); container: sheet / inline-size; }
.sh-head { padding: 22px 24px 18px; }
.sh-title { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; }
h1.rid { font-family: var(--mono); font-weight: 500; font-size: 19px; line-height: 1.3; letter-spacing: -.01em;
         overflow-wrap: anywhere; }
.badge { font-style: italic; font-size: 17px; line-height: 1.3; white-space: nowrap; }
.badge.lg { font-size: 26px; }
.badge.lg .dm { width: 9px; height: 9px; margin-right: 12px; vertical-align: .18em; }
.facts { margin-top: 6px; font-size: 16px; line-height: 1.5; color: var(--ink-64); }
.facts .alarm, .facts .alarm .n { color: var(--alarm-ink); }
.facts .tag { margin-left: 8px; }
.facts a { font-style: normal; }
.state { margin-top: 2px; font-style: italic; font-size: 15.5px; line-height: 1.5; color: var(--ink-64); }
.state .m { color: var(--ink-70); }
.state .dm { margin-right: 8px; }

.cols { position: sticky; top: 0; z-index: 3; display: flex; justify-content: space-between; gap: 16px;
        padding: 8px 24px 7px 48px; background: var(--leaf); border-top: 1px solid var(--ink-12);
        border-bottom: 1px solid var(--ink-12); }
.cols .c-hash { display: none; }
.pager { padding: 10px 24px 11px 48px; border-bottom: 1px solid var(--ink-12); font-style: italic; font-size: 15px;
         line-height: 1.5; color: var(--ink-64); }
.pager.end { border-bottom: 0; border-top: 1px solid var(--ink-12); padding-bottom: 14px; }
.pager .m { font-size: 12.5px; }
.pager a.go { color: var(--ink); }

.tl { position: relative; padding: 6px 0 12px; }
.tl::before { content: ''; position: absolute; left: 25px; top: 0; bottom: 0; width: 1px; background: var(--ink-12); }
.grp-label { position: relative; padding: 16px 24px 4px 48px; }
.grp-label.day { padding-top: 10px; color: var(--ink-50); }
.rows { list-style: none; }
.row { position: relative; --d: 0; --bg: var(--leaf);
       --rails: repeating-linear-gradient(to right, var(--ink-12) 0 1px, transparent 1px var(--step)) 25px 0 / calc((var(--d) + 1) * var(--step)) 100% no-repeat;
       background: var(--rails); }
.row.d1 { --d: 1; } .row.d2 { --d: 2; } .row.d3 { --d: 3; } .row.d4 { --d: 4; } .row.d5 { --d: 5; } .row.d6 { --d: 6; }
.sum { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: "t tm" "k h";
       column-gap: 16px; align-items: baseline; padding: 9px 24px 10px calc(48px + var(--d) * var(--step));
       list-style: none; background: var(--rails), var(--bg); }
summary.sum { cursor: pointer; }
summary.sum::-webkit-details-marker { display: none; }
summary.sum::marker { content: ''; }
summary.sum:focus-visible { outline-offset: -1px; }
.sum::before { content: ''; position: absolute; left: calc(22px + var(--d) * var(--step)); top: 17px; width: 7px; height: 7px;
               background: var(--ink); transform: rotate(45deg); box-shadow: 0 0 0 3px var(--bg); }
.sum > span[id] { position: absolute; top: 0; left: 0; scroll-margin-top: 44px; }
/* A title holds at most two lines; the expanded row holds the rest. */
.sum .t { grid-area: t; min-width: 0; font-size: 17px; line-height: 24px; text-wrap: pretty; overflow-wrap: anywhere;
          display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; line-clamp: 2; overflow: hidden; }
.sum .t .m { font-size: 13.5px; color: var(--ink-70); }
.sum .t .s, .sum .t .q { font-style: italic; color: var(--ink-70); }
.sum .t .alarm, .sum .t .alarm .m, .sum .t .alarm .s { color: var(--alarm-ink); }
.sum .t .rm { font-style: normal; }
.sum .t a.m { font-style: normal; }
.ar { display: inline-block; width: 15px; height: 9px; margin: 0 5px 0 3px; background: var(--ink-64);
      -webkit-mask: ARROW center / contain no-repeat; mask: ARROW center / contain no-repeat; }
.sum .tt { background-image: linear-gradient(currentColor, currentColor); background-repeat: no-repeat;
           background-position: 0 100%; background-size: 0 1px; transition: background-size .45s var(--ease);
           -webkit-box-decoration-break: clone; box-decoration-break: clone; }
.sum .k, .sum .tm, .sum .h { font-family: var(--mono); font-size: 12.5px; color: var(--ink-64); font-variant-numeric: tabular-nums; }
.sum .k { grid-area: k; min-width: 0; line-height: 19px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sum .tm { grid-area: tm; justify-self: end; line-height: 24px; white-space: nowrap; }
.sum .h { grid-area: h; justify-self: end; line-height: 19px; white-space: nowrap; }
@media (hover: hover) and (pointer: fine) {
  summary.sum:hover { --bg: var(--hover); }
  summary.sum:hover .tt { background-size: 100% 1px; }
}
summary.sum:focus-visible .tt { background-size: 100% 1px; }
details[open] > summary.sum { --bg: var(--band); }
details[open] > summary.sum .t { display: block; overflow: visible; }
.row:has(.sum > span:target) .sum { --bg: var(--hover); }
.row:has(.sum > span:target) .sum::before { box-shadow: 0 0 0 3px var(--bg), 0 0 0 4px var(--ink-30); }

/* Markers (see the design: what each diamond means). */
.mk-ring .sum::before { box-shadow: 0 0 0 3px var(--bg), 0 0 0 4px var(--ink-30); }
.mk-hollow .sum::before, .mk-breathe .sum::before { background: var(--bg); box-shadow: inset 0 0 0 1.5px var(--ink), 0 0 0 3px var(--bg); }
.mk-big .sum::before, .mk-alarm-big .sum::before { left: calc(21px + var(--d) * var(--step)); top: 16px; width: 9px; height: 9px; }
.mk-alarm .sum::before, .mk-alarm-big .sum::before { background: var(--alarm); }
.mk-alarm-hollow .sum::before { background: var(--bg); box-shadow: inset 0 0 0 1.5px var(--alarm), 0 0 0 3px var(--bg); }
.mk-breathe .sum::before { animation: breathe 1.8s ease-in-out infinite; }
.mk-aside .sum::before { left: calc(23px + var(--d) * var(--step)); top: 18px; width: 5px; height: 5px; background: var(--ink-50); }
/* An attempt that stopped without an end: the website's crash row. A
   recorded failure carries the same rule and wash. */
.crash > .sum, .fail .sum { background: linear-gradient(to right, var(--alarm-wash), transparent 85%), var(--rails), var(--bg); }
.crash::after, .fail::after { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--alarm); }
.crash .t { color: var(--alarm-ink); }
.crash .t > .s, .crash .t > .s .m { color: var(--ink-70); }
/* Record keeping written after the run: its own group, on a dotted rail. */
.grp.after { position: relative; margin-top: 6px; }
.grp.after::before { content: ''; position: absolute; left: 25px; top: 0; bottom: -12px; width: 1px;
                     background: repeating-linear-gradient(to bottom, var(--ink-30) 0 2px, var(--leaf) 2px 6px); }
.derived .t { grid-column: 1 / -1; }

.detail { margin: 0 24px 10px calc(48px + var(--d) * var(--step)); padding: 14px 18px 18px; background: var(--band);
          border-top: 1px solid var(--ink-12); }
.ent + .ent { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--ink-12); }
.ent-h { font-family: var(--mono); font-size: 12.5px; line-height: 1.6; overflow-wrap: anywhere; }
.ent-h .dim { margin-left: 10px; }
.ent-w { margin-top: 3px; font-style: italic; font-size: 15px; line-height: 1.5; color: var(--ink-64); }
.ent-w .m { font-size: 12.5px; }
.dl { display: grid; grid-template-columns: minmax(0, 156px) minmax(0, 1fr); column-gap: 12px; margin-top: 10px;
      font-family: var(--mono); font-size: 12.5px; line-height: 21px; }
.dl dt { color: var(--ink-64); }
.dl dd { min-width: 0; overflow-wrap: anywhere; }
.dl dd .q, .dl dd.q { font-family: var(--serif); font-style: italic; font-size: 14.5px; color: var(--ink-64); }
.dl .hr { grid-column: 1 / -1; height: 1px; background: var(--ink-12); margin: 6px 0 7px; }
.dl .res { display: flex; align-items: center; }
.slot-l { margin: 16px 0 6px; overflow-wrap: anywhere; }
pre { margin: 0; padding: 12px 16px; max-height: 28em; overflow: auto; background: var(--leaf);
      border-left: 1px solid var(--ink-12); font-family: var(--mono); font-size: 12.5px; line-height: 1.65;
      color: var(--ink); white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 2; }
pre.json { color: var(--ink-64); }
pre .jk, pre .jv { color: var(--ink); }
pre .js { color: var(--ink-70); }
.gone { padding: 10px 14px 11px; border: 1px dashed var(--ink-30); font-style: italic; font-size: 15px;
        line-height: 1.5; color: var(--ink-64); }
.slot-n { margin-top: 6px; font-style: italic; font-size: 14.5px; line-height: 1.5; color: var(--ink-64); }
.slot-n .m { font-size: 12.5px; }
.commit { margin-top: 6px; font-family: var(--mono); font-size: 12.5px; color: var(--ink-64); overflow-wrap: anywhere; }

.chain { display: flex; flex-wrap: wrap; align-items: baseline; column-gap: 7px; padding: 14px 24px 16px;
         border-top: 1px solid var(--ink-12); background: var(--band); font-size: 16px; line-height: 1.4; }
.chain .dm { align-self: center; width: 7px; height: 7px; margin: 0 6px 0 3px; }
.chain .s { color: var(--ink-70); }
.chain .m { font-size: 12.5px; color: var(--ink-64); }
.chain .hx { -webkit-user-select: all; user-select: all; }
/* The full head takes a line of its own where the sheet cannot hold it
   beside the rest. */
@container sheet (max-width: 780px) {
  .chain .hd { flex-basis: 100%; }
  .chain .hd .d { display: none; }
}
.chain.alarm .s { color: var(--alarm-ink); }

@container sheet (max-width: 600px) {
  .sum .tm, .cols .c-time { display: none; }
  .cols .c-hash { display: inline; }
}
@container sheet (max-width: 480px) {
  .sum { grid-template-areas: "t t" "k h"; column-gap: 10px; }
  .sum .t { -webkit-line-clamp: 3; line-clamp: 3; }
  .sum .k, .sum .h { font-size: 12px; }
  .row { --step: 12px; }
}
@container sheet (max-width: 340px) {
  .sh-head { padding: 18px 16px 14px; }
  .cols, .grp-label, .pager { padding-left: 42px; padding-right: 16px; }
  .tl::before, .grp.after::before { left: 21px; }
  .row { --rails: repeating-linear-gradient(to right, var(--ink-12) 0 1px, transparent 1px var(--step)) 21px 0 / calc((var(--d) + 1) * var(--step)) 100% no-repeat; }
  .sum { grid-template-columns: minmax(0, 1fr); grid-template-areas: "t" "k" "h"; padding: 8px 16px 9px calc(42px + var(--d) * var(--step)); }
  .sum::before { left: calc(18px + var(--d) * var(--step)); }
  .mk-big .sum::before, .mk-alarm-big .sum::before { left: calc(17px + var(--d) * var(--step)); }
  .mk-aside .sum::before { left: calc(19px + var(--d) * var(--step)); }
  .sum .h { justify-self: start; }
  .detail { margin: 0 12px 8px 30px; padding: 12px 12px 14px; }
  .dl { grid-template-columns: minmax(0, 1fr); }
  .chain { padding: 13px 16px 14px; }
}

/* ── Leaves: the side cards ── */
.card { position: relative; min-width: 0; background: var(--leaf); box-shadow: var(--lift-1); container: card / inline-size; }
@container card (max-width: 360px) {
  .card .dl { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); column-gap: 8px; }
  .card .dl.n { grid-template-columns: minmax(0, 92px) minmax(0, 1fr); }
}
.card-h { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; padding: 15px 18px 12px;
          border-bottom: 1px solid var(--ink-12); }
.card-t { display: flex; align-items: baseline; gap: 10px; min-width: 0; font-style: italic; font-size: 17.5px; line-height: 1.3; }
.card-t::before { content: ''; flex: none; width: 6px; height: 6px; background: var(--ink); transform: rotate(45deg);
                  align-self: center; }
.card-t.o::before { background: transparent; box-shadow: inset 0 0 0 1.2px currentColor; }
.card-t.alarm::before { background: transparent; box-shadow: inset 0 0 0 1.2px var(--alarm); }
.card-h .note { font-family: var(--mono); font-size: 12.5px; color: var(--ink-64); white-space: nowrap; }
.card-b { padding: 13px 18px 16px; }
.card-f { padding: 13px 18px 16px; border-top: 1px solid var(--ink-12); background: var(--band); }
.card-b > p, .card-f > p { font-size: 15.5px; line-height: 1.5; color: var(--ink-70); }
.card-b > * + p, .card-f > * + p { margin-top: 8px; }
.card-b .note, .card-f .note { font-style: italic; font-size: 14.5px; color: var(--ink-64); }
.card-b p .m, .card-f p .m { font-size: 12.5px; }
.card .dl { margin-top: 0; grid-template-columns: minmax(0, 160px) minmax(0, 1fr); column-gap: 10px; font-size: 12.5px; line-height: 21px; }
.card .dl.n { grid-template-columns: minmax(0, 92px) minmax(0, 1fr); }
.card .dl dd.full { grid-column: 1 / -1; margin: 0 0 3px; color: var(--ink-70); overflow-wrap: anywhere;
                    -webkit-user-select: all; user-select: all; }
.card .dl dd .s { font-family: var(--serif); font-style: italic; font-size: 14.5px; color: var(--ink-64); }
/* A command: one line, or broken before its options with an indent. */
.cmd { display: block; margin-top: 4px; font-family: var(--mono); font-size: 12.5px; line-height: 1.6; color: var(--ink);
       white-space: pre-wrap; overflow-wrap: anywhere; }
.card-f .lbl { display: flex; align-items: center; justify-content: space-between; gap: 10px; font-style: italic;
               font-size: 15.5px; color: var(--ink); }
.card-f .cmd + .lbl { margin-top: 12px; }
.card-f .note { margin-top: 10px; }
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
.op .st { font-family: var(--mono); font-size: 12.5px; color: var(--ink-64); white-space: nowrap; }
.op .root { grid-column: 2 / -1; font-style: italic; font-size: 14px; line-height: 1.4; color: var(--ink-64); }
.anchor .card-b { padding-top: 10px; }
.card .caps:first-child { margin-top: 0; }

/* The Run card's lists: each attempt, the failures and the record keeping
   after the run, to jump to. */
.card .caps, .card-b > p.caps { display: block; margin: 18px 0 2px; font-size: 11px; line-height: 1.6; color: var(--ink-64); }
.jl { list-style: none; }
.jl li { border-top: 1px solid var(--ink-12); }
.jl li:first-child { border-top: 0; }
.jl a, .jl .ja { display: grid; grid-template-columns: auto minmax(0, 1fr); column-gap: 12px; align-items: baseline;
                 padding: 6px 0 7px; font-style: normal; background: none; }
.jl .w { justify-self: start; font-size: 15.5px; line-height: 1.45; }
.jl .w .m { font-size: 12.5px; }
.jl a .w { background-image: linear-gradient(currentColor, currentColor), linear-gradient(var(--link-rule), var(--link-rule));
           background-repeat: no-repeat; background-position: 0 100%, 0 100%; background-size: 0 1px, 100% 1px;
           transition: background-size .45s var(--ease); }
@media (hover: hover) and (pointer: fine) { .jl a:hover .w { background-size: 100% 1px, 100% 1px; } }
.jl a:focus-visible .w { background-size: 100% 1px, 100% 1px; }
.jl .out { justify-self: end; font-style: italic; font-size: 15px; line-height: 1.45; color: var(--ink-70); text-align: right; }
.jl .out .m { font-size: 12.5px; color: var(--ink-64); }
.jl .who { grid-column: 1 / -1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
           font-family: var(--mono); font-size: 12.5px; line-height: 1.6; color: var(--ink-64); }
.jl .more { padding: 6px 0 2px; font-style: italic; font-size: 14.5px; color: var(--ink-64); }

/* Erasure, for administrators: a quiet disclosure at the end of the side
   column, and the form in a card when it is opened. */
.erase > summary { display: inline-flex; align-items: center; gap: 10px; margin: 2px 0 0 2px; cursor: pointer;
                   list-style: none; font-style: italic; font-size: 15.5px; line-height: 1.4; color: var(--ink-64);
                   padding-bottom: 1px; background: linear-gradient(var(--link-rule), var(--link-rule)) 15px 100% / calc(100% - 15px) 1px no-repeat; }
.erase > summary::-webkit-details-marker { display: none; }
.erase > summary::before { content: ''; width: 5px; height: 5px; box-shadow: inset 0 0 0 1.2px var(--alarm);
                           transform: rotate(45deg); }
@media (hover: hover) and (pointer: fine) { .erase > summary:hover { color: var(--ink); } }
.erase[open] > summary { color: var(--alarm-ink); }
.erase > .card { margin-top: 12px; }
.erase .card-b > p { font-size: 15px; }
.erase form { margin-top: 14px; }
.erase .actions { margin-top: 6px; }

/* ── Forms ── */
.fields { display: grid; gap: 14px; }
.field label, .field .lbl { display: block; margin-bottom: 4px; font-style: italic; font-size: 15px; line-height: 1.4; color: var(--ink-64); }
.field .hint { margin-top: 4px; font-style: italic; font-size: 14px; line-height: 1.45; color: var(--ink-64); }
.field .hint .m { font-size: 12.5px; }
.field .err { margin-top: 4px; font-style: italic; font-size: 14.5px; color: var(--alarm-ink); }
input[type=text], input[type=password], input:not([type]), select {
  display: block; width: 100%; min-height: 38px; padding: 6px 9px; border: 1px solid var(--field); border-radius: 0;
  background: var(--leaf); color: var(--ink); font-family: var(--serif); font-size: 16px; line-height: 1.4;
  -webkit-appearance: none; appearance: none; }
input.m, select.m { font-family: var(--mono); font-size: 13.5px; }
input:focus, select:focus { outline: none; border-color: var(--ink); box-shadow: inset 0 0 0 .5px var(--ink); }
input[aria-invalid=true] { border-color: var(--alarm); }
select { padding-right: 28px; cursor: pointer; }
.sel { position: relative; }
.sel::after { content: ''; position: absolute; right: 11px; bottom: 16px; width: 10px; height: 6px; background: var(--ink-64);
              -webkit-mask: CHEVRON center / contain no-repeat; mask: CHEVRON center / contain no-repeat; pointer-events: none; }
.cbox { display: flex; align-items: baseline; gap: 9px; font-size: 16px; line-height: 1.4; cursor: pointer; }
.cbox input { flex: none; width: 16px; height: 16px; accent-color: var(--ink); transform: translateY(2px); }
.actions { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 24px; margin-top: 18px; }
.btn { display: inline-flex; align-items: center; justify-content: center; min-height: 38px; padding: 8px 18px 9px;
       border: 0; border-radius: 0; background: transparent; color: var(--ink); box-shadow: inset 0 0 0 1px var(--ink);
       font-family: var(--serif); font-style: normal; font-size: 16px; line-height: 1.25; cursor: pointer; white-space: nowrap; }
.btn:hover { background: var(--wash); }
.btn:active { background: var(--press); }
.btn:disabled { color: var(--ink-50); box-shadow: inset 0 0 0 1px var(--ink-30); cursor: default; }
.btn.danger { color: var(--alarm-ink); box-shadow: inset 0 0 0 1px var(--alarm); }
.btn.danger:hover { background: var(--alarm-wash); }
.btn.fill { color: var(--on-alarm); background: var(--alarm-ink); box-shadow: none; }
.btn.fill:hover { background: var(--alarm-press); }
.btn.sm { min-height: 30px; padding: 4px 12px 5px; font-size: 15px; }
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
.band { padding: 16px 20px; background: var(--band); border-bottom: 1px solid var(--ink-12); }
.tscroll { overflow-x: auto;
           background: linear-gradient(to right, var(--leaf) 30%, transparent) left / 40px 100% no-repeat local,
                       linear-gradient(to left, var(--leaf) 30%, transparent) right / 40px 100% no-repeat local,
                       linear-gradient(to right, var(--shade), transparent) left / 14px 100% no-repeat scroll,
                       linear-gradient(to left, var(--shade), transparent) right / 14px 100% no-repeat scroll; }
table { width: 100%; border-collapse: collapse; }
th { padding: 11px 12px 9px; text-align: left; vertical-align: bottom; border-bottom: 1px solid var(--ink-12); white-space: nowrap; }
td { padding: 11px 12px; vertical-align: baseline; border-top: 1px solid var(--ink-12); font-size: 16px; line-height: 1.45; }
tbody tr:first-child td { border-top: 0; }
th:first-child, td:first-child { padding-left: 20px; }
th:last-child, td:last-child { padding-right: 20px; }
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
         padding: 13px 20px 15px; border-top: 1px solid var(--ink-12); background: var(--band); font-size: 15.5px; }
.tfoot .note { font-style: italic; color: var(--ink-64); }
.tfoot .pg { display: flex; gap: 24px; align-items: baseline; }
/* An empty state: a hollow diamond on the first line of a sentence. */
.empty { position: relative; padding: 40px 24px 44px 48px; font-style: italic; font-size: 17px; line-height: 1.55;
         color: var(--ink-64); text-wrap: pretty; }
.empty > .dm { position: absolute; left: 25px; top: calc(40px + .78em - 3px); margin: 0; }
.empty .m { color: var(--ink-70); }
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
  .stack td.head.m { font-size: 14px; }
  .stack td[data-label]::before { content: attr(data-label); display: inline-block; min-width: 116px;
      margin-right: 10px; font-family: var(--mono); font-style: normal; font-size: 11px; letter-spacing: .1em;
      text-transform: uppercase; color: var(--ink-64); }
  .stack td:empty { display: none; }
  .tscroll:has(> .stack) { background: none; }
}

/* ── The list of runs: each run a row in the timeline's language ── */
.rl { list-style: none; padding: 4px 0 6px; }
.rr { position: relative; --bg: var(--leaf); }
.rr + .rr { border-top: 1px solid var(--ink-12); }
.rr::before { content: ''; position: absolute; left: 22px; top: 23px; width: 7px; height: 7px; background: var(--ink);
              transform: rotate(45deg); z-index: 1; pointer-events: none; }
.rr.mk-hollow::before, .rr.mk-breathe::before { background: var(--bg); box-shadow: inset 0 0 0 1.5px var(--ink); }
.rr.mk-alarm::before, .rr.mk-alarm-big::before { background: var(--alarm); }
.rr.mk-alarm-hollow::before { background: var(--bg); box-shadow: inset 0 0 0 1.5px var(--alarm); }
.rr.mk-breathe::before { animation: breathe 1.8s ease-in-out infinite; }
.rr-a { display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: "t tm" "s h"; column-gap: 20px;
        align-items: baseline; padding: 14px 24px 15px 48px; font-style: normal; background: var(--bg); }
@media (hover: hover) and (pointer: fine) { .rr-a:hover { --bg: var(--hover); background: var(--hover); } .rr-a:hover .rid { text-decoration: underline; text-decoration-color: var(--ink-30); text-underline-offset: 3px; } }
.rr-a:focus-visible { outline-offset: -2px; }
.rr-t { grid-area: t; display: flex; flex-wrap: wrap; align-items: baseline; gap: 2px 14px; min-width: 0; }
.rr-t .rid { font-family: var(--mono); font-weight: 500; font-size: 14.5px; line-height: 1.5; color: var(--ink); overflow-wrap: anywhere; }
.rr-t .badge { font-size: 15.5px; color: var(--ink-70); }
.rr-t .badge .dm { width: 5px; height: 5px; margin-right: 7px; }
.rr-s { grid-area: s; min-width: 0; font-style: italic; font-size: 15.5px; line-height: 1.5; color: var(--ink-64); }
.rr-s .alarm { color: var(--alarm-ink); }
.rr-s .q { font-style: italic; }
.rr-tm, .rr-h { font-family: var(--mono); font-size: 12.5px; color: var(--ink-64); white-space: nowrap; justify-self: end; }
.rr-tm { grid-area: tm; }
.rr-h { grid-area: h; }
.runs .cols .c-hash { display: none; }
@container main (max-width: 600px) {
  .runs .cols .c-time { display: none; }
  .runs .cols .c-hash { display: inline; }
  .rr-a { grid-template-columns: minmax(0, 1fr); grid-template-areas: "t" "s" "tm"; padding-right: 18px; }
  .rr-tm { justify-self: start; margin-top: 2px; }
  .rr-h { display: none; }
}

/* The filter bar */
.filters .row1 { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px 16px; }
.filters .fq { flex: 0 1 300px; min-width: 200px; }
.filters .fs { flex: 0 1 200px; }
.filters details { margin-top: 12px; }
.filters summary { display: inline; cursor: pointer; list-style: none; font-style: italic; font-size: 15.5px;
                   color: var(--ink-70); padding-bottom: 1px;
                   background: linear-gradient(var(--link-rule), var(--link-rule)) 0 100% / 100% 1px no-repeat; }
.filters summary::-webkit-details-marker { display: none; }
.filters .more { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px 16px; margin-top: 12px; }
.filters .clear { align-self: center; font-size: 15.5px; }
@media (max-width: 639px) {
  .filters .row1 { display: grid; }
  .filters .fq, .filters .fs { min-width: 0; }
  .filters .btn { width: 100%; }
  .filters .more { grid-template-columns: minmax(0, 1fr); }
}

/* Cards that stand alone in the middle of a page: sign in,
   confirmations, errors. */
.solo { width: 100%; margin: 24px auto 0; background: var(--leaf); box-shadow: var(--lift-2); padding: 34px 36px 36px; }
.solo.w420 { max-width: 440px; }
.solo.w560 { max-width: 560px; }
.solo.w640 { max-width: 640px; }
.solo .lbl { display: flex; align-items: center; margin-bottom: 12px; }
.solo .lbl.alarm { color: var(--alarm-ink); }
.solo h1.title + * { margin-top: 12px; }
.solo .lede + .lede { margin-top: 10px; }
.solo .ledger { list-style: none; margin-top: 20px; border-top: 1px solid var(--ink-12); }
.solo .ledger li { padding: 8px 0; border-bottom: 1px solid var(--ink-12); font-size: 15.5px; line-height: 1.45; overflow-wrap: anywhere; }
.solo .ledger .m { font-size: 12.5px; }
.solo .err-line { display: flex; align-items: baseline; margin: 0 0 14px; font-style: italic; font-size: 15.5px; color: var(--alarm-ink); }
.solo .fields { margin-top: 22px; }
.lockup { display: flex; align-items: center; gap: 13px; }
.lockup .mark { width: 29px; height: 29px; }
.lockup span { font-size: 27.5px; line-height: 1; transform: translateY(-2px); }
.lockup-sub { margin: 6px 0 26px 42px; font-style: italic; font-size: 15.5px; color: var(--ink-64); }
.center main { padding-top: max(28px, 8vh); }
.under { max-width: 440px; margin: 18px auto 0; text-align: center; font-style: italic; font-size: 15px; color: var(--ink-64); }
.center .notice { width: 100%; max-width: 440px; margin: 24px auto 0; }
.center .notice + .solo { margin-top: 12px; }
.issued { margin-bottom: 24px; padding: 20px 22px 22px; background: var(--leaf); box-shadow: var(--lift-2); border-left: 2px solid var(--ink); }
.issued .t { font-style: italic; font-size: 17px; }
.issued .t .m { font-size: 13.5px; }
.issued p { margin-top: 6px; font-size: 15.5px; color: var(--ink-70); }
.secret { display: block; margin-top: 12px; padding: 10px 12px; background: var(--band); font-family: var(--mono);
          font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; -webkit-user-select: all; user-select: all; }
.formcard { margin-top: 24px; }
.formcard .card-b { padding: 16px 20px 20px; }
.grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px 16px; }
.grid3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px 16px; }
.span2 { grid-column: span 2; }
@media (max-width: 639px) {
  .grid2, .grid3 { grid-template-columns: minmax(0, 1fr); }
  .span2 { grid-column: auto; }
  .solo { padding: 26px 22px 28px; }
}

/* The evidence report. */
.verdict { padding: 26px 26px 28px; }
.verdict .exit { margin-left: 14px; font-family: var(--mono); font-size: 12.5px; color: var(--ink-64); }
.verdict .lede { margin-top: 10px; }
.verdict .lede .m { font-size: .8em; white-space: nowrap; }
.verdict .facts { margin-top: 14px; }
.verdict .facts .m { font-size: .8em; }
.caveat { margin-top: 14px; font-style: italic; font-size: 15.5px; line-height: 1.55; color: var(--ink-64); max-width: 80ch; }
.anc { padding: 15px 20px; border-top: 1px solid var(--ink-12); }
.anc:first-child { border-top: 0; }
.anc > p { font-size: 15.5px; line-height: 1.5; }
.anc > p .m { font-size: 12.5px; }
.anc .ops { padding: 6px 0 0; }
.anc .op { padding: 5px 0; }
.anc .op .root .m { font-size: 12px; }

/* ── Footer ── */
.foot { flex: none; width: 100%; max-width: calc(1240px + 2 * var(--gut)); margin: 56px auto 0; padding: 0 var(--gut); }
.foot-in { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 32px; padding: 18px 0 30px;
           border-top: 1px solid var(--ink-12); font-style: italic; font-size: 15px; line-height: 1.5; color: var(--ink-64); }
.foot-in .m { font-size: 12.5px; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
@media (forced-colors: active) {
  .dm, .sum::before, .card-t::before, .op > i, .rhead::before, .nav a[aria-current]::before, .rr::before, .erase > summary::before {
    forced-color-adjust: none; background: CanvasText; box-shadow: none !important; border: 1px solid CanvasText; }
  .dm.o, .mk-hollow .sum::before, .mk-alarm-hollow .sum::before, .mk-breathe .sum::before, .card-t.o::before, .op > i.o,
  .rr.mk-hollow::before, .rr.mk-alarm-hollow::before, .rr.mk-breathe::before, .erase > summary::before {
    background: Canvas; }
  .rule > span { background: none; border-top: 1px solid CanvasText; }
  .tag { border: 1px solid CanvasText; box-shadow: none; }
  .btn { border: 1px solid ButtonText; }
  input, select { border: 1px solid FieldText; }
  input:focus, select:focus, input:focus-visible, select:focus-visible { outline: 2px solid Highlight; outline-offset: 1px; }
  .sel::after { forced-color-adjust: none; background: FieldText; }
  .crash::after, .fail::after { background: none; border-left: 2px solid CanvasText; }
}
@media print {
  :root { --paper: #fff; --leaf: #fff; --band: #fff; --hover: #fff; }
  @page { margin: 16mm; }
  .sheet, .card, .tsheet, .solo, .notice, .issued { box-shadow: none; border: 1px solid var(--ink-12); }
  .mast .nav, .out, .skip, form, .btn, .erase, .filters { display: none !important; }
  .run-grid { display: block; }
  .side { display: block; column-count: 2; column-gap: 16px; margin-top: 16px; }
  .side > .stick { position: static !important; max-height: none !important; overflow: visible !important; display: block; margin: 0; padding: 0; }
  .side .card { break-inside: avoid; margin-bottom: 16px; }
  .row, .rr, .op, .dl, .jl li { break-inside: avoid; }
  .grp-label, .card-h { break-after: avoid; }
  .crash > .sum, .crash::after, .fail .sum, .fail::after { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .cols { position: static; }
  .sum .t { display: block; overflow: visible; }
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
         <meta name=\"color-scheme\" content=\"light\">\n{refresh}\
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

/// The masthead, as on the website: the mark and wordmark (linked to
/// `home` when given), the breadcrumb after it (`Pragmatic / journals /
/// refund-20417`), and `right` (escaped HTML) at the far end. The last
/// crumb is the current page; the ones before it drop away on a narrow
/// screen. A top-level page has no crumbs: its navigation says where it is.
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
        let mono = if c.mono { " class=\"m\"" } else { "" };
        let inner = match c.href {
            Some(h) if !last => format!("<a{mono} href=\"{}\">{}</a>", esc(h), esc(c.text)),
            _ if last => format!("<span{mono} aria-current=\"page\">{}</span>", esc(c.text)),
            _ => format!("<span{mono}>{}</span>", esc(c.text)),
        };
        trail.push_str(&format!(
            "<span class=\"c {}\"><span class=\"sep\" aria-hidden=\"true\">/</span>{inner}</span>",
            if last { "cur" } else { "up" }
        ));
    }
    let crumbs = if trail.is_empty() {
        String::new()
    } else {
        format!("<nav class=\"crumbs\" aria-label=\"Breadcrumb\">{trail}</nav>")
    };
    format!(
        "<header class=\"mast\"><div class=\"mast-in\">{brand}{crumbs}\
         <div class=\"mast-r\">{right}</div></div></header>"
    )
}

/// The breadcrumb's name for a directory of journals: its last component
/// (`journals` for `./var/journals/`), or none for the current directory.
pub fn dir_name(source: &str) -> Option<&str> {
    let trimmed = source.trim_end_matches(['/', '\\']);
    let last = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    (!last.is_empty() && last != "." && last != "..").then_some(last)
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

/// The widest command, in characters, set on one line in a side card.
const COMMAND_LINE: usize = 40;

/// A shell command (its words, then each option with its value, all plain
/// text) as a block: on one line when it fits a side card, otherwise
/// broken before each option with a continuation, so it still runs when
/// copied.
pub fn command(parts: &[String]) -> String {
    let one = parts.join(" ");
    let text = if one.chars().count() <= COMMAND_LINE {
        one
    } else {
        parts.join(" \\\n    ")
    };
    format!("<code class=\"cmd\">{}</code>", esc(&text))
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
    let mut w = Pretty {
        out: String::with_capacity(text.len() + text.len() / 4),
        html: false,
        max: usize::MAX,
        cut: false,
    };
    w.value(&doc, 0);
    Some(w.out)
}

/// Indented JSON as escaped HTML with its keys, strings and other values
/// marked for the stylesheet, or `None` if `text` is not JSON.
pub fn pretty_json_html(text: &str) -> Option<String> {
    pretty_json_html_capped(text, usize::MAX).map(|(html, _)| html)
}

/// [`pretty_json_html`], stopping once the HTML reaches about `max` bytes,
/// and saying whether it stopped. Indentation and markup make the HTML far
/// larger than the JSON (a deeply nested array of zeros grows more than
/// seventy times), so it is the output that is capped, never the input.
/// The HTML stays well formed: a string cut short still closes its span.
pub fn pretty_json_html_capped(text: &str, max: usize) -> Option<(String, bool)> {
    let doc = Json::parse(text).ok()?;
    let mut w = Pretty {
        out: String::with_capacity(text.len().min(max).saturating_mul(2)),
        html: true,
        max,
        cut: false,
    };
    w.value(&doc, 0);
    Some((w.out, w.cut))
}

/// Escaped HTML of `s`, stopping before the output passes `max` bytes, and
/// whether it stopped.
pub fn esc_capped(s: &str, max: usize) -> (String, bool) {
    let mut out = String::with_capacity(s.len().min(max) + 16);
    for (i, c) in s.char_indices() {
        if out.len() + 6 > max {
            return (out, i < s.len());
        }
        push_escaped(&mut out, c);
    }
    (out, false)
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#39;"),
        c => out.push(c),
    }
}

/// The writer of indented JSON, as text or as HTML, with a cap.
struct Pretty {
    out: String,
    html: bool,
    max: usize,
    cut: bool,
}

impl Pretty {
    fn full(&mut self) -> bool {
        if self.out.len() >= self.max {
            self.cut = true;
        }
        self.cut
    }

    fn pad(&mut self, depth: usize) {
        self.out.push('\n');
        self.out.extend(std::iter::repeat_n("  ", depth));
    }

    fn scalar(&mut self, text: &str, class: &str) {
        if !self.html {
            self.out.push_str(text);
            return;
        }
        self.out.push_str(&format!("<span class=\"{class}\">"));
        let room = self.max.saturating_sub(self.out.len());
        let (e, cut) = esc_capped(text, room);
        self.out.push_str(&e);
        self.out.push_str("</span>");
        self.cut |= cut;
    }

    fn value(&mut self, v: &Json, depth: usize) {
        if self.full() {
            return;
        }
        match v {
            Json::Array(items) if !items.is_empty() => {
                self.out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if self.full() {
                        return;
                    }
                    if i > 0 {
                        self.out.push(',');
                    }
                    self.pad(depth + 1);
                    self.value(item, depth + 1);
                }
                if self.full() {
                    return;
                }
                self.pad(depth);
                self.out.push(']');
            }
            Json::Object(members) if !members.is_empty() => {
                self.out.push('{');
                for (i, (k, item)) in members.iter().enumerate() {
                    if self.full() {
                        return;
                    }
                    if i > 0 {
                        self.out.push(',');
                    }
                    self.pad(depth + 1);
                    self.scalar(&Json::String(k.clone()).to_string(), "jk");
                    self.out.push_str(": ");
                    self.value(item, depth + 1);
                }
                if self.full() {
                    return;
                }
                self.pad(depth);
                self.out.push('}');
            }
            Json::String(_) => self.scalar(&v.to_string(), "js"),
            Json::Array(_) | Json::Object(_) => self.out.push_str(&v.to_string()),
            other => self.scalar(&other.to_string(), "jv"),
        }
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
    fn pages_are_paper_and_show_focus_on_every_button() {
        let p = sample(&Frame::FILE);
        assert!(p.contains("<meta name=\"color-scheme\" content=\"light\">"));
        assert!(p.contains("color-scheme: light;"));
        assert!(!p.contains("prefers-color-scheme"), "no dark scheme");
        // The filled confirming button's text is the card's colour: its
        // focus ring is drawn in ink, outside it.
        assert!(p.contains(
            ".btn:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }"
        ));
        // Fields have an edge of at least 3:1, and keep it in forced colours.
        assert!(p.contains("--field: rgba(26,23,18,.55);"));
        assert!(p.contains("input, select { border: 1px solid FieldText; }"));
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
        assert!(m.contains(
            "<span class=\"c cur\"><span class=\"sep\" aria-hidden=\"true\">/</span>\
             <span class=\"m\" aria-current=\"page\">&lt;id&gt;</span></span>"
        ));
        assert!(m.contains("<a href=\"/r\">Runs</a>"));
        assert!(!masthead(None, &[], "").contains("crumbs"));
        assert_eq!(dir_name("journals"), Some("journals"));
        assert_eq!(dir_name("./var/journals/"), Some("journals"));
        assert_eq!(dir_name("."), None);
        assert_eq!(dir_name(""), None);
    }

    #[test]
    fn pretty_prints_json() {
        assert_eq!(
            pretty_json(r#"{"a":[1,{"b":null}],"c":{}}"#).unwrap(),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {}\n}"
        );
        assert!(pretty_json("nope").is_none());
        // The cap holds the output, however the JSON nests.
        let nested = format!("{}{}", "[".repeat(63), "]".repeat(63));
        let zeros = format!("[{}0]", "0,".repeat(30_000));
        for doc in [nested, zeros, format!("[\"{}\"]", "&".repeat(60_000))] {
            let (html, cut) = pretty_json_html_capped(&doc, 4096).unwrap();
            assert!(html.len() < 4096 + 64, "{}", html.len());
            assert!(cut || html.len() < 4096);
            assert_eq!(
                html.matches("<span").count(),
                html.matches("</span>").count()
            );
        }
        let (whole, cut) = pretty_json_html_capped("{\"a\":1}", 4096).unwrap();
        assert!(!cut);
        assert_eq!(whole, pretty_json_html("{\"a\":1}").unwrap());
        assert_eq!(esc_capped("<<<<", 10), ("&lt;&lt;".to_string(), true));
        assert_eq!(esc_capped("ab", 10), ("ab".to_string(), false));
        assert_eq!(
            pretty_json_html(r#"{"<k>":"</pre><script>"}"#).unwrap(),
            "{\n  <span class=\"jk\">&quot;&lt;k&gt;&quot;</span>: \
             <span class=\"js\">&quot;&lt;/pre&gt;&lt;script&gt;&quot;</span>\n}"
        );
    }
}
