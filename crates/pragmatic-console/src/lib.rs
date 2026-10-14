//! # pragmatic-console
//!
//! The views of Pragmatic's system of record: HTML pages of runs and
//! evidence bundles, and CSV of a bundle's records. The CLI uses them for
//! `export`, `serve` and `render-evidence`, and Pragmatic Server's console
//! renders the same pages, so a run looks the same wherever it is read.
//!
//! - [`render_run`]: one run's page. The run sheet holds the run's title,
//!   facts and state, its timeline and its chain; beside it sit the
//!   Anchoring, Evidence check and Run cards. Format 2 runs are shown in
//!   full (attempts as groups, branches and parallel regions as nested
//!   lanes, each step's intent with its results in one row, erased,
//!   withheld and ref slots, notes, times); format 1 runs read-only. Long
//!   timelines are shown a page at a time ([`render_run_page`]).
//! - [`render_index`]: the list of runs.
//! - [`render_evidence`]: a bundle's verification report and timeline.
//! - [`render_csv`]: a bundle's records for spreadsheets.
//! - [`text`]: the one-line labels and summaries the CLI prints.
//! - [`html`]: the frame, stylesheet and parts every page shares, which
//!   Pragmatic Server's other console pages use too.
//!
//! The pages share the website's design: warm paper and ink, EB Garamond
//! for words and IBM Plex Mono for data, the brand's diamond as the only
//! icon, and terracotta kept for trouble. Each row of a timeline says in
//! the console's own words what happened; recorded content appears only as
//! a quoted excerpt or a gist of data ([`gist`]), and the entries
//! themselves are one click away.
//!
//! # Safety of the output
//!
//! Everything shown comes from journals and bundles, which are untrusted:
//! a model's output or a tool's result can be written to attack whoever
//! reads it. Every page escapes all such text, contains no script, and
//! carries a Content-Security-Policy that forbids loading anything but the
//! console's own fonts, so opening a page makes no network request to
//! anyone else (a single-file page carries its fonts inline, and makes
//! none at all). Binary content is summarized by media type, size and
//! SHA-256 and never inlined, text is cut at 64 KiB per slot, and a page
//! of a timeline holds at most [`PAGE_ENTRIES`] entries and about
//! [`PAGE_BYTES`] of HTML, so a page stays a size a browser (or a server
//! rendering it) can handle whatever the journal holds. The plain-text
//! helpers escape control characters, so journal content printed to a
//! terminal cannot drive it.
//!
//! The crate has no dependencies beyond the core. It bundles EB Garamond
//! (SIL Open Font License 1.1, `assets/fonts/OFL.txt`); see [`fonts`].

mod evidence;
pub mod fonts;
pub mod gist;
pub mod html;
mod index;
mod rows;
mod run;
pub mod slots;
pub mod text;

pub use evidence::{render_csv, render_evidence};
pub use index::{render_index, render_index_of, RunRow};
pub use run::{
    render_run, render_run_page, AnchorStatus, AnchorWitness, RunPage, RunView, ServerRun,
    SlotFilter, WitnessTrust, PAGE_BYTES, PAGE_ENTRIES,
};

#[cfg(test)]
mod tests;
