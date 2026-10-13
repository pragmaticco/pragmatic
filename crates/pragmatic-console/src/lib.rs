//! # pragmatic-console
//!
//! The views of Pragmatic's system of record: HTML pages of runs and
//! evidence bundles, and CSV of a bundle's records. The CLI uses them for
//! `export`, `serve` and `render-evidence`, and Pragmatic Server's console
//! renders the same pages, so a run looks the same wherever it is read.
//!
//! - [`render_run`]: one run's page (format 2 runs in full: attempts,
//!   branches and parallel regions as nested lanes, intents with their
//!   results, erased, withheld and ref slots, notes, times, the
//!   verification report and, when known, anchoring; format 1 runs
//!   read-only). Long timelines are shown a page at a time
//!   ([`render_run_page`]).
//! - [`render_index`]: the list of runs.
//! - [`render_evidence`]: a bundle's verification report and timeline.
//! - [`render_csv`]: a bundle's records for spreadsheets.
//! - [`text`]: the one-line labels and summaries the CLI prints.
//!
//! # Safety of the output
//!
//! Everything shown comes from journals and bundles, which are untrusted:
//! a model's output or a tool's result can be written to attack whoever
//! reads it. Every page escapes all such text, contains no script, and
//! carries a Content-Security-Policy that forbids loading anything, so
//! opening a page makes no network request. Binary content is summarized
//! by media type, size and SHA-256 and never inlined, text is cut at
//! 64 KiB per slot, and a page of a timeline holds at most
//! [`PAGE_ENTRIES`] entries and about [`PAGE_BYTES`] of HTML, so a
//! page stays a size a browser (or a server rendering it) can handle
//! whatever the journal holds. The plain-text helpers escape control characters, so
//! journal content printed to a terminal cannot drive it.
//!
//! The crate has no dependencies beyond the core.

mod evidence;
pub mod html;
mod index;
mod run;
pub mod slots;
pub mod text;

pub use evidence::{render_csv, render_evidence};
pub use index::{render_index, render_index_of, RunRow};
pub use run::{
    render_run, render_run_page, AnchorStatus, RunPage, RunView, SlotFilter, PAGE_BYTES,
    PAGE_ENTRIES,
};

#[cfg(test)]
mod tests;
