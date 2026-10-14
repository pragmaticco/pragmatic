//! Pragmatic Server: the system of record for AI agent runs (design
//! section 4).
//!
//! The server stores run journals for SDKs that append to them under
//! leases, and serves them to auditors and operators with access control,
//! redaction, an access log, erasure, legal holds, retention, backups and
//! anchoring.
//!
//! Licensed under the Business Source License 1.1 (see `LICENSE` in this
//! crate): non-production use is free; production use needs a commercial
//! license from Pragmatic Research, Inc. Each version converts to
//! Apache-2.0 four years after its release.

pub mod access_log;
pub mod anchoring;
pub mod api;
pub mod config;
pub mod console;
pub mod console_ui;
pub mod error;
pub mod evidence;
pub mod fsutil;
pub mod holds;
pub mod hooks;
pub mod keys;
pub mod layout;
pub mod ledger;
pub mod metrics;
pub mod ops;
pub mod policy;
pub mod redaction;
pub mod retention;
pub mod server;
pub mod store;
pub mod summary;
pub mod timefmt;
pub mod tokens;
pub mod views;
pub mod webhooks;
pub mod witness;
