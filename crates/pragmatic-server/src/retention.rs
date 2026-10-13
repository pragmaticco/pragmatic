//! Retention runs and data verification (design 4.9 and 4.13).
//!
//! # Retention
//!
//! Hourly and on demand (`POST /v1/retention/run`), every run is checked
//! against the `[[retention]]` policies that match it (see
//! [`crate::policy`] for how overlapping policies combine). Ages count from
//! the run's last append. A run past `shred_after_days` has every content
//! slot erased (reason code `retention`); a run past `delete_after_days` is
//! deleted and tombstoned, and its id can never be used again.
//!
//! Each action is decided twice: once from a quick look, and again under
//! the run's exclusive lock immediately before acting, where holds are
//! re-read and a run with a live lease is skipped. A hold placed, or an
//! append made, while retention runs therefore wins. Runs with reserved
//! `pragmatic:` ids (the server's own records, such as witness logs) are
//! never touched, and neither is the access log.
//!
//! # verify-data
//!
//! Every `verify_interval_hours` and on demand: every run's chain,
//! commitments and erasure accounting, the access log's chain, and every
//! anchor inclusion and consistency proof (through the anchoring library).
//! The result is an access-log record.

use pragmatic::journal::RESERVED_RUN_ID_PREFIX;
use pragmatic::Journal;
use serde_json::{json, Value as JsonValue};

use crate::access_log::{self, AccessRecord};
use crate::error::ApiError;
use crate::ledger::LedgerKind;
use crate::policy::{self, Action};
use crate::server::App;
use crate::store::{EraseContext, EraseParams, Selector};
use crate::timefmt;

/// What one retention run did.
#[derive(Debug, Default)]
struct Report {
    checked: u64,
    shredded: Vec<String>,
    deleted: Vec<String>,
    skipped_held: Vec<String>,
    skipped_leased: Vec<String>,
    errors: Vec<JsonValue>,
}

/// Apply retention to every run now. Returns the report.
pub fn run(app: &App) -> JsonValue {
    let mut report = Report::default();
    let now = timefmt::now_unix_secs();
    for run_id in app.store.run_ids() {
        if run_id.starts_with(RESERVED_RUN_ID_PREFIX) {
            continue;
        }
        let Some(run) = app.store.get(&run_id) else {
            continue;
        };
        let (labels, updated, sealed) = {
            let st = run.lock();
            if st.deleted || st.missing || st.broken.is_some() {
                continue;
            }
            let updated = timefmt::parse_rfc3339(&st.meta.updated_at).unwrap_or(now);
            (
                st.meta.summary.labels.clone(),
                updated,
                st.meta.summary.sealed_slots > 0,
            )
        };
        report.checked += 1;
        let Some(eff) = policy::effective(&app.config.retention, &run_id, &labels) else {
            continue;
        };
        let action = eff.action(updated, now, sealed);
        if action == Action::Nothing {
            continue;
        }
        if !app.holds.matching(&run_id).is_empty() {
            report.skipped_held.push(run_id);
            continue;
        }
        let policy_json = json!({
            "retain_min_days": eff.retain_min_days,
            "shred_after_days": eff.shred_after_days,
            "delete_after_days": eff.delete_after_days,
        });
        let result = match action {
            Action::Shred => shred(app, &run_id),
            Action::Delete => delete(app, &run_id, policy_json),
            Action::Nothing => continue,
        };
        match result {
            Ok(()) if action == Action::Shred => report.shredded.push(run_id),
            Ok(()) => report.deleted.push(run_id),
            Err(e) if e.code == "on_hold" => report.skipped_held.push(run_id),
            Err(e) if e.code == "run_locked" => report.skipped_leased.push(run_id),
            Err(e) => report
                .errors
                .push(json!({"run_id": run_id, "code": e.code, "message": e.message})),
        }
    }
    json!({
        "checked": report.checked,
        "shredded": report.shredded,
        "deleted": report.deleted,
        "skipped_held": report.skipped_held,
        "skipped_leased": report.skipped_leased,
        "errors": report.errors,
    })
}

fn intent(action: &str, run_id: &str) -> AccessRecord {
    AccessRecord::new(
        "intent",
        json!({"action": action, "run_id": run_id, "token_id": "server:retention", "role": "admin"}),
    )
}

fn shred(app: &App, run_id: &str) -> Result<(), ApiError> {
    let params = EraseParams {
        selector: Selector::All,
        reason_code: "retention".into(),
        reason: String::new(),
        force: false,
        allow_unfinished: true,
        by: "server:retention".into(),
        kind: LedgerKind::Shred,
    };
    let cx = EraseContext {
        holds: &app.holds,
        policies: &app.config.retention,
        access: &app.access,
        ledger: &app.ledger,
        intent: intent("shred", run_id),
    };
    match app.store.erase(run_id, &params, cx) {
        Ok(_) => Ok(()),
        // Everything was already erased: nothing to do.
        Err(e) if e.code == "bad_request" && e.message.starts_with("nothing to erase") => Ok(()),
        Err(e) => Err(e),
    }
}

fn delete(app: &App, run_id: &str, policy_json: JsonValue) -> Result<(), ApiError> {
    app.store
        .delete_run(
            run_id,
            policy_json,
            &app.holds,
            &app.access,
            &app.ledger,
            intent("delete", run_id),
        )
        .map(|_| ())
}

/// Verify every run, the access log and the anchor proofs, and record the
/// result in the access log. Returns the result.
pub fn verify_data(app: &App) -> JsonValue {
    let (checked, failing) = app.store.verify_all();
    let failing_runs: Vec<String> = app
        .store
        .all()
        .iter()
        .filter(|r| r.lock().broken.is_some())
        .map(|r| r.id.clone())
        .collect();
    let access_log = verify_access_log(app);
    let anchors = app
        .hooks
        .anchoring
        .verify()
        .unwrap_or_else(|e| json!({"error": e.0}));
    let result = json!({
        "runs_checked": checked,
        "runs_failing": failing,
        "failing_run_ids": failing_runs,
        "access_log": access_log,
        "anchors": anchors,
        "at": timefmt::now_rfc3339(),
    });
    let mut record = AccessRecord::new("verify-data", result.clone());
    record.run_id = None;
    let _ = app.access.durable_blocking(record);
    result
}

/// The access log's chain, read from disk.
fn verify_access_log(app: &App) -> JsonValue {
    let path = access_log::path(&app.config.data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => match Journal::audit_bytes(&bytes, None) {
            Ok((j, report)) => {
                json!({"ok": report.is_ok(), "entries": j.len(), "first_bad": report.first_bad})
            }
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}
