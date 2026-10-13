//! Witness mode (design 4.8): cosigning other logs' checkpoints under the
//! C2SP `tlog-witness` protocol.
//!
//! The protocol's checks and the cosigning key are the anchoring library's
//! ([`WitnessCore`]), so this server cosigns exactly as the library's own
//! witness does. A log submits `old <size>`, the consistency proof from
//! that size, a blank line and its signed checkpoint, and the checks run in
//! the protocol's order:
//!
//! 1. the origin bound to the caller's `witness_client` token is
//!    configured (404) and the body is well formed (400);
//! 2. the checkpoint names that origin line: the origin always comes from
//!    the configuration, never from the body (403);
//! 3. the log's signature, against the log keys configured for it (403);
//! 4. `old` is not larger than the checkpoint's size (400);
//! 5. under the lock of the origin's record, `old` equals the size this
//!    witness last cosigned for the origin, otherwise 409 with the
//!    witness's size as a `text/x.tlog.size` body, so the log can retry
//!    with the right proof;
//! 6. the consistency proof from the last cosigned tree to the new one
//!    (RFC 9162), which is what refuses a fork (422).
//!
//! It then answers with a `cosignature/v1` line, signed with the witness's
//! own key (`[witness_mode] key_file`), never the log key.
//!
//! # The record
//!
//! Every cosigned checkpoint is appended to the witness's own record for
//! its origin, the server-written run `pragmatic:witness:<name>`, as a
//! `witness.cosign` note `{origin, old_size, tree_size, root, timestamp}`
//! whose payload slot holds the cosigned checkpoint (the signed note with
//! this witness's cosignature line). The note is durable before the line
//! is returned, and the size check reads the record under the same lock as
//! the append, so a crash can never make the witness forget a cosignature
//! and sign a fork. A correctly signed checkpoint that fails the
//! consistency checks is a fork attempt by the log, and the refusal is
//! evidence: it is recorded, in the same append, as a `witness.reject`
//! note `{origin, old_size, tree_size, root, reason}` with the submitted
//! note as its payload. A damaged record refuses writes, so the witness
//! stops cosigning for that origin rather than start a record that has
//! forgotten what it cosigned.
//!
//! The record is anchored in the server's own log like any run, so the
//! witness's history is time-stamped by its own TSAs, and
//! `GET /v1/witness/log/{origin}` serves it for audits.

use std::cell::Cell;

use pragmatic::encoding::{hex_decode_exact, hex_encode};
use pragmatic::sha256::Digest;
use pragmatic::{Event, Value};
use pragmatic_anchor::witness::AddCheckpointError;
use pragmatic_anchor::{WitnessCore, WitnessOrigin};
use serde_json::{json, Value as JsonValue};

use crate::config::Config;
use crate::error::ApiError;
use crate::keys;
use crate::store::Store;
use crate::timefmt;

/// The note kind of a cosigned checkpoint in the witness record.
pub const COSIGN_KIND: &str = pragmatic_anchor::witness::COSIGN_NOTE;

/// The note kind of a refused fork attempt in the witness record.
pub const REJECT_KIND: &str = pragmatic_anchor::witness::REJECT_NOTE;

/// The most record entries one `GET /v1/witness/log/{origin}` reads.
pub const LOG_PAGE: u64 = 1000;

/// The run that records what the witness cosigned for the origin entry
/// named `name`.
pub fn record_run_id(name: &str) -> String {
    format!("pragmatic:witness:{name}")
}

/// A refusal in the protocol's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessError {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl From<AddCheckpointError> for WitnessError {
    fn from(e: AddCheckpointError) -> WitnessError {
        WitnessError {
            status: e.status(),
            content_type: e.content_type(),
            body: e.body(),
        }
    }
}

/// The witness: the anchoring library's checks and key, over records in
/// the run store.
pub struct Witness {
    core: WitnessCore,
}

/// The last cosigned `(size, root)` for `origin` in a witness record, or
/// `None` before the first.
fn last_cosigned(journal: &pragmatic::Journal, origin: &str) -> Option<(u64, Digest)> {
    for e in journal.entries().iter().rev() {
        let Event::Note { kind, data, .. } = &e.event else {
            continue;
        };
        if kind != COSIGN_KIND {
            continue;
        }
        let Ok(doc) = serde_json::from_str::<JsonValue>(data) else {
            continue;
        };
        if doc["origin"].as_str() != Some(origin) {
            continue;
        }
        let size = doc["tree_size"].as_u64();
        let root = doc["root"]
            .as_str()
            .and_then(|r| hex_decode_exact::<32>(r).ok());
        if let (Some(size), Some(root)) = (size, root) {
            return Some((size, root));
        }
    }
    None
}

impl Witness {
    /// The witness for `[witness_mode]`, or `None` when it is off. Reads
    /// the witness key.
    pub fn from_config(config: &Config) -> Result<Option<Witness>, String> {
        let w = &config.witness_mode;
        if !w.enabled {
            return Ok(None);
        }
        let cosigner = keys::load_cosigner(&w.key_file).map_err(|e| {
            format!("witness_mode: {e} (create one with `pragmatic-server keygen --witness`)")
        })?;
        if cosigner.name() != w.name {
            return Err(format!(
                "witness_mode: the key in {} is named {:?}, but witness_mode.name is {:?}",
                w.key_file.display(),
                cosigner.name(),
                w.name
            ));
        }
        let mut origins = Vec::new();
        for o in &w.origins {
            let log_keys = o
                .log_vkeys
                .iter()
                .map(|v| pragmatic::note::VerifierKey::parse(v))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("witness_mode origin {}: {e}", o.name))?;
            origins.push(WitnessOrigin {
                name: o.name.clone(),
                origin: o.origin.clone(),
                log_keys,
            });
        }
        let core = WitnessCore::new(cosigner, origins).map_err(|e| format!("witness_mode: {e}"))?;
        Ok(Some(Witness { core }))
    }

    /// The witness's verifier key (`cosignature/v1`), for logs to pin.
    pub fn vkey(&self) -> String {
        self.core.cosigner().verifier_key().encode()
    }

    /// The cosigner name.
    pub fn name(&self) -> &str {
        self.core.cosigner().name()
    }

    /// Handle one `add-checkpoint` for the origin entry named `name` (the
    /// caller's bound origin). Returns the cosignature line,
    /// newline-terminated.
    pub fn add_checkpoint(
        &self,
        store: &Store,
        name: &str,
        body: &[u8],
    ) -> Result<String, WitnessError> {
        let sub = self.core.check(name, body)?;
        // What decide refused with nothing to record (a conflict, or a
        // failure to sign): nothing is appended, and the refusal is
        // answered.
        let unrecorded: Cell<Option<AddCheckpointError>> = Cell::new(None);
        let decided = store.internal_append(&record_run_id(name), |journal| {
            let latest = last_cosigned(journal, &sub.origin.origin);
            let now = timefmt::now_unix_secs().max(0) as u64;
            match self.core.decide(&sub, latest, now) {
                Ok(record) => {
                    let data = json!({
                        "origin": record.origin,
                        "old_size": record.old_size,
                        "tree_size": record.tree_size,
                        "root": hex_encode(&record.root),
                        "timestamp": record.timestamp,
                    })
                    .to_string();
                    let payload = vec![Value::from(record.cosigned_note())];
                    Ok((
                        COSIGN_KIND.to_string(),
                        data,
                        payload,
                        Ok(record.cosignature),
                    ))
                }
                Err(refused) => match refused.reject {
                    Some(reject) => {
                        let data = json!({
                            "origin": reject.origin,
                            "old_size": reject.old_size,
                            "tree_size": reject.tree_size,
                            "root": hex_encode(&reject.root),
                            "reason": reject.reason,
                        })
                        .to_string();
                        let payload = vec![Value::from(reject.checkpoint)];
                        Ok((REJECT_KIND.to_string(), data, payload, Err(refused.error)))
                    }
                    None => {
                        unrecorded.set(Some(refused.error));
                        Err(ApiError::bad_request("refused"))
                    }
                },
            }
        });
        match decided {
            Ok((Ok(line), _)) => Ok(format!("{line}\n")),
            Ok((Err(refusal), _)) => Err(refusal.into()),
            Err(e) => match unrecorded.take() {
                Some(refusal) => Err(refusal.into()),
                // The record could not be read or written: nothing was
                // cosigned.
                None => Err(AddCheckpointError::Unavailable(e.message).into()),
            },
        }
    }

    /// The cosigned history of the origin entry `name` after cursor
    /// `after`: at most [`LOG_PAGE`] entries of the record, read from disk,
    /// and the cursor to continue after when more follow. Each record's
    /// `checkpoint` is the cosigned note, which verifies with this
    /// witness's vkey; the `checkpoint`s of every page, in order, are the
    /// `checkpoints` of a `--witness-log` file (design 5.3).
    pub fn log(
        &self,
        store: &Store,
        name: &str,
        after: Option<u64>,
    ) -> Result<JsonValue, ApiError> {
        let Some(entry) = self.core.origin(name) else {
            return Err(ApiError::not_found());
        };
        let from = after.map_or(0, |a| a.saturating_add(1));
        let page = match store.entries_page(&record_run_id(name), from, LOG_PAGE) {
            Ok(p) => Some(p),
            Err(e) if e.code == "not_found" => None,
            Err(e) => return Err(e),
        };
        let mut cosigned = Vec::new();
        let mut next = None;
        if let Some(page) = page {
            for read in &page.entries {
                let e = &read.entry;
                let Event::Note { kind, data, .. } = &e.event else {
                    continue;
                };
                if kind != COSIGN_KIND {
                    continue;
                }
                let mut doc: JsonValue = serde_json::from_str(data).unwrap_or(JsonValue::Null);
                doc["cursor"] = e.cursor.into();
                doc["at"] = timefmt::rfc3339_ns(e.at).into();
                doc["checkpoint"] = read
                    .contents()
                    .first()
                    .and_then(|c| c.value())
                    .map_or(JsonValue::Null, |v| v.as_str().into_owned().into());
                cosigned.push(doc);
            }
            next = page.next.map(|n| n - 1);
        }
        Ok(json!({
            "origin": name,
            "origin_line": entry.origin,
            "witness": self.name(),
            "cosigned": cosigned,
            "next": next,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_cosigned_size_is_read_from_the_record() {
        let mut j = pragmatic::Journal::new(None);
        assert_eq!(last_cosigned(&j, "pragmatic/acme/00"), None);
        for (origin, size) in [("pragmatic/acme/00", 3u64), ("pragmatic/other/00", 9)] {
            j.append(
                pragmatic::journal::META,
                Event::Note {
                    kind: COSIGN_KIND.into(),
                    data: json!({
                        "origin": origin, "old_size": 0, "tree_size": size,
                        "root": hex_encode(&[size as u8; 32]), "timestamp": 1,
                    })
                    .to_string(),
                    payload: vec![],
                },
            )
            .unwrap();
        }
        assert_eq!(last_cosigned(&j, "pragmatic/acme/00"), Some((3, [3; 32])));
        assert_eq!(last_cosigned(&j, "pragmatic/other/00"), Some((9, [9; 32])));
    }
}
