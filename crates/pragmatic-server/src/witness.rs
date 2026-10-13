//! Witness mode (design 4.8): cosigning other logs' checkpoints under the
//! C2SP `tlog-witness` protocol.
//!
//! A log submits `old <size>`, the consistency proof from that size, a
//! blank line and its signed checkpoint. The witness checks, in order:
//!
//! 1. the body is well formed (400);
//! 2. the checkpoint's origin is the one the caller's `witness_client`
//!    token is bound to: the origin always comes from the configuration,
//!    never from the body (403);
//! 3. the log's signature, against the key configured for that origin
//!    (403);
//! 4. `old` is not larger than the checkpoint's size (400);
//! 5. `old` equals the size this witness last cosigned for the origin,
//!    otherwise 409 with the witness's size as a `text/x.tlog.size` body,
//!    so the log can retry with the right proof;
//! 6. the consistency proof from the last cosigned tree to the new one
//!    (RFC 9162), which is what rejects a fork (422).
//!
//! It then answers with a `cosignature/v1` line: an Ed25519 signature over
//! `"cosignature/v1\ntime <unix>\n"` and the checkpoint body.
//!
//! Every cosigned checkpoint is appended to the witness's own record, the
//! server-written run `pragmatic:witness:<origin>`. That run is anchored
//! like any other, so the witness's own history is timestamped by its own
//! TSAs, and `GET /v1/witness/log/{origin}` serves it for audits. The last
//! cosigned size is read back from that record under the run's lock, so
//! the record and the witness's state can never disagree.
//!
//! A correctly signed checkpoint that fails the consistency check is a
//! fork attempt by the log, and the refusal is evidence: it is recorded
//! as a `witness.reject` note with the submitted checkpoint, as the
//! anchoring library's witness does.

use std::collections::HashMap;
use std::sync::Arc;

use pragmatic::encoding::base64_decode_exact;
use pragmatic::note::{self, Checkpoint, Note, NoteSignature, SignatureType, VerifierKey};
use pragmatic::{merkle, Event, Value};
use serde_json::{json, Value as JsonValue};

use crate::config::Config;
use crate::error::ApiError;
use crate::keys::ServerKey;
use crate::store::Store;
use crate::timefmt;

/// The note kind of a cosigned checkpoint in the witness record.
pub const COSIGN_KIND: &str = "witness.cosign";

/// The note kind of a refused fork attempt in the witness record.
pub const REJECT_KIND: &str = "witness.reject";

/// The most record entries one `GET /v1/witness/log/{origin}` reads.
pub const LOG_PAGE: u64 = 1000;

/// The run that records what the witness cosigned for an origin.
pub fn record_run_id(origin: &str) -> String {
    format!("pragmatic:witness:{origin}")
}

/// A refusal in the protocol's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessError {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl WitnessError {
    fn text(status: u16, body: impl Into<String>) -> WitnessError {
        WitnessError {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into(),
        }
    }
}

/// The witness: its cosigner name, key and the logs it witnesses.
pub struct Witness {
    name: String,
    key: Arc<ServerKey>,
    origins: HashMap<String, VerifierKey>,
}

/// A parsed `add-checkpoint` body.
struct Submission {
    old: u64,
    proof: Vec<[u8; 32]>,
    note_text: String,
    note: Note,
    checkpoint: Checkpoint,
}

fn parse_body(body: &[u8]) -> Result<Submission, WitnessError> {
    let bad = |m: &str| WitnessError::text(400, m);
    let text = std::str::from_utf8(body).map_err(|_| bad("body is not UTF-8"))?;
    let (head, note_text) = text.split_once("\n\n").ok_or_else(|| {
        bad("expected an old size line, proof lines, a blank line and a checkpoint")
    })?;
    let mut lines = head.split('\n');
    let old = lines
        .next()
        .and_then(|l| l.strip_prefix("old "))
        .and_then(|n| {
            let canonical =
                n == "0" || (!n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()));
            canonical.then(|| n.parse::<u64>().ok()).flatten()
        })
        .ok_or_else(|| bad("the first line must be \"old <size>\""))?;
    let mut proof = Vec::new();
    for line in lines {
        proof.push(
            base64_decode_exact::<32>(line)
                .map_err(|_| bad("a proof line is not base64 of 32 bytes"))?,
        );
        if proof.len() > 63 {
            return Err(bad("the consistency proof is too long"));
        }
    }
    let note = Note::parse(note_text).map_err(|e| bad(&format!("checkpoint note: {e}")))?;
    let checkpoint = Checkpoint::parse(&note.body).map_err(|e| bad(&format!("checkpoint: {e}")))?;
    Ok(Submission {
        old,
        proof,
        note_text: note_text.to_string(),
        note,
        checkpoint,
    })
}

/// The last cosigned `(size, root)` in a witness record: `(0, empty root)`
/// before the first.
fn last_cosigned(journal: &pragmatic::Journal) -> (u64, [u8; 32]) {
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
        let size = doc["tree_size"].as_u64();
        let root = doc["root"]
            .as_str()
            .and_then(|r| base64_decode_exact::<32>(r).ok());
        if let (Some(size), Some(root)) = (size, root) {
            return (size, root);
        }
    }
    (0, merkle::empty_root())
}

impl Witness {
    /// The witness for `[witness_mode]`, or `None` when it is off.
    pub fn from_config(
        config: &Config,
        name: &str,
        key: Arc<ServerKey>,
    ) -> Result<Option<Witness>, String> {
        if !config.witness_mode.enabled {
            return Ok(None);
        }
        if !note::is_valid_origin(name) {
            return Err(format!(
                "witness_mode: the server name '{name}' is not a valid cosigner name"
            ));
        }
        let mut origins = HashMap::new();
        for o in &config.witness_mode.origins {
            let vkey = VerifierKey::parse(&o.public_key)
                .map_err(|e| format!("witness_mode origin {}: {e}", o.name))?;
            origins.insert(o.name.clone(), vkey);
        }
        Ok(Some(Witness {
            name: name.to_string(),
            key,
            origins,
        }))
    }

    /// The witness's verifier key (`cosignature/v1`), for logs to pin.
    pub fn vkey(&self) -> Result<String, String> {
        VerifierKey::new(
            &self.name,
            SignatureType::CosignatureV1,
            self.key.public_key(),
        )
        .map(|k| k.encode())
        .map_err(|e| e.to_string())
    }

    /// Handle one `add-checkpoint` for `origin` (the caller's bound
    /// origin). Returns the cosignature line, newline-terminated.
    pub fn add_checkpoint(
        &self,
        store: &Store,
        origin: &str,
        body: &[u8],
    ) -> Result<String, WitnessError> {
        let sub = parse_body(body)?;
        if sub.checkpoint.origin != origin {
            return Err(WitnessError::text(
                403,
                "the checkpoint is for another origin than this token's",
            ));
        }
        let vkey = self
            .origins
            .get(origin)
            .ok_or_else(|| WitnessError::text(404, "unknown origin"))?;
        note::verify_note(&sub.note, std::slice::from_ref(vkey))
            .map_err(|e| WitnessError::text(403, format!("log signature: {e}")))?;
        if sub.old > sub.checkpoint.tree_size {
            return Err(WitnessError::text(
                400,
                "old size is larger than the checkpoint's size",
            ));
        }
        let decided = store.internal_append(&record_run_id(origin), |journal| {
            let (size, root) = last_cosigned(journal);
            if sub.old != size {
                return Err(ApiError::new(409, "witness_size", size.to_string()));
            }
            if !merkle::verify_consistency(
                size,
                sub.checkpoint.tree_size,
                &root,
                &sub.checkpoint.root,
                &sub.proof,
            ) {
                return Err(ApiError::new(
                    422,
                    "witness_proof",
                    "the consistency proof does not verify",
                ));
            }
            let line = self.cosign(&sub.note.body).map_err(ApiError::bad_request)?;
            let data = json!({
                "origin": origin,
                "old_size": sub.old,
                "tree_size": sub.checkpoint.tree_size,
                "root": pragmatic::encoding::base64_encode(&sub.checkpoint.root),
                "timestamp": line.1,
            })
            .to_string();
            let record = format!("{}{}\n", sub.note_text, line.0);
            Ok((
                COSIGN_KIND.to_string(),
                data,
                vec![Value::from(record)],
                line.0,
            ))
        });
        match decided {
            Ok((line, _)) => Ok(format!("{line}\n")),
            Err(e) if e.code == "witness_size" => Err(WitnessError {
                status: 409,
                content_type: "text/x.tlog.size",
                body: format!("{}\n", e.message),
            }),
            Err(e) if e.code == "witness_proof" => {
                self.record_reject(store, origin, &sub, &e.message);
                Err(WitnessError::text(422, e.message))
            }
            Err(e) => Err(WitnessError::text(e.status, e.message)),
        }
    }

    /// Record a fork attempt: a checkpoint the log signed that does not
    /// extend what this witness cosigned. Best effort: the refusal stands
    /// whether or not the record could be written, and a record that
    /// cannot be written refuses every later cosignature too.
    fn record_reject(&self, store: &Store, origin: &str, sub: &Submission, reason: &str) {
        let data = json!({
            "origin": origin,
            "old_size": sub.old,
            "tree_size": sub.checkpoint.tree_size,
            "root": pragmatic::encoding::base64_encode(&sub.checkpoint.root),
            "reason": reason,
        })
        .to_string();
        let note_text = sub.note_text.clone();
        let _ = store.internal_append(&record_run_id(origin), |_| {
            Ok((
                REJECT_KIND.to_string(),
                data,
                vec![Value::from(note_text)],
                (),
            ))
        });
    }

    /// A `cosignature/v1` line for a checkpoint body, and its timestamp.
    fn cosign(&self, body: &str) -> Result<(String, u64), String> {
        let ts = timefmt::now_unix_secs().max(0) as u64;
        let sig = self
            .key
            .sign(note::cosignature_v1_message(ts, body).as_bytes());
        let mut signature = ts.to_be_bytes().to_vec();
        signature.extend_from_slice(&sig);
        let line = NoteSignature {
            name: self.name.clone(),
            key_id: note::key_id(
                &self.name,
                SignatureType::CosignatureV1,
                &self.key.public_key(),
            ),
            signature,
        }
        .to_line()
        .map_err(|e| e.to_string())?;
        Ok((line, ts))
    }

    /// The cosigned history of an origin after cursor `after`: at most
    /// [`LOG_PAGE`] entries of the record, read from disk, and the cursor
    /// to continue after when more follow.
    pub fn log(
        &self,
        store: &Store,
        origin: &str,
        after: Option<u64>,
    ) -> Result<(Vec<JsonValue>, Option<u64>), ApiError> {
        if !self.origins.contains_key(origin) {
            return Err(ApiError::not_found());
        }
        let from = after.map_or(0, |a| a.saturating_add(1));
        let page = match store.entries_page(&record_run_id(origin), from, LOG_PAGE) {
            Ok(p) => p,
            Err(e) if e.code == "not_found" => return Ok((Vec::new(), None)),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for read in &page.entries {
            let e = &read.entry;
            let Event::Note {
                kind,
                data,
                payload,
            } = &e.event
            else {
                continue;
            };
            if kind != COSIGN_KIND {
                continue;
            }
            let mut doc: JsonValue = serde_json::from_str(data).unwrap_or(JsonValue::Null);
            doc["cursor"] = e.cursor.into();
            doc["at"] = timefmt::rfc3339_ns(e.at).into();
            doc["checkpoint"] = payload
                .first()
                .and_then(|c| c.value())
                .map_or(JsonValue::Null, |v| v.as_str().into_owned().into());
            out.push(doc);
        }
        let next = page.next.map(|n| n - 1);
        Ok((out, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_are_parsed_strictly() {
        assert_eq!(parse_body(b"old 01\n\nx").err().unwrap().status, 400);
        assert_eq!(parse_body(b"new 1\n\nx").err().unwrap().status, 400);
        assert_eq!(
            parse_body(b"old 1\nnot-base64\n\nx").err().unwrap().status,
            400
        );
        assert_eq!(parse_body(b"old 1").err().unwrap().status, 400);
    }
}
