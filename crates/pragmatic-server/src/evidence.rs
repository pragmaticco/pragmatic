//! Evidence bundles (design 5): the server's [`EvidenceBuilder`], built
//! with the core evidence module and the anchoring library's anchor
//! section, so a bundle verifies with `pragmatic verify-evidence` and the
//! reference verifier exactly as the format says.
//!
//! A bundle is built from the run's durable journal, read under its shared
//! lock and the store's byte budget, in this order:
//!
//! 1. the journal as a local bundle would hold it ([`Bundle::local`]): its
//!    bytes, `entries`, `head` and decoded `records`;
//! 2. redaction: every sealed slot the requested mode withholds (design
//!    4.10 and 5.1, [`Redactor::withholds`]) is withheld whole, state 3
//!    with its commitment only, and the journal, records and
//!    `redacted_slots` are rebuilt from the withheld journal; chain hashes
//!    do not change, so every anchor still applies;
//! 3. the run's anchors: its leaf chain (each leaf with its inclusion
//!    proof, checkpoint, anchor digest, consistency proof to the bundle's
//!    latest checkpoint and witness results), through the checkpoint that
//!    was the latest when the journal was read, which is also the bundle's
//!    `latest_checkpoint`, with the run's `anchor_id` under HMAC run ids.
//!    The cut is by checkpoint, never by entries: a batch that anchored
//!    appends made after the read is left out whole (its leaf could not be
//!    checked against the journal, and a later latest checkpoint would
//!    contain a leaf the bundle omits, which the full-log audit rightly
//!    fails), while every leaf placed before the read stays in, so a run
//!    rolled back after it was anchored carries the leaf its journal
//!    contradicts and fails verification instead of hiding the regression;
//! 4. `generator`, `requested_by` (the token id), `redaction` (the mode,
//!    and for `detectors` the detectors and the digest of the configured
//!    patterns), `independent` (true only when an external witness is
//!    configured and one of the bundle's anchors is independently
//!    witnessed) and `verification_spec` (the procedure that ships with
//!    this version, by URL and SHA-256);
//! 5. the signature: Ed25519 with the log key over SHA-256 of the canonical
//!    bundle without `signature`, carrying the 4-byte note key id and the
//!    full public key.
//!
//! Access control happened before: the requester may see the run, and a
//! viewer without `view_raw` never gets `redact=none` or `redact=binary`
//! (both carry text slots unredacted).

use pragmatic::evidence::{Bundle, BundleSignature, Redact, Redaction, VerificationSpec};
use pragmatic::journal::{Journal, SlotState};
use pragmatic::sha256::sha256;

use crate::hooks::{EvidenceBuilder, EvidenceBundle, EvidenceError, EvidenceRequest};
use crate::redaction::Redactor;

/// The normative format and verification procedure this version ships,
/// the same file the CLI prints with `--explain` (a CLI test keeps it equal
/// to `docs/evidence-format.md`).
pub const PROCEDURE: &str = include_str!("../../pragmatic-cli/assets/evidence-format.md");

/// Where the procedure is published for this version, and its digest.
pub fn verification_spec() -> VerificationSpec {
    VerificationSpec {
        url: format!(
            "https://github.com/pragmaticco/pragmatic/blob/v{}/docs/evidence-format.md",
            env!("CARGO_PKG_VERSION")
        ),
        sha256: sha256(PROCEDURE.as_bytes()),
    }
}

/// The sealed slots of `journal` that redaction `mode` withholds.
pub fn slots_to_withhold(journal: &Journal, redactor: &Redactor, mode: &str) -> Vec<(u64, u8)> {
    if mode == "none" {
        return Vec::new();
    }
    let mut out = Vec::new();
    for e in journal.entries() {
        for (k, (meta, content)) in e.slots.iter().zip(e.event.slot_contents()).enumerate() {
            if meta.state != SlotState::Sealed {
                continue;
            }
            if let Some(v) = content.value() {
                if redactor.withholds(mode, v.as_bytes()) {
                    out.push((e.cursor, k as u8));
                }
            }
        }
    }
    out
}

/// A file name for the bundle: the run id with anything outside
/// `[A-Za-z0-9._-]` replaced, so the header cannot be broken by the id.
fn file_name(run_id: &str) -> String {
    let safe: String = run_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.evidence.json")
}

/// The integrated evidence builder. See the module documentation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundleBuilder;

impl BundleBuilder {
    /// The bundle, before it is serialized.
    pub fn bundle(&self, req: &EvidenceRequest<'_>) -> Result<Bundle, EvidenceError> {
        let mut bundle = Bundle::local(req.journal_bytes, req.run_id, &Redact::None)
            .map_err(|f| EvidenceError::BadRequest(format!("this run has no bundle: {f}")))?;
        let withheld = slots_to_withhold(req.journal, req.redactor, req.redact);
        if !withheld.is_empty() {
            bundle
                .withhold(&withheld)
                .map_err(|f| EvidenceError::Internal(format!("withholding slots: {f}")))?;
        }
        let anchors = req
            .anchoring
            .run_anchors_through(req.run_id, req.anchors_through)
            .map_err(|e| EvidenceError::Internal(format!("anchoring: {e}")))?;
        let witnessed = anchors.witnessing.iter().any(|w| w.independent);
        if !anchors.anchors.is_empty() {
            bundle.anchor_id = anchors.anchor_id;
            bundle.latest_checkpoint = anchors.latest_checkpoint;
        }
        bundle.anchors = anchors.anchors;
        bundle.generator = req.generator.to_string();
        bundle.requested_by = req.requested_by.to_string();
        bundle.independent = req.independent && witnessed;
        bundle.redaction = if req.redact == "detectors" {
            Redaction {
                mode: "detectors".into(),
                detectors: req
                    .redactor
                    .detector_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                patterns_sha256: req.redactor.patterns_digest(),
            }
        } else {
            Redaction {
                mode: req.redact.to_string(),
                ..Redaction::none()
            }
        };
        bundle.verification_spec = Some(verification_spec());
        bundle.signature = Some(BundleSignature {
            key_id: req.key.key_id_bytes(),
            public_key: req.key.public_key(),
            value: req.key.sign(&bundle.signature_message()),
        });
        Ok(bundle)
    }
}

impl EvidenceBuilder for BundleBuilder {
    fn build(&self, req: EvidenceRequest<'_>) -> Result<EvidenceBundle, EvidenceError> {
        let bundle = self.bundle(&req)?;
        Ok(EvidenceBundle {
            file_name: file_name(req.run_id),
            content_type: "application/json".into(),
            body: bundle.to_json().into_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_safe() {
        assert_eq!(file_name("acme:run-1"), "acme_run-1.evidence.json");
        assert_eq!(file_name("a\"b\r\n"), "a_b__.evidence.json");
    }

    #[test]
    fn the_spec_is_the_shipped_procedure() {
        let spec = verification_spec();
        assert!(spec.url.ends_with("/docs/evidence-format.md"));
        assert_eq!(spec.sha256, sha256(PROCEDURE.as_bytes()));
    }
}
