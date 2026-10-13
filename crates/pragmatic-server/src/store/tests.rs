use std::sync::Arc;
use std::time::Duration;

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{META, ROOT};
use pragmatic::{Content, Event, Journal};

use super::*;
use crate::fsutil::testdir::TestDir;
use crate::layout;
use crate::tokens::Principal;

fn store(dir: &std::path::Path) -> Store {
    Store::new(
        Layout::new(dir),
        StoreOptions {
            lease_ttl: Duration::from_secs(30),
            max_clock_skew: Duration::from_secs(300),
            index_key: [7u8; 32],
        },
        Signals {
            metrics: Arc::new(Metrics::default()),
            webhooks: Webhooks::disabled(),
            anchor_soon: Arc::new(AnchorSoon::default()),
        },
    )
}

fn agent() -> Principal {
    Principal {
        token_id: "tok_a".into(),
        name: "a".into(),
        principal: "svc".into(),
        role: crate::tokens::Role::Agent,
        scopes: vec!["*".into()],
        view_raw: false,
    }
}

fn recv(text: &str) -> Event {
    Event::ChannelRecv {
        channel: "in".into(),
        value: Content::from(text),
    }
}

/// A client journal with `run.start` and `n` receives.
fn client(run: &str, n: usize) -> Journal {
    let mut j = Journal::new(None);
    j.append(
        META,
        Event::Note {
            kind: "run.start".into(),
            data: format!("{{\"run_id\":\"{run}\"}}"),
            payload: vec![],
        },
    )
    .unwrap();
    for i in 0..n {
        j.append(ROOT, recv(&format!("m{i}"))).unwrap();
    }
    j
}

fn push(s: &Store, run: &str, lease: &str, j: &mut Journal) -> Result<AppendOk, ApiError> {
    let (at, frames, head) = j.pending().unwrap();
    let k = j.len() - at;
    let frames = frames.to_vec();
    let head = hex_encode(&head);
    let ok = s.append(
        &agent(),
        run,
        AppendRequest {
            at,
            count: k,
            lease,
            head: &head,
            body: &frames,
        },
    )?;
    if !ok.duplicate {
        j.mark_persisted(j.len());
    }
    Ok(ok)
}

#[test]
fn appends_reach_disk_and_meta_follows_on_flush() {
    let d = TestDir::new("store-append");
    let s = store(&d);
    let grant = s.create_run(&agent(), "r", None).unwrap();
    let mut j = client("r", 3);
    let ok = push(&s, "r", &grant.lease, &mut j).unwrap();
    assert_eq!(ok.entries, 4);
    assert_eq!(ok.head, hex_encode(&j.head()));
    let on_disk = std::fs::read(s.layout.journal(&layout::stem("r"))).unwrap();
    assert_eq!(on_disk, j.to_bytes());
    s.flush_meta(true);
    let meta: Meta = crate::fsutil::read_json(&s.layout.meta(&layout::stem("r")))
        .unwrap()
        .unwrap();
    assert_eq!(meta.entries, 4);
    assert_eq!(meta.byte_len, on_disk.len() as u64);
    assert_eq!(meta.leases.len(), 1);
}

#[test]
fn a_second_store_trusts_a_matching_meta_and_reparses_a_stale_one() {
    let d = TestDir::new("store-index");
    let s = store(&d);
    let grant = s.create_run(&agent(), "r", None).unwrap();
    let mut j = client("r", 2);
    push(&s, "r", &grant.lease, &mut j).unwrap();
    s.flush_meta(true);
    let again = store(&d);
    let report = again.index();
    assert_eq!((report.runs, report.trusted, report.reparsed), (1, 1, 0));
    // An append whose meta never reached disk: the next start reparses.
    j.append(ROOT, recv("late")).unwrap();
    push(&again, "r", &grant.lease, &mut j).unwrap();
    let third = store(&d);
    let report = third.index();
    assert_eq!((report.trusted, report.reparsed), (0, 1));
    assert_eq!(third.get("r").unwrap().lock().meta.entries, 4);
}

#[test]
fn a_journal_changed_behind_the_servers_back_is_damaged() {
    let d = TestDir::new("store-tamper");
    let s = store(&d);
    let grant = s.create_run(&agent(), "r", None).unwrap();
    let mut j = client("r", 1);
    push(&s, "r", &grant.lease, &mut j).unwrap();
    // Drop the cached writer, then grow the file outside the server.
    s.get("r").unwrap().lock().writer = None;
    let path = s.layout.journal(&layout::stem("r"));
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(b"junk");
    std::fs::write(&path, bytes).unwrap();
    j.append(ROOT, recv("x")).unwrap();
    let err = push(&s, "r", &grant.lease, &mut j).unwrap_err();
    assert_eq!(err.code, "chain_broken");
    assert!(s.get("r").unwrap().lock().broken.is_some());
}

#[test]
fn duplicates_are_recognized_by_their_stored_hashes() {
    let d = TestDir::new("store-dup");
    let s = store(&d);
    let grant = s.create_run(&agent(), "r", None).unwrap();
    let mut j = client("r", 2);
    let (at, frames, head) = j.pending().map(|(a, f, h)| (a, f.to_vec(), h)).unwrap();
    push(&s, "r", &grant.lease, &mut j).unwrap();
    let head = hex_encode(&head);
    let req = AppendRequest {
        at,
        count: 3,
        lease: "not-even-a-lease",
        head: &head,
        body: &frames,
    };
    let dup = s.append(&agent(), "r", req).unwrap();
    assert!(dup.duplicate);
    assert_eq!(dup.entries, 3);
}

#[test]
fn tips_cover_changed_runs_only() {
    let d = TestDir::new("store-tips");
    let s = store(&d);
    let g = s.create_run(&agent(), "a", None).unwrap();
    s.create_run(&agent(), "b", None).unwrap();
    let tips = s.anchor_tips();
    assert_eq!(
        tips.len(),
        2,
        "runs created by PUT are included with zero entries"
    );
    s.record_leaves(&[
        crate::hooks::LeafPlaced {
            run_id: Some("a".into()),
            entries: 0,
            leaf_index: 0,
        },
        crate::hooks::LeafPlaced {
            run_id: Some("b".into()),
            entries: 0,
            leaf_index: 1,
        },
    ]);
    assert!(s.anchor_tips().is_empty());
    let mut j = client("a", 1);
    push(&s, "a", &g.lease, &mut j).unwrap();
    let tips = s.anchor_tips();
    assert_eq!(tips.len(), 1);
    assert_eq!(
        (tips[0].run_id.as_str(), tips[0].entries, tips[0].prev_leaf),
        ("a", 2, Some(0))
    );
    s.mark_anchored(&[("a".into(), 2)]);
    assert_eq!(s.get("a").unwrap().lock().meta.anchored_entries, 2);
}
