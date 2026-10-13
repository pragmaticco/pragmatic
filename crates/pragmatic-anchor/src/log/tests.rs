use super::*;
use pragmatic::merkle::{verify_consistency, verify_inclusion};
use pragmatic::note::{verify_note, Note};

fn signer() -> LogSigner {
    LogSigner::from_seed("pragmatic/test", [5u8; 32]).unwrap()
}

fn run(id: &str, entries: u64) -> NewLeaf {
    NewLeaf {
        leaf_type: LeafType::Run,
        plain_id: id.to_string(),
        leaf_id: id.as_bytes().to_vec(),
        entries,
        head: head_for(id, entries),
    }
}

fn head_for(id: &str, entries: u64) -> Digest {
    pragmatic::sha256::sha256(format!("{id}/{entries}").as_bytes())
}

fn open(dir: &Path) -> (AnchorLog, RecoveryReport) {
    AnchorLog::open_with_chunk_bits(dir, 2).unwrap()
}

/// Every proof the log serves verifies against the checkpoints it signed.
fn assert_proofs_verify(log: &AnchorLog) {
    let latest = log.latest_checkpoint().unwrap();
    for meta in log.checkpoints() {
        let stored = log.checkpoint(meta.seq).unwrap();
        assert_eq!(stored.root(), log.root(meta.tree_size).unwrap());
        for index in 0..meta.tree_size {
            let leaf = log.read_leaf(index).unwrap();
            let proof = log.inclusion_proof(index, meta.tree_size).unwrap();
            assert!(verify_inclusion(
                &leaf.hash(),
                index,
                meta.tree_size,
                &proof,
                &meta.root
            ));
        }
        let c = log
            .consistency_proof(meta.tree_size, latest.tree_size)
            .unwrap();
        assert!(verify_consistency(
            meta.tree_size,
            latest.tree_size,
            &meta.root,
            &latest.root,
            &c
        ));
        // The stored proof from the previous checkpoint verifies too.
        let prev_root = log.root(stored.prev_tree_size).unwrap();
        assert!(verify_consistency(
            stored.prev_tree_size,
            meta.tree_size,
            &prev_root,
            &meta.root,
            &stored.consistency_from_prev
        ));
    }
}

#[test]
fn batches_are_ordered_linked_signed_and_provable() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, report) = open(dir.path());
    assert_eq!(report.next_seq, 0);
    assert_eq!(log.size(), 0);

    let b0 = log
        .append_batch(
            vec![run("zeta", 3), run("alpha", 1), run("mid", 0)],
            &signer(),
            1000,
        )
        .unwrap();
    assert_eq!(b0.checkpoint.seq, 0);
    let ids: Vec<&str> = b0.leaves.iter().map(|c| c.plain_id.as_str()).collect();
    assert_eq!(ids, ["alpha", "mid", "zeta"], "ordered by raw id bytes");
    assert!(b0.leaves.iter().all(|c| c.leaf.prev_leaf_index.is_none()));

    let mut access = run("access", 9);
    access.leaf_type = LeafType::AccessLog;
    let b1 = log
        .append_batch(vec![access, run("alpha", 4)], &signer(), 1010)
        .unwrap();
    assert_eq!(b1.checkpoint.seq, 1);
    assert_eq!(b1.leaves[0].plain_id, "alpha", "runs before the access log");
    assert_eq!(b1.leaves[0].leaf.prev_leaf_index, Some(0));
    assert_eq!(b1.leaves[1].leaf.leaf_type, LeafType::AccessLog);
    assert_eq!(b1.checkpoint.prev_tree_size, 3);
    assert_eq!(b1.checkpoint.tree_size(), 5);

    // The checkpoint is a signed note the core verifies with the vkey.
    let note = Note::parse(&b1.checkpoint.signed.note).unwrap();
    assert!(verify_note(&note, &[signer().verifier_key()]).is_ok());
    assert_eq!(
        b1.checkpoint.signed.anchor_digest,
        pragmatic::sha256::sha256(note.body.as_bytes())
    );

    // Leaf chain and lookups.
    let chain = log.leaf_chain(LeafType::Run, b"alpha").unwrap();
    assert_eq!(chain.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 3]);
    assert_eq!(chain[1].1.entries, 4);
    assert_eq!(log.checkpoint_for_leaf(2).unwrap().seq, 0);
    assert_eq!(log.checkpoint_for_leaf(3).unwrap().seq, 1);
    assert!(log.checkpoint_for_leaf(5).is_none());
    assert_eq!(log.latest_leaf(LeafType::Run, b"alpha").unwrap().entries, 4);
    assert!(log.latest_leaf(LeafType::AccessLog, b"alpha").is_none());
    let index = log.batch_index(1).unwrap();
    assert_eq!(index[1].id, "access");
    assert_eq!(index[1].leaf_index, 4);
    assert_proofs_verify(&log);
}

#[test]
fn duplicate_ids_abort_the_batch_and_write_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    log.append_batch(vec![run("a", 1)], &signer(), 1).unwrap();
    let err = log
        .append_batch(vec![run("b", 1), run("c", 1), run("b", 2)], &signer(), 2)
        .unwrap_err();
    assert!(
        matches!(err, AnchorError::DuplicateId { leaf_type: 0, .. }),
        "{err}"
    );
    assert_eq!(log.size(), 1);
    assert_eq!(log.next_seq(), 1);
    assert!(!dir.path().join(STH_DIR).join(seq_name(1, ".json")).exists());
    assert!(matches!(
        log.append_batch(vec![], &signer(), 3),
        Err(AnchorError::EmptyBatch)
    ));
    // The same id under another type is not a duplicate.
    let mut access = run("b", 1);
    access.leaf_type = LeafType::AccessLog;
    log.append_batch(vec![run("b", 1), access], &signer(), 4)
        .unwrap();
}

#[test]
fn restart_recovers_seq_tree_and_latest_leaves() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    for batch in 0..20u64 {
        let leaves = (0..(batch % 5 + 1))
            .map(|r| run(&format!("run-{r}"), batch * 10 + r))
            .collect();
        log.append_batch(leaves, &signer(), batch).unwrap();
    }
    let size = log.size();
    let root = log.root(size).unwrap();
    let latest = log.latest_leaf(LeafType::Run, b"run-0").unwrap();
    drop(log);

    let (log, report) = open(dir.path());
    assert_eq!(report.next_seq, 20);
    assert_eq!(report.leaves, size);
    assert_eq!(report.checkpoints, 20);
    assert!(report.missing_seqs.is_empty() && report.moved_aside.is_none());
    assert_eq!(log.root(size).unwrap(), root);
    assert_eq!(log.latest_leaf(LeafType::Run, b"run-0"), Some(latest));
    assert_eq!(log.ids(), 5);
    assert_proofs_verify(&log);
    // The default chunk size reads the same files.
    drop(log);
    let (log, _) = AnchorLog::open(dir.path()).unwrap();
    assert_eq!(log.root(size).unwrap(), root);
}

#[test]
fn uncommitted_leaves_are_moved_aside() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    log.append_batch(vec![run("a", 1)], &signer(), 1).unwrap();
    let leaves_len = fs::metadata(dir.path().join(LEAVES_FILE)).unwrap().len();
    drop(log);
    // A crash after the leaves of batch 1 were written, before its
    // checkpoint: the leaves and a batch index exist, the checkpoint not.
    let leaf = Leaf {
        leaf_type: LeafType::Run,
        id: b"b".to_vec(),
        entries: 1,
        head: [0; 32],
        prev_leaf_index: None,
    }
    .encode();
    let mut f = OpenOptions::new()
        .append(true)
        .open(dir.path().join(LEAVES_FILE))
        .unwrap();
    f.write_all(&(leaf.len() as u32).to_le_bytes()).unwrap();
    f.write_all(&leaf).unwrap();
    f.write_all(&[1, 2, 3]).unwrap(); // and a torn record after it
    drop(f);
    let stale_batch = dir.path().join(BATCH_DIR).join(seq_name(1, ".json"));
    fs::write(&stale_batch, b"{}").unwrap();

    let (mut log, report) = open(dir.path());
    assert_eq!(report.uncommitted_bytes, 4 + leaf.len() as u64 + 3);
    let aside = report.moved_aside.unwrap();
    assert_eq!(
        fs::read(&aside).unwrap().len() as u64,
        report.uncommitted_bytes
    );
    assert_eq!(report.removed_stale, vec![stale_batch.clone()]);
    assert!(!stale_batch.exists());
    assert_eq!(
        fs::metadata(dir.path().join(LEAVES_FILE)).unwrap().len(),
        leaves_len
    );
    assert_eq!(log.size(), 1);
    // The next batch takes seq 1 and appends cleanly.
    let b = log.append_batch(vec![run("b", 2)], &signer(), 2).unwrap();
    assert_eq!(b.checkpoint.seq, 1);
    assert_proofs_verify(&log);
}

#[test]
fn a_torn_latest_checkpoint_is_moved_aside_with_its_leaves() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    log.append_batch(vec![run("a", 1)], &signer(), 1).unwrap();
    log.append_batch(vec![run("a", 2), run("b", 1)], &signer(), 2)
        .unwrap();
    drop(log);
    let sth = dir.path().join(STH_DIR).join(seq_name(1, ".json"));
    let bytes = fs::read(&sth).unwrap();
    fs::write(&sth, &bytes[..bytes.len() / 2]).unwrap();

    let (log, report) = open(dir.path());
    assert!(report.torn_checkpoint.is_some());
    assert!(!sth.exists());
    assert_eq!(log.size(), 1);
    assert_eq!(log.next_seq(), 1);
    assert!(report.moved_aside.is_some());
    assert_eq!(report.removed_stale.len(), 1, "batch index of seq 1");
    assert_eq!(log.latest_leaf(LeafType::Run, b"a").unwrap().entries, 1);
}

#[test]
fn damage_inside_the_checkpointed_prefix_is_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    log.append_batch(vec![run("a", 1), run("b", 1)], &signer(), 1)
        .unwrap();
    log.append_batch(vec![run("a", 2)], &signer(), 2).unwrap();
    drop(log);
    let path = dir.path().join(LEAVES_FILE);
    let good = fs::read(&path).unwrap();
    let corrupt = |dir: &Path| {
        matches!(
            AnchorLog::open_with_chunk_bits(dir, 2),
            Err(AnchorError::Corrupt(_))
        )
    };

    // A flipped byte in a leaf's head: the root no longer matches.
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 20] ^= 1;
    fs::write(&path, &bad).unwrap();
    assert!(corrupt(dir.path()));

    // A leaf that no longer decodes.
    let mut bad = good.clone();
    bad[LEAVES_HEADER_LEN as usize + 4] = b'X';
    fs::write(&path, &bad).unwrap();
    assert!(corrupt(dir.path()));

    // Leaves missing that a checkpoint covers.
    fs::write(&path, &good[..good.len() - 10]).unwrap();
    assert!(corrupt(dir.path()));

    // A checkpoint re-signed over another root (consistent JSON, valid
    // signature, wrong tree).
    fs::write(&path, &good).unwrap();
    let sth = dir.path().join(STH_DIR).join(seq_name(0, ".json"));
    let doc = Json::parse_bytes(&fs::read(&sth).unwrap()).unwrap();
    let stored = StoredCheckpoint::from_json(&doc).unwrap();
    let forged = StoredCheckpoint {
        signed: signer().sign_checkpoint(2, [9; 32]).unwrap(),
        ..stored
    };
    fs::write(&sth, json_file_bytes(&forged.to_json())).unwrap();
    assert!(corrupt(dir.path()));
}

#[test]
fn a_missing_checkpoint_file_is_reported_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    for i in 0..3 {
        log.append_batch(vec![run("a", i + 1)], &signer(), i)
            .unwrap();
    }
    drop(log);
    fs::remove_file(dir.path().join(STH_DIR).join(seq_name(1, ".json"))).unwrap();
    let (log, report) = open(dir.path());
    assert_eq!(report.missing_seqs, vec![1]);
    assert_eq!(log.next_seq(), 3);
    // Leaf 1 is now proven under checkpoint 2.
    assert_eq!(log.checkpoint_for_leaf(1).unwrap().seq, 2);
}

#[test]
fn checkpoint_files_are_strict() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    let b = log.append_batch(vec![run("a", 1)], &signer(), 7).unwrap();
    let doc = b.checkpoint.to_json();
    assert_eq!(StoredCheckpoint::from_json(&doc).unwrap(), b.checkpoint);
    let mut extra = doc.clone();
    if let Json::Object(m) = &mut extra {
        m.push(("extra".into(), Json::Null));
    }
    assert!(StoredCheckpoint::from_json(&extra).is_err());
    let mut wrong_size = doc.clone();
    if let Json::Object(m) = &mut wrong_size {
        m.retain(|(k, _)| k != "tree_size");
        m.push(("tree_size".into(), 2u64.into()));
    }
    assert!(StoredCheckpoint::from_json(&wrong_size).is_err());
}

#[test]
fn witness_records_are_write_once_and_torn_ones_are_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = open(dir.path());
    log.append_batch(vec![run("a", 1)], &signer(), 1).unwrap();
    let record = WitnessRecord {
        seq: 0,
        label: "tsa-0123abcd".into(),
        kind: WitnessKind::Rfc3161,
        operator: "digicert".into(),
        time: 100,
        recorded_at: 101,
        object: Json::Object(vec![("type".into(), "rfc3161".into())]),
    };
    assert!(log.store_witness(&record).unwrap());
    let second = WitnessRecord {
        time: 200,
        ..record.clone()
    };
    assert!(!log.store_witness(&second).unwrap(), "first result wins");
    assert_eq!(log.witnesses(0).unwrap(), vec![record.clone()]);
    // A torn file (crash mid-write) counts for nothing and is replaced.
    let path = dir
        .path()
        .join(WITNESS_DIR)
        .join(seq_name(0, ""))
        .join("tsa-0123abcd.json");
    fs::write(&path, b"{\"seq\":").unwrap();
    assert!(log.witnesses(0).unwrap().is_empty());
    assert!(log.store_witness(&second).unwrap());
    assert_eq!(log.witnesses(0).unwrap(), vec![second]);
    // Unknown checkpoints and unsafe labels are refused.
    let unknown = WitnessRecord {
        seq: 5,
        ..record.clone()
    };
    assert!(log.store_witness(&unknown).is_err());
    let unsafe_label = WitnessRecord {
        label: "../x".into(),
        ..record
    };
    assert!(log.store_witness(&unsafe_label).is_err());
}

/// A log of 100,000 leaves in 20 batches: a restart rebuilds it, and
/// proofs read from disk verify.
#[test]
fn large_log_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (mut log, _) = AnchorLog::open(dir.path()).unwrap();
    let s = signer();
    for batch in 0..20u64 {
        let leaves = (0..5000u64)
            .map(|r| run(&format!("r{r:05}"), batch + 1))
            .collect();
        log.append_batch(leaves, &s, batch).unwrap();
    }
    assert_eq!(log.size(), 100_000);
    let latest = log.latest_checkpoint().unwrap();
    drop(log);
    let (log, report) = AnchorLog::open(dir.path()).unwrap();
    assert_eq!(report.leaves, 100_000);
    for index in [0u64, 1, 4999, 50_000, 99_999] {
        let meta = log.checkpoint_for_leaf(index).unwrap();
        let leaf = log.read_leaf(index).unwrap();
        let proof = log.inclusion_proof(index, meta.tree_size).unwrap();
        assert!(verify_inclusion(
            &leaf.hash(),
            index,
            meta.tree_size,
            &proof,
            &meta.root
        ));
        let c = log
            .consistency_proof(meta.tree_size, latest.tree_size)
            .unwrap();
        assert!(verify_consistency(
            meta.tree_size,
            latest.tree_size,
            &meta.root,
            &latest.root,
            &c
        ));
    }
    let chain = log.leaf_chain(LeafType::Run, b"r00042").unwrap();
    assert_eq!(chain.len(), 20);
    assert!(chain
        .windows(2)
        .all(|w| w[1].1.prev_leaf_index == Some(w[0].0)));
}
