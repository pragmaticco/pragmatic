//! The deployment files (design 4.7 and 4.15): the pinned TSA anchors in
//! `deploy/tsa-roots/`, their documented fingerprints, and the example
//! configuration that uses them.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::tsa::openssl_usable;
use pragmatic::encoding::hex_encode;
use pragmatic_anchor::tsa::{anchor_fingerprints, check_operator_anchors, TsaConfig};
use pragmatic_server::config::Config;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn roots_dir() -> PathBuf {
    repo().join("deploy/tsa-roots")
}

/// `file -> (operator, fingerprint as lowercase hex)` from the README's
/// first table.
fn documented() -> HashMap<String, (String, String)> {
    let text = std::fs::read_to_string(roots_dir().join("README.md")).unwrap();
    let mut out = HashMap::new();
    for line in text.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // | file | operator | service | certificate | kind | fingerprint | until |
        if cells.len() != 9 || !cells[1].ends_with(".pem`") {
            continue;
        }
        let file = cells[1].trim_matches('`').to_string();
        let operator = cells[2].trim_matches('`').to_string();
        let fp = cells[6].trim_matches('`').replace(':', "").to_lowercase();
        out.insert(file, (operator, fp));
    }
    out
}

#[test]
fn every_pinned_anchor_matches_its_documented_fingerprint() {
    let table = documented();
    let mut files: Vec<String> = std::fs::read_dir(roots_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".pem"))
        .collect();
    files.sort();
    assert_eq!(files.len(), table.len(), "{files:?} vs {table:?}");
    let mut configs = Vec::new();
    for file in &files {
        let (operator, fp) = table
            .get(file)
            .unwrap_or_else(|| panic!("{file} is undocumented"));
        assert_eq!(file, &format!("{operator}.pem"), "one file per operator");
        let anchors = anchor_fingerprints(&roots_dir().join(file)).unwrap();
        assert_eq!(anchors.len(), 1, "{file} holds one certificate");
        assert_eq!(&hex_encode(&anchors[0]), fp, "{file}");
        configs
            .push(TsaConfig::new("https://tsa.example", operator, roots_dir().join(file)).unwrap());
    }
    // No two operators share an anchor.
    check_operator_anchors(&configs.iter().collect::<Vec<_>>()).unwrap();
}

#[test]
fn the_example_configuration_pins_digicert_and_sectigo_by_operator() {
    let text = std::fs::read_to_string(repo().join("deploy/pragmatic.example.toml")).unwrap();
    let config = Config::parse(&text).unwrap();
    let table = documented();
    let tsas: Vec<(String, String)> = config
        .anchoring
        .tsa
        .iter()
        .map(|t| (t.operator.clone(), t.url.clone()))
        .collect();
    assert_eq!(
        tsas,
        [
            (
                "digicert".to_string(),
                "http://timestamp.digicert.com".to_string()
            ),
            (
                "sectigo".to_string(),
                "http://timestamp.sectigo.com".to_string()
            ),
        ]
    );
    for t in &config.anchoring.tsa {
        let file = t
            .roots_pem
            .strip_prefix("/etc/pragmatic/tsa-roots")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let (operator, _) = &table[&file];
        assert_eq!(operator, &t.operator, "{file}");
        assert!(roots_dir().join(&file).is_file());
    }
    assert_eq!(config.anchoring.min_independent_operators, 2);
    // The container image puts the files where the example looks.
    let dockerfile = std::fs::read_to_string(repo().join("Dockerfile")).unwrap();
    assert!(dockerfile.contains("COPY deploy/tsa-roots /etc/pragmatic/tsa-roots"));
}

/// The recorded tokens of `crates/pragmatic/tests/fixtures/tsp/` verify
/// against their operator's pinned file and against no other: the issuing
/// CAs are narrow enough that QuoVadis EU (also DigiCert) does not pass
/// as `timestamp.digicert.com`.
#[test]
fn recorded_tokens_verify_only_against_their_operators_anchor() {
    if !openssl_usable() {
        return;
    }
    let fixtures = repo().join("crates/pragmatic/tests/fixtures/tsp");
    let verifies = |name: &str, file: &str| {
        let out = Command::new("openssl")
            .args(["ts", "-verify", "-in"])
            .arg(fixtures.join(format!("{name}.tsr")))
            .arg("-queryfile")
            .arg(fixtures.join(format!("{name}.tsq")))
            .arg("-CAfile")
            .arg(roots_dir().join(file))
            .arg("-partial_chain")
            // The day the tokens were recorded, so the check does not
            // depend on today's date once a TSA certificate expires.
            .args(["-attime", "1791910800"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Verification: OK")
    };
    for (token, own) in [("digicert", "digicert.pem"), ("microsoft", "microsoft.pem")] {
        assert!(verifies(token, own), "{token} against {own}");
        for other in [
            "digicert.pem",
            "sectigo.pem",
            "microsoft.pem",
            "globalsign.pem",
            "freetsa.pem",
        ] {
            if other != own {
                assert!(!verifies(token, other), "{token} against {other}");
            }
        }
    }
    assert!(!verifies("quovadis", "digicert.pem"));
}
