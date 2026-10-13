//! The `pragmatic-server` binary's subcommands (design 4.1 and 4.13).

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::*;
use pragmatic_server::config::Config;
use reqwest::StatusCode;
use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pragmatic-server"))
}

fn write_config(dir: &Path, config: &Config) -> std::path::PathBuf {
    let path = dir.join("pragmatic.toml");
    std::fs::write(&path, toml::to_string(config).unwrap()).unwrap();
    path
}

fn run(cmd: &mut Command) -> (bool, String, String) {
    let Output {
        status,
        stdout,
        stderr,
    } = cmd.output().unwrap();
    (
        status.success(),
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_subcommands_talk_to_a_running_server() {
    let ts = TestServer::start(|_| {}).await;
    let cfg = write_config(ts.dir.path(), &ts.config);
    let url = ts.url.clone();
    let admin = ts.admin.clone();
    let out = tokio::task::spawn_blocking(move || {
        let (ok, out, err) = run(bin()
            .args([
                "--config",
                cfg.to_str().unwrap(),
                "token",
                "--url",
                &url,
                "new",
            ])
            .args([
                "--name",
                "ci",
                "--principal",
                "svc-ci",
                "--role",
                "agent",
                "--scope",
                "ci:",
            ])
            .env("PRAGMATIC_TOKEN", &admin));
        assert!(ok, "{err}");
        let issued: Value = serde_json::from_str(&out).unwrap();
        let (ok, list, err) = run(bin()
            .args([
                "--config",
                cfg.to_str().unwrap(),
                "token",
                "--url",
                &url,
                "list",
            ])
            .env("PRAGMATIC_TOKEN", &admin));
        assert!(ok, "{err}");
        let id = issued["record"]["id"].as_str().unwrap().to_string();
        assert!(list.contains(&id));
        let (ok, _, err) = run(bin()
            .args([
                "--config",
                cfg.to_str().unwrap(),
                "token",
                "--url",
                &url,
                "revoke",
                &id,
            ])
            .env("PRAGMATIC_TOKEN", &admin));
        assert!(ok, "{err}");
        // Without an admin token the command explains itself and fails.
        let (ok, _, err) = run(bin()
            .args([
                "--config",
                cfg.to_str().unwrap(),
                "token",
                "--url",
                &url,
                "list",
            ])
            .env_remove("PRAGMATIC_TOKEN"));
        assert!(!ok && err.contains("PRAGMATIC_TOKEN"), "{err}");
        issued
    })
    .await
    .unwrap();
    let value = out["token"].as_str().unwrap();
    assert_eq!(
        ts.get("/v1/whoami", value).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn token_bootstrap_prints_a_token_and_its_hash() {
    let (ok, out, _) = run(bin().args(["token", "bootstrap"]));
    assert!(ok);
    let token = out.lines().next().unwrap().strip_prefix("token ").unwrap();
    assert!(out.contains(&pragmatic_server::tokens::token_sha256(token)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keygen_rotation_backup_verify_data_and_migrate() {
    let dir = TempDir::new("cli");
    let mut config = test_config(dir.path());
    config.bootstrap.admin_token_sha256 = pragmatic_server::tokens::token_sha256(&admin_token());
    let cfg = write_config(dir.path(), &config);
    let c = cfg.to_str().unwrap().to_string();

    // keygen writes a key and refuses to overwrite it.
    let (ok, out, err) = run(bin().args(["--config", &c, "keygen"]));
    assert!(ok, "{err}");
    assert!(out.contains("key_id "));
    let (ok, _, err) = run(bin().args(["--config", &c, "keygen"]));
    assert!(!ok && err.contains("--rotate"), "{err}");

    // Start, write a run, stop.
    let data_dir = config.data_dir.clone();
    let mut ts = TestServer::boot(
        std::sync::Arc::new(TempDir(dir.path().join("unused"))),
        config.clone(),
        None,
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    Writer::create(&ts, &agent, "r").await.attempt(&ts, 1).await;
    let old_key = ts.app().key.key_id();
    ts.stop().await;
    let old_backup = dir.path().join("old-backup");
    pragmatic_server::ops::backup(&config, &old_backup).unwrap();

    // Rotation: both keys in the ring, a signed record in the access log.
    let (ok, out, err) = run(bin().args(["--config", &c, "keygen", "--rotate"]));
    assert!(ok, "{err}");
    assert!(out.contains("old key kept at"));
    let ring = pragmatic_server::keys::read_key_ring(&data_dir).unwrap();
    assert_eq!(ring.len(), 2);
    assert_eq!(ring[0].key_id, old_key);
    assert!(ring[0].not_after.is_some());

    // Offline verification is recorded in the access log.
    let (ok, out, err) = run(bin().args(["--config", &c, "verify-data", "--offline"]));
    assert!(ok, "{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["runs_checked"], 1);
    assert_eq!(v["runs_failing"], 0);

    // migrate on a current directory does nothing.
    let (ok, out, _) = run(bin().args(["--config", &c, "migrate"]));
    assert!(ok && out.contains("current"), "{out}");

    // The server starts with the new key and lists both.
    let ts = TestServer::boot(
        std::sync::Arc::new(TempDir(dir.path().join("unused2"))),
        config.clone(),
        None,
    )
    .await;
    let v: Value = ts.get("/v1/keys", &ts.admin).await.json().await.unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 2);
    assert_ne!(ts.app().key.key_id(), old_key);
    let records = ts.audit().await;
    assert!(records
        .iter()
        .any(|r| r["kind"] == "key.rotate" && r["old_key_id"] == old_key));
    assert!(records
        .iter()
        .any(|r| r["kind"] == "verify-data" && r["offline"] == true));

    // Online verify-data and a live backup through the binary.
    let url = ts.url.clone();
    let backup = dir.path().join("backup");
    let (c2, b2) = (c.clone(), backup.clone());
    tokio::task::spawn_blocking(move || {
        let (ok, out, err) = run(bin()
            .args(["--config", &c2, "verify-data", "--url", &url])
            .env("PRAGMATIC_TOKEN", admin_token()));
        assert!(ok, "{err}");
        assert!(out.contains("runs_checked"));
        let (ok, out, err) =
            run(bin().args(["--config", &c2, "backup", "--to", b2.to_str().unwrap()]));
        assert!(ok, "{err}");
        assert!(out.contains("backed up 1 runs"), "{out}");
    })
    .await
    .unwrap();
    let trusted = pragmatic_server::ops::trusted_keys(&config, &[]).unwrap();
    assert!(pragmatic_server::ops::verify_backup(&backup, &trusted).is_ok());
    // A backup signed before the rotation is still trusted: the retired key
    // is kept next to the new one.
    assert_eq!(trusted.len(), 2);
    assert!(pragmatic_server::ops::verify_backup(&old_backup, &trusted).is_ok());
}

#[test]
fn migrate_records_the_format_of_an_older_directory() {
    let dir = TempDir::new("migrate");
    let config = test_config(dir.path());
    let l = pragmatic_server::layout::Layout::new(config.data_dir.clone());
    std::fs::create_dir_all(l.runs_dir()).unwrap();
    std::fs::write(config.data_dir.join("tokens.json"), r#"{"tokens": []}"#).unwrap();
    assert!(pragmatic_server::layout::check_format(&l)
        .unwrap_err()
        .contains("migrate"));
    let out = pragmatic_server::ops::migrate(&config).unwrap();
    assert!(out.contains("recorded data format 1"), "{out}");
    pragmatic_server::layout::check_format(&l).unwrap();
}
