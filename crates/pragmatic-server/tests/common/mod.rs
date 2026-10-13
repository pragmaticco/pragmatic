//! An in-process server on a random port with a temporary data directory,
//! and a client-side journal that writes to it the way an SDK does.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{self, META, ROOT};
use pragmatic::{Content, Event, Journal};
use pragmatic_server::config::Config;
use pragmatic_server::hooks::InstantAnchoring;
use pragmatic_server::keys::ServerKey;
use pragmatic_server::server::{self, Hooks, ServerHandle};
use pragmatic_server::tokens;
use reqwest::{Method, Response, StatusCode};
use serde_json::{json, Value};

/// A directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> TempDir {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "pragmatic-server-it-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running test server.
pub struct TestServer {
    pub handle: Option<ServerHandle>,
    pub dir: Arc<TempDir>,
    pub config: Config,
    pub admin: String,
    pub url: String,
    pub client: reqwest::Client,
    pub anchoring: Option<Arc<InstantAnchoring>>,
}

/// A config for a test server in `dir`.
pub fn test_config(dir: &Path) -> Config {
    let mut c = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: dir.join("data"),
        lease_ttl_secs: 2,
        ..Config::default()
    };
    c.anchoring.allow_self_anchoring = true;
    c.keys.signing_key_file = dir.join("keys").join("server.ed25519");
    c.name = "test.example".into();
    c
}

/// The admin token value every test server accepts.
pub fn admin_token() -> String {
    "prag_test_admin_token".into()
}

impl TestServer {
    pub async fn start(customize: impl FnOnce(&mut Config)) -> TestServer {
        TestServer::start_with(customize, false).await
    }

    /// Start with [`InstantAnchoring`] instead of the stub.
    pub async fn start_anchored(customize: impl FnOnce(&mut Config)) -> TestServer {
        TestServer::start_with(customize, true).await
    }

    async fn start_with(customize: impl FnOnce(&mut Config), anchored: bool) -> TestServer {
        let dir = Arc::new(TempDir::new("srv"));
        let mut config = test_config(dir.path());
        config.bootstrap.admin_token_sha256 = tokens::token_sha256(&admin_token());
        customize(&mut config);
        if !config.keys.signing_key_file.exists() {
            ServerKey::generate()
                .unwrap()
                .write_new(&config.keys.signing_key_file)
                .unwrap();
        }
        TestServer::boot(
            dir,
            config,
            anchored.then(|| Arc::new(InstantAnchoring::default())),
        )
        .await
    }

    /// Start (again) on an existing directory and config.
    pub async fn boot(
        dir: Arc<TempDir>,
        config: Config,
        anchoring: Option<Arc<InstantAnchoring>>,
    ) -> TestServer {
        let mut hooks = Hooks::stubs(&config);
        if let Some(a) = &anchoring {
            hooks.anchoring = a.clone();
        }
        TestServer::boot_hooks(dir, config, anchoring, hooks).await
    }

    /// Start with hooks of the test's choosing (anchoring is
    /// [`InstantAnchoring`] unless the closure replaces it).
    pub async fn start_hooked(
        customize: impl FnOnce(&mut Config),
        hooks: impl FnOnce(&mut Hooks),
    ) -> TestServer {
        let dir = Arc::new(TempDir::new("srv"));
        let mut config = test_config(dir.path());
        config.bootstrap.admin_token_sha256 = tokens::token_sha256(&admin_token());
        customize(&mut config);
        ServerKey::generate()
            .unwrap()
            .write_new(&config.keys.signing_key_file)
            .unwrap();
        let anchoring = Arc::new(InstantAnchoring::default());
        let mut h = Hooks::stubs(&config);
        h.anchoring = anchoring.clone();
        hooks(&mut h);
        TestServer::boot_hooks(dir, config, Some(anchoring), h).await
    }

    async fn boot_hooks(
        dir: Arc<TempDir>,
        config: Config,
        anchoring: Option<Arc<InstantAnchoring>>,
        hooks: Hooks,
    ) -> TestServer {
        let handle = server::start(config.clone(), [0u8; 32], hooks)
            .await
            .expect("server starts");
        handle.wait_ready().await;
        TestServer {
            url: handle.url(),
            handle: Some(handle),
            dir,
            config,
            admin: admin_token(),
            client: reqwest::Client::new(),
            anchoring,
        }
    }

    /// Stop the server, keeping its directory.
    pub async fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await.unwrap();
        }
    }

    /// Stop and start again on the same data.
    pub async fn restart(mut self) -> TestServer {
        self.stop().await;
        let (dir, config, anchoring) = (
            self.dir.clone(),
            self.config.clone(),
            self.anchoring.clone(),
        );
        drop(self);
        TestServer::boot(dir, config, anchoring).await
    }

    pub fn app(&self) -> &pragmatic_server::server::App {
        &self.handle.as_ref().expect("running").app
    }

    pub fn data_dir(&self) -> PathBuf {
        self.config.data_dir.clone()
    }

    /// A request with a bearer token.
    pub fn req(&self, method: Method, path: &str, token: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.url, path))
            .bearer_auth(token)
    }

    pub async fn get(&self, path: &str, token: &str) -> Response {
        self.req(Method::GET, path, token).send().await.unwrap()
    }

    pub async fn post_json(&self, path: &str, token: &str, body: Value) -> Response {
        self.req(Method::POST, path, token)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap()
    }

    /// Issue a token through the API; returns its value and id.
    pub async fn issue(&self, role: &str, scopes: &[&str], view_raw: bool) -> (String, String) {
        let resp = self
            .post_json(
                "/v1/tokens",
                &self.admin,
                json!({"name": format!("{role} test"), "principal": format!("{role}@example.test"),
                       "role": role, "scopes": scopes, "view_raw": view_raw}),
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "{}",
            resp.text().await.unwrap()
        );
        let v: Value = resp.json().await.unwrap();
        (
            v["token"].as_str().unwrap().to_string(),
            v["record"]["id"].as_str().unwrap().to_string(),
        )
    }

    /// Every access-log record, as admin.
    pub async fn audit(&self) -> Vec<Value> {
        // Records are queued when responses are sent; wait until every
        // record so far is durable, as a reader a moment later would see.
        self.app().access.flush().await.unwrap();
        let mut out = Vec::new();
        let mut after: Option<u64> = None;
        loop {
            let path = match after {
                Some(a) => format!("/v1/audit?limit=1000&after={a}"),
                None => "/v1/audit?limit=1000".to_string(),
            };
            let v: Value = self.get(&path, &self.admin).await.json().await.unwrap();
            out.extend(v["records"].as_array().unwrap().iter().cloned());
            match v["next"].as_u64() {
                Some(n) => after = Some(n),
                None => return out,
            }
        }
    }
}

/// `/v1/runs/{id}` with the id percent-encoded.
pub fn run_path(run: &str, rest: &str) -> String {
    let id = percent_encoding::utf8_percent_encode(run, percent_encoding::NON_ALPHANUMERIC);
    format!("/v1/runs/{id}{rest}")
}

/// A client's copy of a run's journal, written to the server the way an
/// SDK does it.
pub struct Writer {
    pub run: String,
    pub token: String,
    pub lease: String,
    pub journal: Journal,
}

pub fn note(kind: &str, data: Value, payload: Vec<Content>) -> Event {
    Event::Note {
        kind: kind.into(),
        data: data.to_string(),
        payload,
    }
}

pub fn recv(value: &str) -> Event {
    Event::ChannelRecv {
        channel: "in".into(),
        value: Content::from(value),
    }
}

impl Writer {
    /// PUT the run (which grants the lease) and append `run.start`.
    pub async fn create(ts: &TestServer, token: &str, run: &str) -> Writer {
        let resp = ts
            .req(Method::PUT, &run_path(run, ""), token)
            .body(journal::header(0).to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "{}",
            resp.text().await.unwrap()
        );
        let v: Value = resp.json().await.unwrap();
        let mut w = Writer {
            run: run.into(),
            token: token.into(),
            lease: v["lease"].as_str().unwrap().into(),
            journal: Journal::new(None),
        };
        w.journal
            .append(
                META,
                note(
                    "run.start",
                    json!({"run_id": run, "format": 2, "labels": {}}),
                    vec![],
                ),
            )
            .unwrap();
        w
    }

    /// Append on the root branch.
    pub fn add(&mut self, event: Event) -> u64 {
        let branch = if matches!(event, Event::Note { .. }) {
            META
        } else {
            ROOT
        };
        self.journal.append(branch, event).unwrap()
    }

    /// The pending frames, `at` and head, without sending.
    pub fn pending(&self) -> (u64, Vec<u8>, String, u64) {
        let (at, frames, head) = self.journal.pending().expect("pending frames");
        let k = self.journal.len() - at;
        (at, frames.to_vec(), hex_encode(&head), k)
    }

    /// Send the pending frames; on success mark them persisted.
    pub async fn push(&mut self, ts: &TestServer) -> Response {
        let (at, frames, head, k) = self.pending();
        let resp = send_frames(
            ts,
            &self.token,
            &self.run,
            &self.lease,
            at,
            k,
            &head,
            frames,
        )
        .await;
        if resp.status() == StatusCode::OK {
            self.journal.mark_persisted(self.journal.len());
        }
        resp
    }

    /// Append a full attempt: attempt.start, `n` receives, attempt.end ok.
    pub async fn attempt(&mut self, ts: &TestServer, n: usize) {
        self.add(note(
            "attempt.start",
            json!({"attempt": 1, "mode": "run"}),
            vec![],
        ));
        for i in 0..n {
            self.add(recv(&format!("message {i}")));
        }
        self.add(note(
            "attempt.end",
            json!({"attempt": 1, "outcome": "ok"}),
            vec![],
        ));
        let resp = self.push(ts).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.text().await.unwrap()
        );
    }

    /// DELETE the lease.
    pub async fn release(&self, ts: &TestServer) -> Response {
        ts.req(Method::DELETE, &run_path(&self.run, "/lease"), &self.token)
            .header("pragmatic-lease", &self.lease)
            .send()
            .await
            .unwrap()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn send_frames(
    ts: &TestServer,
    token: &str,
    run: &str,
    lease: &str,
    at: u64,
    k: u64,
    head: &str,
    frames: Vec<u8>,
) -> Response {
    ts.req(
        Method::POST,
        &run_path(run, &format!("/frames?at={at}")),
        token,
    )
    .header("pragmatic-lease", lease)
    .header("pragmatic-frames", k.to_string())
    .header("pragmatic-head", head)
    .body(frames)
    .send()
    .await
    .unwrap()
}

/// The error code of a JSON error response.
pub async fn code(resp: Response) -> (StatusCode, String) {
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    (
        status,
        v["error"]["code"].as_str().unwrap_or("").to_string(),
    )
}

/// The server's stored journal of a run, parsed.
pub fn stored(ts: &TestServer, run: &str) -> Journal {
    let stem = pragmatic_server::layout::stem(run);
    let path = ts
        .data_dir()
        .join("runs")
        .join(&stem[..2])
        .join(format!("{stem}.journal"));
    Journal::parse(&std::fs::read(path).unwrap(), None)
        .unwrap()
        .journal
}
