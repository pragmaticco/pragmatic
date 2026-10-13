//! Every endpoint, for every role, on a run inside and outside the token's
//! scopes (design 4.3 and 4.4).
//!
//! "Allowed" means the request got past authentication, role and scope:
//! whatever it answers, it is not 401, 403 or 404. Out-of-scope run
//! endpoints answer 404, exactly like a run that does not exist; only `PUT`
//! answers 403 for an out-of-scope id.

mod common;

use common::*;
use pragmatic_server::config::WitnessOrigin;
use pragmatic_server::tokens::token_sha256;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Agent,
    Auditor,
    AuditorRaw,
    Admin,
    Witness,
}

const ROLES: [Role; 5] = [
    Role::Agent,
    Role::Auditor,
    Role::AuditorRaw,
    Role::Admin,
    Role::Witness,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Allowed,
    Forbidden,
    NotFound,
}

use Expect::*;

/// One endpoint: how to call it on a run, and what each role should get
/// in scope and out of scope.
struct Case {
    name: &'static str,
    method: Method,
    path: fn(&str) -> String,
    body: fn() -> Option<Vec<u8>>,
    expect: fn(Role, bool) -> Expect,
}

fn none() -> Option<Vec<u8>> {
    None
}

fn readers(r: Role, inside: bool) -> Expect {
    match r {
        Role::Witness => Forbidden,
        Role::Admin => Allowed,
        _ if inside => Allowed,
        _ => NotFound,
    }
}

fn writers(r: Role, inside: bool) -> Expect {
    match r {
        Role::Agent if inside => Allowed,
        Role::Agent => NotFound,
        Role::Admin => Allowed,
        _ => Forbidden,
    }
}

fn admin_only(r: Role, _: bool) -> Expect {
    if r == Role::Admin {
        Allowed
    } else {
        Forbidden
    }
}

fn auditors(r: Role, inside: bool) -> Expect {
    match r {
        Role::Admin => Allowed,
        Role::Auditor | Role::AuditorRaw if inside => Allowed,
        Role::Auditor | Role::AuditorRaw => NotFound,
        _ => Forbidden,
    }
}

fn anchor_readers(r: Role, _: bool) -> Expect {
    match r {
        Role::Admin | Role::Auditor | Role::AuditorRaw => Allowed,
        _ => Forbidden,
    }
}

fn anyone(_: Role, _: bool) -> Expect {
    Allowed
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "info",
            method: Method::GET,
            path: |_| "/v1/info".into(),
            body: none,
            expect: anyone,
        },
        Case {
            name: "whoami",
            method: Method::GET,
            path: |_| "/v1/whoami".into(),
            body: none,
            expect: anyone,
        },
        Case {
            name: "keys",
            method: Method::GET,
            path: |_| "/v1/keys".into(),
            body: none,
            expect: anyone,
        },
        Case {
            name: "list runs",
            method: Method::GET,
            path: |_| "/v1/runs".into(),
            body: none,
            expect: |r, _| {
                if r == Role::Witness {
                    Forbidden
                } else {
                    Allowed
                }
            },
        },
        Case {
            name: "get run",
            method: Method::GET,
            path: |id| run_path(id, ""),
            body: none,
            expect: readers,
        },
        Case {
            name: "entries",
            method: Method::GET,
            path: |id| run_path(id, "/entries"),
            body: none,
            expect: readers,
        },
        Case {
            name: "slot",
            method: Method::GET,
            path: |id| run_path(id, "/entries/2/slots/0"),
            body: none,
            expect: readers,
        },
        Case {
            name: "journal",
            method: Method::GET,
            path: |id| run_path(id, "/journal"),
            body: none,
            expect: |r, inside| match r {
                Role::Admin => Allowed,
                Role::AuditorRaw if inside => Allowed,
                Role::Agent | Role::Auditor | Role::AuditorRaw if !inside => NotFound,
                _ => Forbidden,
            },
        },
        Case {
            name: "create",
            method: Method::PUT,
            path: |id| run_path(&format!("{id}.new"), ""),
            body: || Some(pragmatic::journal::header(0).to_vec()),
            expect: |r, inside| match r {
                Role::Admin => Allowed,
                Role::Agent if inside => Allowed,
                _ => Forbidden,
            },
        },
        Case {
            name: "lease",
            method: Method::POST,
            path: |id| run_path(id, "/lease"),
            body: || Some(br#"{"holder":"matrix"}"#.to_vec()),
            expect: writers,
        },
        Case {
            name: "release",
            method: Method::DELETE,
            path: |id| run_path(id, "/lease"),
            body: none,
            expect: writers,
        },
        Case {
            name: "frames",
            method: Method::POST,
            path: |id| run_path(id, "/frames?at=0"),
            body: || Some(vec![1, 2, 3]),
            expect: writers,
        },
        Case {
            name: "evidence",
            method: Method::GET,
            path: |id| run_path(id, "/evidence"),
            body: none,
            expect: auditors,
        },
        Case {
            name: "erase",
            method: Method::POST,
            path: |id| run_path(id, "/erase"),
            body: || {
                Some(br#"{"slots":[[2,0]],"reason_code":"test","allow_unfinished":true}"#.to_vec())
            },
            expect: admin_only,
        },
        Case {
            name: "accept-regression",
            method: Method::POST,
            path: |id| run_path(id, "/accept-regression"),
            body: none,
            expect: admin_only,
        },
        Case {
            name: "add hold",
            method: Method::POST,
            path: |_| "/v1/holds".into(),
            body: || Some(br#"{"matter":"m","scope":{"prefix":"zzz:"}}"#.to_vec()),
            expect: admin_only,
        },
        Case {
            name: "list holds",
            method: Method::GET,
            path: |_| "/v1/holds".into(),
            body: none,
            expect: admin_only,
        },
        Case {
            name: "remove hold",
            method: Method::DELETE,
            path: |_| "/v1/holds/hold_missing".into(),
            body: none,
            expect: |r, _| {
                if r == Role::Admin {
                    NotFound
                } else {
                    Forbidden
                }
            },
        },
        Case {
            name: "subjects",
            method: Method::POST,
            path: |_| "/v1/subjects/search".into(),
            body: || Some(br#"{"subject":"user-1"}"#.to_vec()),
            expect: admin_only,
        },
        Case {
            name: "retention",
            method: Method::POST,
            path: |_| "/v1/retention/run".into(),
            body: none,
            expect: admin_only,
        },
        Case {
            name: "verify-data",
            method: Method::POST,
            path: |_| "/v1/verify-data".into(),
            body: none,
            expect: admin_only,
        },
        Case {
            name: "anchors",
            method: Method::GET,
            path: |_| "/v1/anchors".into(),
            body: none,
            expect: anchor_readers,
        },
        Case {
            name: "anchor log",
            method: Method::GET,
            path: |_| "/v1/anchors/log".into(),
            body: none,
            expect: anchor_readers,
        },
        Case {
            name: "one anchor",
            method: Method::GET,
            path: |_| "/v1/anchors/0".into(),
            body: none,
            // No checkpoint exists, so the allowed answer is 404 here.
            expect: |r, _| match r {
                Role::Admin | Role::Auditor | Role::AuditorRaw => NotFound,
                _ => Forbidden,
            },
        },
        Case {
            name: "audit for a run",
            method: Method::GET,
            path: |id| format!("/v1/audit?run_id={id}"),
            body: none,
            expect: auditors,
        },
        Case {
            name: "audit",
            method: Method::GET,
            path: |_| "/v1/audit".into(),
            body: none,
            expect: anchor_readers,
        },
        Case {
            name: "issue token",
            method: Method::POST,
            path: |_| "/v1/tokens".into(),
            body: || {
                Some(br#"{"name":"n","principal":"p","role":"auditor","scopes":["*"]}"#.to_vec())
            },
            expect: admin_only,
        },
        Case {
            name: "list tokens",
            method: Method::GET,
            path: |_| "/v1/tokens".into(),
            body: none,
            expect: admin_only,
        },
        Case {
            name: "revoke token",
            method: Method::DELETE,
            path: |_| "/v1/tokens/tok_missing".into(),
            body: none,
            expect: |r, _| {
                if r == Role::Admin {
                    NotFound
                } else {
                    Forbidden
                }
            },
        },
        Case {
            name: "witness",
            method: Method::POST,
            path: |_| "/v1/witness".into(),
            body: || Some(b"garbage".to_vec()),
            expect: |r, _| {
                if r == Role::Witness {
                    Allowed
                } else {
                    Forbidden
                }
            },
        },
        Case {
            name: "add-checkpoint",
            method: Method::POST,
            path: |_| "/add-checkpoint".into(),
            body: || Some(b"garbage".to_vec()),
            expect: |r, _| {
                if r == Role::Witness {
                    Allowed
                } else {
                    Forbidden
                }
            },
        },
        Case {
            name: "witness log",
            method: Method::GET,
            path: |_| "/v1/witness/log/example.com%2Flog".into(),
            body: none,
            expect: |r, _| match r {
                Role::Admin => Allowed,
                Role::Auditor | Role::AuditorRaw => NotFound,
                _ => Forbidden,
            },
        },
    ]
}

fn classify(status: StatusCode) -> Expect {
    match status.as_u16() {
        403 => Forbidden,
        404 => NotFound,
        _ => Allowed,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_endpoint_for_every_role_in_and_out_of_scope() {
    let log_key = pragmatic_server::keys::ServerKey::generate().unwrap();
    let vkey = pragmatic::note::VerifierKey::new(
        "example.com/log",
        pragmatic::note::SignatureType::Ed25519,
        log_key.public_key(),
    )
    .unwrap()
    .encode();
    let ts = TestServer::start(|c| {
        c.witness_mode.enabled = true;
        c.witness_mode.origins.push(WitnessOrigin {
            name: "example.com/log".into(),
            token_sha256: token_sha256("prag_witness_client"),
            public_key: vkey,
        });
    })
    .await;
    let (writer_token, _) = ts.issue("agent", &["*"], false).await;
    for run in ["a:in", "b:out"] {
        let mut w = Writer::create(&ts, &writer_token, run).await;
        w.attempt(&ts, 2).await;
    }
    let tokens = [
        ts.issue("agent", &["a:"], false).await.0,
        ts.issue("auditor", &["a:"], false).await.0,
        ts.issue("auditor", &["a:"], true).await.0,
        ts.admin.clone(),
        "prag_witness_client".to_string(),
    ];
    let mut failures = Vec::new();
    for case in cases() {
        for (role, token) in ROLES.iter().zip(&tokens) {
            for (run, inside) in [("a:in", true), ("b:out", false)] {
                let mut req = ts.req(case.method.clone(), &(case.path)(run), token);
                if let Some(b) = (case.body)() {
                    req = req.header("content-type", "application/json").body(b);
                }
                let resp = req.send().await.unwrap();
                let status = resp.status();
                let got = classify(status);
                let want = (case.expect)(*role, inside);
                if got != want {
                    let body = resp.text().await.unwrap_or_default();
                    failures.push(format!(
                        "{} as {role:?} on {run}: want {want:?}, got {status} {body}",
                        case.name
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lists_and_access_logs_are_filtered_by_scope() {
    let ts = TestServer::start(|_| {}).await;
    let (w_token, _) = ts.issue("agent", &["*"], false).await;
    for run in ["a:1", "a:2", "b:1"] {
        Writer::create(&ts, &w_token, run)
            .await
            .attempt(&ts, 1)
            .await;
    }
    let (agent, _) = ts.issue("agent", &["a:"], false).await;
    let v: Value = ts.get("/v1/runs", &agent).await.json().await.unwrap();
    let ids: Vec<&str> = v["runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["run_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["a:1", "a:2"]);
    let v: Value = ts
        .get("/v1/runs?limit=1", &agent)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["runs"].as_array().unwrap().len(), 1);
    assert_eq!(v["next"], "a:1");
    let v: Value = ts
        .get("/v1/runs?after=a:1", &agent)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["runs"][0]["run_id"], "a:2");

    let (auditor, _) = ts.issue("auditor", &["a:"], false).await;
    let v: Value = ts.get("/v1/audit", &auditor).await.json().await.unwrap();
    let runs: Vec<&str> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["run_id"].as_str())
        .collect();
    assert!(!runs.is_empty());
    assert!(runs.iter().all(|r| r.starts_with("a:")), "{runs:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthenticated_and_revoked_tokens_get_401() {
    let ts = TestServer::start(|_| {}).await;
    let resp = ts
        .client
        .get(format!("{}/v1/info", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(resp).await,
        (StatusCode::UNAUTHORIZED, "unauthorized".into())
    );
    let resp = ts.get("/v1/info", "prag_wrong").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let (token, id) = ts.issue("auditor", &["*"], false).await;
    assert_eq!(ts.get("/v1/whoami", &token).await.status(), StatusCode::OK);
    let resp = ts
        .req(Method::DELETE, &format!("/v1/tokens/{id}"), &ts.admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        ts.get("/v1/whoami", &token).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // Health endpoints need no token.
    let resp = ts
        .client
        .get(format!("{}/healthz", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = ts
        .client
        .get(format!("{}/readyz", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let metrics = ts
        .client
        .get(format!("{}/metrics", ts.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("pragmatic_tokens_total{kind=\"rejected\"} 2"),
        "{metrics}"
    );
    // Failed attempts are logged with a fingerprint, never the credential.
    let records = ts.audit().await;
    let failed: Vec<&Value> = records.iter().filter(|r| r["status"] == 401).collect();
    assert!(failed
        .iter()
        .any(|r| r["token_fp"] == token_sha256("prag_wrong")[..8]));
    let text = serde_json::to_string(&records).unwrap();
    assert!(!text.contains("prag_wrong"));
    assert!(!text.contains(&token));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whoami_and_info() {
    let ts = TestServer::start(|c| c.license.licensee = "Example Corp".into()).await;
    let (token, id) = ts.issue("auditor", &["x:"], true).await;
    let v: Value = ts.get("/v1/whoami", &token).await.json().await.unwrap();
    assert_eq!(
        v,
        json!({"token_id": id, "name": "auditor test", "principal": "auditor@example.test",
                         "role": "auditor", "scopes": ["x:"]})
    );
    let v: Value = ts.get("/v1/info", &token).await.json().await.unwrap();
    assert_eq!(v["api_version"], 1);
    assert_eq!(v["journal_format"], 2);
    assert_eq!(v["chain"], "sha256");
    assert_eq!(v["licensee"], "Example Corp");
    assert_eq!(v["independent_witness"], false);
    let v: Value = ts.get("/v1/keys", &token).await.json().await.unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
}
