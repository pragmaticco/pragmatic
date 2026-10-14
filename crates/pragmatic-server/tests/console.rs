//! The integrated console (design 4.3 and 4.14) as a browser uses it:
//! signing in with a token, pages rendered with `pragmatic-console` under
//! a policy that loads nothing, redaction for viewers without `view_raw`,
//! anchoring status, evidence downloads, and the administrators' forms,
//! each refused without the session's CSRF token or from another site.

mod common;

use common::*;
use pragmatic_server::hooks::BatchReason;
use reqwest::{redirect, StatusCode};
use serde_json::Value;

/// A browser that does not follow redirects, with the cookies it holds.
struct Browser {
    client: reqwest::Client,
    url: String,
    cookies: Vec<String>,
}

fn csrf_of(html: &str) -> String {
    let at = html
        .find("name=\"csrf\" value=\"")
        .expect("a form with a csrf field");
    let rest = &html[at + "name=\"csrf\" value=\"".len()..];
    rest[..rest.find('"').unwrap()].to_string()
}

impl Browser {
    fn new(ts: &TestServer) -> Browser {
        Browser {
            client: reqwest::Client::builder()
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            url: ts.url.clone(),
            cookies: Vec::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies.join("; ")
    }

    fn keep(&mut self, resp: &reqwest::Response) {
        for v in resp.headers().get_all("set-cookie") {
            let pair = v.to_str().unwrap().split(';').next().unwrap().to_string();
            let name = pair.split('=').next().unwrap().to_string();
            self.cookies.retain(|c| !c.starts_with(&format!("{name}=")));
            if !pair.ends_with('=') {
                self.cookies.push(pair);
            }
        }
    }

    async fn get(&mut self, path: &str) -> reqwest::Response {
        let resp = self
            .client
            .get(format!("{}{path}", self.url))
            .header("cookie", self.cookie_header())
            .send()
            .await
            .unwrap();
        self.keep(&resp);
        resp
    }

    async fn page(&mut self, path: &str) -> String {
        let resp = self.get(path).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        resp.text().await.unwrap()
    }

    async fn post(&mut self, path: &str, form: &[(&str, &str)], site: &str) -> reqwest::Response {
        let body: String = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let resp = self
            .client
            .post(format!("{}{path}", self.url))
            .header("cookie", self.cookie_header())
            .header("content-type", "application/x-www-form-urlencoded")
            .header("sec-fetch-site", site)
            .body(body)
            .send()
            .await
            .unwrap();
        self.keep(&resp);
        resp
    }

    async fn sign_in(&mut self, token: &str) {
        let html = self.page("/console/sign-in").await;
        let csrf = csrf_of(&html);
        let resp = self
            .post(
                "/console/sign-in",
                &[("token", token), ("csrf", &csrf)],
                "same-origin",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(self
            .cookies
            .iter()
            .any(|c| c.starts_with("pragmatic_session=")));
    }
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()["location"].to_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_console_signs_in_shows_runs_redacted_and_guards_its_forms() {
    let ts = TestServer::start_integrated(
        |c| {
            c.license.licensee = "Example Corp".into();
            c.lease_ttl_secs = 60;
        },
        pragmatic_server::anchoring::Options::default(),
    )
    .await;
    let info: Value = ts.get("/v1/info", &ts.admin).await.json().await.unwrap();
    assert_eq!(info["components"]["console"], "integrated");
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(
        &ts,
        &agent,
        "case-1",
        &[
            "hello",
            "write to jane.doe@example.com",
            "<script>alert(1)</script>",
        ],
    )
    .await;
    ts.app().anchor_batch(BatchReason::Interval).unwrap();

    // Not signed in: sent to the sign-in page.
    let mut b = Browser::new(&ts);
    let resp = b.get("/console").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/console/sign-in");
    // A sign-in from another site, or without the form's value, fails.
    let html = b.page("/console/sign-in").await;
    assert!(html.contains("Licensed to Example Corp"));
    // The console's fonts are served to anyone, from its own origin,
    // cached for good; the pages load nothing from anywhere else.
    let name = html
        .split("url(/console/assets/")
        .nth(1)
        .and_then(|r| r.split(')').next())
        .unwrap()
        .to_string();
    let resp = b.get(&format!("/console/assets/{name}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "font/woff2");
    assert_eq!(
        resp.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert!(resp.bytes().await.unwrap().starts_with(b"wOF2"));
    assert_eq!(
        b.get("/console/assets/nope.woff2").await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(!html.contains("<script"));
    let csrf = csrf_of(&html);
    let resp = b
        .post(
            "/console/sign-in",
            &[("token", &ts.admin), ("csrf", &csrf)],
            "cross-site",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = b
        .post(
            "/console/sign-in",
            &[("token", &ts.admin), ("csrf", "forged")],
            "same-origin",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // An auditor without view_raw: runs, a redacted run, the access log.
    let (auditor, _) = ts.issue("auditor", &["case-"], false).await;
    let mut a = Browser::new(&ts);
    a.sign_in(&auditor).await;
    let resp = a.get("/console").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("default-src 'none'") && csp.contains("form-action 'self'"));
    assert!(csp.contains("font-src 'self'") && !csp.contains("script-src"));
    assert_eq!(resp.headers()["referrer-policy"], "same-origin");
    assert_eq!(resp.headers()["x-frame-options"], "DENY");
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let html = resp.text().await.unwrap();
    assert!(html.contains("/console/runs/case-1"), "{html}");
    assert!(html.contains("Licensed to Example Corp"));
    assert!(
        !html.contains("/console/tokens"),
        "no admin links for an auditor"
    );
    let html = a.page("/console/runs/case-1").await;
    assert!(html.contains("Content is redacted for you"));
    assert!(!html.contains("jane.doe@example.com"));
    assert!(html.contains("[email]"));
    assert!(!html.contains("<script>alert"));
    assert!(
        html.contains(">Signed by this server only</h2>"),
        "self-anchoring: the operator's signature only"
    );
    assert!(html.contains("/console/runs/case-1/evidence?redact=detectors"));
    assert!(!html.contains("redact=none"));
    assert!(!html.contains("/erase"));
    // A later page of the timeline.
    let html = a.page("/console/runs/case-1?from=3").await;
    assert!(html.contains("Entries #3 to"));
    assert!(html.contains("<a href=\"/console/runs/case-1?from=0\">First page</a>"));
    // A run the token cannot see is a page that says so.
    let resp = a.get("/console/runs/nope-1").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(resp.text().await.unwrap().contains("No run named"));
    // The evidence download, as the API serves it: a bundle that carries
    // text unredacted needs view_raw, so this auditor gets detectors.
    assert_eq!(
        a.get("/console/runs/case-1/evidence?redact=binary")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let resp = a
        .get("/console/runs/case-1/evidence?redact=detectors")
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .contains("case-1.evidence.json"));
    let bundle: Value = resp.json().await.unwrap();
    assert_eq!(bundle["redaction"]["mode"], "detectors");
    ts.app().access.flush().await.unwrap();
    let html = a.page("/console/access").await;
    assert!(
        html.contains("/console/runs/{id}"),
        "the auditor's own reads"
    );
    assert!(html.contains("<span class=\"s dim\">withheld</span>"));
    assert!(!html.contains("[withheld]"));
    let resp = a.get("/console/tokens").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("This page is not open to your role"));
    // The agent may read the run but not download evidence.
    let mut g = Browser::new(&ts);
    g.sign_in(&agent).await;
    assert_eq!(
        g.get("/console/runs/case-1/evidence").await.status(),
        StatusCode::FORBIDDEN
    );
    // With view_raw the content is shown.
    let (raw, _) = ts.issue("auditor", &["*"], true).await;
    let mut r = Browser::new(&ts);
    r.sign_in(&raw).await;
    let html = r.page("/console/runs/case-1").await;
    assert!(html.contains("jane.doe@example.com"));
    assert!(!html.contains("Content is redacted for you"));

    // An administrator's forms.
    b.sign_in(&ts.admin).await;
    let html = b.page("/console/holds").await;
    let csrf = csrf_of(&html);
    let hold = [
        ("matter", "Matter 7"),
        ("prefix", "case-"),
        ("run_ids", ""),
        ("csrf", csrf.as_str()),
    ];
    let resp = b
        .post(
            "/console/holds",
            &[("matter", "x"), ("prefix", "case-"), ("csrf", "nope")],
            "same-origin",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no CSRF token");
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("This form could not be accepted"));
    let resp = b.post("/console/holds", &hold, "cross-site").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "from another site");
    let resp = b.post("/console/holds", &hold, "same-origin").await;
    assert_eq!(location(&resp), "/console/holds?done=hold_placed");
    let html = b.page("/console/holds?done=hold_placed").await;
    assert!(html.contains("The hold is placed."));
    assert!(html.contains("Matter 7"));
    // Erasure under a hold is refused, and says why.
    let erase = [
        ("slots", "3:0"),
        ("match", ""),
        ("reason_code", "dsar"),
        ("reason", "request 12"),
        ("csrf", csrf.as_str()),
    ];
    let resp = b
        .post("/console/runs/case-1/erase", &erase, "same-origin")
        .await;
    assert_eq!(location(&resp), "/console/runs/case-1?error=on_hold");
    let html = b.page("/console/runs/case-1?error=on_hold").await;
    assert!(html.contains("The request was refused: the run is under a legal hold."));
    // Remove the hold, then erase.
    let holds: Value = ts.get("/v1/holds", &ts.admin).await.json().await.unwrap();
    let id = holds["holds"][0]["id"].as_str().unwrap().to_string();
    // Removing a hold asks first; only the confirming post acts.
    let resp = b
        .post(
            &format!("/console/holds/{id}/remove"),
            &[("csrf", &csrf)],
            "same-origin",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Remove the hold"));
    assert!(html.contains("name=\"confirm\" value=\"1\""));
    assert_eq!(csrf_of(&html), csrf);
    let resp = b
        .post(
            &format!("/console/holds/{id}/remove"),
            &[("csrf", &csrf), ("confirm", "1")],
            "same-origin",
        )
        .await;
    assert_eq!(location(&resp), "/console/holds?done=hold_removed");
    // Erasure shows what it would erase, from the stored journal, and
    // erases nothing until it is confirmed.
    let before = stored(&ts, "case-1").len();
    let resp = b
        .post("/console/runs/case-1/erase", &erase, "same-origin")
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Erase 1 slot from"), "{html}");
    assert!(html.contains("#3 \u{b7} slot 0"));
    assert!(html.contains("value=\"dsar\""));
    assert_eq!(stored(&ts, "case-1").len(), before, "nothing erased yet");
    let mut confirmed = erase.to_vec();
    confirmed.push(("confirm", "1"));
    let resp = b
        .post("/console/runs/case-1/erase", &confirmed, "same-origin")
        .await;
    assert_eq!(location(&resp), "/console/runs/case-1?done=erased");
    let j = stored(&ts, "case-1");
    assert!(note_kinds(&j).iter().any(|k| k == "erasure"));
    // Retention, and a token issued and revoked.
    let resp = b
        .post("/console/retention/run", &[("csrf", &csrf)], "same-origin")
        .await;
    assert!(resp.text().await.unwrap().contains("Run retention now?"));
    let resp = b
        .post(
            "/console/retention/run",
            &[("csrf", &csrf), ("confirm", "1")],
            "same-origin",
        )
        .await;
    assert_eq!(location(&resp), "/console/holds?done=retention");
    let resp = b
        .post(
            "/console/tokens",
            &[
                ("name", "ci"),
                ("principal", "svc-ci"),
                ("role", "agent"),
                ("scopes", "ci: case-"),
                ("csrf", &csrf),
            ],
            "same-origin",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = resp.text().await.unwrap();
    assert!(html.contains("It is shown only this once"));
    let value = html
        .split("<span class=\"secret\">")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_string();
    assert!(value.starts_with("prag_"));
    let who: Value = ts.get("/v1/whoami", &value).await.json().await.unwrap();
    assert_eq!(who["scopes"], serde_json::json!(["ci:", "case-"]));
    let id = who["token_id"].as_str().unwrap();
    let resp = b
        .post(
            &format!("/console/tokens/{id}/revoke"),
            &[("csrf", &csrf)],
            "same-origin",
        )
        .await;
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains(&format!("Revoke <span class=\"m\">{id}</span>?")));
    let resp = b
        .post(
            &format!("/console/tokens/{id}/revoke"),
            &[("csrf", &csrf), ("confirm", "1")],
            "same-origin",
        )
        .await;
    assert_eq!(location(&resp), "/console/tokens?done=token_revoked");
    assert_eq!(
        ts.get("/v1/whoami", &value).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // Signing out needs the session's token too, and is logged.
    let resp = b
        .post("/console/sign-out", &[("csrf", "nope")], "same-origin")
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = b
        .post("/console/sign-out", &[("csrf", &csrf)], "same-origin")
        .await;
    assert_eq!(location(&resp), "/console/sign-in?notice=signed_out");
    assert!(b
        .page("/console/sign-in?notice=signed_out")
        .await
        .contains("You are signed out."));
    let resp = b.get("/console").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/console/sign-in");
    // A session that ended on its own says so on the way to sign in.
    ts.app()
        .sessions
        .age(std::time::Duration::from_secs(16 * 60));
    let resp = a.get("/console").await;
    assert_eq!(location(&resp), "/console/sign-in?notice=ended");
    assert!(a
        .page("/console/sign-in?notice=ended")
        .await
        .contains("Your session has ended"));
    let records = ts.audit().await;
    for action in ["sign_in", "sign_out"] {
        assert!(
            records
                .iter()
                .any(|r| r["action"] == action && r["token_id"] == "bootstrap"),
            "{action}"
        );
    }
    assert!(records
        .iter()
        .any(|r| r["kind"] == "intent" && r["action"] == "hold.add"));
    assert!(records
        .iter()
        .any(|r| r["kind"] == "intent" && r["action"] == "token.issue"));
}
