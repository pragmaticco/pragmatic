//! `pragmatic serve`: the console as a local web app, with no
//! dependencies. It binds loopback only and re-reads the journal directory
//! on every request, so it follows runs live as they record. It never
//! writes to the directory.
//!
//! Routes:
//! - `GET /`                   the run index
//! - `GET /run/<id>[?from=N]`  one run's page (the timeline page from N)
//! - `GET /healthz`            liveness probe
//!
//! Binding to loopback is not enough on its own: a web page the user opens
//! can point its own host name at 127.0.0.1 (DNS rebinding) and then read
//! this console as if it were its own origin, prompts and personal data
//! included. So every request must name this console in its `Host` header
//! (`127.0.0.1`, `localhost` or `[::1]`, with this port or none), and a
//! request a browser marks as coming from another site is refused.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use pragmatic::Backend;
use pragmatic_console::fonts::{self, Fonts};
use pragmatic_console::html::{
    document, esc, masthead, solo_card, source_note, Crumb, Frame, Page, SERVE_POLICY,
};
use pragmatic_console::{render_index_of, render_run, RunRow, RunView};

use crate::journals::{backend, discover, open};

/// Where this console serves its fonts.
const ASSETS: &str = "/assets/";

/// The frame of every page: fonts from this console, links home to the
/// index, and the directory on the masthead.
fn with_frame<T>(dir: &Path, f: impl FnOnce(&Frame<'_>) -> T) -> T {
    let nav = source_note(&dir.display().to_string(), true);
    f(&Frame {
        csp: SERVE_POLICY,
        fonts: Fonts::Served(ASSETS),
        home: Some("/"),
        nav: &nav,
        footer: "",
    })
}

fn index_page(dir: &Path, key: Option<&[u8]>) -> String {
    let runs = discover(dir).unwrap_or_default();
    let rows: Vec<RunRow> = runs
        .iter()
        .map(|run| match open(dir, run, key) {
            Ok(j) => RunRow::from_journal(run, &j, &j.audit()).linked(&format!("/run/{run}")),
            Err(e) => RunRow::unreadable(run, &e),
        })
        .collect();
    let source = dir.display().to_string();
    with_frame(dir, |frame| {
        render_index_of(&rows, Some(&source), Some(frame))
    })
}

fn run_page(dir: &Path, run: &str, from: u64, key: Option<&[u8]>) -> Result<String, String> {
    let journal = open(dir, run, key)?;
    // The backend's report reads past corruption; the snapshot shows the
    // valid prefix.
    let report = backend(dir)?
        .verify(run, key)
        .unwrap_or_else(|_| journal.audit());
    let source = dir.display().to_string();
    let link = format!("/run/{run}?from=");
    Ok(with_frame(dir, |frame| {
        let view = RunView {
            source: Some(&source),
            from: from.min(journal.len()),
            page_link: Some(&link),
            frame: Some(frame),
            ..RunView::new(run, &journal, &report)
        };
        render_run(&view)
    }))
}

/// The page for a run this directory does not hold.
fn missing_page(dir: &Path, run: &str) -> String {
    with_frame(dir, |frame| {
        let body = format!(
            "<p class=\"lede\">There is no readable run with this id in <span class=\"m\">{}</span>. \
             The id may be mistyped, or the run may have been moved.</p>\
             <p class=\"actions\"><a class=\"go\" href=\"/\">Back to runs</a></p>",
            esc(&dir.display().to_string())
        );
        document(
            frame,
            &Page {
                title: "No such run",
                masthead: masthead(
                    frame.home,
                    &[Crumb::word("Runs", frame.home), Crumb::id(run, None)],
                    frame.nav,
                ),
                main: solo_card(
                    "Error 404",
                    &format!("No run named <span class=\"m\">{}</span>", esc(run)),
                    &body,
                ),
                ..Page::default()
            },
        )
    })
}

/// The value of header `name` (case-insensitive) in a request head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Whether a `Host` header names this console: a loopback name, with this
/// port or none.
fn is_own_host(host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    let (name, given) = match host.rsplit_once(':') {
        // `[::1]` alone has colons inside its brackets.
        Some((n, p)) if !p.contains(']') => (n.to_string(), Some(p.to_string())),
        _ => (host.clone(), None),
    };
    let named = matches!(name.as_str(), "127.0.0.1" | "localhost" | "[::1]");
    named && given.is_none_or(|p| p == port.to_string())
}

/// Why a request is refused before it is routed, if it is.
fn refusal(head: &str, port: u16) -> Option<(&'static str, &'static str)> {
    match header(head, "host") {
        Some(h) if is_own_host(h, port) => {}
        _ => return Some(("421 Misdirected Request", "")),
    }
    // Browsers say where a request comes from; only this console's own
    // pages, and a user typing the address, may read it.
    match header(head, "sec-fetch-site") {
        None => None,
        Some(v) if v.eq_ignore_ascii_case("same-origin") || v.eq_ignore_ascii_case("none") => None,
        Some(_) => Some(("403 Forbidden", "")),
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let content_type = format!("{content_type}; charset=utf-8");
    respond_bytes(stream, status, &content_type, "no-store", body.as_bytes());
}

fn respond_bytes(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    cache: &str,
    body: &[u8],
) {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\n\
         content-security-policy: {SERVE_POLICY}\r\n\
         x-content-type-options: nosniff\r\nreferrer-policy: same-origin\r\n\
         cache-control: {cache}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn handle(mut stream: TcpStream, dir: &Path, key: Option<&[u8]>, port: u16) {
    // Read the request head (it may arrive in pieces), up to 8 KiB.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while buf.len() < 8192 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    if buf.is_empty() {
        return;
    }
    let request = String::from_utf8_lossy(&buf);
    if let Some((status, body)) = refusal(&request, port) {
        respond(&mut stream, status, "text/plain", body);
        return;
    }
    let mut line = request.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (line.next().unwrap_or(""), line.next().unwrap_or("/"));
    if method != "GET" {
        respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            "GET only",
        );
        return;
    }
    match path {
        "/healthz" => respond(&mut stream, "200 OK", "text/plain", "ok"),
        "/" => respond(&mut stream, "200 OK", "text/html", &index_page(dir, key)),
        p if p.starts_with(ASSETS) => match fonts::served(&p[ASSETS.len()..]) {
            Some(f) => respond_bytes(
                &mut stream,
                "200 OK",
                fonts::FONT_TYPE,
                fonts::FONT_CACHE,
                f.bytes,
            ),
            None => respond(&mut stream, "404 Not Found", "text/plain", "not found"),
        },
        p if p.starts_with("/run/") => {
            // Run ids are `[A-Za-z0-9._:-]{1,200}`; anything else is cut off.
            let run: String = p["/run/".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
                .take(200)
                .collect();
            let from = p
                .split_once("?from=")
                .and_then(|(_, n)| n.parse::<u64>().ok())
                .unwrap_or(0);
            match run_page(dir, &run, from, key) {
                Ok(html) => respond(&mut stream, "200 OK", "text/html", &html),
                Err(_) => respond(
                    &mut stream,
                    "404 Not Found",
                    "text/html",
                    &missing_page(dir, &run),
                ),
            }
        }
        _ => respond(&mut stream, "404 Not Found", "text/plain", "not found"),
    }
}

/// Serve the console until killed. Loopback only by design: the console
/// shows prompts and outcomes, so putting it on a network is an explicit
/// reverse-proxy decision, never a default.
pub fn serve(dir: PathBuf, key: Option<Vec<u8>>, port: u16) -> Result<(), String> {
    backend(&dir)?;
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("cannot bind 127.0.0.1:{port}: {e}"))?;
    println!(
        "pragmatic console serving {} on http://127.0.0.1:{port}",
        dir.display()
    );
    println!("^C to stop");
    for stream in listener.incoming().flatten() {
        let dir = dir.clone();
        let key = key.clone();
        std::thread::spawn(move || handle(stream, &dir, key.as_deref(), port));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_console_is_served() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:7171",
            "localhost",
            "LOCALHOST:7171",
            "[::1]",
            "[::1]:7171",
        ] {
            assert!(is_own_host(ok, 7171), "{ok}");
        }
        for bad in [
            "attacker.example",
            "attacker.example:7171",
            "127.0.0.1:8080",
            "localhost.attacker.example",
            "127.0.0.1.nip.io:7171",
            "[::1]:80",
            "",
        ] {
            assert!(!is_own_host(bad, 7171), "{bad}");
        }
    }

    #[test]
    fn foreign_hosts_and_cross_site_requests_are_refused() {
        let req = |extra: &str| format!("GET / HTTP/1.1\r\n{extra}\r\n");
        assert_eq!(refusal(&req("Host: localhost:7171\r\n"), 7171), None);
        assert_eq!(
            refusal(&req("Host: evil.example:7171\r\n"), 7171).map(|r| r.0),
            Some("421 Misdirected Request")
        );
        assert!(refusal(&req(""), 7171).is_some(), "no Host header");
        assert_eq!(
            refusal(
                &req("host: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\n"),
                7171
            )
            .map(|r| r.0),
            Some("403 Forbidden")
        );
        assert_eq!(
            refusal(
                &req("host: 127.0.0.1\r\nsec-fetch-site: same-origin\r\n"),
                7171
            ),
            None
        );
    }
}
