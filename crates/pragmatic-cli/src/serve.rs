//! `pragmatic serve`: the console as a local web app, with no
//! dependencies. It binds loopback only and re-reads the journal directory
//! on every request, so it follows runs live as they record. It never
//! writes to the directory.
//!
//! Routes:
//! - `GET /`          the run index
//! - `GET /run/<id>`  one run's page
//! - `GET /healthz`   liveness probe

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use pragmatic::Backend;
use pragmatic_console::html::{esc, CONTENT_SECURITY_POLICY};
use pragmatic_console::{render_index_of, render_run, RunRow, RunView};

use crate::journals::{backend, discover, open};

fn index_page(dir: &Path, key: Option<&[u8]>) -> String {
    let runs = discover(dir).unwrap_or_default();
    let rows: Vec<RunRow> = runs
        .iter()
        .map(|run| match open(dir, run, key) {
            Ok(j) => RunRow::from_journal(run, &j, &j.audit()).linked(&format!("/run/{run}")),
            Err(e) => RunRow::unreadable(run, &e),
        })
        .collect();
    render_index_of(&rows, Some(&dir.display().to_string()), Some("/"))
}

fn run_page(dir: &Path, run: &str, key: Option<&[u8]>) -> Result<String, String> {
    let journal = open(dir, run, key)?;
    // The backend's report reads past corruption; the snapshot shows the
    // valid prefix.
    let report = backend(dir)?
        .verify(run, key)
        .unwrap_or_else(|_| journal.audit());
    let source = dir.display().to_string();
    let view = RunView {
        source: Some(&source),
        home: Some("/"),
        ..RunView::new(run, &journal, &report)
    };
    Ok(render_run(&view))
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}; charset=utf-8\r\n\
         content-security-policy: {CONTENT_SECURITY_POLICY}\r\n\
         x-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\n\
         cache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn handle(mut stream: TcpStream, dir: &Path, key: Option<&[u8]>) {
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
        p if p.starts_with("/run/") => {
            // Run ids are `[A-Za-z0-9._:-]{1,200}`; anything else is cut off.
            let run: String = p["/run/".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
                .take(200)
                .collect();
            match run_page(dir, &run, key) {
                Ok(html) => respond(&mut stream, "200 OK", "text/html", &html),
                Err(e) => respond(
                    &mut stream,
                    "404 Not Found",
                    "text/plain",
                    &format!("no such run '{}': {}", esc(&run), esc(&e)),
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
        std::thread::spawn(move || handle(stream, &dir, key.as_deref()));
    }
    Ok(())
}
