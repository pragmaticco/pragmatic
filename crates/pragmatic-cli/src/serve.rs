//! `pragmatic serve` - the replay console as a local web app, zero
//! dependencies. Binds loopback only; every request re-reads the journal
//! directory, so the console live-follows runs as they record.
//!
//! Routes:
//! - `GET /`          run index (id, entries, chain status, dangling intents)
//! - `GET /run/<id>`  the full replay-console timeline for one run
//! - `GET /healthz`   liveness probe

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use pragmatic::journal_v1::Journal;
use pragmatic::sha256::hex;

use crate::export;

fn open_journal(dir: &Path, run: &str, key: Option<&str>) -> Result<Journal, String> {
    let path = dir.join(format!("{run}.journal"));
    let loaded = match key {
        Some(k) => Journal::open_keyed(&path, k.as_bytes()),
        None => Journal::open(&path),
    };
    loaded.map(|l| l.journal).map_err(|e| e.to_string())
}

fn discover(dir: &Path) -> Vec<String> {
    let mut runs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("journal") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    runs.push(stem.to_string());
                }
            }
        }
    }
    runs.sort();
    runs
}

fn index_page(dir: &Path, key: Option<&str>) -> String {
    let runs = discover(dir);
    let count = runs.len();
    let mut total_steps: u64 = 0;
    let mut verified = 0usize;
    let mut open_intents = 0usize;
    let mut rows = String::new();

    for run in &runs {
        match open_journal(dir, run, key) {
            Ok(j) => {
                total_steps += j.len();
                let chain_ok = j.verify().is_ok();
                if chain_ok {
                    verified += 1;
                }
                let d = j.dangling_intents().len();
                open_intents += d;
                let draws = j
                    .entries()
                    .iter()
                    .filter(|e| matches!(e.event, pragmatic::journal_v1::Event::OracleDraw { .. }))
                    .count();
                let chain = if chain_ok {
                    "verified".to_string()
                } else {
                    "<span class=\"alarm\">BROKEN</span>".to_string()
                };
                let effects = if d > 0 {
                    format!("<span class=\"alarm\">{d} open</span>")
                } else {
                    "<span class=\"faint\">settled</span>".to_string()
                };
                let head = j
                    .head()
                    .map(|h| hex(&h)[..12].to_string())
                    .unwrap_or_else(|| "-".into());
                rows.push_str(&format!(
                    "<tr class=\"run\">\
                       <td class=\"name\"><a href=\"/run/{run}\">{run}</a></td>\
                       <td class=\"r\">{steps}</td>\
                       <td class=\"r\">{draws}</td>\
                       <td>{chain}</td><td>{effects}</td>\
                       <td><span class=\"faint\">{head}</span></td>\
                     </tr>\n",
                    run = export::esc(run),
                    steps = j.len(),
                ));
            }
            Err(e) => {
                rows.push_str(&format!(
                    "<tr class=\"run\"><td class=\"name\">{}</td>\
                     <td colspan=\"5\"><span class=\"alarm\">{}</span></td></tr>\n",
                    export::esc(run),
                    export::esc(&e),
                ));
            }
        }
    }
    let table = if rows.is_empty() {
        "<div class=\"empty\">no journals in this directory - point an agent's \
         runtime here and runs appear as they record</div>"
            .to_string()
    } else {
        format!(
            "<table>\
               <tr><th>run</th><th class=\"r\">steps</th><th class=\"r\">draws</th>\
                   <th>chain</th><th>effects</th><th>head</th></tr>\
               {rows}\
             </table>"
        )
    };

    let open = if open_intents > 0 {
        format!("<div><span class=\"alarm\">{open_intents} OPEN INTENT(S)</span></div>")
    } else {
        String::new()
    };

    let body = format!(
        r#"{mast}
<div class="facts">
  <div><b>{count}</b> runs</div>
  <div><b>{total_steps}</b> journaled steps</div>
  <div>chains <b>{verified}/{count}</b> verified</div>
  {open}
  <div>dir <b>{dir}</b></div>
</div>
{table}"#,
        mast = export::masthead("runs", "live - refresh to follow"),
        dir = export::esc(&dir.display().to_string()),
    );
    export::page("pragmatic console", &body)
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}; charset=utf-8\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn handle(mut stream: TcpStream, dir: &Path, key: Option<&str>) {
    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");

    match path {
        "/healthz" => respond(&mut stream, "200 OK", "text/plain", "ok"),
        "/" => respond(&mut stream, "200 OK", "text/html", &index_page(dir, key)),
        p if p.starts_with("/run/") => {
            // Run ids are filesystem-safe by construction; reject anything else.
            let run: String = p["/run/".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            match open_journal(dir, &run, key) {
                Ok(journal) => respond(
                    &mut stream,
                    "200 OK",
                    "text/html",
                    &export::render(&run, &journal),
                ),
                Err(e) => respond(
                    &mut stream,
                    "404 Not Found",
                    "text/plain",
                    &format!("no such run '{run}': {e}"),
                ),
            }
        }
        _ => respond(&mut stream, "404 Not Found", "text/plain", "not found"),
    }
}

/// Serve the console until killed. Loopback-only by design: the console
/// exposes prompts and outcomes, so putting it on a network is an explicit
/// reverse-proxy decision, not a default.
pub fn serve(dir: PathBuf, key: Option<String>, port: u16) -> Result<(), String> {
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
