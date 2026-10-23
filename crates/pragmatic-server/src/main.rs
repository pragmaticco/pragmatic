//! `pragmatic-server`: the Stet Server binary (design 4.1).
//!
//! ```text
//! pragmatic-server serve [--config FILE]
//! pragmatic-server keygen [--rotate]
//! pragmatic-server token new|revoke|list|bootstrap
//! pragmatic-server backup --to DIR
//! pragmatic-server restore --from DIR [--erasure-ledger FILE] [--trust-key HEX] [--anchors DIR]
//! pragmatic-server confirm-anchors (--checkpoint FILE | --new-log)
//! pragmatic-server verify-data [--offline]
//! pragmatic-server verify-evidence FILE
//! pragmatic-server migrate
//! pragmatic-server accept-regression RUN
//! pragmatic-server witness-resume ORIGIN --checkpoint FILE [--reason TEXT]
//! ```
//!
//! The configuration comes from `--config` or `PRAGMATIC_CONFIG`. The
//! `token`, `accept-regression`, `witness-resume` and (online)
//! `verify-data` subcommands talk to a running server with an admin token
//! from `PRAGMATIC_TOKEN` or `--token-file`; nothing secret is ever taken
//! from the command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pragmatic_server::anchoring::{self, OfflineAnchoring};
use pragmatic_server::config::Config;
use pragmatic_server::server::{self, HooksSource};
use pragmatic_server::{ops, tokens};
use serde_json::{json, Value as JsonValue};

#[derive(Parser)]
#[command(
    name = "pragmatic-server",
    version,
    about = "Stet Server: the system of record for AI agent runs"
)]
struct Cli {
    /// The configuration file.
    #[arg(
        long,
        env = "PRAGMATIC_CONFIG",
        global = true,
        default_value = "/etc/pragmatic/pragmatic.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve,
    /// Write a new key (never over an existing file): the log key by
    /// default, or rotate it, or the witness-mode key, or the anchor key.
    Keygen {
        /// Replace the current log key; the server must be stopped.
        #[arg(long, conflicts_with_all = ["witness", "anchor_key"])]
        rotate: bool,
        /// Write the witness-mode key ([witness_mode] key_file).
        #[arg(long, conflicts_with = "anchor_key")]
        witness: bool,
        /// Write the anchor key for HMAC run ids ([keys] anchor_key_file).
        #[arg(long)]
        anchor_key: bool,
    },
    /// Issue, revoke and list tokens on a running server.
    Token {
        #[command(flatten)]
        conn: Conn,
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Copy the data directory (live) to an empty directory.
    Backup {
        #[arg(long)]
        to: PathBuf,
    },
    /// Restore a backup into an empty data directory (server stopped).
    Restore {
        #[arg(long)]
        from: PathBuf,
        /// The erasure ledger kept off the host; its records newer than the
        /// backup are applied again.
        #[arg(long)]
        erasure_ledger: Option<PathBuf>,
        /// A public key (64 hex digits) to trust as the backup's signer,
        /// besides the configured signing key and the keys it replaced
        /// (repeatable).
        #[arg(long = "trust-key")]
        trust_keys: Vec<String>,
        /// The anchors directory that survived the disaster, restored in
        /// place of the backup's (it must continue the backup's log).
        /// Without it anchoring is held until `confirm-anchors`.
        #[arg(long)]
        anchors: Option<PathBuf>,
    },
    /// Lift the hold on a restored (or forked) anchor log (server stopped).
    ConfirmAnchors {
        /// The newest checkpoint the log published (a signed note): it
        /// must be the restored log's latest.
        #[arg(long, conflicts_with = "new_log", required_unless_present = "new_log")]
        checkpoint: Option<PathBuf>,
        /// Retire the held log and begin a new one under the configured
        /// key, which must be a new log key (a new origin).
        #[arg(long)]
        new_log: bool,
    },
    /// Verify every chain, commitment and anchor proof now.
    VerifyData {
        /// Work on the data directory directly (server stopped).
        #[arg(long)]
        offline: bool,
        #[command(flatten)]
        conn: Conn,
    },
    /// Verify an evidence bundle.
    VerifyEvidence { file: PathBuf },
    /// Bring the data directory to this build's data format.
    Migrate,
    /// Accept a regressed run's journal as its history (logged).
    AcceptRegression {
        run: String,
        #[command(flatten)]
        conn: Conn,
    },
    /// Resume a held witness record from the latest checkpoint the witness
    /// cosigned for the origin, taken from outside this host (logged).
    WitnessResume {
        /// The origin entry's configuration name.
        origin: String,
        /// The cosigned checkpoint: the signed note with this witness's
        /// cosignature line.
        #[arg(long)]
        checkpoint: PathBuf,
        /// Why (recorded in the access log).
        #[arg(long, default_value = "")]
        reason: String,
        #[command(flatten)]
        conn: Conn,
    },
}

#[derive(clap::Args)]
struct Conn {
    /// The server URL (default: public_url, or http://<listen>).
    #[arg(long, env = "PRAGMATIC_URL")]
    url: Option<String>,
    /// A file holding the admin token (default: PRAGMATIC_TOKEN).
    #[arg(long)]
    token_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Issue a token; its value is printed once.
    New {
        #[arg(long)]
        name: String,
        #[arg(long)]
        principal: String,
        /// agent, auditor, admin or witness_client.
        #[arg(long)]
        role: String,
        /// A run-id prefix, or "*" (repeatable).
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long)]
        view_raw: bool,
        /// RFC 3339.
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// Revoke a token by id.
    Revoke { id: String },
    /// List tokens.
    List,
    /// Print a fresh token and its SHA-256 for [bootstrap] (offline).
    Bootstrap,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(out) => {
            if !out.is_empty() {
                print!("{out}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pragmatic-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &Path) -> Result<(Config, [u8; 32]), String> {
    Config::load(path).map_err(|e| e.0)
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

fn pretty(v: &JsonValue) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap_or_default())
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Token {
            action: TokenAction::Bootstrap,
            ..
        } => bootstrap_token(),
        Command::Serve => serve(&cli.config),
        Command::Keygen {
            rotate,
            witness,
            anchor_key,
        } => {
            let kind = match (rotate, witness, anchor_key) {
                (true, _, _) => ops::KeygenKind::Rotate,
                (_, true, _) => ops::KeygenKind::Witness,
                (_, _, true) => ops::KeygenKind::AnchorKey,
                _ => ops::KeygenKind::Log,
            };
            ops::keygen(&load(&cli.config)?.0, kind)
        }
        Command::Backup { to } => {
            let r = ops::backup(&load(&cli.config)?.0, &to)?;
            Ok(format!(
                "backed up {} runs, {} files, {} bytes; manifest {}\n",
                r.runs,
                r.files,
                r.bytes,
                r.manifest.display()
            ))
        }
        Command::Restore {
            from,
            erasure_ledger,
            trust_keys,
            anchors,
        } => {
            let config = load(&cli.config)?.0;
            let anchoring = OfflineAnchoring {
                config: config.clone(),
            };
            let options = ops::RestoreOptions {
                ledger_file: erasure_ledger.as_deref(),
                trust_keys: &trust_keys,
                anchors_from: anchors.as_deref(),
            };
            let report = ops::restore_with(&config, &from, &options, &anchoring)?;
            Ok(pretty(&report))
        }
        Command::ConfirmAnchors {
            checkpoint,
            new_log,
        } => {
            let config = load(&cli.config)?.0;
            let how = match (checkpoint, new_log) {
                (Some(path), false) => ops::ConfirmAnchors::Checkpoint(path),
                (None, true) => ops::ConfirmAnchors::NewLog,
                _ => return Err("give exactly one of --checkpoint FILE and --new-log".into()),
            };
            ops::confirm_anchors(&config, &how)
        }
        Command::VerifyData { offline: true, .. } => {
            let config = load(&cli.config)?.0;
            let anchoring = OfflineAnchoring {
                config: config.clone(),
            };
            Ok(pretty(&ops::verify_data_offline(&config, &anchoring)?))
        }
        Command::VerifyData { conn, .. } => {
            let config = load(&cli.config)?.0;
            call(&config, &conn, "POST", "/v1/verify-data", None)
        }
        Command::VerifyEvidence { file } => Err(format!(
            "verify {} with `pragmatic verify-evidence` from the Stet CLI (Apache-2.0), \
             pinning trust roots of your own choosing: an auditor should not have to trust the \
             operator's server to check its bundles",
            file.display()
        )),
        Command::Migrate => ops::migrate(&load(&cli.config)?.0).map(|s| format!("{s}\n")),
        Command::AcceptRegression { run, conn } => {
            let config = load(&cli.config)?.0;
            let path = format!("/v1/runs/{}/accept-regression", encode_segment(&run));
            call(&config, &conn, "POST", &path, None)
        }
        Command::WitnessResume {
            origin,
            checkpoint,
            reason,
            conn,
        } => {
            let config = load(&cli.config)?.0;
            let text = std::fs::read_to_string(&checkpoint)
                .map_err(|e| format!("{}: {e}", checkpoint.display()))?;
            let path = format!("/v1/witness/resume/{}", encode_segment(&origin));
            let body = json!({"checkpoint": text, "reason": reason});
            call(&config, &conn, "POST", &path, Some(body))
        }
        Command::Token { conn, action } => token(&load(&cli.config)?.0, &conn, action),
    }
}

fn bootstrap_token() -> Result<String, String> {
    let value = tokens::new_token_value().map_err(|e| e.to_string())?;
    Ok(format!(
        "token {value}\nadmin_token_sha256 = \"{}\"\n\
         Keep the token secret; put only the hash in the configuration.\n",
        tokens::token_sha256(&value)
    ))
}

fn serve(config_path: &Path) -> Result<String, String> {
    let (config, sha) = load(config_path)?;
    let hooks = HooksSource::Integrated(anchoring::Options::default());
    runtime()?.block_on(async move {
        let handle = server::start(config, sha, hooks).await.map_err(|e| e.0)?;
        eprintln!("pragmatic-server: listening on {}", handle.url());
        handle.run_until_signal().await.map_err(|e| e.to_string())?;
        Ok(String::new())
    })
}

fn token(config: &Config, conn: &Conn, action: TokenAction) -> Result<String, String> {
    match action {
        TokenAction::New {
            name,
            principal,
            role,
            scopes,
            view_raw,
            expires_at,
        } => {
            let body = json!({
                "name": name, "principal": principal, "role": role,
                "scopes": scopes, "view_raw": view_raw, "expires_at": expires_at,
            });
            call(config, conn, "POST", "/v1/tokens", Some(body))
        }
        TokenAction::Revoke { id } => call(
            config,
            conn,
            "DELETE",
            &format!("/v1/tokens/{}", encode_segment(&id)),
            None,
        ),
        TokenAction::List => call(config, conn, "GET", "/v1/tokens", None),
        TokenAction::Bootstrap => bootstrap_token(),
    }
}

fn encode_segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Call a running server with the admin token and print its answer.
fn call(
    config: &Config,
    conn: &Conn,
    method: &str,
    path: &str,
    body: Option<JsonValue>,
) -> Result<String, String> {
    let base = conn.url.clone().unwrap_or_else(|| {
        if config.public_url.is_empty() {
            format!("http://{}", config.listen)
        } else {
            config.public_url.trim_end_matches('/').to_string()
        }
    });
    let token = match &conn.token_file {
        Some(f) => std::fs::read_to_string(f)
            .map_err(|e| format!("{}: {e}", f.display()))?
            .trim()
            .to_string(),
        None => std::env::var("PRAGMATIC_TOKEN")
            .map_err(|_| "set PRAGMATIC_TOKEN or pass --token-file".to_string())?,
    };
    let url = format!("{base}{path}");
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    runtime()?.block_on(async move {
        let client = reqwest::Client::new();
        let mut req = client.request(method, &url).bearer_auth(token);
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        let shown = serde_json::from_str::<JsonValue>(&text)
            .map(|v| pretty(&v))
            .unwrap_or(text);
        if status.is_success() {
            Ok(shown)
        } else {
            Err(format!("{status}: {shown}"))
        }
    })
}
