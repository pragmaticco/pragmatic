//! `pragmatic-server`: the Pragmatic Server binary (design 4.1).
//!
//! ```text
//! pragmatic-server serve [--config FILE]
//! pragmatic-server keygen [--rotate]
//! pragmatic-server token new|revoke|list|bootstrap
//! pragmatic-server backup --to DIR
//! pragmatic-server restore --from DIR [--erasure-ledger FILE] [--trust-key HEX]
//! pragmatic-server verify-data [--offline]
//! pragmatic-server verify-evidence FILE
//! pragmatic-server migrate
//! pragmatic-server accept-regression RUN
//! ```
//!
//! The configuration comes from `--config` or `PRAGMATIC_CONFIG`. The
//! `token`, `accept-regression` and (online) `verify-data` subcommands talk
//! to a running server with an admin token from `PRAGMATIC_TOKEN` or
//! `--token-file`; nothing secret is ever taken from the command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pragmatic_server::config::Config;
use pragmatic_server::server::{self, Hooks};
use pragmatic_server::{ops, tokens};
use serde_json::{json, Value as JsonValue};

#[derive(Parser)]
#[command(
    name = "pragmatic-server",
    version,
    about = "Pragmatic Server: the system of record for AI agent runs"
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
    /// Write a new signing key (refuses to overwrite), or rotate it.
    Keygen {
        /// Replace the current key; the server must be stopped.
        #[arg(long)]
        rotate: bool,
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
        Command::Keygen { rotate } => ops::keygen(&load(&cli.config)?.0, rotate),
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
        } => {
            let config = load(&cli.config)?.0;
            let hooks = Hooks::stubs(&config);
            let report = ops::restore_trusting(
                &config,
                &from,
                erasure_ledger.as_deref(),
                hooks.anchoring.as_ref(),
                &trust_keys,
            )?;
            Ok(pretty(&report))
        }
        Command::VerifyData { offline: true, .. } => {
            let config = load(&cli.config)?.0;
            let hooks = Hooks::stubs(&config);
            Ok(pretty(&ops::verify_data_offline(
                &config,
                hooks.anchoring.as_ref(),
            )?))
        }
        Command::VerifyData { conn, .. } => {
            let config = load(&cli.config)?.0;
            call(&config, &conn, "POST", "/v1/verify-data", None)
        }
        Command::VerifyEvidence { file } => Err(format!(
            "verify-evidence ({}) is provided by the evidence module, which is not part of this \
             build yet; use `pragmatic verify-evidence` from the CLI",
            file.display()
        )),
        Command::Migrate => ops::migrate(&load(&cli.config)?.0).map(|s| format!("{s}\n")),
        Command::AcceptRegression { run, conn } => {
            let config = load(&cli.config)?.0;
            let path = format!("/v1/runs/{}/accept-regression", encode_segment(&run));
            call(&config, &conn, "POST", &path, None)
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
    let hooks = Hooks::stubs(&config);
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
