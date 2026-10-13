//! Command-line arguments: a command, positional arguments and flags.
//!
//! Flags are checked against the command that receives them, so a flag a
//! command does not understand is an error rather than silently ignored
//! (a mistyped `--witness-key` must never quietly verify less).

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Flags that take a value. Everything else is a switch.
const VALUED: &[&str] = &[
    "--dir",
    "--key",
    "--key-file",
    "-o",
    "--out",
    "--port",
    "--cursor",
    "--slot",
    "--match",
    "--reason-code",
    "--reason",
    "--redact",
    "--detectors",
    "--withhold",
    "--tsa-roots",
    "--witness-key",
    "--log-key",
    "--min-operators",
    "--log",
    "--witness-log",
    "--format",
    "--from",
];

/// Parsed arguments.
#[derive(Debug, Default)]
pub struct Args {
    pub command: String,
    pub positional: Vec<String>,
    /// Every value of every valued flag, in order (`-o` is stored as
    /// `--out`).
    values: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
}

/// A usage error: exit code 64 (`EX_USAGE`), distinct from every
/// verification outcome.
#[derive(Debug)]
pub struct Usage(pub String);

impl Args {
    /// Parse `argv` (without the program name).
    pub fn parse(argv: impl IntoIterator<Item = String>) -> Result<Args, Usage> {
        let mut it = argv.into_iter();
        let mut args = Args {
            command: it.next().unwrap_or_else(|| "help".to_string()),
            ..Args::default()
        };
        if matches!(args.command.as_str(), "-h" | "--help") {
            args.command = "help".into();
        }
        while let Some(a) = it.next() {
            let (flag, inline) = match a.split_once('=') {
                Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
                _ => (a.clone(), None),
            };
            if VALUED.contains(&flag.as_str()) {
                let value = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .ok_or_else(|| Usage(format!("{flag} needs a value")))?,
                };
                let flag = if flag == "-o" {
                    "--out".to_string()
                } else {
                    flag
                };
                args.values.entry(flag).or_default().push(value);
            } else if flag == "-h" || flag == "--help" {
                args.switches.push("--help".into());
            } else if flag.starts_with('-') && flag.len() > 1 {
                if inline.is_some() {
                    return Err(Usage(format!("{flag} does not take a value")));
                }
                args.switches.push(flag);
            } else {
                args.positional.push(a);
            }
        }
        Ok(args)
    }

    /// Refuse flags outside `allowed` (both valued flags and switches).
    pub fn only(&self, allowed: &[&str]) -> Result<(), Usage> {
        for f in self.values.keys().chain(self.switches.iter()) {
            if f != "--help" && !allowed.contains(&f.as_str()) {
                return Err(Usage(format!(
                    "'{}' does not take {f} (try: pragmatic help)",
                    self.command
                )));
            }
        }
        Ok(())
    }

    /// The last value of a flag.
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.values
            .get(flag)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    /// Every value of a repeatable flag.
    pub fn values(&self, flag: &str) -> &[String] {
        self.values.get(flag).map_or(&[], Vec::as_slice)
    }

    pub fn has(&self, switch: &str) -> bool {
        self.switches.iter().any(|s| s == switch)
    }

    pub fn path(&self, flag: &str) -> Option<PathBuf> {
        self.value(flag).map(PathBuf::from)
    }

    /// The journal directory (`--dir`, default `.`).
    pub fn dir(&self) -> PathBuf {
        self.path("--dir").unwrap_or_else(|| PathBuf::from("."))
    }

    /// A number flag.
    pub fn number<T: std::str::FromStr>(&self, flag: &str) -> Result<Option<T>, Usage> {
        self.value(flag)
            .map(|v| {
                v.parse()
                    .map_err(|_| Usage(format!("{flag} must be a number, not {v:?}")))
            })
            .transpose()
    }

    /// The one positional argument a command takes.
    pub fn one(&self, what: &str) -> Result<&str, Usage> {
        match self.positional.as_slice() {
            [one] => Ok(one),
            [] => Err(Usage(format!("usage: pragmatic {} {what}", self.command))),
            _ => Err(Usage(format!(
                "'{}' takes one {what}, got {}",
                self.command,
                self.positional.len()
            ))),
        }
    }
}

/// The HMAC key for keyed journals: `--key-file`, else the deprecated
/// `--key` (which puts the secret in the process list, so it warns), else
/// `PRAGMATIC_JOURNAL_KEY`.
pub fn journal_key(args: &Args) -> Result<Option<Vec<u8>>, String> {
    if let Some(path) = args.path("--key-file") {
        let mut bytes = std::fs::read(&path)
            .map_err(|e| format!("cannot read key file {}: {e}", path.display()))?;
        while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            bytes.pop();
        }
        if bytes.is_empty() {
            return Err(format!("key file {} is empty", path.display()));
        }
        return Ok(Some(bytes));
    }
    if let Some(k) = args.value("--key") {
        eprintln!(
            "warning: --key is deprecated: it exposes the key to other users of this machine; \
             use --key-file or PRAGMATIC_JOURNAL_KEY"
        );
        return Ok(Some(k.as_bytes().to_vec()));
    }
    Ok(std::env::var("PRAGMATIC_JOURNAL_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .map(String::into_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &[&str]) -> Args {
        Args::parse(a.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn values_switches_and_positionals() {
        let a = parse(&[
            "verify-evidence",
            "b.json",
            "--tsa-roots",
            "a.pem",
            "--tsa-roots=b.pem",
            "--explain",
            "-o",
            "x",
        ]);
        assert_eq!(a.command, "verify-evidence");
        assert_eq!(a.positional, ["b.json"]);
        assert_eq!(a.values("--tsa-roots"), ["a.pem", "b.pem"]);
        assert_eq!(a.value("--out"), Some("x"));
        assert!(a.has("--explain"));
        assert!(a.only(&["--tsa-roots", "--explain", "--out"]).is_ok());
        assert!(a.only(&["--tsa-roots"]).is_err());
    }

    #[test]
    fn errors() {
        assert!(Args::parse(["show".to_string(), "--dir".to_string()]).is_err());
        assert!(Args::parse(["show".to_string(), "--all=1".to_string()]).is_err());
        let a = parse(&["show", "--port", "x"]);
        assert!(a.number::<u16>("--port").is_err());
        assert!(parse(&["show"]).one("RUN").is_err());
        assert_eq!(parse(&["--help"]).command, "help");
    }
}
