//! RFC 3161 signature checks with the `openssl` command (design 5.3 step 9).
//!
//! The core parses tokens but does not verify CMS signatures: that needs
//! X.509 path building and several signature algorithms, which OpenSSL
//! does and a zero-dependency crate should not reimplement. Each check runs
//!
//! ```text
//! openssl ts -verify -token_in -in <i>.der -digest <anchor digest>
//!     -CAfile <pinned anchors> -partial_chain -untrusted <i>.pem
//!     -attime <genTime + 1>
//! ```
//!
//! which checks the signature, the ESS signing-certificate binding, the
//! critical `timeStamping` extended key usage, that the imprint is the
//! anchor digest, and that the TSA certificate chains to a pinned anchor as
//! of the time the token was made (so a TSA certificate that has since
//! expired still verifies, and one that was not yet valid does not).
//! `-partial_chain` makes every certificate in the pinned file an anchor,
//! not only self-signed roots, so an auditor can pin the CA that issues an
//! operator's time-stamping certificates instead of a root under which
//! anyone can buy one (design 5.2). A file of roots verifies as before.
//!
//! Not every `openssl` can do this. macOS ships LibreSSL as
//! `/usr/bin/openssl`, whose `ts -verify` has no `-attime`: it prints its
//! usage and fails, which says nothing about the token. So a binary is
//! used only after [`capability`] has seen that it is OpenSSL and that its
//! `ts` command takes `-attime`, and a check counts as a rejected token
//! only when OpenSSL ran the verification and reported it failed
//! (`Verification: FAILED`); anything else (a usage message, a crash) means
//! the token was not checked.
//!
//! The bundle is adversarial input, so the invocation is defensive: the
//! token and certificates are written to a fresh directory only this user
//! can read (mode 0700), under names made from a counter, never from the
//! bundle; the arguments are passed as a vector straight to the process,
//! never through a shell; every path is absolute, so none can be read as
//! an option; the digest is the 64 lowercase hex digits of bytes the core
//! computed; and the token and certificates reached this point only as
//! canonical base64 and PEM blocks the core already checked.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::{TsaCheck, TsaResult, TsaVerifier};

/// Checks tokens with the `openssl` binary at `bin`.
#[derive(Clone, Debug)]
pub struct OpenSslTsa {
    bin: PathBuf,
}

/// What looking for a usable `openssl` found.
#[derive(Debug)]
pub enum Found {
    /// A binary that can check tokens, and its version.
    Usable(OpenSslTsa, String),
    /// `openssl` binaries on `PATH`, none of them usable: the first, and
    /// why not.
    Unusable(PathBuf, String),
    /// No `openssl` on `PATH`.
    Missing,
}

impl OpenSslTsa {
    /// The first `openssl` on `PATH` that can check tokens, so a LibreSSL
    /// earlier on `PATH` (macOS's `/usr/bin`) does not hide an OpenSSL
    /// later on it.
    pub fn find() -> Found {
        let mut first_unusable = None;
        for bin in all_on_path("openssl") {
            match capability(&bin) {
                Ok(version) => return Found::Usable(OpenSslTsa { bin }, version),
                Err(why) => {
                    first_unusable.get_or_insert((bin, why));
                }
            }
        }
        match first_unusable {
            Some((bin, why)) => Found::Unusable(bin, why),
            None => Found::Missing,
        }
    }

    /// The binary in use.
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    fn run(&self, check: &TsaCheck<'_>, dir: &Path) -> Result<TsaResult, String> {
        let digest = hex_encode(check.digest);
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("the digest is not 64 lowercase hex digits".into());
        }
        if check.at_time < 0 {
            return Ok(TsaResult::Rejected("genTime is before 1970".into()));
        }
        let root = std::fs::canonicalize(check.root).map_err(|e| {
            format!(
                "cannot read the pinned anchors {}: {e}",
                check.root.display()
            )
        })?;
        let der = dir.join(format!("{}.der", check.index));
        std::fs::write(&der, check.token).map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&self.bin);
        cmd.args(["ts", "-verify", "-token_in", "-in"])
            .arg(&der)
            .arg("-digest")
            .arg(&digest)
            .arg("-CAfile")
            .arg(&root)
            .arg("-partial_chain")
            .arg("-attime")
            .arg(check.at_time.to_string());
        if !check.certs_pem.trim().is_empty() {
            let pem = dir.join(format!("{}.pem", check.index));
            std::fs::write(&pem, check.certs_pem).map_err(|e| e.to_string())?;
            cmd.arg("-untrusted").arg(&pem);
        }
        let out = cmd
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", self.bin.display()))?;
        Ok(classify(out.status.success(), &out.stdout, &out.stderr))
    }
}

impl TsaVerifier for OpenSslTsa {
    fn verify(&self, check: &TsaCheck<'_>) -> TsaResult {
        let dir = match PrivateDir::new() {
            Ok(d) => d,
            Err(e) => {
                return TsaResult::Unavailable(format!("cannot make a temporary directory: {e}"))
            }
        };
        match self.run(check, dir.path()) {
            Ok(r) => r,
            Err(e) => TsaResult::Unavailable(e),
        }
    }
}

/// What one run of `openssl ts -verify` says about a token. OpenSSL prints
/// `Verification: OK` or `Verification: FAILED` once it has tried to
/// verify; output without either (a usage message from a binary that does
/// not know an option, a crash) is not a verdict on the token, so the
/// token is unchecked rather than rejected.
fn classify(success: bool, stdout: &[u8], stderr: &[u8]) -> TsaResult {
    let out = String::from_utf8_lossy(stdout);
    if success && out.contains("Verification: OK") {
        TsaResult::Verified
    } else if out.contains("Verification: FAILED") {
        TsaResult::Rejected(openssl_reason(stderr))
    } else {
        TsaResult::Unavailable(format!(
            "openssl did not run the check ({})",
            openssl_reason(stderr)
        ))
    }
}

/// Whether `bin` can check tokens as step 9 needs: it is OpenSSL (not
/// LibreSSL) and its `ts` command takes `-attime` and `-partial_chain`.
/// Returns its version, or why not.
pub fn capability(bin: &Path) -> Result<String, String> {
    let run = |args: &[&str]| -> Result<String, String> {
        let out = Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", bin.display()))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(text)
    };
    let version = run(&["version"])?
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let version = pragmatic_console::text::clip(&version, 80);
    if version.contains("LibreSSL") {
        return Err(format!(
            "{version}, whose ts -verify cannot check a token at its signing time (no -attime)"
        ));
    }
    let help = run(&["ts", "-help"])?;
    for option in ["-attime", "-partial_chain"] {
        if !help.contains(option) {
            return Err(format!(
                "{} ({version}) has no ts -verify {option}",
                bin.display()
            ));
        }
    }
    Ok(version)
}

/// The most telling line of OpenSSL's error output, such as `unable to get
/// local issuer certificate`, cleaned of control characters.
fn openssl_reason(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .find(|l| l.contains("Verify error:") || l.contains("verify error"))
        .or_else(|| text.lines().find(|l| l.contains(":error:")))
        .or_else(|| text.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or("openssl ts -verify failed");
    let reason = line.rsplit(':').next().unwrap_or(line).trim();
    let reason = if reason.is_empty() { line } else { reason };
    pragmatic_console::text::clip(reason, 160)
}

/// Every `name` (`name.exe` on Windows) on `PATH` that is an executable
/// file, in `PATH` order, each once.
pub fn all_on_path(name: &str) -> Vec<PathBuf> {
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = Vec::new();
    for p in std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(&file))
    {
        if is_executable(&p) && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// A fresh directory only this user can enter, removed on drop.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new() -> std::io::Result<PrivateDir> {
        let mut random = [0u8; 16];
        pragmatic::rand::fill(&mut random)?;
        let path = std::env::temp_dir().join(format!(
            "pragmatic-tsa-{}-{}",
            std::process::id(),
            hex_encode(&random)
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(PrivateDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_dirs_are_private_and_removed() {
        let d = PrivateDir::new().unwrap();
        let p = d.path().to_path_buf();
        assert!(p.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        drop(d);
        assert!(!p.exists());
    }

    #[test]
    fn only_a_failed_verification_rejects_a_token() {
        assert_eq!(
            classify(true, b"Verification: OK\n", b""),
            TsaResult::Verified
        );
        let failed = classify(
            false,
            b"Verification: FAILED\n",
            b"x:error:...:Verify error:unable to get local issuer certificate\n",
        );
        assert_eq!(
            failed,
            TsaResult::Rejected("unable to get local issuer certificate".into())
        );
        // LibreSSL's answer to -attime: a usage message, no verdict.
        let usage = classify(false, b"", b"usage:\nts -query [-config configfile] ...\n");
        assert!(matches!(usage, TsaResult::Unavailable(_)), "{usage:?}");
        let unknown = classify(false, b"", b"ts: Unknown option: -attime\n");
        assert!(matches!(unknown, TsaResult::Unavailable(_)));
    }

    #[test]
    fn libressl_is_not_used() {
        let libre = Path::new("/usr/bin/openssl");
        let is_libre = Command::new(libre)
            .arg("version")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("LibreSSL"));
        if !is_libre {
            eprintln!("skipped: /usr/bin/openssl is not LibreSSL");
            return;
        }
        let why = capability(libre).unwrap_err();
        assert!(why.contains("LibreSSL") && why.contains("-attime"), "{why}");
    }

    #[test]
    fn reasons_are_short_and_clean() {
        let err = b"Using configuration from x\n\
            8001:error:17800064:time stamp routines:ts_verify_cert:certificate verify error:crypto/ts/ts_rsp_verify.c:182:Verify error:unable to get local issuer certificate\n";
        assert_eq!(
            openssl_reason(err),
            "unable to get local issuer certificate"
        );
        assert_eq!(openssl_reason(b""), "openssl ts -verify failed");
        assert_eq!(openssl_reason(b"bad\x1b[2Jthing"), "bad\\u{1b}[2Jthing");
    }
}
