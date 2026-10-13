//! RFC 3161 signature checks with the `openssl` command (design 5.3 step 9).
//!
//! The core parses tokens but does not verify CMS signatures: that needs
//! X.509 path building and several signature algorithms, which OpenSSL
//! does and a zero-dependency crate should not reimplement. Each check runs
//!
//! ```text
//! openssl ts -verify -token_in -in <i>.der -digest <anchor digest>
//!     -CAfile <pinned root> -untrusted <i>.pem -attime <genTime + 1>
//! ```
//!
//! which checks the signature, the ESS signing-certificate binding, the
//! critical `timeStamping` extended key usage, that the imprint is the
//! anchor digest, and that the TSA certificate chains to the pinned root as
//! of the time the token was made (so a TSA certificate that has since
//! expired still verifies, and one that was not yet valid does not).
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

impl OpenSslTsa {
    /// `openssl` from `PATH`, if it is there.
    pub fn from_path() -> Option<OpenSslTsa> {
        find_on_path("openssl").map(|bin| OpenSslTsa { bin })
    }

    /// The binary in use.
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// `openssl version`, for the report.
    pub fn version(&self) -> Option<String> {
        let out = Command::new(&self.bin)
            .arg("version")
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!v.is_empty()).then_some(v)
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
        let root = std::fs::canonicalize(check.root)
            .map_err(|e| format!("cannot read the pinned root {}: {e}", check.root.display()))?;
        let der = dir.join(format!("{}.der", check.index));
        std::fs::write(&der, check.token).map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&self.bin);
        cmd.args(["ts", "-verify", "-token_in", "-in"])
            .arg(&der)
            .arg("-digest")
            .arg(&digest)
            .arg("-CAfile")
            .arg(&root)
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
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && stdout.contains("Verification: OK") {
            return Ok(TsaResult::Verified);
        }
        Ok(TsaResult::Rejected(openssl_reason(&out.stderr)))
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

/// The first `name` (`name.exe` on Windows) on `PATH` that is a file.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(&file))
        .find(|p| is_executable(p))
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
