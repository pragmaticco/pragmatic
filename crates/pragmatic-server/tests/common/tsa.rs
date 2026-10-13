//! A throwaway RFC 3161 TSA built with the `openssl` command line tool,
//! served over HTTP on a loopback port, and an OpenSSL-backed token
//! verifier for the core's evidence verification, so anchoring and
//! evidence are tested against real tokens and real CMS checks.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::{TsaCheck, TsaResult, TsaVerifier};

use super::TempDir;

/// True if an OpenSSL (not LibreSSL) `openssl` that verifies with
/// `-partial_chain` is on PATH. Tests that need one say why they skip.
pub fn openssl_usable() -> bool {
    let ok = pragmatic_server::anchoring::check_openssl(
        &pragmatic_anchor::tsa::OpensslVerifier::default(),
    )
    .is_ok();
    if !ok {
        eprintln!("skipping: no OpenSSL with `ts -verify -partial_chain` on PATH");
    }
    ok
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .expect("run openssl");
    assert!(
        out.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A local TSA: a throwaway root CA and a TSA certificate signed by it
/// with the critical `timeStamping` extended key usage.
pub struct LocalTsa {
    pub dir: TempDir,
}

impl LocalTsa {
    pub fn new(name: &str) -> LocalTsa {
        let dir = TempDir::new(&format!("tsa-{name}"));
        let d = dir.path();
        std::fs::write(
            d.join("ext.cnf"),
            "[req]\ndistinguished_name = dn\n[dn]\n\
             [v3_ca]\nbasicConstraints = critical, CA:true\n\
             keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n\
             [v3_tsa]\nbasicConstraints = critical, CA:false\n\
             keyUsage = critical, digitalSignature\nextendedKeyUsage = critical, timeStamping\n\
             subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n",
        )
        .unwrap();
        let ec = [
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
        ];
        let ca_subject = format!("/CN={name} Test Root");
        let mut ca = vec!["req", "-x509"];
        ca.extend(ec);
        ca.extend([
            "-keyout",
            "ca.key",
            "-out",
            "root.pem",
            "-days",
            "30",
            "-config",
            "ext.cnf",
            "-extensions",
            "v3_ca",
            "-subj",
            &ca_subject,
        ]);
        openssl(d, &ca);
        let tsa_subject = format!("/CN={name} Test TSA");
        let mut csr = vec!["req", "-new"];
        csr.extend(ec);
        csr.extend([
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-config",
            "ext.cnf",
            "-subj",
            &tsa_subject,
        ]);
        openssl(d, &csr);
        openssl(
            d,
            &[
                "x509",
                "-req",
                "-in",
                "tsa.csr",
                "-CA",
                "root.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "tsa.crt",
                "-days",
                "30",
                "-extfile",
                "ext.cnf",
                "-extensions",
                "v3_tsa",
            ],
        );
        std::fs::write(
            d.join("tsa.cnf"),
            format!(
                "[tsa]\ndefault_tsa = tsa1\n[tsa1]\ndir = {}\nserial = $dir/serial\n\
                 crypto_device = builtin\nsigner_cert = $dir/tsa.crt\nsigner_key = $dir/tsa.key\n\
                 certs = $dir/tsa.crt\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n\
                 other_policies = 1.2.3.4.5\ndigests = sha256\naccuracy = secs:1\n\
                 ordering = no\ntsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n",
                d.display()
            ),
        )
        .unwrap();
        std::fs::write(d.join("serial"), "01\n").unwrap();
        LocalTsa { dir }
    }

    /// The pinned root for this TSA.
    pub fn root_pem(&self) -> PathBuf {
        self.dir.path().join("root.pem")
    }

    /// `openssl ts -reply` for a DER `TimeStampReq`.
    pub fn reply(&self, query: &[u8]) -> Vec<u8> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = self.dir.path();
        let (q, r) = (format!("q{n}.tsq"), format!("r{n}.tsr"));
        std::fs::write(d.join(&q), query).unwrap();
        openssl(
            d,
            &[
                "ts",
                "-reply",
                "-config",
                "tsa.cnf",
                "-queryfile",
                &q,
                "-out",
                &r,
            ],
        );
        std::fs::read(d.join(&r)).unwrap()
    }
}

/// A local TSA on a loopback port. `healthy` can be switched off (503).
pub struct TsaServer {
    pub tsa: Arc<LocalTsa>,
    pub url: String,
    pub healthy: Arc<AtomicBool>,
    pub requests: Arc<AtomicUsize>,
}

impl TsaServer {
    pub fn start(name: &str) -> TsaServer {
        let tsa = Arc::new(LocalTsa::new(name));
        let healthy = Arc::new(AtomicBool::new(true));
        let requests = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/tsr", listener.local_addr().unwrap());
        let (t, h, n) = (tsa.clone(), healthy.clone(), requests.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (t, h, n) = (t.clone(), h.clone(), n.clone());
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut length = 0usize;
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        let header = header.trim_end();
                        if header.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = header.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                length = v.trim().parse().unwrap();
                            }
                        }
                    }
                    let mut body = vec![0u8; length];
                    reader.read_exact(&mut body).unwrap();
                    n.fetch_add(1, Ordering::SeqCst);
                    let (status, reply) = if h.load(Ordering::SeqCst) {
                        (200, t.reply(&body))
                    } else {
                        (503, b"busy".to_vec())
                    };
                    let mut out = stream;
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/timestamp-reply\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.len()
                    );
                    let _ = out.write_all(head.as_bytes());
                    let _ = out.write_all(&reply);
                });
            }
        });
        TsaServer {
            tsa,
            url,
            healthy,
            requests,
        }
    }
}

/// `openssl ts -verify` for the core verifier (design 5.3 step 9): a fresh
/// directory per check, files named by index, no shell.
pub struct OpensslTokens;

impl TsaVerifier for OpensslTokens {
    fn verify(&self, check: &TsaCheck<'_>) -> TsaResult {
        let dir = TempDir::new("verify-token");
        let der = dir.path().join(format!("{}.der", check.index));
        let pem = dir.path().join(format!("{}.pem", check.index));
        std::fs::write(&der, check.token).unwrap();
        std::fs::write(&pem, check.certs_pem).unwrap();
        let digest = hex_encode(check.digest);
        let at = check.at_time.to_string();
        let out = Command::new("openssl")
            .args(["ts", "-verify", "-token_in", "-in"])
            .arg(&der)
            .args(["-digest", &digest, "-CAfile"])
            .arg(check.root)
            .args(["-partial_chain", "-attime", &at, "-untrusted"])
            .arg(&pem)
            .stdin(Stdio::null())
            .output();
        match out {
            Ok(o) if o.status.success() && String::from_utf8_lossy(&o.stdout).contains("OK") => {
                TsaResult::Verified
            }
            Ok(o) => TsaResult::Rejected(String::from_utf8_lossy(&o.stderr).into_owned()),
            Err(e) => TsaResult::Unavailable(e.to_string()),
        }
    }
}
