//! Test fixtures: a throwaway RFC 3161 TSA built with the `openssl` command
//! line tool, and a minimal HTTP/1.1 server to put it (or a witness) on a
//! loopback port, so the clients are exercised over real HTTP.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// True if `openssl` can be run. Tests that need it print why they skip.
pub fn openssl_available() -> bool {
    let ok = Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipping: the openssl command line tool is not available");
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

/// A local TSA: its own throwaway root CA and a TSA certificate signed by
/// it, with the critical `timeStamping` extended key usage RFC 3161
/// requires (OpenSSL refuses to sign or verify tokens without it).
pub struct LocalTsa {
    pub dir: tempfile::TempDir,
    pub name: String,
}

impl LocalTsa {
    pub fn new(name: &str) -> LocalTsa {
        let dir = tempfile::tempdir().unwrap();
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
        let mut ca = vec!["req", "-x509"];
        ca.extend(ec);
        let ca_subject = format!("/CN={name} Test Root");
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
        let mut csr = vec!["req", "-new"];
        csr.extend(ec);
        let tsa_subject = format!("/CN={name} Test TSA");
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
        LocalTsa {
            dir,
            name: name.to_string(),
        }
    }

    /// The pinned root for this TSA.
    pub fn root_pem(&self) -> PathBuf {
        self.dir.path().join("root.pem")
    }

    /// The TSA's own signing certificate, for pinning it directly (a
    /// narrower trust anchor than the root).
    pub fn signer_pem(&self) -> PathBuf {
        self.dir.path().join("tsa.crt")
    }

    /// `openssl ts -reply` for a DER `TimeStampReq`.
    pub fn reply(&self, query: &[u8]) -> Vec<u8> {
        // Requests may arrive concurrently; each gets its own files.
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = self.dir.path();
        let q = format!("q{n}.tsq");
        let r = format!("r{n}.tsr");
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

/// What a test server answers: status, content type and body.
pub type Reply = (u16, String, Vec<u8>);

/// A request as the test server saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub at: std::time::Instant,
}

/// A loopback HTTP server running a handler per request on a thread.
pub struct TestServer {
    pub url: String,
    pub requests: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    pub fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let (reqs, stopped) = (requests.clone(), stop.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (handler, reqs) = (handler.clone(), reqs.clone());
                thread::spawn(move || serve_one(stream, &*handler, &reqs));
            }
        });
        TestServer {
            url,
            requests,
            stop,
        }
    }

    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
    }
}

fn serve_one(stream: TcpStream, handler: &dyn Fn(&Seen) -> Reply, reqs: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).unwrap();
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
            if k == "content-length" {
                length = v.parse().unwrap();
            }
            headers.push((k, v));
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).unwrap();
    let seen = Seen {
        path,
        headers,
        body,
        at: std::time::Instant::now(),
    };
    reqs.lock().unwrap().push(seen.clone());
    let (status, content_type, body) = handler(&seen);
    let mut out = stream;
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(&body);
    let _ = out.flush();
}

/// A TSA on a loopback port. `fail_first` requests get 503 first;
/// `healthy` can be switched off and on.
pub struct TsaServer {
    pub tsa: Arc<LocalTsa>,
    pub server: TestServer,
    pub healthy: Arc<AtomicBool>,
}

impl TsaServer {
    pub fn start(name: &str, fail_first: usize) -> TsaServer {
        let tsa = Arc::new(LocalTsa::new(name));
        let healthy = Arc::new(AtomicBool::new(true));
        let failures = Arc::new(AtomicUsize::new(fail_first));
        let (t, h) = (tsa.clone(), healthy.clone());
        let server = TestServer::start(move |req| {
            let ct = req
                .headers
                .iter()
                .find(|(k, _)| k == "content-type")
                .map(|(_, v)| v.as_str());
            assert_eq!(ct, Some("application/timestamp-query"));
            let failing = failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if failing || !h.load(Ordering::SeqCst) {
                return (503, "text/plain".into(), b"busy".to_vec());
            }
            (
                200,
                "application/timestamp-reply".into(),
                t.reply(&req.body),
            )
        });
        TsaServer {
            tsa,
            server,
            healthy,
        }
    }
}
