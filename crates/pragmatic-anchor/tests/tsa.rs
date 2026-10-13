//! The RFC 3161 client against a local OpenSSL TSA over HTTP: validation,
//! CMS verification against pinned roots, retries with fresh nonces, and
//! request spacing. Skipped, with a message, when `openssl` is missing.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use pragmatic::encoding::base64_decode;
use pragmatic::sha256::sha256;
use pragmatic::tsp;
use pragmatic_anchor::tsa::{
    validate_response, OpensslVerifier, TsaClient, TsaConfig, TsaError, TsaPolicy, UreqTransport,
};
use support::{openssl_available, LocalTsa, TestServer, TsaServer};

fn fast() -> TsaPolicy {
    TsaPolicy {
        timeout: Duration::from_secs(10),
        min_spacing: Duration::ZERO,
        max_attempts: 3,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
    }
}

fn client(url: &str, operator: &str, roots: std::path::PathBuf, policy: TsaPolicy) -> TsaClient {
    TsaClient::new(
        TsaConfig::new(url, operator, roots).unwrap(),
        policy,
        Arc::new(UreqTransport::new()),
        OpensslVerifier::default(),
    )
}

#[test]
fn a_token_is_validated_and_verified_against_the_pinned_root() {
    if !openssl_available() {
        return;
    }
    let tsa = TsaServer::start("Alpha", 0);
    let c = client(&tsa.server.url, "DigiCert", tsa.tsa.root_pem(), fast());
    let digest = sha256(b"checkpoint body\n");
    let token = c.timestamp(&digest).unwrap();
    assert_eq!(tsa.server.count(), 1);
    assert_eq!(token.operator, "digicert");
    assert!(token.info.imprint_matches(&digest));
    assert_eq!(token.info.nonce_u64(), Some(token.nonce));
    assert!(token.certs_pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(token.gen_time_unix() > 1_700_000_000);
    // The evidence object carries exactly the design 5.1 keys, and the
    // token in it is the one OpenSSL verified.
    let obj = token.evidence_json();
    let keys: Vec<&str> = obj
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(keys, ["type", "tsa", "operator", "token", "certs_pem"]);
    let der = base64_decode(obj.get("token").unwrap().as_str().unwrap()).unwrap();
    assert_eq!(tsp::parse_token(&der).unwrap(), token.info);
    // An auditor re-verifies offline with the same pinned root.
    OpensslVerifier::default()
        .verify_token(&der, &digest, &tsa.tsa.root_pem(), &token.certs_pem)
        .unwrap();
}

/// An operator can be pinned by a narrower anchor than its root (here the
/// TSA's own certificate; in production the CA that issues the operator's
/// time-stamping certificates), so time-stamping certificates others buy
/// under the same root do not verify as that operator.
#[test]
fn an_operator_can_be_pinned_below_its_root() {
    if !openssl_available() {
        return;
    }
    let tsa = TsaServer::start("Alpha", 0);
    let c = client(&tsa.server.url, "DigiCert", tsa.tsa.signer_pem(), fast());
    let digest = sha256(b"pinned below the root");
    let token = c.timestamp(&digest).unwrap();
    OpensslVerifier::default()
        .verify_token(
            &token.token,
            &digest,
            &tsa.tsa.signer_pem(),
            &token.certs_pem,
        )
        .unwrap();
    // Another TSA, under its own root, does not verify against that pin.
    let other = TsaServer::start("Beta", 0);
    let c = client(&other.server.url, "DigiCert", tsa.tsa.signer_pem(), fast());
    assert!(matches!(c.timestamp(&digest), Err(TsaError::Verify(_))));
}

#[test]
fn a_token_that_does_not_chain_to_the_pinned_root_is_refused() {
    if !openssl_available() {
        return;
    }
    let tsa = TsaServer::start("Alpha", 0);
    let stranger = LocalTsa::new("Stranger");
    let c = client(&tsa.server.url, "x", stranger.root_pem(), fast());
    let err = c.timestamp(&sha256(b"x")).unwrap_err();
    assert!(matches!(err, TsaError::Verify(_)), "{err}");
    assert_eq!(
        tsa.server.count(),
        1,
        "verification failures are not retried"
    );
    // A pinned root file that does not exist is a local error.
    let c = client(&tsa.server.url, "x", "/nonexistent/root.pem".into(), fast());
    assert!(matches!(
        c.timestamp(&sha256(b"x")),
        Err(TsaError::Local(_))
    ));
}

#[test]
fn transient_failures_are_retried_with_fresh_nonces() {
    if !openssl_available() {
        return;
    }
    let tsa = TsaServer::start("Alpha", 2);
    let c = client(&tsa.server.url, "x", tsa.tsa.root_pem(), fast());
    let token = c.timestamp(&sha256(b"retry")).unwrap();
    let seen = tsa.server.seen();
    assert_eq!(seen.len(), 3);
    // Each attempt carried a different nonce (so a different request).
    assert_ne!(seen[0].body, seen[1].body);
    assert_ne!(seen[1].body, seen[2].body);
    assert_eq!(seen[2].body, tsp::request(&sha256(b"retry"), token.nonce));

    // Out of attempts: the last error is returned.
    let down = TsaServer::start("Beta", 100);
    let c = client(&down.server.url, "x", down.tsa.root_pem(), fast());
    assert_eq!(
        c.timestamp(&sha256(b"x")),
        Err(TsaError::Http { status: 503 })
    );
    assert_eq!(down.server.count(), 3);
}

#[test]
fn mismatched_and_refused_responses_are_rejected() {
    if !openssl_available() {
        return;
    }
    let tsa = Arc::new(LocalTsa::new("Alpha"));
    let digest = sha256(b"anchor");

    // A replayed response for an earlier nonce.
    let stale = tsa.reply(&tsp::request(&digest, 1));
    let s = stale.clone();
    let replay = TestServer::start(move |_| (200, "application/timestamp-reply".into(), s.clone()));
    let c = client(&replay.url, "x", tsa.root_pem(), fast());
    assert_eq!(c.timestamp(&digest), Err(TsaError::NonceMismatch));
    assert_eq!(replay.count(), 3);
    assert_eq!(
        validate_response(&stale, &digest, 2),
        Err(TsaError::NonceMismatch)
    );
    assert!(validate_response(&stale, &digest, 1).is_ok());

    // A token over another digest.
    assert_eq!(
        validate_response(&stale, &sha256(b"other"), 1),
        Err(TsaError::ImprintMismatch)
    );

    // A rejection: PKIStatus 2 with failInfo badAlg.
    let rejection = vec![
        0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x02, 0x03, 0x02, 0x07, 0x80,
    ];
    assert!(matches!(
        validate_response(&rejection, &digest, 1),
        Err(TsaError::Rejected {
            status: 2,
            fail_info: Some(1),
            ..
        })
    ));
}

#[test]
fn requests_to_one_tsa_are_spaced() {
    if !openssl_available() {
        return;
    }
    let tsa = TsaServer::start("Alpha", 0);
    let spacing = Duration::from_millis(400);
    let c = client(
        &tsa.server.url,
        "x",
        tsa.tsa.root_pem(),
        TsaPolicy {
            min_spacing: spacing,
            ..fast()
        },
    );
    let started = Instant::now();
    c.timestamp(&sha256(b"one")).unwrap();
    c.timestamp(&sha256(b"two")).unwrap();
    let seen = tsa.server.seen();
    assert!(seen[1].at.duration_since(seen[0].at) >= spacing - Duration::from_millis(20));
    assert!(started.elapsed() >= spacing);
    // The design's defaults.
    let d = TsaPolicy::default();
    assert_eq!(d.timeout, Duration::from_secs(30));
    assert_eq!(d.min_spacing, Duration::from_secs(15));
}

#[test]
fn an_unreachable_tsa_is_a_transport_error() {
    let c = client("http://127.0.0.1:9", "x", "/nonexistent".into(), fast());
    assert!(matches!(
        c.timestamp(&sha256(b"x")),
        Err(TsaError::Transport(_))
    ));
}
