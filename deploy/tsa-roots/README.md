# Pinned TSA trust anchors

Stet Server verifies every RFC 3161 time-stamp token it stores with

```sh
openssl ts -verify -token_in -in <token> -digest <anchor digest> \
    -CAfile <the operator's file> -partial_chain -untrusted <the token's certificates>
```

and an auditor verifies evidence bundles the same way with
`pragmatic verify-evidence --tsa-roots OPERATOR=FILE`. Every certificate in
a file is a trust anchor (`-partial_chain`), and a token counts for the
operator whose file verifies it, never for the operator a bundle names.

This directory holds one file per operator: the anchors the example
configuration (`deploy/pragmatic.example.toml`) pins for the public TSAs.
The container image carries them in `/etc/pragmatic/tsa-roots/`.

## Narrow anchors first

Anyone who can buy a time-stamping certificate under a pinned anchor can
pass as that anchor's operator. So, where the operator publishes one, a
file holds the CA that issues the operator's own time-stamping
certificates, not a general-purpose root under which other companies'
certificates also chain. Where no such CA is pinned here, the file holds
the operator's root, which works, with that risk.

| File | Operator | Time-stamp service | Certificate | Kind | SHA-256 fingerprint (DER) | Valid until |
|---|---|---|---|---|---|---|
| `digicert.pem` | `digicert` | `http://timestamp.digicert.com` (default) | DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1 | issuing CA | `CA:0B:15:54:EC:D9:01:EA:19:DC:AD:87:49:E9:F2:64:8C:8D:6D:FC:EA:1A:DD:9D:2C:21:09:41:5B:B8:2C:CD` | 2038-01-14 |
| `sectigo.pem` | `sectigo` | `http://timestamp.sectigo.com` (default) | USERTrust RSA Certification Authority | root | `E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2` | 2038-01-18 |
| `microsoft.pem` | `microsoft` | `http://timestamp.acs.microsoft.com` | Microsoft Public RSA Timestamping CA 2020 | issuing CA | `36:E7:31:CF:A9:BF:D6:9D:AF:B6:43:80:9F:6D:EC:50:09:02:F7:19:7D:AE:AA:D8:6E:A0:15:9A:22:68:A2:B8` | 2035-11-19 |
| `globalsign.pem` | `globalsign` | GlobalSign's public time-stamping service | GlobalSign Root CA - R6 | root | `2C:AB:EA:FE:37:D0:6C:A2:2A:BA:73:91:C0:03:3D:25:98:29:52:C4:53:64:73:49:76:3A:3A:B5:AD:6C:CF:69` | 2034-12-10 |
| `freetsa.pem` | `freetsa` | `https://freetsa.org/tsr` (testing only) | www.freetsa.org (Free TSA Root CA) | root | `A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC` | 2041-03-07 |

Print a file's fingerprint with:

```sh
openssl x509 -in deploy/tsa-roots/<file> -noout -subject -fingerprint -sha256
```

The two issuing CAs chain to these roots, whose fingerprints you should
check as well:

| Issuing CA | Its root | Root SHA-256 fingerprint |
|---|---|---|
| DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1 | DigiCert Trusted Root G4 | `55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88` |
| Microsoft Public RSA Timestamping CA 2020 | Microsoft Identity Verification Root Certificate Authority 2020 | `53:67:F2:0C:7A:DE:0E:2B:CA:79:09:15:05:6D:08:6B:72:0C:33:C1:FA:2A:26:61:AC:F7:87:E3:29:2E:12:70` |

`crates/pragmatic-server/tests/deploy.rs` checks that every file here
matches its row, that no two operators share an anchor, and that the
DigiCert and Microsoft tokens recorded in
`crates/pragmatic/tests/fixtures/tsp/` verify against their operator's
file and against no other.

## Obtaining each anchor independently

An anchor decides what counts as evidence, so do not take these files on
faith: compare each fingerprint with at least two sources you obtained
independently of this repository before you configure it, and verify an
issuing CA against a root you obtained independently:

```sh
openssl verify -CAfile <root you downloaded yourself> deploy/tsa-roots/digicert.pem
```

- **DigiCert** (the issuing CA and DigiCert Trusted Root G4): DigiCert's
  certificate repository (`https://www.digicert.com/kb/digicert-root-certificates.htm`,
  which lists the intermediate CAs too, and `https://cacerts.digicert.com/`),
  the Mozilla root store as listed in the Common CA Database (CCADB)
  reports, and the trust stores of Windows and macOS (`security
  find-certificate -a -c "DigiCert Trusted Root G4" -Z
  /System/Library/Keychains/SystemRootCertificates.keychain` prints the
  root's SHA-256 on macOS). The issuing CA is also in every token
  `timestamp.digicert.com` returns: request one and compare.
- **Sectigo** (USERTrust RSA Certification Authority): Sectigo's knowledge
  base page for its root certificates, the CCADB reports, and the operating
  system trust stores. Sectigo issues its time-stamping certificates under
  its Public Time Stamping roots, which USERTrust RSA cross-signs; pin
  Sectigo's time-stamping CA instead once you have obtained it from Sectigo
  and checked it against a token.
- **Microsoft** (the issuing CA and its root): the Microsoft PKI repository
  (`https://www.microsoft.com/pkiops/docs/repository.htm`) and the Windows
  trust store (Microsoft Trusted Root Program).
- **GlobalSign Root CA - R6**: GlobalSign's root certificates page
  (`https://support.globalsign.com/ca-certificates/root-certificates/globalsign-root-certificates`),
  the CCADB reports, and the operating system trust stores.
- **Free TSA Root CA**: `https://freetsa.org/files/cacert.pem`, with the
  fingerprints FreeTSA publishes on `https://freetsa.org/index_en.php`. It
  is in no browser or operating system root program, so there is no second,
  independent publication to compare against; use it for testing only.

A TSA can move to a new issuing CA at any time. Before you pin a file for a
TSA, and again when its tokens stop verifying (the anchoring lag and the
`anchor_failed` webhook say so), request one token and check that
`openssl ts -verify` accepts it with only that file as `-CAfile`:

```sh
openssl ts -query -digest "$(printf probe | shasum -a 256 | cut -d' ' -f1)" -sha256 -cert -out probe.tsq
curl -sS -H 'Content-Type: application/timestamp-query' --data-binary @probe.tsq \
     http://timestamp.digicert.com -o probe.tsr
openssl ts -verify -in probe.tsr -queryfile probe.tsq \
     -CAfile deploy/tsa-roots/digicert.pem -partial_chain
```

## Operators and independence

A checkpoint is independently anchored once witnesses of at least
`min_independent_operators` distinct operators (default 2) have verified
it, and only then does a run's anchored length advance. Independence is
counted by operator: Entrust counts as Sectigo and QuoVadis (including
QuoVadis EU) as DigiCert, so pinning those brands next to the files above
adds no independent operator. Files of different operators must not share
a certificate: the server refuses such a configuration, and a verifier
counts a token that verifies for two operators for neither.

## Permission for automated use

Public TSAs are free services with rate limits, offered on their
operators' terms. Obtain written permission from each TSA operator before
pointing a server at its service for automated use, and keep it with your
deployment records. The server spaces its requests to one TSA at least 15
seconds apart and sends only a 32-byte digest and a nonce, but a busy
deployment still sends a request per witness every anchoring interval.

## Your own TSAs

Any RFC 3161 TSA works, including qualified (eIDAS) providers as a paid
option. Put its issuing CA (or its root) in a PEM file of its own, name the
operator in the `tsa` entry, and give auditors the same file to pin under
the same operator name.
