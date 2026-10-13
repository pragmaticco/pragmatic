# Pinned TSA roots

Pragmatic Server verifies every RFC 3161 time-stamp token it stores with
`openssl ts -verify -CAfile <roots_pem> -partial_chain`, and an auditor
verifies evidence bundles the same way with `pragmatic verify-evidence
--tsa-roots OPERATOR=FILE`. Every certificate in a file is a trust anchor,
so a file may hold the CA that issues an operator's time-stamping
certificates instead of its root, which is narrower.
These files are the root certificates the example configuration pins for
the public TSAs. A root is a trust anchor, so do not take these files on
faith: check each fingerprint against at least two sources you obtained
independently of this repository before you configure it.

Each fingerprint below is the SHA-256 of the certificate's DER encoding, as
printed by:

```sh
openssl x509 -in deploy/tsa-roots/<file> -noout -fingerprint -sha256
```

| File | Certificate (subject CN) | SHA-256 fingerprint | Valid until |
|---|---|---|---|
| `digicert_g4.pem` | DigiCert Trusted Root G4 | `55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88` | 2038-01-15 |
| `usertrust_rsa.pem` | USERTrust RSA Certification Authority | `E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2` | 2038-01-18 |
| `globalsign_r6.pem` | GlobalSign Root CA - R6 | `2C:AB:EA:FE:37:D0:6C:A2:2A:BA:73:91:C0:03:3D:25:98:29:52:C4:53:64:73:49:76:3A:3A:B5:AD:6C:CF:69` | 2034-12-10 |
| `microsoft.pem` | Microsoft Identity Verification Root Certificate Authority 2020 | `53:67:F2:0C:7A:DE:0E:2B:CA:79:09:15:05:6D:08:6B:72:0C:33:C1:FA:2A:26:61:AC:F7:87:E3:29:2E:12:70` | 2045-04-16 |
| `freetsa.pem` | www.freetsa.org (Free TSA Root CA) | `A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC` | 2041-03-07 |

## Which TSA each root is for

| File | Operator (as configured) | Time-stamp service |
|---|---|---|
| `digicert_g4.pem` | `digicert` | `http://timestamp.digicert.com` (in the default configuration) |
| `usertrust_rsa.pem` | `sectigo` | `http://timestamp.sectigo.com` (in the default configuration) |
| `globalsign_r6.pem` | `globalsign` | GlobalSign's public time-stamping service |
| `microsoft.pem` | `microsoft` | Microsoft's public time-stamping service |
| `freetsa.pem` | `freetsa` | `https://freetsa.org/tsr` (a free community service; suitable for testing, not for evidence you rely on) |

The tokens recorded in `crates/pragmatic/tests/fixtures/tsp-live/` from
`timestamp.digicert.com` and `freetsa.org` verify against `digicert_g4.pem`
and `freetsa.pem` respectively. A TSA can move to a new issuing chain at
any time: before pinning a root for a TSA, request one token from it and
check that `openssl ts -verify` accepts it with only that root as
`-CAfile`.

Independence is counted by operator (design 4.7): Entrust counts as
Sectigo and QuoVadis as DigiCert, so pinning roots from those brands next
to the ones above adds no independent operator.

## Where to obtain each root independently

Compare the fingerprint above with each of these. A match in the CA's own
publication and in a root program you trust is the minimum.

- **DigiCert Trusted Root G4**: DigiCert's root certificate page
  (`https://www.digicert.com/kb/digicert-root-certificates.htm`), the
  Mozilla root store as listed in the Common CA Database (CCADB) "Included
  CA Certificates" report, and the trust stores of Windows and macOS
  (`security find-certificate -a -c "DigiCert Trusted Root G4" -Z
  /System/Library/Keychains/SystemRootCertificates.keychain` prints its
  SHA-256 on macOS).
- **USERTrust RSA Certification Authority** (Sectigo): Sectigo's
  knowledge base page for its root certificates, the CCADB report, and
  the operating system trust stores.
- **GlobalSign Root CA - R6**: GlobalSign's root certificates page
  (`https://support.globalsign.com/ca-certificates/root-certificates/globalsign-root-certificates`),
  the CCADB report, and the operating system trust stores.
- **Microsoft Identity Verification Root Certificate Authority 2020**:
  the Microsoft PKI repository
  (`https://www.microsoft.com/pkiops/docs/repository.htm`) and the Windows
  trust store (Microsoft Trusted Root Program).
- **Free TSA Root CA**: `https://freetsa.org/files/cacert.pem`, with the
  fingerprints FreeTSA publishes on `https://freetsa.org/index_en.php`.
  It is in no browser or operating system root program, so there is no
  second, independent publication to compare against; treat it accordingly.

## Using your own roots

Any RFC 3161 TSA works, including qualified (eIDAS) providers as a paid
option. Put its root (or roots, or better its issuing CA) in a PEM file, name the
operator in the `tsa` entry, and pin the same file under the same
operator when verifying evidence. Files of different operators must not
share a certificate: a token that verifies for two operators counts for
neither. Obtain written
permission from TSA operators before automated use; the server already
spaces its requests to one TSA at least 15 seconds apart.
