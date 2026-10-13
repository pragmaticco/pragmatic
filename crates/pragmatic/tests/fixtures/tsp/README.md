# RFC 3161 fixtures

Real time-stamp requests and responses used by the unit tests in
`src/tsp.rs`. Each pair was produced on 2026-10-13 with OpenSSL 3.6.3 and
curl, so the requests are exactly what `openssl ts -query` writes and the
responses are exactly what the live TSAs returned.

| Fixture | TSA URL | Digest preimage | Nonce (OpenSSL's choice) | What it covers |
|---|---|---|---|---|
| `freetsa` | `https://freetsa.org/tsr` | `pragmatic tsp fixture: freetsa` | `0x3F2E6A9BBBF233D8` | RSA, `ordering = TRUE`, TSA name |
| `digicert` | `http://timestamp.digicert.com` | `pragmatic tsp fixture: digicert` | `0xBBBD8A084B593BD9` | nonce with the top bit set (nine-octet INTEGER), 16-byte serial, no TSA name |
| `sigstore` | `https://timestamp.sigstore.dev/api/v1/timestamp` | `pragmatic tsp fixture: sigstore` | `0xF56E935B88DA60E2` | ECDSA, `accuracy.seconds`, 20-byte serial |
| `microsoft` | `http://timestamp.acs.microsoft.com` | `pragmatic tsp fixture: microsoft` | `0xD3EA93B9001C58D6` | fractional `genTime` (`.811Z`), `accuracy.millis` |
| `quovadis` | `http://ts.quovadisglobal.com/eu` | `pragmatic tsp fixture: quovadis` | `0xBFBC0B08F3F29B53` | `statusString` on a granted response, `[1]` extensions (qcStatements) |
| `freetsa-rejected` | `https://freetsa.org/tsr` | (request for `freetsa` with the hash OID changed to SHAKE256) | `0x3F2E6A9BBBF233D8` | `rejection` status with `statusString` and `failInfo = badAlg`, no token |

The digest is `SHA-256(preimage)`, written to the request in hex:

```sh
D=$(printf 'pragmatic tsp fixture: freetsa' | shasum -a 256 | cut -d' ' -f1)
openssl ts -query -digest "$D" -sha256 -cert -out freetsa.tsq
openssl ts -query -in freetsa.tsq -text          # read back the nonce
curl -sS -H 'Content-Type: application/timestamp-query' \
     --data-binary @freetsa.tsq https://freetsa.org/tsr -o freetsa.tsr
openssl ts -reply -in freetsa.tsr -text          # inspect the token
```

For `digicert`, the query was regenerated until OpenSSL picked a nonce with
the top bit set. `freetsa-rejected.tsq` is `freetsa.tsq` with the last
octet of the SHA-256 OID changed from `0x01` to `0x0c`
(2.16.840.1.101.3.4.2.12, SHAKE256), which FreeTSA refuses.

To inspect a token's `TSTInfo`, extract the token and parse the
`eContent` octet string:

```sh
openssl ts -reply -in sigstore.tsr -token_out -out sigstore.tok
openssl asn1parse -inform DER -in sigstore.tok          # find the OCTET STRING offset
openssl asn1parse -inform DER -in sigstore.tok -strparse 60
```

These files are test data only. Their signatures are genuine and can be
checked with `openssl ts -verify -digest <hex> -in <name>.tsr -CAfile
<TSA chain>`, but the tests do not depend on certificate validity, so they
keep passing after the TSA certificates expire.
