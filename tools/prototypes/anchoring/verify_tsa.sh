#!/bin/sh
# verify_tsa.sh <bundle_dir> <trust_dir>
# openssl-only verification of every RFC 3161 token in a Pragmatic anchor bundle.
# trust_dir/<tsa>.pem = the ONE root the auditor pins for that TSA.
set -eu
B=$1; T=$2; OPENSSL=${OPENSSL:-openssl}
# 1. the anchored message is the checkpoint *body*: every line before the first blank line
awk 'NF==0{exit} {print}' "$B/checkpoint" > "$B/.body"
D=$($OPENSSL dgst -sha256 -r "$B/.body" | cut -d' ' -f1)
echo "sha256(checkpoint body) = $D"
for R in "$B"/tsa/*.tsr; do
  N=$(basename "$R" .tsr)
  [ -f "$T/$N.pem" ] || { echo "$N: no pinned root, skipped"; continue; }
  # 2. genTime -> epoch, so chain validity is judged at genTime, not today
  GT=$($OPENSSL ts -reply -in "$R" -text 2>/dev/null | sed -n 's/^Time stamp: //p' | sed 's/\.[0-9]*//')
  AT=$(date -u -j -f '%b %e %H:%M:%S %Y GMT' "$GT" +%s 2>/dev/null || date -u -d "$GT" +%s)
  AT=$((AT + 1))
  # 3. imprint == D, CMS signature, ESS signing-cert binding, critical EKU timeStamping, chain to pinned root
  if $OPENSSL ts -verify -in "$R" -digest "$D" -CAfile "$T/$N.pem" -attime "$AT" >/dev/null 2>&1; then
    echo "$N: OK   genTime=$GT"
  else
    echo "$N: FAIL genTime=$GT"; $OPENSSL ts -verify -in "$R" -digest "$D" -CAfile "$T/$N.pem" -attime "$AT" 2>&1 | grep error | sed 's/^/    /'
  fi
done
rm -f "$B/.body"
