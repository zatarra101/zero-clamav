#!/bin/sh
set -eu

WORK=/tmp/zero-clamav-poc
rm -rf "$WORK"
mkdir -p "$WORK"

# Synthetic clean fixtures. Nothing from a real user is used.
printf '%%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n' > "$WORK/clean.pdf"
printf '\211PNG\r\n\032\n' > "$WORK/clean.png"
printf '\377\330\377\340\000\020JFIF\000\001\001\000\000\001\000\001\000\000\377\331' > "$WORK/clean.jpg"

printf '%s' 'Waiting for ClamAV signature database...\n'

# The official image initializes its database during startup. Wait briefly for it.
ready=0
for i in $(seq 1 60); do
  if [ -f /var/lib/clamav/main.cvd ] || [ -f /var/lib/clamav/main.cud ] || [ -f /var/lib/clamav/main.cld ]; then
    ready=1
    break
  fi
  sleep 2
done

if [ "$ready" -ne 1 ]; then
  echo 'FAIL: ClamAV signature database did not become available.'
  exit 1
fi

echo 'PASS: ClamAV signature database is available.'

if clamscan --no-summary "$WORK/clean.pdf" "$WORK/clean.png" "$WORK/clean.jpg"; then
  echo 'PASS: clean PDF/PNG/JPG were accepted.'
else
  echo 'FAIL: a clean fixture was reported as infected or scanning failed.'
  exit 1
fi

# Construct EICAR at runtime so the test signature is never committed as a file.
EICAR='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s' "$EICAR" > "$WORK/eicar.com"

set +e
clamscan --no-summary "$WORK/eicar.com"
status=$?
set -e

if [ "$status" -eq 1 ]; then
  echo 'PASS: EICAR was detected by ClamAV.'
else
  echo "FAIL: expected ClamAV exit code 1 for EICAR, got $status."
  exit 1
fi

echo 'CLAMAV_POC_RESULT=PASS'
