#!/bin/sh
# CLAMAV_DB=full  official signatures via freshclam (needs ~1.5 GiB RAM and outbound HTTPS) plus the lab EICAR signature
# CLAMAV_DB=test  one local signature that matches the EICAR test string only (for hosts too small for the
#                 full database; same c-icap + ClamAV engine, NOT a real antivirus)
set -eu
DB=/var/lib/clamav
case "${CLAMAV_DB:-full}" in
  test)
    rm -f "$DB"/*.cvd "$DB"/*.cld 2>/dev/null || true
    # body signature: name:target:offset:hex("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    echo 'Lab-EICAR-Anywhere:0:*:45494341522d5354414e444152442d414e544956495255532d544553542d46494c45' > "$DB/lab-test.ndb"
    echo "icap-av: TEST signature database (EICAR only)";;
  full)
    # The lab keeps ONE signature of its own beside the official database: the EICAR test string
    # matched anywhere in a file. ClamAV's own EICAR rule fires only when the string IS the file
    # (first bytes, at most 128 bytes), so "a valid CSV carrying the test string" would otherwise
    # pass a real scanner. The lab signature is named so it is obvious in the logs.
    echo 'Lab-EICAR-Anywhere:0:*:45494341522d5354414e444152442d414e544956495255532d544553542d46494c45' > "$DB/lab-test.ndb"
    # No UpdateLogFile: under rootless Podman /dev/stdout is not openable as a file; --stdout is.
    printf 'DatabaseDirectory %s\nDatabaseMirror database.clamav.net\nForeground yes\nConnectTimeout 60\nReceiveTimeout 300\n' "$DB" > /tmp/freshclam.conf
    if ! ls "$DB"/*.c[vl]d >/dev/null 2>&1; then
      for try in 1 2 3; do freshclam --stdout --config-file=/tmp/freshclam.conf && break; echo "icap-av: freshclam attempt $try failed"; sleep 30; done
      ls "$DB"/*.c[vl]d >/dev/null 2>&1 || { echo "icap-av: no signatures after 3 attempts, refusing to start"; exit 1; }
    fi
    ( while sleep 21600; do freshclam --stdout --config-file=/tmp/freshclam.conf; done ) &
    echo "icap-av: FULL signature database";;
  *) echo "icap-av: CLAMAV_DB='${CLAMAV_DB}' is not full or test (an unexpanded compose variable?); using full"; CLAMAV_DB=full; exec "$0" "$@";;
esac
rm -f /run/c-icap/c-icap.pid /run/c-icap/c-icap.ctl   # stale after an unclean stop; c-icap refuses to start otherwise
touch /var/log/c-icap/server.log /var/log/c-icap/access.log
tail -n0 -F /var/log/c-icap/server.log /var/log/c-icap/access.log &
exec c-icap -N -f /etc/c-icap/c-icap.conf
