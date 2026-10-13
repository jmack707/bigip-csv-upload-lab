#!/usr/bin/env bash
# End-to-end test runner for the BIG-IP-routed flow.
#
#   MODE=bigip  ./run-tests.sh     # through the BIG-IP virtual server (default): WAF, ICAP antivirus, validator, sink
#   MODE=direct ./run-tests.sh     # validator HTTP validate-only endpoint: CSV and multipart rules only
#   MODE=both   ./run-tests.sh
#   OPS=1                          # also run the operational tests (stops/starts containers; needs podman)
#
# Environment:
#   BIGIP_URL   https://<vip>/upload (required unless MODE=direct)   CA_FILE  test/tls/ca.pem (validated by default)
#   DIRECT_URL  http://127.0.0.1:8080/upload   SINK_URL http://127.0.0.1:8081
#   ICAP_AV_CONTAINER csv-icap-av (set empty when the scanner runs on another host; its ops test is then skipped)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES="$HERE/files"; RESULTS="$HERE/results"; mkdir -p "$RESULTS"
TS="$(date +%Y%m%d-%H%M%S)"; RUN_START="$(date -u +%Y-%m-%dT%H:%M:%S)"
LOG="$RESULTS/run-$TS.tsv"
MODE="${MODE:-bigip}"
BIGIP_URL="${BIGIP_URL:-}"
if [[ "$MODE" != direct && -z "$BIGIP_URL" ]]; then echo "set BIGIP_URL=https://<vip>/upload" >&2; exit 2; fi
DIRECT_URL="${DIRECT_URL:-http://127.0.0.1:8080/upload}"
SINK_URL="${SINK_URL:-http://127.0.0.1:8081}"
CA_FILE="${CA_FILE:-$HERE/tls/ca.pem}"
VALIDATOR_CONTAINER="${VALIDATOR_CONTAINER:-csv-validator}"; SINK_CONTAINER="${SINK_CONTAINER:-csv-sink}"
ICAP_AV_CONTAINER="${ICAP_AV_CONTAINER-csv-icap-av}"
PASS=0; FAIL=0
[[ -d "$FILES" ]] || "$HERE/generate-test-files.sh" >/dev/null
printf 'case\ttarget\thttp\texpected_http\treason\texpected_reason\tid\tresult\n' > "$LOG"
say() { printf '%s\n' "$*"; }
ok()  { PASS=$((PASS+1)); printf '%-36s PASS %s\n' "$1" "${2:-}"; }
bad() { FAIL=$((FAIL+1)); printf '%-36s FAIL %s\n' "$1" "${2:-}"; }
jq_() { python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
print(d.get(sys.argv[1],'') if isinstance(d,dict) else '')" "$1"; }

# upload <mode> <file> <filename> <ctype> <url> [extra curl args]; sets HTTP BODY REASON ID
upload() {
  local mode="$1" file="$2" fname="$3" ctype="$4" url="$5"; shift 5
  local -a args=(-s -S -m 60 -o "$RESULTS/body.tmp" -w '%{http_code}')
  [[ "$url" == https://* ]] && args+=(--cacert "$CA_FILE")
  case "$mode" in
    normal)   args+=(-F "file=@$FILES/$file;filename=$fname;type=$ctype") ;;
    field:*)  args+=(-F "${mode#field:}=@$FILES/$file;filename=$fname;type=$ctype") ;;
    nofile)   args+=(-F "note=hello") ;;
    twofiles) args+=(-F "file=@$FILES/$file;filename=$fname;type=$ctype" -F "file=@$FILES/$file;filename=second.csv;type=$ctype") ;;
    ctype:*)  args+=(-H "Content-Type: ${mode#ctype:}" --data-binary "@$FILES/$file") ;;
    raw)      args+=(-H "Content-Type: $ctype" --data-binary "@$FILES/$file") ;;
    *) say "unknown mode $mode"; return 2 ;;
  esac
  : > "$RESULTS/body.tmp"
  HTTP="$(curl "${args[@]}" "$@" "$url" 2>"$RESULTS/err.tmp")" || HTTP="000"
  BODY="$(cat "$RESULTS/body.tmp" 2>/dev/null)"
  REASON="$(printf '%s' "$BODY" | jq_ reason_code)"; [[ -z "$REASON" ]] && REASON="$(printf '%s' "$BODY" | jq_ status)"
  ID="$(printf '%s' "$BODY" | jq_ upload_id)"
  local sup; sup="$(printf '%s' "$BODY" | jq_ support_id)"; [[ -n "$sup" ]] && { ID="support:$sup"; REASON="BIGIP"; }
}

run_table() {  # run_table <direct|bigip> <url>
  local target="$1" url="$2"
  say "== uploads via $target ($url)"
  while IFS=$'\x1f' read -r case layer mode file fname ctype hd hb reason; do
    [[ "$case" == "case" || -z "$case" ]] && continue
    local want_http want_reason="$reason"
    if [[ "$target" == bigip ]]; then
      want_http="$hb"
      [[ "$layer" == bigip || "$layer" == antivirus ]] && want_reason="BIGIP"
      [[ "$layer" == accepted ]] && want_reason="approved"
    else
      [[ "$layer" == antivirus ]] && continue          # the validator does no antivirus
      want_http="$hd"; [[ "$layer" == accepted ]] && want_reason="validated"
    fi
    upload "$mode" "$file" "$fname" "$ctype" "$url"
    local verdict=PASS; [[ "$HTTP" == "$want_http" && "$REASON" == "$want_reason" ]] || verdict=FAIL
    [[ $verdict == PASS ]] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$case" "$target" "$HTTP" "$want_http" "$REASON" "$want_reason" "$ID" "$verdict" >> "$LOG"
    printf '%-36s %-6s %s %s %-26s %s\n' "$case" "$target" "$HTTP" "$verdict" "$REASON" "$ID"
    if [[ "$target" == bigip && "$mode" == normal ]]; then
      local h; h="$(sha256sum "$FILES/$file" | cut -d' ' -f1)"
      if [[ "$layer" == accepted ]]; then echo "$h $case" >> "$RESULTS/expect_in_sink.tmp"; else echo "$h $case" >> "$RESULTS/expect_not_in_sink.tmp"; fi
    fi
  done < <(python3 -c "
import csv,sys
for row in csv.reader(open(sys.argv[1])): print('\x1f'.join(row))" "$HERE/expected-results.csv")
}

sink_rows() { curl -s -m 10 "$SINK_URL/received" | python3 -c "
import sys,json
d=json.load(sys.stdin); print(json.dumps([r for r in d['received'] if r.get('received_at','') >= sys.argv[1]]))" "$RUN_START"; }
sink_count() { curl -s -m 10 "$SINK_URL/received" | jq_ count; }

sink_check() {
  say "== sink check ($SINK_URL/received, records since $RUN_START)"
  local rows; rows="$(sink_rows)" || { bad sink_reachable; return; }
  local inok=0 outok=0
  while read -r h case; do
    if printf '%s' "$rows" | grep -Eq "\"sha256\": ?\"$h\""; then PASS=$((PASS+1)); inok=$((inok+1)); else bad "$case" "accepted file NOT in sink"; fi
  done < <(sort -u "$RESULTS/expect_in_sink.tmp" 2>/dev/null)
  while read -r h case; do
    if printf '%s' "$rows" | grep -Eq "\"sha256\": ?\"$h\""; then bad "$case" "rejected file IS in sink"; else PASS=$((PASS+1)); outok=$((outok+1)); fi
  done < <(sort -u "$RESULTS/expect_not_in_sink.tmp" 2>/dev/null)
  say "  $inok accepted files present, $outok rejected files absent"
}

tls_tests() {
  say "== TLS certificate validation ($BIGIP_URL)"
  local code
  curl -s -m 15 -o /dev/null --cacert "$CA_FILE" -F "file=@$FILES/ok_basic.csv;type=text/csv" "$BIGIP_URL" && ok tls_valid_ca || bad tls_valid_ca
  curl -s -m 15 -o /dev/null -F "file=@$FILES/ok_basic.csv;type=text/csv" "$BIGIP_URL" 2>/dev/null; code=$?
  [[ $code -eq 60 ]] && ok tls_system_trust_rejects "(curl exit 60)" || bad tls_system_trust_rejects "(curl exit $code)"
  curl -s -m 15 -o /dev/null --cacert "$(dirname "$CA_FILE")/wrong-ca.pem" -F "file=@$FILES/ok_basic.csv;type=text/csv" "$BIGIP_URL" 2>/dev/null; code=$?
  [[ $code -eq 60 ]] && ok tls_wrong_ca_rejects "(curl exit 60)" || bad tls_wrong_ca_rejects "(curl exit $code)"
}

wait_healthy() {  # poll until a good upload through the BIG-IP succeeds again (monitors need a few intervals)
  for i in $(seq 1 30); do upload normal ok_ops.csv ok_ops.csv text/csv "$BIGIP_URL"; [[ "$HTTP" == 200 ]] && return 0; sleep 3; done
  say "warning: lab did not return to healthy"; return 1
}

ops_tests() {
  local url="$BIGIP_URL" before after
  say "== operational tests ($url)"
  before="$(sink_count)"; for i in $(seq 1 10); do upload normal ok_ops.csv "conc$i.csv" text/csv "$url" & done; wait; after="$(sink_count)"
  [[ $((after-before)) -eq 10 ]] && ok ops_concurrent_10 || bad ops_concurrent_10 "($before -> $after)"
  local ids=(); for i in 1 2 3; do upload normal ok_ops.csv ok_ops.csv text/csv "$url"; ids+=("$ID"); done
  [[ "$(printf '%s\n' "${ids[@]}" | sort -u | wc -l)" -eq 3 ]] && ok ops_repeated_distinct_ids || bad ops_repeated_distinct_ids
  before="$(sink_count)"
  timeout 2 curl -s -o /dev/null --cacert "$CA_FILE" --limit-rate 50k -F "file=@$FILES/bad_oversized_file.csv;type=text/csv" "$url" >/dev/null 2>&1; sleep 1
  upload normal ok_ops.csv ok_ops.csv text/csv "$url"; after="$(sink_count)"
  [[ "$HTTP" == 200 && $((after-before)) -eq 1 ]] && ok ops_client_disconnect || bad ops_client_disconnect "(http $HTTP, sink $before->$after)"

  # sink bypass: a request that did not pass the validator must be refused by the application
  before="$(sink_count)"
  local c1 c2
  c1="$(curl -s -m 10 -o /dev/null -w '%{http_code}' -F "file=@$FILES/ok_ops.csv;type=text/csv" "$SINK_URL/upload")"
  c2="$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'X-Upload-Id: lab-forged' -H 'X-Validation-Status: passed' -H 'X-Validation-Sig: 00' -F "file=@$FILES/ok_ops.csv;type=text/csv" "$SINK_URL/upload")"
  after="$(sink_count)"
  [[ "$c1" == 403 && "$c2" == 403 && "$after" == "$before" ]] && ok ops_sink_refuses_unapproved || bad ops_sink_refuses_unapproved "($c1 $c2, sink $before->$after)"
  # forged approval headers sent by the client through the BIG-IP must be replaced, not trusted
  upload normal bad_formula_eq.csv bad_formula_eq.csv text/csv "$url" -H 'X-Upload-Id: lab-forged' -H 'X-Validation-Status: passed' -H 'X-Validation-Sig: 00'
  [[ "$HTTP" == 422 && "$REASON" == CSV_FORMULA_CELL ]] && ok ops_client_forged_headers_ignored || bad ops_client_forged_headers_ignored "($HTTP $REASON)"

  # each service down -> no upload succeeds and nothing reaches the sink (fail closed)
  if [[ -n "$ICAP_AV_CONTAINER" ]]; then
    before="$(sink_count)"; podman stop -t 2 "$ICAP_AV_CONTAINER" >/dev/null 2>&1
    upload normal ok_ops.csv ok_ops.csv text/csv "$url"; after="$(sink_count)"; podman start "$ICAP_AV_CONTAINER" >/dev/null
    [[ "$HTTP" != 200 && "$after" == "$before" ]] && ok ops_antivirus_down_fails_closed "(http $HTTP $REASON)" || bad ops_antivirus_down_fails_closed "(http $HTTP, sink $before->$after)"
    wait_healthy
  else say "ops_antivirus_down_fails_closed      SKIP (scanner is not a local container)"; fi
  before="$(sink_count)"; podman stop -t 2 "$VALIDATOR_CONTAINER" >/dev/null 2>&1; sleep 1
  upload normal ok_ops.csv ok_ops.csv text/csv "$url"; after="$(sink_count)"; podman start "$VALIDATOR_CONTAINER" >/dev/null
  [[ "$HTTP" != 200 && "$after" == "$before" ]] && ok ops_validator_down_fails_closed "(http $HTTP)" || bad ops_validator_down_fails_closed "(http $HTTP, sink $before->$after)"
  wait_healthy
  podman stop -t 2 "$SINK_CONTAINER" >/dev/null 2>&1; sleep 1
  upload normal ok_ops.csv ok_ops.csv text/csv "$url"; podman start "$SINK_CONTAINER" >/dev/null
  [[ "$HTTP" != 200 ]] && ok ops_sink_down_no_success "(http $HTTP)" || bad ops_sink_down_no_success
  wait_healthy
}

correlation() {
  say "== log correlation sample"
  upload normal ok_basic.csv ok_basic.csv text/csv "$BIGIP_URL"
  local h; h="$(sha256sum "$FILES/ok_basic.csv" | cut -d' ' -f1)"
  say "  approved upload_id : $ID   sha256 $h"
  say "  validator log      : $(podman logs --since 2m "$VALIDATOR_CONTAINER" 2>&1 | grep "\"upload_id\": \"$ID\"" | tail -1 | cut -c1-150)"
  say "  sink record        : $(curl -s "$SINK_URL/received?upload_id=$ID" | jq_ count) record(s), signature verified"
  upload normal av_eicar_in_csv.csv av_eicar_in_csv.csv text/csv "$BIGIP_URL"
  say "  antivirus block    : http $HTTP $ID"
  [[ -n "$ICAP_AV_CONTAINER" ]] && say "  icap-av log        : $(podman exec "$ICAP_AV_CONTAINER" tail -1 /var/log/c-icap/access.log 2>/dev/null | cut -c1-150)"
  upload normal bad_ext.txt bad_ext.txt text/csv "$BIGIP_URL"
  say "  WAF block          : http $HTTP $ID  (Security > Event Logs > Application > Requests)"
}

rm -f "$RESULTS"/expect_*_sink.tmp
case "$MODE" in
  direct) run_table direct "$DIRECT_URL" ;;
  bigip)  run_table bigip "$BIGIP_URL"; tls_tests; sink_check ;;
  both)   run_table direct "$DIRECT_URL"; run_table bigip "$BIGIP_URL"; tls_tests; sink_check ;;
  *) say "MODE must be direct|bigip|both"; exit 2 ;;
esac
if [[ "${OPS:-0}" == 1 && "$MODE" != direct ]]; then ops_tests; correlation; fi
say ""; say "RESULT: $PASS passed, $FAIL failed  (log: $LOG)"
[[ $FAIL -eq 0 ]]
