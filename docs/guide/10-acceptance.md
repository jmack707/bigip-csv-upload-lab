<!-- nav -->
[Guide index](README.md) · [Intro](01-introduction.md) · [Planning](02-planning.md) · [VMs](03-hosts.md) · [Services](04-services.md) · [LTM objects](05-building-blocks.md) · [WAF policy](06-waf-policy.md) · [Antivirus](07-antivirus.md) · [Validator hop](08-validator-hop.md) · [Entry point](09-entry-point.md) · **Tests** · [Operations](11-operations.md) · [Showcase](12-showcase.md) · [Appendices](13-appendix.md)

---
<!-- /nav -->

# Acceptance tests

The bundle includes a test runner that sends 43 uploads through the BIG-IP,
checks each response, and then asks the upload application what it actually
received.

## Run the tests

On the test host:

```bash
BIGIP_URL=https://<vip>/upload SINK_URL=http://127.0.0.1:8081 \
  MODE=bigip test/run-tests.sh
```

The client validates the BIG-IP's certificate against `test/tls/ca.pem`. Add
`OPS=1` to include the outage tests in the next section. They stop and start
containers with `podman`, so run them on VM 1 as `csvlab`, and set
`ICAP_AV_CONTAINER=` (empty) because the antivirus is on VM 2; do that one
outage test by hand as described below.

**You should see** a line per case and a final result:

```
accept_basic               bigip  200 PASS approved          lab-6d963ac74750d7a2
bigip_ext_txt              bigip  403 PASS BIGIP             support:7553261307881850587
av_eicar_in_valid_csv      bigip  403 PASS BIGIP             support:7553261307881850579
val_formula_eq             bigip  422 PASS CSV_FORMULA_CELL  lab-1ceb08078219e99f
...
  10 accepted files present, 28 rejected files absent
RESULT: 84 passed, 0 failed
```

With `OPS=1` the total is 92. The full record of each run is written to
`test/results/`.

## What is tested

| Group | Cases | Expected |
|---|---|---|
| Accepted | 10: plain, quoted, embedded comma, embedded line break, semicolon, tab, accented UTF-8, signed numbers, phone-like values, CRLF line endings | 200 `approved`; the file is in the application |
| Stopped by the WAF | 13: `.txt`, `.csv.exe`, Windows and Linux executables renamed `.csv`, oversized request, oversized file, wrong field name, no file, two files, wrong content type, malformed body, UTF-16, empty file | 403 with a support ID |
| Stopped by the antivirus | 2: the EICAR test file, and the EICAR string inside an otherwise valid CSV | 403 with a support ID |
| Rejected by the validator | 18: not really CSV (JSON, HTML), invalid UTF-8, broken quoting, uneven columns, blank lines, unsupported delimiter, six kinds of formula cell, markup, a `javascript:` link | 4xx with an upload ID and a reason code |
| Delivery check | all of the above | Every accepted file's hash is in the application. No other file's hash is |
| Certificate validation | 3 | The lab certificate authority is accepted. The system trust store and an unrelated authority are refused |

The second antivirus case is the important one. That file is a perfectly
valid CSV, so the validator approves it. Only the antivirus can stop it, and
it proves the scan really happens. It is detected by the lab's own
`Lab-EICAR-Anywhere` signature (chapter 4); the official EICAR rule would
not match a test string embedded in another file.

## Outage tests

These prove the lab fails closed. Run them with `OPS=1`, or by hand: stop one
container, upload `ok_basic.csv`, start the container again, and wait a few
seconds for the BIG-IP monitors to recover.

| Stop this | You should see | Why |
|---|---|---|
| `csv-icap-av` | 403 with a support ID | *Guarantee Enforcement* blocks uploads that cannot be scanned |
| `csv-validator` | Connection reset | *Service Down Action* is *Reset* |
| `csv-sink` | No response | The pool has no available member |

In no case does the upload return 200 or appear in the application.

`OPS=1` also checks ten simultaneous uploads, that repeated uploads get
different upload IDs, that a client disconnecting mid-upload leaves the lab
healthy, and two attempts to cheat:

- **Posting straight to the application**, with and without forged approval
  headers. The application answers 403: the signature does not verify.
- **Sending forged approval headers through the BIG-IP.** The validator
  strips them and judges the file as usual.

## Acceptance criteria

The lab is working when all of these are true.

1. A valid CSV reaches the application.
2. An invalid CSV, a CSV containing a formula, and the EICAR test file do not.
3. An executable renamed `.csv` is blocked.
4. Extra or unexpected form fields are blocked.
5. With any one service stopped, no upload is delivered.
6. A request that did not pass the validator is refused by the application.
7. The test client validates the BIG-IP's certificate.
8. Every block has a BIG-IP support ID, every validator verdict has an upload
   ID, and the logs tie them to the file's hash.

<!-- nav -->
---
← [The entry point](09-entry-point.md) &nbsp;|&nbsp; [Guide index](README.md) &nbsp;|&nbsp; [Operations](11-operations.md) →
<!-- /nav -->
