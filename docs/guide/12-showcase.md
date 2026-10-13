<!-- nav -->
[Guide index](README.md) · [Intro](01-introduction.md) · [Planning](02-planning.md) · [VMs](03-hosts.md) · [Services](04-services.md) · [LTM objects](05-building-blocks.md) · [WAF policy](06-waf-policy.md) · [Antivirus](07-antivirus.md) · [Validator hop](08-validator-hop.md) · [Entry point](09-entry-point.md) · [Tests](10-acceptance.md) · [Operations](11-operations.md) · **Showcase** · [Appendices](13-appendix.md)

---
<!-- /nav -->

# Show the lab to others

Once the lab passes its tests you can use it to show, in about twenty
minutes, what each layer contributes. The order below builds from the
simplest control to the hardest to explain, and every step has one command
and one thing to point at.

Have three windows open: a terminal on the test host, the BIG-IP request log
(**Security › Event Logs › Application › Requests**), and a terminal on VM 2
running `podman logs -f csv-icap-av`.

## 1. A good file goes through

```bash
u ok_basic.csv
```

Point at: the `approved` response, and the record it creates in the upload
application (on VM 1: `curl http://127.0.0.1:8081/received | tail -c 400`).

## 2. The WAF stops what is not an upload

```bash
u bad_ext.txt
u bad_pe_renamed.csv
```

Point at: the support ID in each 403, then the same ID in the request log.
The first entry says the file name failed the regular expression; the
second says the content was a Windows executable, whatever its name. The
validator and the antivirus never saw either request.

## 3. The antivirus stops a valid CSV that carries a payload

```bash
u av_eicar_in_csv.csv
```

Point at: this file is a correct CSV, so the CSV rules approve it. The 403
comes from the WAF's *Virus detected* violation, and the scanner window
shows the matching `action=blocked virus=Lab-EICAR-Anywhere` line at the
same second. This is the step that proves the BIG-IP really sends files to
the scanner. Say what the signature is: a lab rule matching the test string
anywhere, because the official EICAR rule needs the string to be the whole
file; real malware signatures do match inside files.

## 4. The validator judges what the WAF cannot

```bash
u bad_formula_eq.csv
u bad_missing_column.csv
```

Point at: these get a 422 with a reason code, not a 403. The WAF passed
them, because they are well-formed uploads; the verdict came from the
validator over ICAP, and the BIG-IP returned it to the client. The
application was never contacted.

## 5. Nothing gets in behind the BIG-IP

On VM 1:

```bash
curl -s -F "file=@test/files/ok_basic.csv;type=text/csv" http://127.0.0.1:8081/upload
```

And from any other host, `curl -m 5 http://<lab-host>:8081/health`.

Point at: locally, the application answers 403 with `NO_APPROVAL`, because
the request carries no validator signature. From another host, the
connection does not open at all: the firewall admits only the BIG-IP.

## 6. Every service fails closed

On VM 2: `podman stop csv-icap-av`, then `u ok_basic.csv`.

Point at: a 403 with a support ID for a perfectly good file, because the
scan could not be performed. Start the container again and repeat the
upload; it is approved. Do the same with `csv-validator` on VM 1 and show the
connection reset instead.

## 7. Where the evidence is

Pick one approved upload ID and show it in three places: the validator log,
the application's record, and the file hash that matches in both. Then pick
one support ID and show it in the request log. This is what an incident
responder would follow.

## What to say it is not

Say plainly that the three services are sample code written for this lab,
that antivirus test mode detects only the test string, and that the file
rules in Appendix C are a policy, not a proof that a file is safe. Showing
the limits is part of the demonstration.

<!-- nav -->
---
← [Operations](11-operations.md) &nbsp;|&nbsp; [Guide index](README.md) &nbsp;|&nbsp; [Appendix A: scripted build](13-appendix.md) →
<!-- /nav -->
