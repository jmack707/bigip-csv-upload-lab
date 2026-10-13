<!-- nav -->
[Guide index](README.md) · [Intro](01-introduction.md) · [Planning](02-planning.md) · [VMs](03-hosts.md) · **Services** · [LTM objects](05-building-blocks.md) · [WAF policy](06-waf-policy.md) · [Antivirus](07-antivirus.md) · [Validator hop](08-validator-hop.md) · [Entry point](09-entry-point.md) · [Tests](10-acceptance.md) · [Operations](11-operations.md) · [Showcase](12-showcase.md) · [Appendices](13-appendix.md)

---
<!-- /nav -->

# Build the lab services

In this chapter you start the three sample services and prove each one
answers. Do this first: the BIG-IP health monitors you create later turn
green only when the services are up.

## Start the validator and the upload application

On VM 1, logged in as the `csvlab` account the preparation script created, in the unpacked bundle:

```bash
scripts/gen-secret.sh
podman-compose up -d --build
```

`gen-secret.sh` writes a random secret to `.env`. The validator signs each
approval with it and the application checks the signature, so a request that
skipped the validator is refused. Both services refuse to start without it.

**You should see** both services answer:

```bash
curl -s http://127.0.0.1:8080/ready     # {"status":"ready"}
curl -s http://127.0.0.1:8081/health    # {"status":"ok","service":"upload-sink"}
```

## Start the ICAP antivirus

On VM 2, as `csvlab`, in the bundle's `icap-av` directory, choose one:

```bash
# Full ClamAV signature database. Needs about 2 GB of memory and outbound HTTPS.
podman-compose up -d --build

# Test mode, for a small host or one with no Internet access.
CLAMAV_DB=test ICAP_AV_MEM=256m podman-compose up -d --build
```

> **Test mode is not an antivirus.** It runs the same scanner with a single
> signature that matches the industry-standard EICAR test string. It lets you
> prove that the BIG-IP calls the scanner and acts on the answer. It will not
> detect real malware.

In full mode the scanner also keeps that one lab signature beside the
official database, named `Lab-EICAR-Anywhere` so it stands out in the logs.
ClamAV's own EICAR rule only fires when the test string is the entire file,
which is correct for the test file but would let the lab's "valid CSV
carrying the test string" demonstration pass unnoticed. Real malware
signatures match inside files; only the EICAR convention is this strict.

The first start in full mode downloads about 250 MB of signatures and can
take several minutes.

**You should see** one of these lines:

```bash
podman logs csv-icap-av | head -3
# icap-av: FULL signature database
# icap-av: TEST signature database (EICAR only)
```

## Generate the test files and a certificate

On the host you will run the tests from. VM 1 is the natural choice: it already holds the bundle, and the test runner reads the upload application on `127.0.0.1`. If you use another host, add its address to `--allow` on VM 1 so it can read port 8081.

```bash
test/generate-test-files.sh
VIP_IP=<vip> test/gen-tls.sh
```

The first command writes 40 small files to `test/files/`: valid CSVs, files
each layer should stop, and the EICAR test string. No real malware is
included.

The second creates a private certificate authority and a server certificate
whose subject alternative name is `<vip>`, under `test/tls/`. You import the
certificate into the BIG-IP in chapter 5, and the test client trusts the
authority, so the tests validate the certificate properly instead of
ignoring it.

Copy `test/tls/server.crt` and `test/tls/server.key` to the workstation you
browse the BIG-IP from.

## Try the validator on its own

The validator has a validate-only address that returns its verdict without
delivering anything. It is a quick way to see the rules at work:

```bash
curl -s -F "file=@test/files/ok_basic.csv;type=text/csv"       http://127.0.0.1:8080/upload
# {"accepted":true,"upload_id":"lab-...","status":"validated",...}
curl -s -F "file=@test/files/bad_formula_eq.csv;type=text/csv" http://127.0.0.1:8080/upload
# {"accepted":false,...,"reason_code":"CSV_FORMULA_CELL",...}
```

`;type=text/csv` matters. Without it `curl` labels the file
`application/octet-stream`, which the lab rejects. A browser sets the type by
itself.

<!-- nav -->
---
← [Prepare the two Linux VMs](03-hosts.md) &nbsp;|&nbsp; [Guide index](README.md) &nbsp;|&nbsp; [BIG-IP building blocks](05-building-blocks.md) →
<!-- /nav -->
