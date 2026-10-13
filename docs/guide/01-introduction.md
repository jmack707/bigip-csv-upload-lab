<!-- nav -->
[Guide index](README.md) · **Intro** · [Planning](02-planning.md) · [VMs](03-hosts.md) · [Services](04-services.md) · [LTM objects](05-building-blocks.md) · [WAF policy](06-waf-policy.md) · [Antivirus](07-antivirus.md) · [Validator hop](08-validator-hop.md) · [Entry point](09-entry-point.md) · [Tests](10-acceptance.md) · [Operations](11-operations.md) · [Showcase](12-showcase.md) · [Appendices](13-appendix.md)

---
<!-- /nav -->

# Introduction

This guide walks you through building a small lab that shows how BIG-IP
Advanced WAF can protect an application that accepts CSV file uploads. You
build it in your own environment, run the supplied tests against it, and keep
it for as long as you want to experiment.

It is written for the engineer who builds the lab. It assumes working
knowledge of BIG-IP Local Traffic Manager (LTM) objects and a Linux host that
can run containers. No prior Advanced WAF experience is needed: each task
says why it is there before it says what to click.

Every BIG-IP setting in this guide was built and tested end to end on BIG-IP
Virtual Edition 21.1.0.2, Classic BIG-IP (TMOS). Menu paths refer to that
release. This guide does not apply to F5OS or BIG-IP Next.

## What the lab demonstrates

- **Request protection at the BIG-IP.** Only `POST /upload` with one file is
  accepted. Wrong methods, wrong content types, oversized requests, extra
  form fields, files that are not named `.csv` and executables renamed to
  `.csv` are blocked before anything else sees them.
- **Malware scanning before delivery.** The BIG-IP sends each uploaded file
  to an antivirus scanner over ICAP and blocks the upload if the scanner
  finds something, or cannot be reached.
- **CSV validation as a service.** A small external service decides whether
  the file really is a well-formed CSV and whether any cell would run as a
  spreadsheet formula. The BIG-IP asks it for a verdict; it never touches the
  application.
- **Fail closed at every step.** If any service is down, the upload is not
  delivered.
- **Traceability.** A blocked request carries a BIG-IP support ID. A
  validated one carries an upload ID and a file hash that appear in every
  log.

## Architecture

![The lab, with the addresses used in this guide's worked example. Your values go in the planning worksheet in chapter 2.](img/topology.png)

```
  test client
      | HTTPS
      v
  [ BIG-IP ]  outer virtual server  <vip>:443
      |   1. Advanced WAF policy            -> block, with a support ID
      |   2. antivirus over ICAP -----------> ICAP antivirus   <av-host>:1344   (VM 2)
      |   3. forward to the inner virtual server
      v
  [ BIG-IP ]  inner virtual server  (on no VLAN)
      |   4. request-adapt over ICAP -------> CSV validator    <lab-host>:1345   (VM 1)
      |        approved: request continues with signed headers
      |        rejected: the validator's error goes back to the client
      v
      pool ---------------------------------> upload application <lab-host>:8081   (VM 1)
```

The BIG-IP makes every call. The three services never talk to each other.
They run on two VMs: the validator and the application share one, and the
antivirus has its own, as it would in a real deployment.

## The components

| Component | What it is | Role in the lab |
|---|---|---|
| BIG-IP Advanced WAF | F5 product | Request-level controls, the antivirus call, the validator call, load balancing to the application, logging |
| ICAP antivirus | Sample container: c-icap with the ClamAV engine | Scans each uploaded file |
| CSV validator | Sample container, Python | Checks the multipart structure, the file name, UTF-8, CSV grammar and the formula policy; returns a verdict |
| Upload application | Sample container, Python | Stands in for your application. Stores what it receives and lists it, so the tests can prove what did and did not arrive |

## What this lab is not

- **Not a production design.** It has had no load, high-availability, upgrade
  or independent security testing.
- **The three containers are sample code.** They are provided so that you
  can test the BIG-IP configuration. They are not F5 products and are not
  covered by F5 Support. In a real deployment you would use your own
  antivirus product and your own application, and decide whether CSV
  validation belongs in a service like this one or in the application.
- **Not a guarantee that a file is safe to open.** The validator enforces
  the documented rules in Appendix C and nothing more.
- **Not the only way.** BIG-IP can also be configured without the validator
  hop, or with the antivirus alone. The lab shows the fullest arrangement so
  that you can remove parts and see what changes.

## How the guide is organised

| Chapter | You do | Time |
|---|---|---|
| 2 | Fill in the planning worksheet and check prerequisites | 20 min |
| 3 | Prepare the two Linux VMs | 30 min |
| 4 | Start the three lab services | 20 min |
| 5 | Create the shared BIG-IP objects | 20 min |
| 6 | Build the Advanced WAF policy | 30 min |
| 7 | Turn on antivirus scanning | 10 min |
| 8 | Build the validator hop | 15 min |
| 9 | Build the entry point and send the first upload | 15 min |
| 10 | Run the acceptance tests | 15 min |
| 11 | Operate, troubleshoot and remove the lab | as needed |
| 12 | Show the lab to others | 20 min |

If you would rather script the BIG-IP side, Appendix A builds chapters 5 to 9
with one command. Building it by hand once is the better way to learn what
each object does.

<!-- nav -->
---
← [Repository README](../../README.md) &nbsp;|&nbsp; [Guide index](README.md) &nbsp;|&nbsp; [Planning and prerequisites](02-planning.md) →
<!-- /nav -->
