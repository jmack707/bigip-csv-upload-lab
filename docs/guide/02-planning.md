<!-- nav -->
[Guide index](README.md) · [Intro](01-introduction.md) · **Planning** · [VMs](03-hosts.md) · [Services](04-services.md) · [LTM objects](05-building-blocks.md) · [WAF policy](06-waf-policy.md) · [Antivirus](07-antivirus.md) · [Validator hop](08-validator-hop.md) · [Entry point](09-entry-point.md) · [Tests](10-acceptance.md) · [Operations](11-operations.md) · [Showcase](12-showcase.md) · [Appendices](13-appendix.md)

---
<!-- /nav -->

# Planning and prerequisites

## Planning worksheet

Fill this in before you start. The later chapters use these placeholders.
The examples are the values used when this guide was tested; the screenshots
show them too.

| Placeholder | Meaning | Example | Your value |
|---|---|---|---|
| `<bigip-mgmt>` | BIG-IP management address | `10.2.1.5` | |
| `<vip>` | Address clients upload to. A free address on a BIG-IP VLAN that your test client can reach | `10.2.10.100` | |
| `<lab-host>` | VM 1: the validator and the upload application | `10.2.20.63` | |
| `<av-host>` | VM 2: the ICAP antivirus | `10.2.20.62` | |
| `<bigip-self-ip>` | The BIG-IP self IP that reaches the two VMs. The VMs' firewalls admit only this address | `10.2.20.5` | |
| `<gateway>` | Next hop from the BIG-IP towards `<lab-host>` or `<av-host>`, if either is not on a BIG-IP VLAN | `10.2.20.1` | |
| `<inner-ip>` | Address of the inner virtual server. It is never on a network; any unused address works | `192.0.2.10` | |

The lab uses one administrative partition, `CSV`, so that everything it
creates is easy to find and remove. Object names in this guide are fixed;
keep them, because the scripts and tests expect them.

## Worked example

The examples in the worksheet are one consistent deployment, the one in the
diagram in chapter 1 and in every screenshot. Reading it as a whole makes
the placeholders easier to map onto your own network.

| Network | Address | Role |
|---|---|---|
| External VLAN `10.2.10.0/24` | `10.2.10.5` | BIG-IP self IP |
| | `10.2.10.100` | `<vip>`, the upload address clients use |
| Internal VLAN `10.2.20.0/24` | `10.2.20.5` | BIG-IP self IP; the source of every call to the VMs |
| | `10.2.20.63` | VM 1, `<lab-host>`: validator (1345, 8080) and application (8081) |
| | `10.2.20.62` | VM 2, `<av-host>`: antivirus (1344) |
| Management | `10.2.1.5` | `<bigip-mgmt>`, Configuration utility only |
| None | `192.0.2.10` | `<inner-ip>`: the inner virtual server. A documentation address; it is never on a wire |

Two things carry over to any layout. The VMs must be reachable from a BIG-IP
*self IP* (here `10.2.20.5`), not from the management address, because the
calls come from the traffic path. And the VMs' firewalls admit the lab ports
from that self IP only, so the WAF cannot be bypassed by reaching a service
directly. If your VMs sit on a network the BIG-IP has no self IP on, the
BIG-IP needs a route to them (chapter 5) and the firewall must admit the
self IP the route uses.

## BIG-IP

| Requirement | Detail |
|---|---|
| Version | BIG-IP Virtual Edition 21.1.0.2. Other 21.1 builds should behave the same; earlier releases have the same features but some menu paths and field names differ |
| Licence | Advanced WAF (in the Best bundle, or licensed on its own) |
| Provisioning | **Local Traffic (LTM)** and **Application Security (ASM)** at *Nominal* |
| Resources | 4 vCPU and 8 GB of memory were used |
| Access | An account with the Administrator role |
| Network | A self IP on the VLAN that holds `<vip>`, and a path from a self IP to `<lab-host>` and `<av-host>` |

> **Use a lab BIG-IP.** Chapter 7 changes one setting that applies to the
> whole device, and requires a restart of the Application Security service.
> Do not build this on a BIG-IP that protects live applications.

## Lab VMs

Two small Linux VMs. Chapter 3 prepares them.

| | VM 1, `<lab-host>` | VM 2, `<av-host>` |
|---|---|---|
| Runs | CSV validator and upload application | ICAP antivirus |
| vCPU / memory / disk | 2 / 2 GB / 20 GB | 2 / 4 GB / 20 GB (2 GB is enough in antivirus test mode) |
| Operating system | Ubuntu 24.04 or Debian 13 (tested). Rocky or Alma 9 should work and is untested | same |
| Container runtime | Podman with `podman-compose`, installed by the preparation script. Docker with the Compose plugin takes the same commands but was not tested | same |
| Internet access | Once, to install packages and build the images | The same, plus outbound HTTPS to `database.clamav.net` for signatures, unless you use test mode |

Both VMs must be reachable from `<bigip-self-ip>`. Put them on a VLAN the
BIG-IP has a self IP on; otherwise add a route on the BIG-IP (chapter 5).

## Connectivity

Open these paths before you start. All are TCP.

| From | To | Port | Used for |
|---|---|---|---|
| Test client | `<vip>` | 443 | Uploads |
| BIG-IP self IP | `<av-host>` | 1344 | Antivirus scanning (ICAP) |
| BIG-IP self IP | `<lab-host>` | 1345 | Validator verdicts (ICAP) |
| BIG-IP self IP | `<lab-host>` | 8080 | Validator health check |
| BIG-IP self IP | `<lab-host>` | 8081 | Upload application |
| Test host | `<lab-host>` | 8081 | The test script reads what the application received |
| Your workstation | `<bigip-mgmt>` | 443 | Configuration utility |

## The lab bundle

You received `csv-upload-lab-<version>.zip` with this guide. Unpack it on
`<lab-host>`. It contains:

| Path | Contents |
|---|---|
| `docker-compose.yml` | Validator and upload application |
| `icap-av/` | ICAP antivirus image and its own compose file |
| `validator/`, `sink/` | Source of the two sample services |
| `scripts/gen-secret.sh` | Creates the secret the validator and the application share |
| `test/` | Test files, a certificate generator and the test runner |
| `bigip/` | The WAF policy as JSON and the scripted build of Appendix A |

Nothing in the bundle contains a password, a key or an address from your
environment. The scripts create those locally and keep them out of version
control.

<!-- nav -->
---
← [Introduction](01-introduction.md) &nbsp;|&nbsp; [Guide index](README.md) &nbsp;|&nbsp; [Prepare the two Linux VMs](03-hosts.md) →
<!-- /nav -->
