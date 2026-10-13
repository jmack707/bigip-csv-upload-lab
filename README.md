# BIG-IP Advanced WAF: CSV upload protection lab

Start with **`BIG-IP-Advanced-WAF-CSV-Upload-Lab-Build-Guide.pdf`**. It walks you through the
whole build.

| Path | Contents |
|---|---|
| `docker-compose.yml` | CSV validator and upload application |
| `icap-av/` | ICAP antivirus (c-icap with the ClamAV engine) and its own compose file |
| `validator/`, `sink/` | Source of the two sample services |
| `scripts/prepare-host.sh` | Prepares a fresh Linux VM: rootless Podman, log driver, low ports, firewall |
| `scripts/gen-secret.sh` | Creates the secret the validator and the application share |
| `test/` | Test file generator, certificate generator, test runner |
| `bigip/` | WAF policy (JSON), scripted build and teardown for the BIG-IP |

Quick start, two Linux VMs:

```bash
# VM 1 (validator + application), then as the csvlab account it creates:
sudo scripts/prepare-host.sh --role app --allow <bigip-self-ip>
scripts/gen-secret.sh && podman-compose up -d --build
test/generate-test-files.sh && VIP_IP=<vip> test/gen-tls.sh

# VM 2 (antivirus):
sudo scripts/prepare-host.sh --role av --allow <bigip-self-ip>
cd icap-av && podman-compose up -d --build          # add CLAMAV_DB=test on a small host
```

Then build the BIG-IP side by following the guide, or with Appendix A.

This is a lab for evaluation and testing. It is not a production design. The containers are
sample code: they are not F5 products and are not covered by F5 Support. The antivirus test mode
(`CLAMAV_DB=test`) detects only the EICAR test string; full mode adds the official ClamAV
database and keeps that one lab signature.
