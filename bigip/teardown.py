#!/usr/bin/env python3
"""Remove every object apply.py created, in dependency order. Keeps the partition
unless DELETE_PARTITION=1. Same environment variables as apply.py."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("LAB_HOST", "0.0.0.0")
os.environ.setdefault("ICAP_AV_HOST", "0.0.0.0")
os.environ.setdefault("VIP_IP", "0.0.0.0")
from apply import PART, POLICY_NAME, rest  # noqa: E402


def rm(path: str) -> None:
    st, d = rest("DELETE", path)
    print(f"  {'deleted' if st in (200, 204) else 'absent ' if st == 404 else f'ERR {st}'} {path}")


rm(f"/mgmt/tm/ltm/virtual/~{PART}~vs_csv_lab")
for pol in ("ltm_csv_lab", "asm_csv_lab"):
    rm(f"/mgmt/tm/ltm/policy/~{PART}~{pol}")
    rm(f"/mgmt/tm/ltm/policy/~{PART}~Drafts~{pol}")
rm(f"/mgmt/tm/ltm/virtual/~{PART}~vs_csv_inner")
st, d = rest("GET", f"/mgmt/tm/asm/policies?$filter=name+eq+'{POLICY_NAME}'&$select=id,fullPath")
for p in d.get("items", []):
    if p["fullPath"] == f"/{PART}/{POLICY_NAME}":
        rm(f"/mgmt/tm/asm/policies/{p['id']}")
rm(f"/mgmt/tm/ltm/profile/request-adapt/~{PART}~reqadapt_csv_lab")
rm(f"/mgmt/tm/ltm/virtual/~{PART}~ivs_csv_validator")
rm(f"/mgmt/tm/ltm/profile/icap/~{PART}~icap_csv_validator")
for pool in ("pool_csv_sink", "pool_csv_validator_icap", "pool_csv_validator"):
    rm(f"/mgmt/tm/ltm/pool/~{PART}~{pool}")
for mon in ("mon_csv_sink", "mon_csv_validator", "mon_csv_ready"):
    rm(f"/mgmt/tm/ltm/monitor/http/~{PART}~{mon}")
# device-wide ASM antivirus server: clear it (it was empty before this lab)
st, d = rest("PATCH", "/mgmt/tm/asm/virus-detection-server", {"hostname": ""})
print(f"  {'cleared' if st == 200 else f'ERR {st}'} asm/virus-detection-server")
rm(f"/mgmt/tm/ltm/profile/http/~{PART}~http_csv_lab")
rm(f"/mgmt/tm/ltm/profile/client-ssl/~{PART}~clientssl_csv_lab")
rm(f"/mgmt/tm/sys/crypto/cert/~{PART}~csv_lab.crt")
rm(f"/mgmt/tm/sys/crypto/key/~{PART}~csv_lab.key")
rm(f"/mgmt/tm/net/route/~{PART}~csv_lab_host")
rm(f"/mgmt/tm/net/route/~{PART}~csv_lab_icap_av")
if os.environ.get("DELETE_PARTITION") == "1":
    rm(f"/mgmt/tm/auth/partition/{PART}")
print("done")
