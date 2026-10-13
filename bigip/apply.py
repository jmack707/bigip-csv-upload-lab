#!/usr/bin/env python3
"""Apply the CSV lab configuration to a BIG-IP (21.1.0.2) in partition CSV via iControl REST.

Idempotent: every object is created if missing or patched if present.
Stdlib only. Credentials come from the environment, never from this repo.

  BIGIP_HOST, BIGIP_USER, BIGIP_PASS     management address + admin account
  LAB_HOST                               host running the validator and the upload application
  VALIDATOR_ICAP_PORT (1345)             validator ICAP listener   -> request-adapt internal virtual server
  VALIDATOR_HTTP_PORT (8080)             validator GET /ready      -> health monitor
  SINK_PORT (8081)                       upload application        -> pool of vs_csv_lab
  ICAP_AV_HOST, ICAP_AV_PORT (1344)      ICAP antivirus server used by Advanced WAF (DEVICE-WIDE setting)
  VIP_IP, VIP_PORT (443)                 address clients upload to (required)
  INNER_VS_IP (192.0.2.10)               inner virtual server; never on a network
  LAB_ROUTE_GW                           optional: add a /CSV host route for LAB_HOST via this gateway, when
                                         the host is not on a connected VLAN. ICAP_AV_ROUTE=1 adds one for
                                         ICAP_AV_HOST as well
  TLS_CERT, TLS_KEY                      PEM files for the client-ssl profile (test/tls/server.*)
  PARTITION                              default CSV

Order: partition -> routes -> cert/key -> client-ssl -> monitors -> pools -> http profile
       -> ICAP profile -> internal virtual server -> request-adapt profile
       -> device-wide ASM antivirus (ICAP) server -> WAF policy import -> LTM policy (ASM enable)
       -> inner virtual server -> LTM policy (WAF + forward) -> outer virtual server -> WAF policy apply -> remove objects of the previous flow -> verify.

Traffic: client -> vs_csv_lab [Advanced WAF + ICAP antivirus] -> LTM policy forward -> vs_csv_inner
         [request-adapt -> validator over ICAP] -> pool_csv_sink (upload application). Every hop fails closed.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
H = os.environ["BIGIP_HOST"]
U = os.environ.get("BIGIP_USER", "admin")
P = os.environ["BIGIP_PASS"]
PART = os.environ.get("PARTITION", "CSV")
LAB_HOST = os.environ["LAB_HOST"]
ICAP_VAL_PORT = int(os.environ.get("VALIDATOR_ICAP_PORT", "1345"))
VAL_HTTP_PORT = int(os.environ.get("VALIDATOR_HTTP_PORT", "8080"))
SINK_PORT = int(os.environ.get("SINK_PORT", "8081"))
ICAP_AV_HOST = os.environ["ICAP_AV_HOST"]
ICAP_AV_PORT = int(os.environ.get("ICAP_AV_PORT", "1344"))
INNER_IP = os.environ.get("INNER_VS_IP", "192.0.2.10")   # TEST-NET-1; never on a VLAN
VIP_IP = os.environ["VIP_IP"]
VIP_PORT = int(os.environ.get("VIP_PORT", "443"))
ROUTE_GW = os.environ.get("LAB_ROUTE_GW", "")
TLS_CERT = os.environ.get("TLS_CERT", str(HERE.parent / "test/tls/server.crt"))
TLS_KEY = os.environ.get("TLS_KEY", str(HERE.parent / "test/tls/server.key"))
POLICY_FILE = HERE / "waf_csv_lab.json"
POLICY_NAME = "waf_csv_lab"
LOG_PROFILE = os.environ.get("LOG_PROFILE", "/Common/Log illegal requests")

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE  # lab BIG-IP with a self-signed management cert
_auth = "Basic " + base64.b64encode(f"{U}:{P}".encode()).decode()


def rest(method: str, path: str, body: dict | None = None, raw: bytes | None = None, headers: dict | None = None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    h = {"Authorization": _auth, "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(f"https://{H}{path}", method=method, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=120) as r:
            out = r.read()
            return r.status, (json.loads(out) if out and r.headers.get_content_type() == "application/json" else out)
    except urllib.error.HTTPError as e:
        out = e.read()
        try:
            return e.code, json.loads(out)
        except Exception:
            return e.code, out


def ensure(collection: str, name: str, body: dict, partition: str = PART, sub: str = "", create_only: tuple = ()) -> None:
    """POST if absent, PATCH if present. `collection` like /mgmt/tm/ltm/pool.
    Keys in `create_only` are sent on create and left out of the PATCH (immutable properties)."""
    path = f"{collection}/~{partition}~{sub + '~' if sub else ''}{name}"
    st, _ = rest("GET", path)
    if st == 404:
        st, d = rest("POST", collection, {"name": name, "partition": partition, **({"subPath": sub} if sub else {}), **body})
        action = "created"
    else:
        st, d = rest("PATCH", path, {k: v for k, v in body.items() if k not in create_only})
        action = "updated"
    if st not in (200, 201):
        sys.exit(f"FAIL {collection}/{name}: {st} {d}")
    print(f"  {action:8s} {collection.split('/mgmt/tm/')[1]}/{partition}/{name}")


def upload(endpoint: str, name: str, data: bytes) -> None:
    """Chunked upload to /mgmt/shared/file-transfer/uploads or /mgmt/tm/asm/file-transfer/uploads."""
    chunk = 512 * 1024
    for start in range(0, len(data), chunk):
        end = min(start + chunk, len(data))
        st, d = rest("POST", f"{endpoint}/{name}", raw=data[start:end],
                     headers={"Content-Type": "application/octet-stream", "Content-Range": f"{start}-{end - 1}/{len(data)}"})
        if st not in (200, 201):
            sys.exit(f"FAIL upload {name}: {st} {d}")


def wait_task(path: str, label: str) -> dict:
    for _ in range(90):
        st, d = rest("GET", path)
        if d.get("status") in ("COMPLETED", "FAILURE"):
            break
        time.sleep(2)
    msg = d.get("result", {}).get("message", "")
    print(f"  {label}: {d.get('status')} {msg}")
    if d.get("status") != "COMPLETED":
        sys.exit(f"FAIL {label}")
    return d


def main() -> None:
    print(f"== BIG-IP {H}, partition {PART}, VIP {VIP_IP}:{VIP_PORT}, lab host {LAB_HOST}, ICAP antivirus {ICAP_AV_HOST}:{ICAP_AV_PORT}")
    st, d = rest("GET", "/mgmt/tm/sys/version")
    ver = list(d["entries"].values())[0]["nestedStats"]["entries"]["Version"]["description"]
    print(f"  version {ver}")
    st, d = rest("GET", "/mgmt/tm/sys/provision/asm")
    if d.get("level", "none") == "none":
        sys.exit("FAIL: ASM (Advanced WAF) is not provisioned. Run: tmsh modify sys provision asm level nominal")

    # 1. partition
    st, _ = rest("GET", f"/mgmt/tm/auth/partition/{PART}")
    if st == 404:
        st, d = rest("POST", "/mgmt/tm/auth/partition", {"name": PART, "description": "CSV upload validation lab"})
        print(f"  created  auth/partition/{PART}")
    else:
        print(f"  exists   auth/partition/{PART}")

    # 2. optional host route
    if ROUTE_GW:
        ensure("/mgmt/tm/net/route", "csv_lab_host", {"network": f"{LAB_HOST}/32", "gw": ROUTE_GW,
               "description": "CSV lab: validator host is off-link"})
        if ICAP_AV_HOST != LAB_HOST and os.environ.get("ICAP_AV_ROUTE", "0") == "1":
            ensure("/mgmt/tm/net/route", "csv_lab_icap_av", {"network": f"{ICAP_AV_HOST}/32", "gw": ROUTE_GW,
                   "description": "CSV lab: ICAP antivirus host is off-link"})

    # 3. certificate and key
    cert = Path(TLS_CERT).read_bytes()
    key = Path(TLS_KEY).read_bytes()
    upload("/mgmt/shared/file-transfer/uploads", "csv_lab.crt", cert)
    upload("/mgmt/shared/file-transfer/uploads", "csv_lab.key", key)
    for kind, fname in (("cert", "csv_lab.crt"), ("key", "csv_lab.key")):
        st, d = rest("POST", f"/mgmt/tm/sys/crypto/{kind}", {"command": "install", "name": fname, "partition": PART,
                                                           "from-local-file": f"/var/config/rest/downloads/{fname}"})
        if st not in (200, 201):
            sys.exit(f"FAIL install {kind}: {st} {d}")
        print(f"  installed sys/crypto/{kind}/{PART}/{fname}")

    # 4. client-ssl profile
    ensure("/mgmt/tm/ltm/profile/client-ssl", "clientssl_csv_lab", {
        "defaultsFrom": "/Common/clientssl",
        "certKeyChain": [{"name": "csv_lab", "cert": f"/{PART}/csv_lab.crt", "key": f"/{PART}/csv_lab.key"}],
    })

    # 5. monitors + pools
    ensure("/mgmt/tm/ltm/monitor/http", "mon_csv_validator", {
        "defaultsFrom": "/Common/http", "destination": f"*:{VAL_HTTP_PORT}",
        "send": "GET /ready HTTP/1.1\\r\\nHost: csv-validator\\r\\nConnection: close\\r\\n\\r\\n",
        "recv": "status.:.ready", "interval": 5, "timeout": 16,   # regex: quotes are stripped by the REST layer
    })
    ensure("/mgmt/tm/ltm/monitor/http", "mon_csv_sink", {
        "defaultsFrom": "/Common/http",
        "send": "GET /health HTTP/1.1\\r\\nHost: csv-sink\\r\\nConnection: close\\r\\n\\r\\n",
        "recv": "status.:.ok", "interval": 5, "timeout": 16,
    })
    ensure("/mgmt/tm/ltm/pool", "pool_csv_validator_icap", {
        "monitor": f"/{PART}/mon_csv_validator",
        "members": [{"name": f"{LAB_HOST}:{ICAP_VAL_PORT}", "address": LAB_HOST}],
        "description": "CSV validator, ICAP REQMOD (health checked on its HTTP /ready)",
    })
    ensure("/mgmt/tm/ltm/pool", "pool_csv_sink", {
        "monitor": f"/{PART}/mon_csv_sink",
        "members": [{"name": f"{LAB_HOST}:{SINK_PORT}", "address": LAB_HOST}],
        "description": "Upload application: receives only requests the WAF, antivirus and validator approved",
    })

    # 6. http profile (X-Forwarded-For so the validator and application can log the real client)
    ensure("/mgmt/tm/ltm/profile/http", "http_csv_lab", {"defaultsFrom": "/Common/http", "insertXforwardedFor": "enabled"})

    # 6a. ICAP profile + internal virtual server + request-adapt profile (validator verdict, fail closed)
    ensure("/mgmt/tm/ltm/profile/icap", "icap_csv_validator", {
        "defaultsFrom": "/Common/icap", "uri": "icap://${SERVER_IP}:${SERVER_PORT}/validate", "previewLength": 0,
    })
    ensure("/mgmt/tm/ltm/virtual", "ivs_csv_validator", {
        "destination": f"/{PART}/0.0.0.0:0", "mask": "any", "internal": True, "ipProtocol": "tcp",
        "pool": f"/{PART}/pool_csv_validator_icap", "sourceAddressTranslation": {"type": "automap"},
        "profiles": [{"name": "/Common/tcp"}, {"name": f"/{PART}/icap_csv_validator"}],
        "description": "Internal virtual server: sends each upload to the CSV validator over ICAP",
    }, create_only=("destination", "mask", "internal"))
    ensure("/mgmt/tm/ltm/profile/request-adapt", "reqadapt_csv_lab", {
        "defaultsFrom": "/Common/requestadapt", "enabled": "yes", "internalVirtual": f"/{PART}/ivs_csv_validator",
        "previewSize": 0, "serviceDownAction": "reset", "timeout": 20000, "allowHttp_10": "no",
    })

    # 6b. Advanced WAF antivirus: ICAP server is ONE device-wide setting (Security > Options >
    #     Application Security > Integrated Services > Anti-Virus Protection). Guarantee Enforcement
    #     = block uploads when the scan cannot be performed.
    st, cur = rest("GET", "/mgmt/tm/asm/virus-detection-server")
    av_changed = (cur.get("hostname"), cur.get("port")) != (ICAP_AV_HOST, ICAP_AV_PORT)
    st, d = rest("PATCH", "/mgmt/tm/asm/virus-detection-server",
                 {"hostname": ICAP_AV_HOST, "port": ICAP_AV_PORT, "guaranteeEnforcement": True})
    if st != 200:
        sys.exit(f"FAIL virus-detection-server: {st} {d}")
    print(f"  set      asm/virus-detection-server {d.get('hostname')}:{d.get('port')} guaranteeEnforcement={d.get('guaranteeEnforcement')} (device-wide)")

    # 7. WAF policy: import declarative JSON (replace if it exists), then apply
    st, d = rest("GET", f"/mgmt/tm/asm/policies?$filter=name+eq+'{POLICY_NAME}'&$select=id,fullPath")
    existing = [p for p in d.get("items", []) if p["fullPath"] == f"/{PART}/{POLICY_NAME}"]
    upload("/mgmt/tm/asm/file-transfer/uploads", "waf_csv_lab.json", POLICY_FILE.read_bytes())
    task = {"filename": "waf_csv_lab.json"}
    if existing:
        task["policyReference"] = {"link": f"https://localhost/mgmt/tm/asm/policies/{existing[0]['id']}"}
    else:
        task["policy"] = {"fullPath": f"/{PART}/{POLICY_NAME}"}
    st, d = rest("POST", "/mgmt/tm/asm/tasks/import-policy", task)
    if st != 201:
        sys.exit(f"FAIL import-policy: {st} {d}")
    wait_task(f"/mgmt/tm/asm/tasks/import-policy/{d['id']}", "import-policy")
    st, d = rest("GET", f"/mgmt/tm/asm/policies?$filter=name+eq+'{POLICY_NAME}'&$select=id,fullPath,enforcementMode,isModified")
    pol = [p for p in d["items"] if p["fullPath"] == f"/{PART}/{POLICY_NAME}"][0]

    # 8. inner virtual server: request-adapt (validator verdict over ICAP) then the upload application.
    #    Reachable only from the outer virtual server (enabled on no VLAN). Two chained virtual servers
    #    are needed because on ONE virtual server request-adapt runs before Advanced WAF (seen on 21.1.0.2).
    ensure("/mgmt/tm/ltm/virtual", "vs_csv_inner", {
        "destination": f"/{PART}/{INNER_IP}:80", "mask": "255.255.255.255", "ipProtocol": "tcp",
        "vlansEnabled": True, "vlans": [],
        "pool": f"/{PART}/pool_csv_sink", "sourceAddressTranslation": {"type": "automap"},
        "profiles": [{"name": "/Common/tcp"}, {"name": "/Common/http"},
                     {"name": f"/{PART}/reqadapt_csv_lab", "context": "clientside"}],
        "description": "Inner hop: CSV validator (ICAP, fail closed) then upload application. No VLANs: internal only.",
    })

    # 8a. LTM policy on the outer virtual server: enable Advanced WAF, then forward to the inner virtual server
    st, _ = rest("GET", f"/mgmt/tm/ltm/policy/~{PART}~ltm_csv_lab")
    if st == 404:
        st, d = rest("POST", "/mgmt/tm/ltm/policy", {
            "name": "ltm_csv_lab", "partition": PART, "subPath": "Drafts", "strategy": "/Common/first-match",
            "controls": ["asm", "forwarding"], "requires": ["http"],
            "rules": [{"name": "waf_then_inner", "ordinal": 1, "actions": [
                {"name": "0", "asm": True, "enable": True, "policy": f"/{PART}/{POLICY_NAME}"},
                {"name": "1", "forward": True, "select": True, "virtual": f"/{PART}/vs_csv_inner"}]}],
        })
        if st not in (200, 201):
            sys.exit(f"FAIL ltm policy draft: {st} {d}")
        st, d = rest("POST", "/mgmt/tm/ltm/policy", {"command": "publish", "name": f"/{PART}/Drafts/ltm_csv_lab"})
        if st not in (200, 201):
            sys.exit(f"FAIL ltm policy publish: {st} {d}")
        print(f"  created  ltm/policy/{PART}/ltm_csv_lab (published)")
    else:
        print(f"  exists   ltm/policy/{PART}/ltm_csv_lab")

    # 9. virtual server
    ensure("/mgmt/tm/ltm/virtual", "vs_csv_lab", {
        "destination": f"/{PART}/{VIP_IP}:{VIP_PORT}", "mask": "255.255.255.255", "ipProtocol": "tcp",
        "pool": "none",
        "sourceAddressTranslation": {"type": "automap"},
        "profiles": [{"name": "/Common/tcp"}, {"name": f"/{PART}/http_csv_lab"},
                     {"name": f"/{PART}/clientssl_csv_lab", "context": "clientside"}, {"name": "/Common/websecurity"}],
        "policies": [{"name": "ltm_csv_lab", "partition": PART}],
        "securityLogProfiles": [LOG_PROFILE],
        "description": "CSV upload lab entry point (HTTPS)",
    })

    # 10. apply the policy AFTER the virtual server exists: associating a virtual server
    # counts as a policy change on 21.1, so applying earlier leaves isModified=true.
    for attempt in (1, 2):
        st, d = rest("POST", "/mgmt/tm/asm/tasks/apply-policy", {"policyReference": {"link": f"https://localhost/mgmt/tm/asm/policies/{pol['id']}"}})
        if st != 201:
            sys.exit(f"FAIL apply-policy: {st} {d}")
        wait_task(f"/mgmt/tm/asm/tasks/apply-policy/{d['id']}", f"apply-policy (pass {attempt})")
        time.sleep(3)
        st, d = rest("GET", f"/mgmt/tm/asm/policies/{pol['id']}?$select=isModified")
        if not d.get("isModified"):
            break

    # 11. verify
    st, d = rest("GET", f"/mgmt/tm/asm/policies/{pol['id']}?$select=isModified,enforcementMode,virtualServers,active")
    print(f"  policy applied: isModified={d.get('isModified')} enforcement={d.get('enforcementMode')} active={d.get('active')} vs={d.get('virtualServers')}")
    if d.get("isModified"):
        sys.exit("FAIL: policy has unapplied changes")
    # The WAF daemon reads the antivirus server only at start (seen on 21.1.0.2: after the address was
    # set, no ICAP connection was attempted and infected uploads passed until ASM was restarted).
    if av_changed:
        if os.environ.get("RESTART_ASM", "0") == "1":
            st, d = rest("POST", "/mgmt/tm/util/bash", {"command": "run", "utilCmdArgs": "-c 'bigstart restart asm'"})
            print("  restarted ASM (antivirus server changed); waiting for it to come back")
            for _ in range(40):
                time.sleep(6)
                st, d = rest("GET", "/mgmt/tm/asm/policies?$select=name&$top=1")
                if st == 200:
                    break
            time.sleep(20)
        else:
            print("  WARNING: antivirus server changed. ASM must be restarted before uploads are scanned:")
            print("           re-run with RESTART_ASM=1, or run `bigstart restart asm` on the BIG-IP (brief WAF outage).")

    # remove objects of the previous (validator-as-proxy) flow
    for old in (f"/mgmt/tm/ltm/policy/~{PART}~asm_csv_lab", f"/mgmt/tm/ltm/pool/~{PART}~pool_csv_validator",
                f"/mgmt/tm/ltm/monitor/http/~{PART}~mon_csv_ready"):
        st, _ = rest("DELETE", old)
        if st in (200, 204):
            print(f"  removed  {old.split('/mgmt/tm/')[1]}")
    time.sleep(8)
    for pool, port in (("pool_csv_validator_icap", ICAP_VAL_PORT), ("pool_csv_sink", SINK_PORT)):
        st, d = rest("GET", f"/mgmt/tm/ltm/pool/~{PART}~{pool}/members/~{PART}~{LAB_HOST}:{port}?$select=state,session")
        print(f"  {pool} {LAB_HOST}:{port}: state={d.get('state')} session={d.get('session')}")
    st, d = rest("GET", f"/mgmt/tm/ltm/virtual/~{PART}~vs_csv_lab/stats")
    e = list(d["entries"].values())[0]["nestedStats"]["entries"]
    print(f"  virtual server: {e['status.availabilityState']['description']} / {e['status.enabledState']['description']}")
    print("done")


if __name__ == "__main__":
    main()
