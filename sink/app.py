"""Upload application ("sink"): the BIG-IP pool member.

It receives the client's original POST /upload only after the BIG-IP has run it through
Advanced WAF, ICAP antivirus and the CSV validator. It performs NO content validation.
It does verify one thing: the validator's approval signature (HMAC over upload ID, file
SHA-256 and size). A request that did not pass through the validator, or whose file bytes
differ from what the validator saw, is refused and not recorded.

  POST /upload    multipart field `file` + X-Upload-Id / X-Validation-* headers -> 200 approved
  GET  /received  records (optional ?sha256= / ?upload_id=)
  GET  /health
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import threading
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

DATA_DIR = Path(os.environ.get("SINK_DATA_DIR", "/data"))
FILES_DIR = DATA_DIR / "files"
LOG = DATA_DIR / "received.jsonl"
SECRET = os.environ.get("VALIDATION_SECRET", "")
_lock = threading.Lock()
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

app = FastAPI(title="upload-sink", docs_url=None, redoc_url=None)


def _log(**f: object) -> None:
    sys.stdout.write(json.dumps({"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"), **f}) + "\n")
    sys.stdout.flush()


@app.on_event("startup")
def _init() -> None:
    if not SECRET:
        raise RuntimeError("VALIDATION_SECRET is not set")
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    LOG.touch()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "upload-sink"}


def _refuse(reason: str, upload_id: str, client: str | None) -> JSONResponse:
    _log(event="refused", reason=reason, upload_id=upload_id, client=client)
    return JSONResponse({"accepted": False, "status": "refused", "reason_code": reason,
                         "message": "Request did not carry a valid validator approval."}, status_code=403)


@app.post("/upload")
async def upload(request: Request):
    h = request.headers
    client = request.client.host if request.client else None
    upload_id = h.get("x-upload-id", "")
    if not _SAFE_ID.match(upload_id) or h.get("x-validation-status") != "passed":
        return _refuse("NO_APPROVAL", upload_id[:64], client)
    form = await request.form()
    f = form.get("file")
    if f is None or isinstance(f, str):
        return _refuse("NO_FILE", upload_id, client)
    data = await f.read()
    digest = hashlib.sha256(data).hexdigest()
    want = hmac.new(SECRET.encode(), f"{upload_id}.{digest}.{len(data)}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, h.get("x-validation-sig", "")):
        return _refuse("BAD_SIGNATURE", upload_id, client)
    # Storage name comes from the upload ID only. The client filename is metadata.
    (FILES_DIR / f"{upload_id}.csv").write_bytes(data)
    rec = {
        "upload_id": upload_id,
        "received_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
        "client_filename": f.filename or "",
        "sha256": digest,
        "bytes": len(data),
        "validation_status": "passed",
        "validation_signature": "verified",
        "antivirus": "enforced by BIG-IP (ICAP) before delivery; see BIG-IP and icap-av logs",
        "csv_delimiter": h.get("x-csv-delimiter", ""),
        "csv_records": h.get("x-csv-records", ""),
        "csv_columns": h.get("x-csv-columns", ""),
        "validated_at": h.get("x-validated-at", ""),
        "xff": h.get("x-forwarded-for", ""),
    }
    with _lock, LOG.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    _log(event="received", upload_id=upload_id, sha256=digest, bytes=len(data), client=client)
    return JSONResponse({"accepted": True, "upload_id": upload_id, "status": "approved", "sha256": digest, "bytes": len(data)},
                        headers={"X-Upload-Id": upload_id})


@app.get("/received")
def received(sha256: str | None = None, upload_id: str | None = None) -> dict:
    with _lock:
        rows = [json.loads(line) for line in LOG.read_text().splitlines() if line.strip()]
    if sha256:
        rows = [r for r in rows if r["sha256"] == sha256]
    if upload_id:
        rows = [r for r in rows if r["upload_id"] == upload_id]
    return {"count": len(rows), "received": rows}
