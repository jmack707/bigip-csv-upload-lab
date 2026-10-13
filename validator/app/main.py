"""CSV validation service (verdict only).

  ICAP  :1344  REQMOD   called by BIG-IP request-adapt for every upload (see icap_server.py)
  HTTP  :8080  GET /health, GET /ready   monitoring
               POST /upload              validate-only: returns the verdict, delivers nothing

The validator no longer calls antivirus or the upload application. The BIG-IP does the routing:
Advanced WAF -> ICAP antivirus -> this validator (ICAP) -> pool (upload application).
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import icap_server
from .config import settings
from .verdict import evaluate, log


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.VALIDATION_SECRET:
        raise RuntimeError("VALIDATION_SECRET is not set; refusing to start (the sink could not verify approvals).")
    app.state.icap = await icap_server.start() if settings.ICAP_ENABLED else None
    log(event="started", icap_port=settings.ICAP_PORT if settings.ICAP_ENABLED else None)
    yield
    if app.state.icap:
        app.state.icap.close()
        await app.state.icap.wait_closed()


app = FastAPI(title="csv-validator", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "csv-validator"}


@app.get("/ready")
async def ready(request: Request) -> JSONResponse:
    srv = request.app.state.icap
    if settings.ICAP_ENABLED and (srv is None or not srv.is_serving()):
        return JSONResponse({"status": "not-ready", "detail": "ICAP listener down"}, status_code=503)
    return JSONResponse({"status": "ready"})


@app.post("/upload")
async def upload(request: Request) -> JSONResponse:
    """Validate-only. Same checks as the ICAP path; nothing is forwarded anywhere."""
    cl = request.headers.get("content-length")
    declared = int(cl) if cl is not None and cl.isdigit() else None
    if request.headers.get("transfer-encoding", "").lower() == "chunked":
        declared = None
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > settings.MAX_REQUEST_BYTES:
            break
    v = evaluate(request.headers.get("content-type", ""), bytes(buf), declared_length=declared, via="http",
                 client=request.client.host if request.client else None, xff=request.headers.get("x-forwarded-for"))
    return JSONResponse(v.body(), status_code=v.status_code, headers={"X-Upload-Id": v.upload_id})
