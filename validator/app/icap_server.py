"""Minimal ICAP/1.0 server (RFC 3507) exposing one REQMOD service for BIG-IP request-adapt.

BIG-IP sends each client request here before it reaches the pool. This service answers:
  - approved : ICAP 200 with the ORIGINAL request, plus X-Upload-Id / X-Validation-* headers.
               BIG-IP then forwards that request to the pool (the upload application).
  - rejected : ICAP 200 with an encapsulated HTTP error response (JSON). BIG-IP returns it to
               the client and nothing reaches the pool.
Any client-supplied X-Upload-Id / X-Validation-* / X-Csv-* headers are stripped first.
No 204 is ever returned: an approved request always carries the validator's headers.
"""
from __future__ import annotations

import asyncio
import json

from .config import settings
from .verdict import REASON_PHRASE, Verdict, evaluate, log

ISTAG = '"csv-validator-2"'
STRIP_PREFIXES = ("x-upload-id", "x-validation-", "x-csv-", "x-validated-at")


class IcapError(Exception):
    pass


async def _read_headers(reader: asyncio.StreamReader, limit: int = 65536) -> bytes:
    data = await reader.readuntil(b"\r\n\r\n")
    if len(data) > limit:
        raise IcapError("headers too large")
    return data


async def _read_chunks(reader: asyncio.StreamReader, buf: bytearray, limit: int) -> bool:
    """Read ICAP chunks into buf until a zero chunk. Returns True if the zero chunk carried `ieof`."""
    while True:
        line = (await reader.readuntil(b"\r\n")).strip()
        size_s, _, ext = line.partition(b";")
        size = int(size_s, 16)
        if size == 0:
            await reader.readuntil(b"\r\n")  # blank line after the last chunk
            return b"ieof" in ext
        chunk = await reader.readexactly(size)
        await reader.readexactly(2)
        if len(buf) + size > limit:
            raise IcapError("body too large")
        buf += chunk


def _parse(head: bytes) -> tuple[str, dict[str, str]]:
    lines = head.decode("latin-1").split("\r\n")
    hdrs: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs


def _encap(hdrs: dict[str, str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in hdrs.get("encapsulated", "").split(","):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            out[k] = int(v)
    return out


def _chunked(body: bytes) -> bytes:
    return (f"{len(body):x}\r\n".encode() + body + b"\r\n" if body else b"") + b"0\r\n\r\n"


def _icap_reject(v: Verdict) -> bytes:
    payload = json.dumps(v.body()).encode()
    code = v.status_code
    http = (f"HTTP/1.1 {code} {REASON_PHRASE.get(code, 'Error')}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\nX-Upload-Id: {v.upload_id}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").encode()
    icap = (f"ICAP/1.0 200 OK\r\nISTag: {ISTAG}\r\nServer: csv-validator\r\nConnection: close\r\n"
            f"Encapsulated: res-hdr=0, res-body={len(http)}\r\n\r\n").encode()
    return icap + http + _chunked(payload)


def _icap_approve(v: Verdict, request_line: str, raw_headers: list[str], body: bytes) -> bytes:
    kept = [h for h in raw_headers if not h.split(":", 1)[0].strip().lower().startswith(STRIP_PREFIXES)]
    added = [f"{k}: {val}" for k, val in v.headers_for_sink()]
    http = ("\r\n".join([request_line] + kept + added) + "\r\n\r\n").encode("latin-1")
    icap = (f"ICAP/1.0 200 OK\r\nISTag: {ISTAG}\r\nServer: csv-validator\r\nConnection: close\r\n"
            f"Encapsulated: req-hdr=0, req-body={len(http)}\r\n\r\n").encode()
    return icap + http + _chunked(body)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    client = peer[0] if peer else None
    try:
        head = await asyncio.wait_for(_read_headers(reader), settings.ICAP_READ_TIMEOUT)
        start, ih = _parse(head)
        method = start.split(" ", 1)[0].upper()
        if method == "OPTIONS":
            writer.write((f"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\nService: csv-validator\r\nISTag: {ISTAG}\r\n"
                          "Max-Connections: 32\r\nOptions-TTL: 300\r\nAllow: 204\r\nPreview: 0\r\nTransfer-Preview: *\r\n"
                          "Connection: close\r\nEncapsulated: null-body=0\r\n\r\n").encode())
            return
        if method != "REQMOD":
            writer.write(f"ICAP/1.0 405 Method Not Allowed\r\nISTag: {ISTAG}\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n".encode())
            return
        enc = _encap(ih)
        body_off = enc.get("req-body", enc.get("null-body"))
        if "req-hdr" not in enc or body_off is None:
            raise IcapError("unsupported Encapsulated header")
        http_head = (await asyncio.wait_for(reader.readexactly(body_off), settings.ICAP_READ_TIMEOUT)).decode("latin-1")
        hlines = [ln for ln in http_head.split("\r\n") if ln]
        request_line, raw_headers = hlines[0], hlines[1:]
        hh = {ln.split(":", 1)[0].strip().lower(): ln.split(":", 1)[1].strip() for ln in raw_headers if ":" in ln}

        body = bytearray()
        too_large = False
        if "req-body" in enc:
            try:
                ieof = await asyncio.wait_for(_read_chunks(reader, body, settings.MAX_REQUEST_BYTES), settings.ICAP_READ_TIMEOUT)
                if "preview" in ih and not ieof:
                    writer.write(b"ICAP/1.0 100 Continue\r\n\r\n")
                    await writer.drain()
                    await asyncio.wait_for(_read_chunks(reader, body, settings.MAX_REQUEST_BYTES), settings.ICAP_READ_TIMEOUT)
            except IcapError:
                too_large = True

        parts = request_line.split(" ")
        http_method, target = (parts[0].upper(), parts[1]) if len(parts) >= 2 else ("", "")
        if target.startswith("http://") or target.startswith("https://"):
            target = "/" + target.split("/", 3)[3] if target.count("/") >= 3 else "/"
        xff = hh.get("x-forwarded-for")
        if target != settings.UPLOAD_PATH:
            v = Verdict(False, "none", "NOT_FOUND", "Only the upload URL is served.")
            log(event="rejected", via="icap", reason_code="NOT_FOUND", target=target[:80], client=client, xff=xff)
        elif http_method != "POST":
            v = Verdict(False, "none", "METHOD_NOT_ALLOWED", "Only POST is accepted.")
            log(event="rejected", via="icap", reason_code="METHOD_NOT_ALLOWED", client=client, xff=xff)
        elif too_large:
            v = evaluate("", b"", declared_length=settings.MAX_REQUEST_BYTES + 1, via="icap", client=client, xff=xff)
        else:
            cl = hh.get("content-length")
            declared = int(cl) if cl is not None and cl.isdigit() else None
            if "chunked" in hh.get("transfer-encoding", "").lower():
                declared = None
            v = evaluate(hh.get("content-type", ""), bytes(body), declared_length=declared, via="icap", client=client, xff=xff)
        writer.write(_icap_approve(v, request_line, raw_headers, bytes(body)) if v.accepted else _icap_reject(v))
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError, IcapError, ValueError) as exc:
        # Fail closed: an ICAP error makes BIG-IP apply its service-down action (reset).
        log(event="icap_error", client=client, detail=f"{exc.__class__.__name__}: {exc}"[:160])
        try:
            writer.write(f"ICAP/1.0 500 Server Error\r\nISTag: {ISTAG}\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n".encode())
        except Exception:
            pass
    finally:
        try:
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start() -> asyncio.AbstractServer:
    return await asyncio.start_server(handle, "0.0.0.0", settings.ICAP_PORT, limit=2 * 1024 * 1024)
