"""ICAP REQMOD listener, driven over a real socket."""
import asyncio
import hashlib
import hmac
import json

import pytest

from app import icap_server
from app.config import settings

B = "----labboundary"
GOOD = b"id,name\n1,alice\n"


def mp(data=GOOD, filename="a.csv", name="file"):
    return (f'--{B}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: text/csv\r\n\r\n'.encode()
            + data + f"\r\n--{B}--\r\n".encode())


def icap_reqmod(body: bytes, *, method="POST", path="/upload", extra=(), preview=None, content_length=True) -> bytes:
    hdrs = [f"{method} {path} HTTP/1.1", "Host: vip", f"Content-Type: multipart/form-data; boundary={B}"]
    if content_length:
        hdrs.append(f"Content-Length: {len(body)}")
    hdrs += list(extra)
    http = ("\r\n".join(hdrs) + "\r\n\r\n").encode()
    icap = "REQMOD icap://v/validate ICAP/1.0\r\nHost: v\r\nAllow: 204\r\n"
    if preview is not None:
        icap += f"Preview: {preview}\r\n"
    icap += f"Encapsulated: req-hdr=0, req-body={len(http)}\r\n\r\n"
    return icap.encode() + http


def chunk(b: bytes) -> bytes:
    return f"{len(b):x}\r\n".encode() + b + b"\r\n"


async def talk(port, first: bytes, rest: bytes | None = None) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(first)
    await w.drain()
    out = b""
    if rest is not None:
        out = await r.readuntil(b"\r\n\r\n")
        assert out.startswith(b"ICAP/1.0 100"), out
        w.write(rest)
        await w.drain()
        out = b""
    out += await r.read()
    w.close()
    return out


@pytest.fixture
def run(monkeypatch):
    monkeypatch.setattr(settings, "VALIDATION_SECRET", "test-secret")
    monkeypatch.setattr(settings, "ICAP_PORT", 0)

    def _run(coro_factory):
        async def main():
            srv = await icap_server.start()
            port = srv.sockets[0].getsockname()[1]
            try:
                return await coro_factory(port)
            finally:
                srv.close()
                await srv.wait_closed()
        return asyncio.run(main())
    return _run


def split(resp: bytes):
    icap, _, rest = resp.partition(b"\r\n\r\n")
    return icap.decode(), rest


def test_options(run):
    resp = run(lambda p: talk(p, b"OPTIONS icap://v/validate ICAP/1.0\r\nHost: v\r\n\r\n")).decode()
    assert resp.startswith("ICAP/1.0 200") and "Methods: REQMOD" in resp and "ISTag:" in resp


def test_approved_returns_modified_request(run):
    body = mp()
    resp = run(lambda p: talk(p, icap_reqmod(body, extra=["X-Upload-Id: forged", "X-Validation-Sig: forged"]) + chunk(body) + b"0\r\n\r\n"))
    icap, rest = split(resp)
    assert icap.startswith("ICAP/1.0 200") and "req-hdr=0, req-body=" in icap
    http, _, chunks = rest.partition(b"\r\n\r\n")
    h = dict(l.split(": ", 1) for l in http.decode().split("\r\n")[1:])
    assert http.startswith(b"POST /upload HTTP/1.1")
    assert h["X-Upload-Id"].startswith("lab-") and h["X-Upload-Id"] != "forged"
    sha = hashlib.sha256(GOOD).hexdigest()
    assert h["X-Validation-Sha256"] == sha and h["X-Validation-Status"] == "passed"
    want = hmac.new(b"test-secret", f"{h['X-Upload-Id']}.{sha}.{len(GOOD)}".encode(), hashlib.sha256).hexdigest()
    assert h["X-Validation-Sig"] == want
    assert http.decode().count("X-Upload-Id:") == 1 and http.decode().count("X-Validation-Sig:") == 1
    assert chunks == chunk(body) + b"0\r\n\r\n"  # body passed through unchanged


def test_rejected_returns_http_response(run):
    body = mp(b"a,b\n1,=1+1\n")
    icap, rest = split(run(lambda p: talk(p, icap_reqmod(body) + chunk(body) + b"0\r\n\r\n")))
    assert "res-hdr=0, res-body=" in icap
    http, _, chunks = rest.partition(b"\r\n\r\n")
    assert http.startswith(b"HTTP/1.1 422")
    payload = json.loads(chunks.split(b"\r\n")[1])
    assert payload["accepted"] is False and payload["reason_code"] == "CSV_FORMULA_CELL"


def test_preview_then_continue(run):
    body = mp()
    first = icap_reqmod(body, preview=10) + chunk(body[:10]) + b"0\r\n\r\n"
    rest = chunk(body[10:]) + b"0\r\n\r\n"
    icap, _ = split(run(lambda p: talk(p, first, rest)))
    assert "req-hdr=0, req-body=" in icap


def test_preview_ieof(run):
    body = mp()
    icap, _ = split(run(lambda p: talk(p, icap_reqmod(body, preview=4096) + chunk(body) + b"0; ieof\r\n\r\n")))
    assert "req-hdr=0, req-body=" in icap


@pytest.mark.parametrize("kw,code,http", [
    (dict(path="/other"), "NOT_FOUND", b"404"),
    (dict(method="PUT"), "METHOD_NOT_ALLOWED", b"405"),
    (dict(content_length=False), "REQUEST_LENGTH_REQUIRED", b"411"),
    (dict(extra=["Transfer-Encoding: chunked"]), "REQUEST_LENGTH_REQUIRED", b"411"),
])
def test_request_level_rejections(run, kw, code, http):
    body = mp()
    _, rest = split(run(lambda p: talk(p, icap_reqmod(body, **kw) + chunk(body) + b"0\r\n\r\n")))
    head, _, chunks = rest.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 " + http) and json.loads(chunks.split(b"\r\n")[1])["reason_code"] == code


def test_oversized_body(run, monkeypatch):
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 200)
    body = mp(b"a,b\n" + b"1,2\n" * 100)
    _, rest = split(run(lambda p: talk(p, icap_reqmod(body) + chunk(body) + b"0\r\n\r\n")))
    assert rest.startswith(b"HTTP/1.1 413")


def test_garbage_fails_closed(run):
    resp = run(lambda p: talk(p, b"REQMOD icap://v/validate ICAP/1.0\r\nHost: v\r\nEncapsulated: bogus\r\n\r\n"))
    assert resp.startswith(b"ICAP/1.0 500")
