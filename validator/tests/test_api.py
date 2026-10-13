"""HTTP validate-only endpoint."""
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

B = "----labboundary"
CT = f"multipart/form-data; boundary={B}"
GOOD = b"id,name\n1,alice\n"


def mp(parts, close=True):
    out = b""
    for headers, data in parts:
        out += f"--{B}\r\n{headers}\r\n\r\n".encode() + data + b"\r\n"
    return out + (f"--{B}--\r\n".encode() if close else b"")


def fpart(name="file", filename="a.csv", ctype="text/csv", data=GOOD):
    h = f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'
    return (h + (f"\r\nContent-Type: {ctype}" if ctype else ""), data)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "VALIDATION_SECRET", "test-secret")
    monkeypatch.setattr(settings, "ICAP_ENABLED", False)
    with TestClient(app) as c:
        yield c


def post(client, body, ct=CT):
    return client.post("/upload", content=body, headers={"Content-Type": ct, "Content-Length": str(len(body))})


def test_health_ready(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").status_code == 200


def test_validated(client):
    r = post(client, mp([fpart()]))
    j = r.json()
    assert r.status_code == 200 and j["accepted"] is True and j["status"] == "validated" and j["bytes"] == len(GOOD)
    assert r.headers["X-Upload-Id"] == j["upload_id"]


def test_rejected_shape(client):
    r = post(client, mp([fpart(data=b"a,b\n1,=1+1\n")]))
    j = r.json()
    assert r.status_code == 422
    assert j == {"accepted": False, "upload_id": j["upload_id"], "status": "rejected", "reason_code": "CSV_FORMULA_CELL", "message": j["message"]}


@pytest.mark.parametrize("parts,code,http", [
    ([fpart(name="upload")], "UNEXPECTED_PART", 400),
    ([("Content-Disposition: form-data; name=\"note\"", b"x")], "UNEXPECTED_PART", 400),
    ([fpart(), fpart(filename="b.csv")], "UNEXPECTED_PART", 400),
    ([fpart(filename="a.txt")], "FILENAME_EXTENSION", 400),
    ([fpart(filename="a.csv.exe")], "FILENAME_EXTENSION", 400),
    ([fpart(ctype="text/plain")], "CONTENT_TYPE", 415),
    ([fpart(ctype=None)], "CONTENT_TYPE", 415),
    ([fpart(data=b"")], "EMPTY_FILE", 422),
    ([fpart(data=b"a,b\n1,\xff\n")], "INVALID_UTF8", 422),
])
def test_rejections(client, parts, code, http):
    r = post(client, mp(parts))
    assert (r.status_code, r.json()["reason_code"]) == (http, code), r.text


def test_malformed_and_not_multipart(client):
    assert post(client, b"\x00\x01garbage").json()["reason_code"] == "MALFORMED_MULTIPART"
    r = post(client, b"{}", ct="application/json")
    assert (r.status_code, r.json()["reason_code"]) == (415, "NOT_MULTIPART")


def test_size_limits(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_FILE_BYTES", 10)
    r = post(client, mp([fpart(data=b"a,b\n" + b"1,2\n" * 10)]))
    assert (r.status_code, r.json()["reason_code"]) == (413, "FILE_TOO_LARGE")
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 50)
    r = post(client, mp([fpart()]))
    assert (r.status_code, r.json()["reason_code"]) == (413, "REQUEST_TOO_LARGE")


def test_chunked_rejected(client):
    r = client.post("/upload", content=iter([mp([fpart()])]), headers={"Content-Type": CT, "Transfer-Encoding": "chunked"})
    assert (r.status_code, r.json()["reason_code"]) == (411, "REQUEST_LENGTH_REQUIRED")


def test_refuses_to_start_without_secret(monkeypatch):
    monkeypatch.setattr(settings, "VALIDATION_SECRET", "")
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass
