"""One upload in, one verdict out. Shared by the ICAP listener (BIG-IP request-adapt)
and the HTTP validate-only endpoint. No antivirus and no forwarding happen here:
the BIG-IP routes to ICAP antivirus and to the upload application itself."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import secrets
import sys
from dataclasses import dataclass, field

from .config import settings
from .csvpolicy import CsvPolicyError, validate_csv
from .multipart_strict import MultipartError, check_filename, extract_single_file

HTTP_FOR_REASON = {
    "REQUEST_LENGTH_REQUIRED": 411, "REQUEST_TOO_LARGE": 413, "FILE_TOO_LARGE": 413,
    "NOT_MULTIPART": 415, "CONTENT_TYPE": 415, "NOT_FOUND": 404, "METHOD_NOT_ALLOWED": 405,
}
REASON_PHRASE = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 411: "Length Required",
                 413: "Payload Too Large", 415: "Unsupported Media Type", 422: "Unprocessable Entity"}


def http_status(reason_code: str) -> int:
    if reason_code in HTTP_FOR_REASON:
        return HTTP_FOR_REASON[reason_code]
    if reason_code.startswith("CSV_") or reason_code in ("INVALID_UTF8", "EMPTY_FILE"):
        return 422
    return 400


def log(**fields: object) -> None:
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"), **fields}
    sys.stdout.write(json.dumps(rec, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def sign(upload_id: str, sha256: str, nbytes: int) -> str:
    """HMAC the sink uses to prove a request passed through this validator."""
    msg = f"{upload_id}.{sha256}.{nbytes}".encode()
    return hmac.new(settings.VALIDATION_SECRET.encode(), msg, hashlib.sha256).hexdigest()


@dataclass
class Verdict:
    accepted: bool
    upload_id: str
    reason_code: str = ""
    message: str = ""
    sha256: str | None = None
    nbytes: int = 0
    filename: str | None = None
    delimiter: str = ""
    records: int = 0
    columns: int = 0
    validated_at: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"))

    @property
    def status_code(self) -> int:
        return 200 if self.accepted else http_status(self.reason_code)

    def body(self) -> dict:
        if self.accepted:
            return {"accepted": True, "upload_id": self.upload_id, "status": "validated", "sha256": self.sha256, "bytes": self.nbytes}
        return {"accepted": False, "upload_id": self.upload_id, "status": "rejected", "reason_code": self.reason_code, "message": self.message}

    def headers_for_sink(self) -> list[tuple[str, str]]:
        return [
            ("X-Upload-Id", self.upload_id), ("X-Validation-Status", "passed"), ("X-Validation-Sha256", self.sha256 or ""),
            ("X-Validation-Bytes", str(self.nbytes)), ("X-Validation-Sig", sign(self.upload_id, self.sha256 or "", self.nbytes)),
            ("X-Csv-Delimiter", self.delimiter), ("X-Csv-Records", str(self.records)), ("X-Csv-Columns", str(self.columns)),
            ("X-Validated-At", self.validated_at),
        ]


def evaluate(content_type: str, body: bytes, *, declared_length: int | None, via: str, client: str | None = None, xff: str | None = None) -> Verdict:
    """Run every request-level and CSV check. Never raises."""
    upload_id = settings.UPLOAD_ID_PREFIX + secrets.token_hex(8)
    v = Verdict(accepted=False, upload_id=upload_id)
    try:
        if declared_length is None:
            raise MultipartError("REQUEST_LENGTH_REQUIRED", "Content-Length is required; chunked uploads are not accepted.")
        if declared_length > settings.MAX_REQUEST_BYTES or len(body) > settings.MAX_REQUEST_BYTES:
            raise MultipartError("REQUEST_TOO_LARGE", f"Request exceeds {settings.MAX_REQUEST_BYTES} bytes.")
        if declared_length != len(body) or not body:
            raise MultipartError("MALFORMED_REQUEST", "Body is empty or does not match Content-Length.")
        part = extract_single_file(content_type, body, settings.FILE_FIELD)
        v.filename = repr(part.filename)
        check_filename(part.filename)
        ct = part.content_type
        if ct not in settings.ALLOWED_CONTENT_TYPES and not (settings.CONTENT_TYPE_COMPAT and ct in (None, "application/octet-stream")):
            raise MultipartError("CONTENT_TYPE", f"Part Content-Type {ct!r} is not accepted.")
        if len(part.data) == 0:
            raise MultipartError("EMPTY_FILE", "The file is empty.")
        if len(part.data) > settings.MAX_FILE_BYTES:
            raise MultipartError("FILE_TOO_LARGE", f"File exceeds {settings.MAX_FILE_BYTES} bytes.")
        v.sha256, v.nbytes = hashlib.sha256(part.data).hexdigest(), len(part.data)
        report = validate_csv(part.data, delimiters=settings.DELIMITERS,
                              ignore_trailing_blank_lines=settings.IGNORE_TRAILING_BLANK_LINES,
                              min_columns=settings.MIN_COLUMNS, min_records=settings.MIN_RECORDS,
                              allow_signed_numbers=settings.ALLOW_SIGNED_NUMBERS)
        v.accepted = True
        v.delimiter = {",": "comma", ";": "semicolon", "\t": "tab"}[report.delimiter]
        v.records, v.columns = report.records, report.columns
    except (MultipartError, CsvPolicyError) as exc:
        v.reason_code, v.message = exc.reason_code, exc.message
    except Exception as exc:  # fail closed on anything unexpected
        v.reason_code, v.message = "INTERNAL_ERROR", "Validator error; upload rejected (fail closed)."
        log(event="error", upload_id=upload_id, detail=repr(exc)[:200])
    log(event="validated" if v.accepted else "rejected", via=via, upload_id=upload_id, reason_code=v.reason_code or None,
        message=v.message or None, sha256=v.sha256, bytes=v.nbytes, filename=v.filename, client=client, xff=xff,
        csv_delimiter=v.delimiter or None, csv_records=v.records or None, csv_columns=v.columns or None)
    return v
