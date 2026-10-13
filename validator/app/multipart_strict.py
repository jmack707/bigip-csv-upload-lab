"""Strict multipart/form-data handling on top of python-multipart's streaming parser.

The parser (python-multipart) does the byte-level boundary work; this module adds
the policy: exactly the parts we expect, headers we can reason about, and a
filename that is treated as untrusted metadata.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from python_multipart.multipart import MultipartParser, parse_options_header

# RFC 2046 boundary characters, 1..70 long.
_BOUNDARY_RE = re.compile(rb"^[0-9A-Za-z'()+_,\-./:=? ]{1,70}$")
# RFC 7230 token for header names.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class MultipartError(ValueError):
    """Raised with a reason_code and a message."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


@dataclass
class Part:
    headers: list[tuple[str, str]] = field(default_factory=list)
    data: bytearray = field(default_factory=bytearray)
    finished: bool = False

    def header(self, name: str) -> list[str]:
        name = name.lower()
        return [v for (n, v) in self.headers if n.lower() == name]


@dataclass
class FilePart:
    field_name: str
    filename: str
    content_type: str | None
    data: bytes


def _boundary_from(content_type: str) -> bytes:
    ctype, params = parse_options_header(content_type)
    if ctype != b"multipart/form-data":
        raise MultipartError("NOT_MULTIPART", "Content-Type must be multipart/form-data.")
    boundary = params.get(b"boundary")
    if not boundary or not _BOUNDARY_RE.match(boundary):
        raise MultipartError("MALFORMED_MULTIPART", "Missing or invalid multipart boundary.")
    return boundary


def parse_parts(content_type: str, body: bytes) -> list[Part]:
    """Parse the body into parts. Any parser complaint is a hard reject."""
    boundary = _boundary_from(content_type)
    parts: list[Part] = []
    state = {"name": bytearray(), "value": bytearray(), "ended": False}

    def on_part_begin() -> None:
        parts.append(Part())

    def on_header_field(data: bytes, start: int, end: int) -> None:
        state["name"] += data[start:end]

    def on_header_value(data: bytes, start: int, end: int) -> None:
        state["value"] += data[start:end]

    def on_header_end() -> None:
        name = bytes(state["name"]).decode("latin-1")
        value = bytes(state["value"]).decode("latin-1")
        state["name"].clear()
        state["value"].clear()
        parts[-1].headers.append((name, value))

    def on_headers_finished() -> None:
        pass

    def on_part_data(data: bytes, start: int, end: int) -> None:
        parts[-1].data += data[start:end]

    def on_part_end() -> None:
        parts[-1].finished = True

    def on_end() -> None:
        state["ended"] = True

    parser = MultipartParser(
        boundary,
        {
            "on_part_begin": on_part_begin,
            "on_header_field": on_header_field,
            "on_header_value": on_header_value,
            "on_header_end": on_header_end,
            "on_headers_finished": on_headers_finished,
            "on_part_data": on_part_data,
            "on_part_end": on_part_end,
            "on_end": on_end,
        },
    )
    try:
        parser.write(body)
        parser.finalize()
    except Exception as exc:  # python-multipart raises MultipartParseError and friends
        raise MultipartError("MALFORMED_MULTIPART", f"Malformed multipart body: {exc}") from exc

    if not state["ended"] or not parts or not all(p.finished for p in parts):
        raise MultipartError("MALFORMED_MULTIPART", "Multipart body is truncated or has no closing boundary.")
    return parts


def _check_part_headers(part: Part) -> tuple[str, str | None, str | None]:
    """Return (field name, raw filename or None, content type or None)."""
    for name, value in part.headers:
        if not _TOKEN_RE.match(name):
            raise MultipartError("MALFORMED_MULTIPART", "Invalid part header name.")
        if "\r" in value or "\n" in value or "\x00" in value:
            raise MultipartError("MALFORMED_MULTIPART", "Invalid part header value.")

    cd = part.header("Content-Disposition")
    if len(cd) != 1:
        raise MultipartError("MALFORMED_MULTIPART", "Each part needs exactly one Content-Disposition header.")
    raw_cd = cd[0]
    if "filename*" in raw_cd.lower():
        # RFC 5987 extended parameter: encoding/charset negotiation we refuse to interpret.
        raise MultipartError("FILENAME_ENCODING", "filename*= (RFC 5987) is not accepted.")
    disp, params = parse_options_header(raw_cd.encode("latin-1"))
    if disp != b"form-data":
        raise MultipartError("MALFORMED_MULTIPART", "Content-Disposition must be form-data.")
    name_b = params.get(b"name")
    if not name_b:
        raise MultipartError("MALFORMED_MULTIPART", "Part has no field name.")
    try:
        field_name = name_b.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MultipartError("MALFORMED_MULTIPART", "Non-ASCII field name.") from exc

    filename: str | None = None
    if b"filename" in params:
        fn_b = params[b"filename"]
        try:
            filename = fn_b.decode("ascii")
        except UnicodeDecodeError as exc:
            raise MultipartError("FILENAME_ENCODING", "Filename must be plain ASCII.") from exc
        if "%" in filename:
            # Percent-encoded names are another encoding negotiation we do not do.
            raise MultipartError("FILENAME_ENCODING", "Percent-encoded filename is not accepted.")

    ct = part.header("Content-Type")
    if len(ct) > 1:
        raise MultipartError("MALFORMED_MULTIPART", "Part has more than one Content-Type header.")
    content_type = ct[0].split(";", 1)[0].strip().lower() if ct else None
    return field_name, filename, content_type


_FILENAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,100}\.csv$")


def check_filename(filename: str | None) -> str:
    """Enforce the lab filename policy. Returns the filename if acceptable.

    Policy: 1..100 characters of [A-Za-z0-9_-], then exactly one extension `.csv`
    (lower-case). No path separators, no dots other than the extension, no
    spaces. The value is only ever logged; it is never used as a storage path.
    """
    if filename is None or filename == "":
        raise MultipartError("FILENAME_MISSING", "The file part has no filename.")
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise MultipartError("FILENAME_PATH", "Filename must not contain path components.")
    if not filename.endswith(".csv"):
        raise MultipartError("FILENAME_EXTENSION", "Filename must end in .csv.")
    if not _FILENAME_RE.match(filename):
        raise MultipartError(
            "FILENAME_EXTENSION",
            "Filename must be [A-Za-z0-9_-] with a single .csv extension.",
        )
    return filename


def extract_single_file(content_type: str, body: bytes, file_field: str) -> FilePart:
    """Parse and enforce: exactly one part, named `file_field`, carrying a file."""
    parts = parse_parts(content_type, body)
    found: FilePart | None = None
    for part in parts:
        field_name, filename, part_ct = _check_part_headers(part)
        if field_name != file_field:
            raise MultipartError("UNEXPECTED_PART", f"Unexpected form part '{field_name}'.")
        if filename is None:
            raise MultipartError("FILENAME_MISSING", "The file part has no filename.")
        if found is not None:
            raise MultipartError("UNEXPECTED_PART", "More than one file part.")
        found = FilePart(field_name=field_name, filename=filename, content_type=part_ct, data=bytes(part.data))
    if found is None:
        raise MultipartError("MISSING_FILE_FIELD", f"Form field '{file_field}' is missing.")
    return found
