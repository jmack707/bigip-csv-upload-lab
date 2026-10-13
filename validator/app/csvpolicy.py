"""CSV grammar validation and the spreadsheet-formula / markup policy.

Two parsers are used on purpose: a strict RFC 4180 state machine (the policy
gate) and Python's csv module (a maintained, well-tested parser). The file is
accepted only if both agree on the records. Neither is regex-based.

This module implements the documented policy only. It does not make a file
"safe to open" in every spreadsheet application.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass

LEADING_WS = " \t\r\n\x0b\x0c"
QUOTE_CHARS = "\"'"
PLAIN_NUMBER_RE = re.compile(r"[+-]?(?:\d+(?:\.\d+)?|\.\d+)")
TAG_LIKE_RE = re.compile(r"<[a-zA-Z!?/]")
SCRIPT_URI_RE = re.compile(r"(?:^|[^a-z])(?:javascript|vbscript):", re.IGNORECASE)
HTML_DATA_URI_RE = re.compile(r"data:text/html", re.IGNORECASE)


class CsvPolicyError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


@dataclass
class CsvReport:
    delimiter: str
    records: int
    columns: int


# --------------------------------------------------------------------------
# Strict RFC 4180 tokenizer
# --------------------------------------------------------------------------
def _tokenize(text: str, delim: str) -> list[list[str] | None]:
    """Return a list of records. A blank line yields None instead of a record.

    Accepts CRLF or LF record terminators. Quoted fields may contain the
    delimiter, quotes doubled as "", and line breaks. A quote anywhere in an
    unquoted field, or anything between a closing quote and the next delimiter
    or line end, is an error. EOF inside a quoted field is an error.
    """
    records: list[list[str] | None] = []
    fields: list[str] = []
    buf: list[str] = []
    i, n = 0, len(text)
    # states: 0 = start of field, 1 = in unquoted field, 2 = in quoted field, 3 = after closing quote
    state = 0
    line_has_content = False

    def end_record() -> None:
        nonlocal fields, buf, line_has_content
        if not line_has_content:
            records.append(None)
        else:
            fields.append("".join(buf))
            records.append(fields)
        fields, buf, line_has_content = [], [], False

    while i < n:
        c = text[i]
        if state == 0:
            if c == '"':
                state, line_has_content = 2, True
            elif c == delim:
                fields.append("")
                line_has_content = True
            elif c == "\r":
                if i + 1 < n and text[i + 1] == "\n":
                    end_record()
                    i += 1
                else:
                    raise CsvPolicyError("CSV_BAD_LINE_ENDING", "Bare carriage return in file.")
            elif c == "\n":
                end_record()
            else:
                buf.append(c)
                state, line_has_content = 1, True
        elif state == 1:
            if c == '"':
                raise CsvPolicyError("CSV_BAD_QUOTING", "Quote character inside an unquoted field.")
            if c == delim:
                fields.append("".join(buf))
                buf = []
                state = 0
            elif c == "\r":
                if i + 1 < n and text[i + 1] == "\n":
                    end_record()
                    state = 0
                    i += 1
                else:
                    raise CsvPolicyError("CSV_BAD_LINE_ENDING", "Bare carriage return in file.")
            elif c == "\n":
                end_record()
                state = 0
            else:
                buf.append(c)
        elif state == 2:
            if c == '"':
                if i + 1 < n and text[i + 1] == '"':
                    buf.append('"')
                    i += 1
                else:
                    state = 3
            else:
                buf.append(c)
        else:  # state 3: just closed a quoted field
            if c == delim:
                fields.append("".join(buf))
                buf = []
                state = 0
            elif c == "\r":
                if i + 1 < n and text[i + 1] == "\n":
                    end_record()
                    state = 0
                    i += 1
                else:
                    raise CsvPolicyError("CSV_BAD_LINE_ENDING", "Bare carriage return in file.")
            elif c == "\n":
                end_record()
                state = 0
            else:
                raise CsvPolicyError("CSV_BAD_QUOTING", "Text after a closing quote.")
        i += 1

    if state == 2:
        raise CsvPolicyError("CSV_UNCLOSED_QUOTE", "Unclosed quoted field at end of file.")
    if state in (1, 3) or line_has_content:
        end_record()  # last record without a trailing newline
    return records


def _count_outside_quotes(line: str, candidates: str) -> dict[str, int]:
    counts = {c: 0 for c in candidates}
    inq = False
    for ch in line:
        if ch == '"':
            inq = not inq
        elif not inq and ch in counts:
            counts[ch] += 1
    return counts


def _first_logical_line(text: str) -> str:
    """The header line including any quoted line breaks."""
    inq = False
    for i, ch in enumerate(text):
        if ch == '"':
            inq = not inq
        elif ch == "\n" and not inq:
            return text[:i]
    return text


def detect_delimiter(text: str, candidates: str) -> str:
    counts = _count_outside_quotes(_first_logical_line(text), candidates)
    best = max(counts.values()) if counts else 0
    if best == 0:
        raise CsvPolicyError("CSV_UNSUPPORTED_DELIMITER", "No supported delimiter (comma, semicolon, TAB) found in the header line.")
    winners = [d for d, c in counts.items() if c == best]
    if len(winners) > 1:
        raise CsvPolicyError("CSV_AMBIGUOUS_DELIMITER", "Header line uses more than one candidate delimiter equally.")
    return winners[0]


# --------------------------------------------------------------------------
# Cell policy
# --------------------------------------------------------------------------
def _normalize(cell: str) -> str:
    s = cell.lstrip(LEADING_WS)
    while s and s[0] in QUOTE_CHARS:
        s = s[1:].lstrip(LEADING_WS)
    return s


def check_cell(cell: str, allow_signed_numbers: bool) -> None:
    """Raise CsvPolicyError if the cell violates the formula or markup policy.

    Formula policy (applied to the cell and, separately, to every line inside a
    multi-line cell): after stripping leading whitespace (space, TAB, CR, LF, VT,
    FF) and any leading quote characters, the value must not begin with = or @.
    It must not begin with + or - unless it is a plain number ([+-]digits[.digits]).
    Markup policy: no tag-like `<x`, `<!`, `<?`, `</` sequences (a letter, !, ? or /
    directly after `<`); no javascript:
    or vbscript: scheme; no data:text/html URI.
    """
    for piece in cell.split("\n"):
        s = _normalize(piece)
        if not s:
            continue
        c0 = s[0]
        if c0 in "=@":
            raise CsvPolicyError("CSV_FORMULA_CELL", "The upload contains a spreadsheet formula cell.")
        if c0 in "+-":
            if not (allow_signed_numbers and PLAIN_NUMBER_RE.fullmatch(s)):
                raise CsvPolicyError("CSV_FORMULA_CELL", "The upload contains a cell starting with + or - that is not a plain number.")
    if TAG_LIKE_RE.search(cell):
        raise CsvPolicyError("CSV_ACTIVE_MARKUP", "The upload contains markup.")
    if SCRIPT_URI_RE.search(re.sub(r"\s", "", cell)) or HTML_DATA_URI_RE.search(cell):
        raise CsvPolicyError("CSV_ACTIVE_CONTENT", "The upload contains a script URI.")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def validate_csv(
    data: bytes,
    *,
    delimiters: str = ",;\t",
    ignore_trailing_blank_lines: bool = False,
    min_columns: int = 2,
    min_records: int = 2,
    allow_signed_numbers: bool = True,
) -> CsvReport:
    if not data:
        raise CsvPolicyError("EMPTY_FILE", "The file is empty.")
    if b"\x00" in data:
        raise CsvPolicyError("INVALID_UTF8", "The file contains NUL bytes (binary or UTF-16 content).")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CsvPolicyError("INVALID_UTF8", "The file is not valid UTF-8.") from exc
    if text.startswith("﻿"):
        text = text[1:]
    if not text.strip(LEADING_WS):
        raise CsvPolicyError("EMPTY_FILE", "The file contains only whitespace.")

    delim = detect_delimiter(text, delimiters)
    raw_records = _tokenize(text, delim)

    # Blank-line policy
    while raw_records and raw_records[-1] is None:
        if not ignore_trailing_blank_lines:
            raise CsvPolicyError("CSV_BLANK_LINE", "Trailing blank line(s) are not allowed.")
        raw_records.pop()
    if any(r is None for r in raw_records):
        raise CsvPolicyError("CSV_BLANK_LINE", "Blank line between records.")
    records: list[list[str]] = [r for r in raw_records if r is not None]

    if len(records) < min_records:
        raise CsvPolicyError("CSV_TOO_FEW_RECORDS", f"At least {min_records} records (header + data) are required.")
    columns = len(records[0])
    if columns < min_columns:
        raise CsvPolicyError("CSV_UNSUPPORTED_DELIMITER", f"Fewer than {min_columns} columns; delimiter not recognised.")
    for idx, rec in enumerate(records):
        if len(rec) != columns:
            raise CsvPolicyError("CSV_FIELD_COUNT", f"Record {idx + 1} has {len(rec)} fields, header has {columns}.")

    # Cross-check with the standard library parser (fail closed on disagreement).
    text_for_csv = text if not ignore_trailing_blank_lines else text.rstrip("\r\n") + "\n"
    try:
        reader = csv.reader(io.StringIO(text_for_csv, newline=""), delimiter=delim, quotechar='"',
                            doublequote=True, strict=True, skipinitialspace=False)
        stdlib = [row for row in reader if row != []]
    except csv.Error as exc:
        raise CsvPolicyError("CSV_BAD_QUOTING", f"CSV parser error: {exc}") from exc
    if stdlib != records:
        raise CsvPolicyError("CSV_PARSER_DISAGREEMENT", "Strict parser and csv module disagree; rejecting.")

    for rec in records:
        for cell in rec:
            check_cell(cell, allow_signed_numbers)

    return CsvReport(delimiter=delim, records=len(records), columns=columns)
