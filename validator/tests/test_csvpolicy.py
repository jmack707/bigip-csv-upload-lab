import pytest

from app.csvpolicy import CsvPolicyError, check_cell, validate_csv


def ok(data: bytes, **kw):
    return validate_csv(data, **kw)


def bad(data: bytes, code: str, **kw):
    with pytest.raises(CsvPolicyError) as ei:
        validate_csv(data, **kw)
    assert ei.value.reason_code == code, ei.value.message


# ---- accepted -------------------------------------------------------------
def test_basic_comma():
    r = ok(b"id,name\n1,alice\n2,bob\n")
    assert (r.delimiter, r.records, r.columns) == (",", 3, 2)


def test_quoted_fields_embedded_comma_and_newline():
    r = ok(b'id,note\n1,"hello, world"\n2,"line one\nline two"\n')
    assert r.records == 3


def test_escaped_quotes():
    assert ok(b'id,q\n1,"say ""hi"""\n').records == 2


def test_semicolon_and_tab():
    assert ok(b"a;b\n1;2\n").delimiter == ";"
    assert ok(b"a\tb\n1\t2\n").delimiter == "\t"


def test_utf8_accents():
    ok("id,name\n1,Zoë Ångström\n".encode())


def test_crlf_and_no_trailing_newline():
    ok(b"a,b\r\n1,2\r\n")
    ok(b"a,b\n1,2")


def test_negative_and_signed_numbers_accepted():
    ok(b"a,b\n-5,+3.20\n")


def test_phone_like_values_without_plus():
    ok(b"name,phone\nbob,555-0100\nann,(555) 010-0100\n")


def test_trailing_blank_lines_only_when_configured():
    bad(b"a,b\n1,2\n\n", "CSV_BLANK_LINE")
    ok(b"a,b\n1,2\n\n\n", ignore_trailing_blank_lines=True)


# ---- rejected -------------------------------------------------------------
def test_empty_file():
    bad(b"", "EMPTY_FILE")
    bad(b"   \n", "EMPTY_FILE")


def test_json_renamed():
    bad(b'{"a": 1, "b": 2}\n', "CSV_BAD_QUOTING")


def test_html_renamed():
    bad(b"<html><body><p>hi</p></body></html>\n", "CSV_UNSUPPORTED_DELIMITER")
    bad(b"<html>,x\n<p>,y\n", "CSV_ACTIVE_MARKUP")


def test_invalid_utf8_and_utf16():
    bad(b"a,b\n1,\xff\xfe\n", "INVALID_UTF8")
    bad("a,b\n1,2\n".encode("utf-16"), "INVALID_UTF8")


def test_unclosed_quote():
    bad(b'a,b\n1,"open\n', "CSV_UNCLOSED_QUOTE")


def test_quote_inside_unquoted_field():
    bad(b'a,b\n1,ab"c\n', "CSV_BAD_QUOTING")


def test_text_after_closing_quote():
    bad(b'a,b\n1,"x"y\n', "CSV_BAD_QUOTING")


def test_missing_and_extra_column():
    bad(b"a,b\n1\n", "CSV_FIELD_COUNT")
    bad(b"a,b\n1,2,3\n", "CSV_FIELD_COUNT")


def test_blank_line_between_records():
    bad(b"a,b\n1,2\n\n3,4\n", "CSV_BLANK_LINE")


def test_unsupported_delimiter():
    bad(b"a|b\n1|2\n", "CSV_UNSUPPORTED_DELIMITER")


def test_ambiguous_delimiter():
    bad(b"a,b;c\n1,2;3\n", "CSV_AMBIGUOUS_DELIMITER")


def test_too_few_records():
    bad(b"a,b\n", "CSV_TOO_FEW_RECORDS")


def test_bare_cr():
    bad(b"a,b\r1,2\r", "CSV_BAD_LINE_ENDING")


@pytest.mark.parametrize(
    "cell",
    [
        "=1+1", "@SUM(A1)", "+cmd|' /C calc'!A0", "-2+3", "  =1", "\t=1", '"=1+1"', "'=1",
        "=HYPERLINK(\"http://x\")", "abc\n=1", "+1 555 0100", "-",
    ],
)
def test_formula_cells(cell):
    with pytest.raises(CsvPolicyError) as ei:
        check_cell(cell, allow_signed_numbers=True)
    assert ei.value.reason_code == "CSV_FORMULA_CELL"


@pytest.mark.parametrize("cell", ["-5", "+3.20", "-.5", "0", "555-0100", "a=b", "x@y.com", "price+tax", "", "   "])
def test_non_formula_cells(cell):
    check_cell(cell, allow_signed_numbers=True)


def test_signed_numbers_can_be_disallowed():
    with pytest.raises(CsvPolicyError):
        check_cell("-5", allow_signed_numbers=False)


def test_formula_in_file_rejected_even_when_quoted():
    bad(b'a,b\n1,"=1+1"\n', "CSV_FORMULA_CELL")
    bad(b'a,b\n1,"x\n=1+1"\n', "CSV_FORMULA_CELL")


@pytest.mark.parametrize("cell,code", [
    ("<script>alert(1)</script>", "CSV_ACTIVE_MARKUP"),
    ("<!DOCTYPE html>", "CSV_ACTIVE_MARKUP"),
    ("javascript:alert(1)", "CSV_ACTIVE_CONTENT"),
    ("JAVA SCRIPT:x", "CSV_ACTIVE_CONTENT"),
    ("data:text/html;base64,AAAA", "CSV_ACTIVE_CONTENT"),
])
def test_markup_policy(cell, code):
    with pytest.raises(CsvPolicyError) as ei:
        check_cell(cell, allow_signed_numbers=True)
    assert ei.value.reason_code == code


def test_markup_policy_allows_plain_text():
    check_cell("a < b and b > c", True)
    check_cell("metadata: fine", True)
